package piivault

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

// recordingBus captures published invalidations and lets a test deliver them, so
// the two halves of cross-replica invalidation can be exercised without a broker.
type recordingBus struct {
	mu        sync.Mutex
	published [][]byte
	failWith  error

	subs []func([]byte)
	// stop closes to end a Subscribe call, standing in for a dropped connection.
	stop chan struct{}
}

func newRecordingBus() *recordingBus { return &recordingBus{stop: make(chan struct{})} }

func (b *recordingBus) Publish(_ context.Context, _ string, message []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failWith != nil {
		return b.failWith
	}
	b.published = append(b.published, append([]byte(nil), message...))
	return nil
}

func (b *recordingBus) Subscribe(ctx context.Context, _ string, fn func([]byte)) error {
	b.mu.Lock()
	b.subs = append(b.subs, fn)
	b.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.stop:
		return errors.New("connection dropped")
	}
}

// deliver simulates a message arriving from another replica.
func (b *recordingBus) deliver(message string) {
	b.mu.Lock()
	subs := append([]func([]byte){}, b.subs...)
	b.mu.Unlock()
	for _, fn := range subs {
		fn([]byte(message))
	}
}

func (b *recordingBus) publishedIDs() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.published))
	for _, m := range b.published {
		out = append(out, string(m))
	}
	return out
}

func newTestCache(t *testing.T, bus *recordingBus, ttl time.Duration) *KeyCache {
	t.Helper()
	kc, err := NewKeyCache(KeyCacheOptions{TTL: ttl, Capacity: 8, Bus: bus})
	if err != nil {
		t.Fatalf("NewKeyCache: %v", err)
	}
	return kc
}

// A key cache with no way to hear about erasures elsewhere is not a degraded
// cache, it is an incorrect one. Building must fail rather than silently produce
// a TTL-only cache that works in development and leaks in production.
func TestNewKeyCacheRequiresBus(t *testing.T) {
	_, err := NewKeyCache(KeyCacheOptions{TTL: time.Minute, Capacity: 8})
	if err == nil {
		t.Fatal("expected NewKeyCache to refuse a cache with no invalidation bus")
	}
	if !strings.Contains(err.Error(), "Bus") && !strings.Contains(err.Error(), "bus") {
		t.Fatalf("error should name the missing bus, got %q", err)
	}
}

// The cache must hand out copies. If it returned its own slice, a caller's
// ordinary `defer crypto.Zero(dek)` would blank the cached entry and every later
// hit would decrypt with zeroes.
func TestGetReturnsCopyNotCachedSlice(t *testing.T) {
	kc := newTestCache(t, newRecordingBus(), time.Minute)
	original := []byte("0123456789abcdef0123456789abcdef")
	kc.put("subj_1", original)

	first, erased, ok := kc.get("subj_1")
	if !ok || erased {
		t.Fatalf("expected a live cached key, got ok=%v erased=%v", ok, erased)
	}
	// Exactly what a caller does with a key it is finished with.
	for i := range first {
		first[i] = 0
	}

	second, _, ok := kc.get("subj_1")
	if !ok {
		t.Fatal("second read missed; the cache entry was destroyed by the caller")
	}
	if string(second) != string(original) {
		t.Fatalf("cached key was mutated through the returned slice: got %q", second)
	}

	// And the caller's own copy must not alias the stored one either way.
	original[0] = 'X'
	if third, _, _ := kc.get("subj_1"); third[0] == 'X' {
		t.Fatal("cache aliases the slice it was given; a caller can mutate it after Put")
	}
}

// Invalidation must survive a concurrent read that is about to write the same key
// back. This is the race the sticky tombstone exists for: reader fetches the
// wrapped key, erasure happens, reader finishes unwrapping and caches it.
func TestInvalidateBeatsConcurrentWriteBack(t *testing.T) {
	kc := newTestCache(t, newRecordingBus(), time.Minute)
	dek := []byte("0123456789abcdef0123456789abcdef")

	// The reader has already read from PostgreSQL and is about to cache.
	if err := kc.Invalidate(context.Background(), "subj_1"); err != nil {
		t.Fatalf("Invalidate: %v", err)
	}
	kc.put("subj_1", dek) // arrives late, carrying a key that no longer exists

	got, erased, ok := kc.get("subj_1")
	if !ok {
		t.Fatal("expected the tombstone to remain cached")
	}
	if !erased || got != nil {
		t.Fatalf("a destroyed key was written back into the cache: erased=%v key=%q", erased, got)
	}
}

// Erasure travels to other replicas, and arriving invalidations are applied.
func TestInvalidatePublishesAndWatchApplies(t *testing.T) {
	bus := newRecordingBus()
	// Two caches over one bus: this replica, and another one.
	local := newTestCache(t, bus, time.Minute)
	remote := newTestCache(t, bus, time.Minute)

	remote.put("subj_1", []byte("0123456789abcdef0123456789abcdef"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watching := make(chan struct{})
	go func() { close(watching); _ = remote.Watch(ctx) }()
	<-watching
	// Wait for Subscribe to have registered before publishing.
	waitFor(t, func() bool {
		bus.mu.Lock()
		defer bus.mu.Unlock()
		return len(bus.subs) > 0
	})

	if err := local.Invalidate(ctx, "subj_1"); err != nil {
		t.Fatalf("Invalidate: %v", err)
	}
	if ids := bus.publishedIDs(); len(ids) != 1 || ids[0] != "subj_1" {
		t.Fatalf("expected the subject id to be published, got %v", ids)
	}

	bus.deliver("subj_1")
	waitFor(t, func() bool {
		_, erased, ok := remote.get("subj_1")
		return ok && erased
	})
}

// A publish failure must surface. The durable erasure succeeded, so the operation
// is safe to retry — but silently accepting it would leave other replicas holding
// a destroyed key with nobody aware.
func TestInvalidateReportsPublishFailure(t *testing.T) {
	bus := newRecordingBus()
	bus.failWith = errors.New("valkey down")
	kc := newTestCache(t, bus, time.Minute)
	kc.put("subj_1", []byte("0123456789abcdef0123456789abcdef"))

	err := kc.Invalidate(context.Background(), "subj_1")
	if err == nil {
		t.Fatal("expected a failed publish to be reported")
	}
	// Whatever happened to the other replicas, THIS one must already be correct.
	if _, erased, ok := kc.get("subj_1"); !ok || !erased {
		t.Fatal("local cache still holds the key after a failed publish")
	}
}

// A dropped subscription may have missed an invalidation, and there is no way to
// learn which. Every key held becomes suspect, so the cache purges.
func TestWatchPurgesWhenSubscriptionDrops(t *testing.T) {
	bus := newRecordingBus()
	kc := newTestCache(t, bus, time.Minute)
	kc.put("subj_1", []byte("0123456789abcdef0123456789abcdef"))
	kc.put("subj_2", []byte("fedcba9876543210fedcba9876543210"))

	done := make(chan error, 1)
	go func() { done <- kc.Watch(context.Background()) }()
	waitFor(t, func() bool {
		bus.mu.Lock()
		defer bus.mu.Unlock()
		return len(bus.subs) > 0
	})

	close(bus.stop)
	if err := <-done; err == nil {
		t.Fatal("expected Watch to report the dropped subscription")
	}
	if n := kc.Len(); n != 0 {
		t.Fatalf("expected every cached key to be purged after a dropped subscription, %d remain", n)
	}
}

// Expiry must free the key, not merely hide it: a destroyed key left resident in
// memory is the thing this cache is not allowed to do.
func TestSweepRemovesExpiredKeys(t *testing.T) {
	bus := newRecordingBus()
	kc := newTestCache(t, bus, 20*time.Millisecond)
	kc.put("subj_1", []byte("0123456789abcdef0123456789abcdef"))

	if kc.Sweep() != 0 {
		t.Fatal("a live key was swept")
	}
	time.Sleep(40 * time.Millisecond)
	if swept := kc.Sweep(); swept != 1 {
		t.Fatalf("expected 1 expired key swept, got %d", swept)
	}
	if kc.Len() != 0 {
		t.Fatal("expired key still resident after Sweep")
	}
}

// ---- Erase, end to end through the vault ---------------------------------

// noopTX satisfies db.SystemTX without a database. Every statement the vault
// runs against it succeeds and returns nothing, which is all Erase needs: what is
// under test is what happens to the CACHE once the durable erasure has succeeded.
type noopTX struct{ err error }

func (t noopTX) InSystemTx(ctx context.Context, fn func(context.Context, db.Querier) error) error {
	if t.err != nil {
		return t.err
	}
	return fn(ctx, noopQuerier{})
}

type noopQuerier struct{}

func (noopQuerier) Exec(context.Context, string, ...any) (int64, error) { return 1, nil }
func (noopQuerier) Query(context.Context, string, ...any) (db.Rows, error) {
	return nil, errors.New("not used")
}
func (noopQuerier) QueryRow(context.Context, string, ...any) db.Row { return noopRow{} }

type noopRow struct{}

func (noopRow) Scan(...any) error { return errors.New("not used") }

// Erasing must destroy the cached key, not just the stored one. A key still
// cached after its own destruction makes the erasure a lie until the TTL expires.
func TestEraseInvalidatesCachedKey(t *testing.T) {
	bus := newRecordingBus()
	kc := newTestCache(t, bus, time.Minute)
	v := New(noopTX{}, nil, WithKeyCache(kc))

	if !v.HasKeyCache() {
		t.Fatal("WithKeyCache did not attach the cache")
	}
	kc.put("subj_1", []byte("0123456789abcdef0123456789abcdef"))

	if err := v.Erase(context.Background(), "subj_1"); err != nil {
		t.Fatalf("Erase: %v", err)
	}
	if dek, erased, ok := kc.get("subj_1"); dek != nil || !ok || !erased {
		t.Fatalf("cached key survived erasure: key=%q erased=%v cached=%v", dek, erased, ok)
	}
	if ids := bus.publishedIDs(); len(ids) != 1 || ids[0] != "subj_1" {
		t.Fatalf("erasure was not published to other replicas, got %v", ids)
	}
}

// A failed durable erasure must NOT be reported as success, and must not be
// papered over by a successful cache invalidation.
func TestEraseReportsDatabaseFailure(t *testing.T) {
	bus := newRecordingBus()
	kc := newTestCache(t, bus, time.Minute)
	v := New(noopTX{err: errors.New("postgres down")}, nil, WithKeyCache(kc))

	if err := v.Erase(context.Background(), "subj_1"); err == nil {
		t.Fatal("expected the database failure to surface")
	}
	if ids := bus.publishedIDs(); len(ids) != 0 {
		t.Fatalf("erasure was announced despite failing, got %v", ids)
	}
}

// Without a cache the vault must still work — the absent cache is the SLOW path,
// never a broken one.
func TestEraseWithoutCache(t *testing.T) {
	v := New(noopTX{}, nil)
	if v.HasKeyCache() {
		t.Fatal("no cache was configured yet HasKeyCache reports one")
	}
	if err := v.Erase(context.Background(), pii.SubjectID("subj_1")); err != nil {
		t.Fatalf("Erase without a cache: %v", err)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met within 2s")
}

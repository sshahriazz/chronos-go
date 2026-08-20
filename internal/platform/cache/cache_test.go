package cache_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/cache"
)

// ---- keys ----------------------------------------------------------------

func TestNamespaceKey(t *testing.T) {
	ns := cache.Namespace("session")

	got, err := ns.Key("org_1", "user_2")
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	if want := "session:org_1:user_2"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	// A key part carrying the separator could address another namespace's
	// entries. Rejected rather than escaped.
	for _, bad := range [][]string{
		{"org:1"},
		{""},
		{},
	} {
		if _, err := ns.Key(bad...); !errors.Is(err, cache.ErrBadKey) {
			t.Fatalf("Key(%q) should be rejected, got %v", bad, err)
		}
	}
	if _, err := cache.Namespace("").Key("x"); !errors.Is(err, cache.ErrBadKey) {
		t.Fatal("an empty namespace should be rejected")
	}
}

func TestValidateTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second} {
		if err := cache.ValidateTTL(ttl); !errors.Is(err, cache.ErrNoTTL) {
			t.Fatalf("ValidateTTL(%s) should be rejected, got %v", ttl, err)
		}
	}
	if err := cache.ValidateTTL(time.Millisecond); err != nil {
		t.Fatalf("ValidateTTL(1ms): %v", err)
	}
}

// ---- Memo ----------------------------------------------------------------

func TestMemoExpiresAndDisposes(t *testing.T) {
	now := time.Unix(0, 0)
	var disposed []string
	m := cache.NewMemo[string](cache.MemoOptions[string]{
		TTL: time.Minute, Capacity: 4,
		Now:     func() time.Time { return now },
		Dispose: func(v string) { disposed = append(disposed, v) },
	})

	m.Put("a", "value-a")
	if v, ok := m.Get("a"); !ok || v != "value-a" {
		t.Fatalf("expected a live entry, got %q ok=%v", v, ok)
	}

	now = now.Add(time.Minute) // exactly at expiry: expired, not live
	if _, ok := m.Get("a"); ok {
		t.Fatal("an entry at its expiry instant must be treated as expired")
	}
	if len(disposed) != 1 || disposed[0] != "value-a" {
		t.Fatalf("expiry must dispose the value, got %v", disposed)
	}
	if m.Len() != 0 {
		t.Fatal("an expired entry must be removed, not merely hidden")
	}
}

func TestMemoEvictsLeastRecentlyUsed(t *testing.T) {
	var disposed []string
	m := cache.NewMemo[string](cache.MemoOptions[string]{
		TTL: time.Minute, Capacity: 2,
		Dispose: func(v string) { disposed = append(disposed, v) },
	})

	m.Put("a", "A")
	m.Put("b", "B")
	m.Get("a") // a is now the most recently used
	m.Put("c", "C")

	if _, ok := m.Get("b"); ok {
		t.Fatal("b was least recently used and should have been evicted")
	}
	if _, ok := m.Get("a"); !ok {
		t.Fatal("a was recently used and should have survived")
	}
	if len(disposed) != 1 || disposed[0] != "B" {
		t.Fatalf("eviction must dispose the value, got %v", disposed)
	}
	if m.Len() != 2 {
		t.Fatalf("capacity exceeded: %d entries", m.Len())
	}
}

// PutIf decides and writes under one lock. Without that atomicity an
// invalidation can be undone by a write that was already in flight.
func TestMemoPutIfIsAtomic(t *testing.T) {
	m := cache.NewMemo[string](cache.MemoOptions[string]{TTL: time.Minute, Capacity: 4})
	m.Put("a", "tombstone")

	if m.PutIf("a", "live", func(existing string, found bool) bool {
		return !found || existing != "tombstone"
	}) {
		t.Fatal("PutIf wrote despite allow returning false")
	}
	if v, _ := m.Get("a"); v != "tombstone" {
		t.Fatalf("value was overwritten: %q", v)
	}

	if !m.PutIf("b", "live", func(string, bool) bool { return true }) {
		t.Fatal("PutIf refused an allowed write")
	}
	if v, _ := m.Get("b"); v != "live" {
		t.Fatalf("allowed write did not land: %q", v)
	}
}

// An expired entry must be reported to allow as ABSENT. Reporting a stale value
// would let a caller make its decision on data that no longer exists.
func TestMemoPutIfTreatsExpiredAsAbsent(t *testing.T) {
	now := time.Unix(0, 0)
	m := cache.NewMemo[string](cache.MemoOptions[string]{
		TTL: time.Minute, Capacity: 4, Now: func() time.Time { return now },
	})
	m.Put("a", "old")
	now = now.Add(2 * time.Minute)

	var sawFound bool
	m.PutIf("a", "new", func(_ string, found bool) bool { sawFound = found; return true })
	if sawFound {
		t.Fatal("an expired entry was reported as present")
	}
	if v, _ := m.Get("a"); v != "new" {
		t.Fatalf("write did not land: %q", v)
	}
}

func TestMemoPurgeAndSweep(t *testing.T) {
	now := time.Unix(0, 0)
	var disposed int
	m := cache.NewMemo[string](cache.MemoOptions[string]{
		TTL: time.Minute, Capacity: 8,
		Now:     func() time.Time { return now },
		Dispose: func(string) { disposed++ },
	})
	m.Put("a", "A")
	now = now.Add(2 * time.Minute)
	m.Put("b", "B") // fresh

	if swept := m.Sweep(); swept != 1 {
		t.Fatalf("expected 1 expired entry swept, got %d", swept)
	}
	if m.Len() != 1 {
		t.Fatalf("sweep removed the wrong entries: %d remain", m.Len())
	}
	if purged := m.Purge(); purged != 1 {
		t.Fatalf("expected 1 entry purged, got %d", purged)
	}
	if disposed != 2 {
		t.Fatalf("every removed value must be disposed, got %d", disposed)
	}
}

// Concurrent misses for one key must produce one load, not N. Otherwise a
// popular key expiring under load stampedes the source.
func TestMemoLoadCollapsesConcurrentMisses(t *testing.T) {
	m := cache.NewMemo[string](cache.MemoOptions[string]{TTL: time.Minute, Capacity: 4})
	var loads atomic.Int32
	release := make(chan struct{})

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			_, _ = m.Load(context.Background(), "a", "a", func(context.Context) (string, error) {
				loads.Add(1)
				<-release
				return "A", nil
			})
		})
	}
	// Let them all pile up on the same key before the loader returns.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if n := loads.Load(); n != 1 {
		t.Fatalf("expected a single load for 20 concurrent misses, got %d", n)
	}
}

func TestMemoRequiresBounds(t *testing.T) {
	for name, opts := range map[string]cache.MemoOptions[string]{
		"no ttl":      {Capacity: 1},
		"no capacity": {TTL: time.Minute},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("expected a panic: both bounds are what make Memo safe")
				}
			}()
			cache.NewMemo[string](opts)
		})
	}
}

// ---- Store ---------------------------------------------------------------

// fakeCache is an in-memory Cache that can be told to fail, so degradation is
// testable without stopping a server.
type fakeCache struct {
	mu     sync.Mutex
	items  map[string][]byte
	ttls   map[string]time.Duration
	getErr error
	setErr error
}

func newFakeCache() *fakeCache {
	return &fakeCache{items: map[string][]byte{}, ttls: map[string]time.Duration{}}
}

func (f *fakeCache) Get(_ context.Context, key string) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, false, f.getErr
	}
	v, ok := f.items[key]
	return v, ok, nil
}

func (f *fakeCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	if err := cache.ValidateTTL(ttl); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setErr != nil {
		return f.setErr
	}
	f.items[key] = value
	f.ttls[key] = ttl
	return nil
}

func (f *fakeCache) Delete(_ context.Context, keys ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range keys {
		delete(f.items, k)
	}
	return nil
}

type value struct {
	Name string `json:"name"`
}

func newStore(t *testing.T, c cache.Cache, ttl time.Duration) *cache.Store[value] {
	t.Helper()
	s, err := cache.NewStore(c, cache.StoreOptions[value]{Namespace: "test", TTL: ttl})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

// A TTL is a decision the caller must make. Defaulting it would apply a number
// nobody chose to data nobody thought about.
func TestNewStoreRequiresNamespaceAndTTL(t *testing.T) {
	c := newFakeCache()
	if _, err := cache.NewStore(c, cache.StoreOptions[value]{TTL: time.Minute}); err == nil {
		t.Fatal("expected a missing namespace to be rejected")
	}
	if _, err := cache.NewStore(c, cache.StoreOptions[value]{Namespace: "test"}); !errors.Is(err, cache.ErrNoTTL) {
		t.Fatalf("expected a missing TTL to be rejected, got %v", err)
	}
	if _, err := cache.NewStore[value](nil, cache.StoreOptions[value]{Namespace: "t", TTL: time.Minute}); err == nil {
		t.Fatal("expected a nil Cache to be rejected")
	}
}

func TestStoreRoundTripAppliesTTL(t *testing.T) {
	c := newFakeCache()
	s := newStore(t, c, 30*time.Second)

	if err := s.Set(context.Background(), value{Name: "a"}, "k1"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, ok := s.Get(context.Background(), "k1")
	if !ok || got.Name != "a" {
		t.Fatalf("round trip failed: %+v ok=%v", got, ok)
	}
	if ttl := c.ttls["test:k1"]; ttl != 30*time.Second {
		t.Fatalf("entry stored with TTL %s, want 30s", ttl)
	}
}

// An unreachable cache must read as a miss. Anything else forces every call site
// to handle an error whose only correct response is to consult the source —
// which is how a Valkey restart turns into a 500.
func TestStoreReadFailureIsAMiss(t *testing.T) {
	c := newFakeCache()
	c.getErr = errors.New("valkey down")
	s := newStore(t, c, time.Minute)

	if _, ok := s.Get(context.Background(), "k1"); ok {
		t.Fatal("a failed read reported a hit")
	}

	loaded, err := s.Load(context.Background(),
		func(context.Context) (value, error) { return value{Name: "from-source"}, nil }, "k1")
	if err != nil {
		t.Fatalf("Load must survive an unreachable cache, got %v", err)
	}
	if loaded.Name != "from-source" {
		t.Fatalf("Load returned %+v", loaded)
	}
}

// A write failure must not fail the caller: the value was loaded successfully,
// and failing because the optimisation failed inverts the point of caching.
func TestStoreLoadSurvivesWriteFailure(t *testing.T) {
	c := newFakeCache()
	c.setErr = errors.New("valkey read-only")
	s := newStore(t, c, time.Minute)

	got, err := s.Load(context.Background(),
		func(context.Context) (value, error) { return value{Name: "x"}, nil }, "k1")
	if err != nil {
		t.Fatalf("Load should have survived the write failure, got %v", err)
	}
	if got.Name != "x" {
		t.Fatalf("got %+v", got)
	}
}

// A value this build cannot decode was written by another one. Serving it would
// mean returning a shape whose fields no longer mean what they did.
func TestStoreDropsUndecodableEntry(t *testing.T) {
	c := newFakeCache()
	c.items["test:k1"] = []byte("{not json")
	s := newStore(t, c, time.Minute)

	if _, ok := s.Get(context.Background(), "k1"); ok {
		t.Fatal("an undecodable entry was served")
	}
	c.mu.Lock()
	_, still := c.items["test:k1"]
	c.mu.Unlock()
	if still {
		t.Fatal("an undecodable entry was left in place to fail again")
	}
}

func TestStoreLoadCollapsesConcurrentMisses(t *testing.T) {
	s := newStore(t, newFakeCache(), time.Minute)
	var loads atomic.Int32
	release := make(chan struct{})

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			_, _ = s.Load(context.Background(), func(context.Context) (value, error) {
				loads.Add(1)
				<-release
				return value{Name: "a"}, nil
			}, "k1")
		})
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if n := loads.Load(); n != 1 {
		t.Fatalf("expected a single load for 20 concurrent misses, got %d", n)
	}
}

func TestStoreLoadPropagatesSourceError(t *testing.T) {
	s := newStore(t, newFakeCache(), time.Minute)
	sentinel := errors.New("source down")

	_, err := s.Load(context.Background(),
		func(context.Context) (value, error) { return value{}, sentinel }, "k1")
	if !errors.Is(err, sentinel) {
		t.Fatalf("a source failure must reach the caller, got %v", err)
	}
}

func TestStoreDeleteRejectsBadKey(t *testing.T) {
	s := newStore(t, newFakeCache(), time.Minute)
	if err := s.Delete(context.Background(), "a:b"); !errors.Is(err, cache.ErrBadKey) {
		t.Fatalf("expected a separator in a key part to be rejected, got %v", err)
	}
	if err := s.Set(context.Background(), value{}, "a:b"); !errors.Is(err, cache.ErrBadKey) {
		t.Fatalf("expected Set to reject the same key, got %v", err)
	}
}

func TestStoreName(t *testing.T) {
	if got := newStore(t, newFakeCache(), time.Minute).Name(); !strings.EqualFold(got, "test") {
		t.Fatalf("Name() = %q", got)
	}
}

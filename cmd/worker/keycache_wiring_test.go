package main

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/piivault"
	"github.com/chronos/chronos-go/internal/platform/config"
)

// The key cache is only safe because erasures propagate between replicas, and
// that propagation is started HERE — by the composition root, not by the cache
// itself. A cache built, handed to the vault and then left with nobody running
// Watch holds keys that no erasure can reach, and nothing at runtime says so.
//
// This asserts the duties are actually started. It deliberately does NOT go
// through newDependencies: constructing a Valkey client dials eagerly, so a test
// that did would pass only where the stack is running and fail in CI. The
// end-to-end version lives in the integration build.
func TestStartKeyCacheRunsItsDuties(t *testing.T) {
	bus := &countingBus{subscribed: make(chan struct{}, 1), stop: make(chan struct{})}
	kc, err := piivault.NewKeyCache(piivault.KeyCacheOptions{
		TTL: time.Minute, Capacity: 8, Bus: bus, Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("NewKeyCache: %v", err)
	}

	d := &dependencies{keyCache: kc, cacheTTL: time.Minute,
		cacheEvery: 10 * time.Millisecond, cacheRetry: 10 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.startKeyCache(ctx, slog.New(slog.DiscardHandler))

	select {
	case <-bus.subscribed:
	case <-time.After(2 * time.Second):
		t.Fatal("startKeyCache did not subscribe: erasures published by other replicas " +
			"would never reach this process's cached keys")
	}

	// A dropped subscription must be retried, not given up on.
	close(bus.stop)
	deadline := time.Now().Add(5 * time.Second)
	for bus.subscribeCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("a dropped subscription was never retried")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Called on the shutdown path as well as the startup one, so a cancelled context
// must be a clean no-op rather than a spin or a panic.
func TestStartKeyCacheHandlesCancelledContext(t *testing.T) {
	bus := &countingBus{subscribed: make(chan struct{}, 1), stop: make(chan struct{})}
	kc, err := piivault.NewKeyCache(piivault.KeyCacheOptions{
		TTL: time.Minute, Capacity: 8, Bus: bus, Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("NewKeyCache: %v", err)
	}
	d := &dependencies{keyCache: kc, cacheTTL: time.Minute, cacheEvery: time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d.startKeyCache(ctx, slog.New(slog.DiscardHandler))
}

// With no cache the worker must still start. An absent cache is the SLOW path,
// never a broken one.
func TestStartKeyCacheWithoutACache(t *testing.T) {
	d := &dependencies{}
	d.startKeyCache(context.Background(), slog.New(slog.DiscardHandler))
}

// The configured defaults must satisfy the constraints the cache relies on,
// checked against the same config the binary loads.
func TestKeyCacheConfigDefaultsAreSafe(t *testing.T) {
	cfg := testConfig(t)
	if cfg.Valkey.KeyCacheTTL > config.MaxKeyCacheTTL {
		t.Errorf("default TTL %s exceeds the %s ceiling", cfg.Valkey.KeyCacheTTL, config.MaxKeyCacheTTL)
	}
	if cfg.Valkey.KeyCacheSweep > cfg.Valkey.KeyCacheTTL {
		t.Errorf("default sweep %s is longer than the TTL %s, so keys expire without being zeroed",
			cfg.Valkey.KeyCacheSweep, cfg.Valkey.KeyCacheTTL)
	}
}

// countingBus records how many times Subscribe was called, so a retry loop is
// observable without a broker.
type countingBus struct {
	mu         sync.Mutex
	calls      int
	subscribed chan struct{}
	stop       chan struct{}
}

func (b *countingBus) Publish(context.Context, string, []byte) error { return nil }

func (b *countingBus) Subscribe(ctx context.Context, _ string, _ func([]byte)) error {
	b.mu.Lock()
	b.calls++
	first := b.calls == 1
	b.mu.Unlock()
	if first {
		b.subscribed <- struct{}{}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.stop:
		return errors.New("connection dropped")
	}
}

func (b *countingBus) subscribeCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

// reactor_processed gains one row per event per reactor, and nothing removed
// them: Dedup.Forget was written, documented, and had an index built for it —
// then called by no binary at all. That is the same failure as the three
// notification channels that were built, tested and constructed by nobody.
//
// A component test of Forget passes either way, so the assertion has to be here.
func TestDedupRetentionIsConfiguredAtTheCompositionRoot(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	if d.dedupDays < config.MinDedupRetentionDays {
		t.Errorf("dedup retention is %d days, below the %d-day floor: a reactor that "+
			"forgets an event still eligible for redelivery sends the email twice",
			d.dedupDays, config.MinDedupRetentionDays)
	}
	if d.dedupEvery <= 0 {
		t.Error("no dedup sweep interval was carried through: reactor_processed grows " +
			"for the lifetime of the deployment and its index grows with it")
	}

	// A cancelled context must end the sweep rather than spin.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pruneDedup(ctx, d, slog.New(slog.DiscardHandler))
}

// Asserting the LIST main starts, not the functions themselves.
//
// A test that calls pruneDedup directly passes whether or not any binary ever
// runs it — which is precisely how Dedup.Forget came to be written, documented,
// indexed for, and called by nobody. Every duty this binary owns besides its
// reactors has to appear here.
func TestEveryBackgroundDutyIsStarted(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	started := map[string]bool{}
	for _, task := range backgroundTasks(nil, d) {
		if task.run == nil {
			t.Errorf("background task %q has no function: it is listed but does nothing", task.name)
		}
		if started[task.name] {
			t.Errorf("background task %q is listed twice", task.name)
		}
		started[task.name] = true
	}

	for _, required := range []string{"parked-poll", "dedup-retention", "pii-key-cache"} {
		if !started[required] {
			t.Errorf("%q is not started by the worker: it runs only in its own test", required)
		}
	}

	// And they must all stop when told to.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan string, len(backgroundTasks(nil, d)))
	for _, task := range backgroundTasks(nil, d) {
		go func(task backgroundTask) {
			task.run(ctx, d, slog.New(slog.DiscardHandler))
			done <- task.name
		}(task)
	}
	for range backgroundTasks(nil, d) {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("a background task did not stop when its context was cancelled")
		}
	}
}

// With no database the worker must still start; retention is Degradable.
func TestPruneDedupWithoutADatabase(t *testing.T) {
	pruneDedup(context.Background(), &dependencies{}, slog.New(slog.DiscardHandler))
}

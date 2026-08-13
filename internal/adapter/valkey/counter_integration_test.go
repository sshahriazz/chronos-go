//go:build integration

package valkey_test

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	adapter "github.com/chronos/chronos-go/internal/adapter/valkey"
	"github.com/chronos/chronos-go/internal/platform/ratelimit"
	valkeygo "github.com/valkey-io/valkey-go"
)

// These run against a live Valkey. The properties they check are properties of
// the SERVER, so a fake counter asserts nothing about them: the in-memory tests
// in platform/ratelimit cover the policy, and these cover the mechanism.
//
// Two things are covered and one is not, and the distinction is worth being
// precise about:
//
//   - Increment atomicity IS covered. A client-side read-modify-write turns 200
//     concurrent increments into a final count of 3, which
//     TestConcurrentIncrementsAreAtomic catches. Verified by mutation, not
//     assumed.
//   - The TTL being applied, and not extended, IS covered.
//   - The increment and the expiry being applied TOGETHER is NOT covered.
//     Breaking that needs a process death between two round trips, which no test
//     can stage — swapping the script for INCR-then-PEXPIRE passes everything
//     here. The script is chosen because it removes that failure mode, not
//     because anything below demonstrates its absence.
func newClient(t *testing.T) valkeygo.Client {
	t.Helper()
	addr := os.Getenv("VALKEY_ADDR")
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	client, err := valkeygo.NewClient(valkeygo.ClientOption{
		InitAddress: []string{addr},
	})
	if err != nil {
		t.Skipf("valkey is unavailable at %s: %v", addr, err)
	}
	t.Cleanup(client.Close)
	return client
}

func uniqueKey(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("test:ratelimit:%s:%d", t.Name(), time.Now().UnixNano())
}

// The counter increments and reports the running total.
func TestIncrementReturnsTheRunningCount(t *testing.T) {
	ctx := context.Background()
	c := adapter.NewCounter(newClient(t))
	key := uniqueKey(t)

	for want := int64(1); want <= 5; want++ {
		got, err := c.Incr(ctx, key, time.Minute)
		if err != nil {
			t.Fatalf("incr: %v", err)
		}
		if got != want {
			t.Fatalf("increment %d returned %d", want, got)
		}
	}
}

// THE ONE THAT MATTERS: a TTL is actually applied, in the same operation.
//
// INCR followed by a separate EXPIRE leaves a window in which the process dies
// between them. The key then has no expiry, the counter never resets, and that
// scope is refused forever — presenting as one user permanently unable to log
// in, with a Valkey key nobody thinks to inspect.
func TestTheCounterAlwaysCarriesAnExpiry(t *testing.T) {
	ctx := context.Background()
	client := newClient(t)
	c := adapter.NewCounter(client)
	key := uniqueKey(t)

	if _, err := c.Incr(ctx, key, 30*time.Second); err != nil {
		t.Fatalf("incr: %v", err)
	}

	ttl, err := client.Do(ctx, client.B().Pttl().Key(key).Build()).AsInt64()
	if err != nil {
		t.Fatalf("pttl: %v", err)
	}
	// -1 means the key exists with no expiry; -2 means it does not exist.
	if ttl == -1 {
		t.Fatal("the counter has no expiry: it never resets, so the scope that reached the " +
			"limit is refused forever and FLUSHALL is the only remedy")
	}
	if ttl < 0 {
		t.Fatalf("PTTL returned %d; the key was not created", ttl)
	}
	if ttl > 30_000 {
		t.Fatalf("the TTL is %dms, longer than the %dms window requested", ttl, 30_000)
	}
}

// The window is NOT extended by later increments.
//
// Refreshing the TTL on every increment turns a fixed window into a sliding ban:
// an attacker at one attempt per second holds the counter above the limit
// indefinitely, and so does a stuck client retrying in a loop.
func TestLaterIncrementsDoNotExtendTheWindow(t *testing.T) {
	ctx := context.Background()
	client := newClient(t)
	c := adapter.NewCounter(client)
	key := uniqueKey(t)

	if _, err := c.Incr(ctx, key, 10*time.Second); err != nil {
		t.Fatalf("incr: %v", err)
	}
	first, err := client.Do(ctx, client.B().Pttl().Key(key).Build()).AsInt64()
	if err != nil {
		t.Fatalf("pttl: %v", err)
	}

	time.Sleep(1200 * time.Millisecond)

	if _, err := c.Incr(ctx, key, 10*time.Second); err != nil {
		t.Fatalf("second incr: %v", err)
	}
	second, err := client.Do(ctx, client.B().Pttl().Key(key).Build()).AsInt64()
	if err != nil {
		t.Fatalf("pttl: %v", err)
	}

	if second >= first {
		t.Fatalf("the TTL went from %dms to %dms across a 1.2s gap: the window is refreshed "+
			"on every increment, so a steady trickle of attempts keeps a scope banned forever",
			first, second)
	}
}

// The window actually elapses and the counter resets.
func TestTheCounterResetsAfterItsWindow(t *testing.T) {
	ctx := context.Background()
	c := adapter.NewCounter(newClient(t))
	key := uniqueKey(t)

	for range 3 {
		if _, err := c.Incr(ctx, key, 700*time.Millisecond); err != nil {
			t.Fatalf("incr: %v", err)
		}
	}
	time.Sleep(1200 * time.Millisecond)

	got, err := c.Incr(ctx, key, 700*time.Millisecond)
	if err != nil {
		t.Fatalf("incr after the window: %v", err)
	}
	if got != 1 {
		t.Fatalf("the counter read %d after its window elapsed: it never resets, so a user "+
			"who hits the ceiling once is refused permanently", got)
	}
}

// Concurrent increments lose nothing.
//
// A client-side read-modify-write passes every sequential test and drops
// increments under exactly the concurrency an attacker produces — measured, not
// asserted: substituting one produced a final count of 3 for 200 concurrent
// increments, meaning the configured ceiling would silently be ~66x higher.
func TestConcurrentIncrementsAreAtomic(t *testing.T) {
	ctx := context.Background()
	c := adapter.NewCounter(newClient(t))
	key := uniqueKey(t)

	const n = 200
	var wg sync.WaitGroup
	seen := make([]int64, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got, err := c.Incr(ctx, key, time.Minute)
			if err != nil {
				t.Errorf("incr: %v", err)
				return
			}
			seen[i] = got
		}(i)
	}
	wg.Wait()

	final, err := c.Incr(ctx, key, time.Minute)
	if err != nil {
		t.Fatalf("final incr: %v", err)
	}
	if final != n+1 {
		t.Fatalf("%d concurrent increments produced a final count of %d: increments are lost "+
			"under concurrency, so the ceiling is silently higher than configured", n, final-1)
	}

	// Every increment returned a DISTINCT value. A lost update shows up here as a
	// duplicate even when the final total happens to be right.
	counts := map[int64]int{}
	for _, v := range seen {
		counts[v]++
	}
	for v, times := range counts {
		if times > 1 {
			t.Fatalf("the value %d was returned to %d callers: two attempts observed the same "+
				"pre-increment state", v, times)
		}
	}
}

// The whole limiter works end to end against a real counter.
func TestTheLimiterRefusesPastItsCeilingAgainstLiveValkey(t *testing.T) {
	ctx := context.Background()
	c := adapter.NewCounter(newClient(t))
	l, err := ratelimit.New(c, uniqueKey(t),
		ratelimit.Rule{Name: "burst", Limit: 3, Window: time.Minute})
	if err != nil {
		t.Fatalf("limiter: %v", err)
	}

	for i := 1; i <= 3; i++ {
		d, err := l.Allow(ctx, "usr_1")
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if !d.Allowed() {
			t.Fatalf("attempt %d of 3 was refused", i)
		}
		if d.Degraded {
			t.Fatal("a decision against live Valkey was marked Degraded")
		}
	}
	d, err := l.Allow(ctx, "usr_1")
	if err != nil {
		t.Fatalf("fourth attempt: %v", err)
	}
	if d.Allowed() {
		t.Fatal("the fourth attempt against a limit of 3 was permitted")
	}
}

// A non-positive window is refused rather than deleting the key.
//
// PEXPIRE with a non-positive value DELETES the key, so the counter would be
// created and immediately dropped — every attempt reads 1 and the ceiling is
// never reached.
func TestANonPositiveWindowIsRefused(t *testing.T) {
	ctx := context.Background()
	c := adapter.NewCounter(newClient(t))

	for _, window := range []time.Duration{0, -time.Second} {
		if _, err := c.Incr(ctx, uniqueKey(t), window); err == nil {
			t.Errorf("a window of %v was accepted: PEXPIRE deletes the key, so every attempt "+
				"reads 1 and the ceiling is never reached", window)
		}
	}
}

// A sub-millisecond window is REFUSED.
//
// Duration.Milliseconds() truncates, so anything under 1ms becomes 0 — and
// PEXPIRE with 0 deletes the key. The counter would be created and destroyed on
// every call, every attempt would read 1, and the limiter would silently permit
// everything.
//
// Asserted as a refusal rather than as a rounding, because a 1ms key may or may
// not survive to the next assertion and the check would go unverified.
func TestASubMillisecondWindowIsRefused(t *testing.T) {
	ctx := context.Background()
	c := adapter.NewCounter(newClient(t))

	for _, window := range []time.Duration{time.Nanosecond, 100 * time.Microsecond, 999 * time.Microsecond} {
		if _, err := c.Incr(ctx, uniqueKey(t), window); err == nil {
			t.Errorf("a window of %v was accepted: it truncates to 0ms, PEXPIRE deletes the "+
				"key, and every attempt reads 1 so the ceiling is never reached", window)
		}
	}
	// And exactly 1ms is still accepted, so the guard is a floor rather than a
	// blanket refusal.
	if _, err := c.Incr(ctx, uniqueKey(t), time.Millisecond); err != nil {
		t.Errorf("a 1ms window was refused: %v", err)
	}
}

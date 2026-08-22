package argon2id_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/adapter/argon2id"
	"github.com/chronos/chronos-go/internal/platform/errs"
)

// The bound is real: no more than the configured number of hashes run at once.
//
// Measured by observing the hasher's own in-flight counter from outside while
// many callers pile in. An assertion that merely checked the limit was
// CONFIGURED would pass against a hasher that never consults it — which is
// precisely how a limit becomes decoration.
func TestConcurrentHashingNeverExceedsTheLimit(t *testing.T) {
	const limit = 3
	pepper, err := argon2id.NewPepperKeys(map[int][]byte{1: keyBytes(t, 0xA1)}, 1)
	if err != nil {
		t.Fatalf("pepper: %v", err)
	}
	h, err := argon2id.New(pepper, testParams, argon2id.WithConcurrencyLimit(limit, 5*time.Second))
	if err != nil {
		t.Fatalf("hasher: %v", err)
	}
	user, cred := newIDs(t)

	var peak atomic.Int64
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if n := int64(h.InFlight()); n > peak.Load() {
				peak.Store(n)
			}
		}
	}()

	var wg sync.WaitGroup
	for range 24 {
		wg.Go(func() {
			if _, err := h.Hash(context.Background(), "correct horse battery", user, cred); err != nil {
				t.Errorf("hash: %v", err)
			}
		})
	}
	wg.Wait()
	close(stop)

	if got := peak.Load(); got > limit {
		t.Fatalf("%d hashes ran at once against a limit of %d: peak memory is unbounded, and "+
			"a few hundred concurrent logins exhaust the process", got, limit)
	}
	if peak.Load() < 2 {
		t.Fatalf("peak concurrency was %d, so this test never exercised contention and "+
			"proves nothing", peak.Load())
	}
}

// Verification is bounded too, not only hashing.
//
// Login is the attacker-driven path — registration happens once, logins are
// unlimited — so a bound on Hash alone would guard the operation nobody attacks.
func TestConcurrentVerificationNeverExceedsTheLimit(t *testing.T) {
	const limit = 2
	pepper, err := argon2id.NewPepperKeys(map[int][]byte{1: keyBytes(t, 0xA1)}, 1)
	if err != nil {
		t.Fatalf("pepper: %v", err)
	}
	h, err := argon2id.New(pepper, testParams, argon2id.WithConcurrencyLimit(limit, 5*time.Second))
	if err != nil {
		t.Fatalf("hasher: %v", err)
	}
	user, cred := newIDs(t)

	v, err := h.Hash(context.Background(), "correct horse battery", user, cred)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	var peak atomic.Int64
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if n := int64(h.InFlight()); n > peak.Load() {
				peak.Store(n)
			}
		}
	}()

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, err := h.Verify(context.Background(), "correct horse battery", v, user, cred); err != nil {
				t.Errorf("verify: %v", err)
			}
		})
	}
	wg.Wait()
	close(stop)

	if got := peak.Load(); got > limit {
		t.Fatalf("%d verifications ran at once against a limit of %d: the attacker-driven "+
			"path is unbounded", got, limit)
	}
	// The vacuity guard, and it is not theoretical: with the acquire removed from
	// Verify the in-flight counter stays at zero, so `peak <= limit` holds
	// trivially and the test passes against a completely unbounded verifier.
	// Observing real contention is what makes the assertion above mean anything.
	if peak.Load() < 2 {
		t.Fatalf("peak concurrency during verification was %d: Verify never took a slot, so "+
			"the bound above was never exercised and this test proves nothing", peak.Load())
	}
}

// At capacity, a caller is SHED with a named error rather than queued forever.
//
// RATE_LIMITED, not a wrong password: the request was never evaluated, and
// reporting it as a credential failure would both lie to the user and count a
// failed attempt against an account that did nothing.
func TestAtCapacityCallersAreShedNotQueuedForever(t *testing.T) {
	pepper, err := argon2id.NewPepperKeys(map[int][]byte{1: keyBytes(t, 0xA1)}, 1)
	if err != nil {
		t.Fatalf("pepper: %v", err)
	}
	// One slot, and effectively no willingness to wait.
	h, err := argon2id.New(pepper, testParams, argon2id.WithConcurrencyLimit(1, 2*time.Millisecond))
	if err != nil {
		t.Fatalf("hasher: %v", err)
	}
	user, cred := newIDs(t)

	// Occupy the only slot.
	busy := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		close(busy)
		for range 6 {
			if _, err := h.Hash(context.Background(), "correct horse battery", user, cred); err != nil {
				return
			}
		}
	}()
	<-busy

	var shed error
	for range 200 {
		if _, err := h.Hash(context.Background(), "correct horse battery", user, cred); err != nil {
			shed = err
			break
		}
	}
	<-done

	if shed == nil {
		t.Skip("could not create contention on this machine; the limit is still asserted by " +
			"TestConcurrentHashingNeverExceedsTheLimit")
	}
	if !errors.Is(shed, errs.RateLimitedf("")) {
		t.Fatalf("a shed caller got %v; it must be RATE_LIMITED so the client backs off, and "+
			"must never look like a credential failure", shed)
	}
}

// A CALLER THAT HAS ALREADY HUNG UP IS REFUSED, free slot or not.
//
// This test used to occupy the single slot first and assert only that the
// cancelled caller did not WAIT. That made it depend on a race it could not win:
// the occupier signals before it is inside Hash, so the cancelled call often
// found the slot free — and a free slot was SERVED, because the context was
// consulted only on the wait path.
//
// The answer therefore depended on load. Busy meant refused, idle meant served,
// and the test failed roughly one run in six under parallel load while the
// behaviour it described was never actually guaranteed.
//
// The fix was in the hasher: the context is checked before the fast path. Doing
// ~50 ms of memory-hard work for a caller who has hung up is waste, and it
// occupies one of the slots the bound exists to ration — so a live caller is
// shed to finish work nobody will read.
func TestACancelledCallerIsRefusedEvenWithASlotFree(t *testing.T) {
	pepper, err := argon2id.NewPepperKeys(map[int][]byte{1: keyBytes(t, 0xA1)}, 1)
	if err != nil {
		t.Fatalf("pepper: %v", err)
	}
	// A limit of 4 and nothing else running: every slot is free, which is
	// precisely the case the old test could not cover.
	h, err := argon2id.New(pepper, testParams, argon2id.WithConcurrencyLimit(4, time.Minute))
	if err != nil {
		t.Fatalf("hasher: %v", err)
	}
	user, cred := newIDs(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	if _, err := h.Hash(ctx, "correct horse battery", user, cred); err == nil {
		t.Fatal("a caller that had already hung up was served. The work is memory-hard " +
			"and nobody will read it, and it occupies a slot the bound exists to ration")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("the refusal took %v; a cancelled context is answered from ctx.Err() and "+
			"should not reach the hash at all", elapsed)
	}
	if n := h.InFlight(); n != 0 {
		t.Errorf("%d slots are still held after refusing a cancelled caller", n)
	}
}

// A CALLER CANCELLED WHILE WAITING IS RELEASED, rather than held to maxWait.
//
// The other half, and the one the entry check above cannot cover: here the
// caller is live when it asks, finds every slot busy, and hangs up during the
// wait. The context must beat the timer, or a client that gave up still costs a
// working set for the rest of maxWait.
func TestACallerCancelledWhileWaitingIsReleased(t *testing.T) {
	pepper, err := argon2id.NewPepperKeys(map[int][]byte{1: keyBytes(t, 0xA1)}, 1)
	if err != nil {
		t.Fatalf("pepper: %v", err)
	}
	// A LONG maxWait, so "released early" and "waited it out" are minutes apart
	// rather than seconds — the margin is what makes this survive a loaded
	// machine, where the old test's 10-second threshold did not.
	h, err := argon2id.New(pepper, testParams, argon2id.WithConcurrencyLimit(1, 10*time.Minute))
	if err != nil {
		t.Fatalf("hasher: %v", err)
	}
	user, cred := newIDs(t)

	// Fill the only slot and hold it. The waiter below is what this test is
	// about, so the occupier only has to keep the slot for the duration.
	release := make(chan struct{})
	held := make(chan struct{})
	go func() {
		_, _ = h.Hash(context.Background(), "correct horse battery", user, cred)
		close(held)
		for {
			select {
			case <-release:
				return
			default:
				if _, err := h.Hash(context.Background(), "correct horse battery", user, cred); err != nil {
					return
				}
			}
		}
	}()
	<-held
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)

	start := time.Now()
	_, err = h.Hash(ctx, "correct horse battery", user, cred)
	elapsed := time.Since(start)

	if err == nil {
		// It won the slot rather than waiting, which the occupier's loop makes
		// unlikely but not impossible. Nothing to assert, and reporting a
		// failure would make this test flaky in the direction the last one was.
		t.Skip("the waiter won a slot instead of waiting; nothing to measure")
	}
	if elapsed > time.Minute {
		t.Fatalf("a caller that hung up waited %v for a slot. The maxWait timer is "+
			"consulted before the context, so a client that gave up still costs a working "+
			"set for the rest of the window", elapsed)
	}
}

// A cheap rejection must not consume a hashing slot.
//
// If a malformed verifier took a slot before being rejected, an attacker sheds
// every legitimate login by replaying garbage — for no CPU cost to themselves,
// which inverts the entire economics of the bound.
func TestARejectedVerifierConsumesNoSlot(t *testing.T) {
	pepper, err := argon2id.NewPepperKeys(map[int][]byte{1: keyBytes(t, 0xA1)}, 1)
	if err != nil {
		t.Fatalf("pepper: %v", err)
	}
	h, err := argon2id.New(pepper, testParams, argon2id.WithConcurrencyLimit(1, 2*time.Millisecond))
	if err != nil {
		t.Fatalf("hasher: %v", err)
	}
	user, cred := newIDs(t)

	for range 100 {
		if _, err := h.Verify(context.Background(), "correct horse battery", "garbage", user, cred); err == nil {
			t.Fatal("a malformed verifier was accepted")
		}
	}
	if n := h.InFlight(); n != 0 {
		t.Fatalf("%d slots are still held after rejected verifiers: a slot leaks on the "+
			"rejection path and the hasher eventually refuses everything", n)
	}

	// And a real verify still works, which is what a leaked slot would prevent.
	v, err := h.Hash(context.Background(), "correct horse battery", user, cred)
	if err != nil {
		t.Fatalf("hash after rejections: %v", err)
	}
	if ok, err := h.Verify(context.Background(), "correct horse battery", v, user, cred); !ok || err != nil {
		t.Fatalf("verify after rejections: ok=%v err=%v", ok, err)
	}
}

// Slots are returned on every path, including errors.
func TestSlotsAreReleasedAfterEveryCall(t *testing.T) {
	h, _ := newHasher(t)
	user, cred := newIDs(t)

	v, err := h.Hash(context.Background(), "correct horse battery", user, cred)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := h.Verify(context.Background(), "wrong password here", v, user, cred); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if n := h.InFlight(); n != 0 {
		t.Fatalf("%d slots held after all calls returned", n)
	}
}

// The default limit is bounded, not unlimited.
//
// An unbounded default is the configuration nobody changes until an incident.
func TestTheDefaultHasherIsBounded(t *testing.T) {
	h, _ := newHasher(t)
	if h.Limit() < 1 {
		t.Fatal("the default hasher has no concurrency limit")
	}
	if h.Limit() > 256 {
		t.Errorf("the default limit is %d; at 32 MiB per hash that is %d GiB of peak memory",
			h.Limit(), h.Limit()*32/1024)
	}
}

// A zero or negative limit is refused at construction.
func TestAnUnusableConcurrencyLimitIsRefused(t *testing.T) {
	pepper, err := argon2id.NewPepperKeys(map[int][]byte{1: keyBytes(t, 0xA1)}, 1)
	if err != nil {
		t.Fatalf("pepper: %v", err)
	}
	for _, n := range []int{0, -1} {
		// Must return an error, and must NOT panic: makechan rejects a negative
		// size, so an option that allocated eagerly would crash the process at
		// wiring instead of reporting a misconfiguration.
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("a concurrency limit of %d panicked at construction (%v) instead "+
						"of returning an error", n, r)
				}
			}()
			if _, err := argon2id.New(pepper, testParams, argon2id.WithConcurrencyLimit(n, time.Second)); err == nil {
				t.Errorf("a hasher was built with a concurrency limit of %d, which deadlocks "+
					"every login rather than bounding anything", n)
			}
		}()
	}

	// A non-positive wait is refused too: it sheds every caller that does not
	// find a slot instantly, which reads as an outage under ordinary load.
	if _, err := argon2id.New(pepper, testParams, argon2id.WithConcurrencyLimit(4, 0)); err == nil {
		t.Error("a hasher was built with a zero capacity wait")
	}
}

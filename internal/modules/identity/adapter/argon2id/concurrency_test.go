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
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := h.Hash(context.Background(), "correct horse battery", user, cred); err != nil {
				t.Errorf("hash: %v", err)
			}
		}()
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
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := h.Verify(context.Background(), "correct horse battery", v, user, cred); err != nil {
				t.Errorf("verify: %v", err)
			}
		}()
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

// A caller whose context ends stops holding a slot.
//
// Without this, a client that hung up still costs a full working set until its
// hash finishes — so an attacker who opens connections and drops them
// immediately gets the memory cost for free.
func TestACancelledCallerDoesNotWaitForASlot(t *testing.T) {
	pepper, err := argon2id.NewPepperKeys(map[int][]byte{1: keyBytes(t, 0xA1)}, 1)
	if err != nil {
		t.Fatalf("pepper: %v", err)
	}
	h, err := argon2id.New(pepper, testParams, argon2id.WithConcurrencyLimit(1, time.Minute))
	if err != nil {
		t.Fatalf("hasher: %v", err)
	}
	user, cred := newIDs(t)

	// Fill the single slot and keep it busy.
	release := make(chan struct{})
	occupied := make(chan struct{})
	go func() {
		close(occupied)
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
	<-occupied
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already dead when it asks

	start := time.Now()
	_, err = h.Hash(ctx, "correct horse battery", user, cred)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a cancelled caller was served")
	}
	if elapsed > 10*time.Second {
		t.Fatalf("a cancelled caller waited %v for a slot: the maxWait timer is consulted "+
			"before the context, so a hung-up client still costs a working set", elapsed)
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

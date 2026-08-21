package clock_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/clock"
)

func TestOffset_StartsAtTheBaseClock(t *testing.T) {
	base := clock.NewFixed(time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC))
	o := clock.NewOffset(base)

	if got := o.Offset(); got != 0 {
		t.Errorf("a new offset clock is %s ahead of its base, want 0", got)
	}
	if !o.Now().Equal(base.Now()) {
		t.Errorf("a new offset clock reads %s, want its base's %s", o.Now(), base.Now())
	}
}

func TestOffset_AdvanceMovesForwardAndAccumulates(t *testing.T) {
	base := clock.NewFixed(time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC))
	o := clock.NewOffset(base)

	if got, err := o.Advance(31 * time.Second); err != nil || got != 31*time.Second {
		t.Fatalf("Advance(31s) = %s, %v; want 31s, nil", got, err)
	}
	if got, err := o.Advance(29 * time.Second); err != nil || got != time.Minute {
		t.Fatalf("a second advance must accumulate: got %s, %v; want 1m, nil", got, err)
	}
	if want := base.Now().Add(time.Minute); !o.Now().Equal(want) {
		t.Errorf("now = %s, want %s", o.Now(), want)
	}
}

// The security property. A clock that can be rewound un-expires an expired
// token, restores an elapsed lockout, and steps back into a TOTP step whose
// code somebody has already seen.
func TestOffset_RefusesToMoveBackwards(t *testing.T) {
	base := clock.NewFixed(time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC))
	o := clock.NewOffset(base)
	if _, err := o.Advance(time.Hour); err != nil {
		t.Fatalf("Advance(1h): %v", err)
	}

	for _, d := range []time.Duration{-time.Nanosecond, -time.Second, -time.Hour, 0} {
		t.Run(d.String(), func(t *testing.T) {
			got, err := o.Advance(d)
			if !errors.Is(err, clock.ErrNotForward) {
				t.Fatalf("Advance(%s) returned %v; want ErrNotForward", d, err)
			}
			if got != time.Hour {
				t.Errorf("the refused advance reported an offset of %s, want the "+
					"unchanged 1h", got)
			}
			if o.Offset() != time.Hour {
				t.Fatalf("a REFUSED advance still moved the clock: offset is now %s. "+
					"Every time-derived rule in the process — token expiry, session "+
					"deadlines, lockouts, TOTP steps — just moved with it", o.Offset())
			}
		})
	}
}

func TestOffset_IsAlwaysUTC(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	o := clock.NewOffset(clock.NewFixed(time.Date(2026, 8, 21, 12, 0, 0, 0, ny)))
	if _, err := o.Advance(time.Second); err != nil {
		t.Fatalf("Advance: %v", err)
	}
	if loc := o.Now().Location(); loc != time.UTC {
		t.Fatalf("ADR-008: got %v want UTC", loc)
	}
}

// It tracks a MOVING base rather than snapshotting it. This is what lets a test
// that sleeps in real time still see the server's clock advance, and it is the
// difference between an offset clock and a frozen one.
func TestOffset_FollowsItsBase(t *testing.T) {
	base := clock.NewFixed(time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC))
	o := clock.NewOffset(base)
	if _, err := o.Advance(time.Minute); err != nil {
		t.Fatalf("Advance: %v", err)
	}

	base.Advance(10 * time.Second)
	want := time.Date(2026, 8, 21, 12, 1, 10, 0, time.UTC)
	if !o.Now().Equal(want) {
		t.Errorf("now = %s, want %s: an offset clock is an offset FROM the base clock, "+
			"not a replacement for it", o.Now(), want)
	}
}

// Concurrent readers and writers, because in cmd/api the control's HTTP handler
// writes while every request handler in the process reads.
func TestOffset_IsSafeUnderConcurrency(t *testing.T) {
	o := clock.NewOffset(clock.System{})

	const writers, each = 8, 100
	var wg sync.WaitGroup
	for range writers {
		wg.Go(func() {
			for range each {
				if _, err := o.Advance(time.Millisecond); err != nil {
					t.Errorf("Advance: %v", err)
					return
				}
			}
		})
	}
	for range 4 {
		wg.Go(func() {
			for range each {
				_ = o.Now()
			}
		})
	}
	wg.Wait()

	if want := writers * each * time.Millisecond; o.Offset() != want {
		t.Errorf("offset = %s after %d concurrent advances, want %s",
			o.Offset(), writers*each, want)
	}
}

// clock.Offset must satisfy clock.Clock; every collaborator takes the interface.
var _ clock.Clock = (*clock.Offset)(nil)

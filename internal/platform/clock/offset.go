package clock

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// ErrNotForward is returned by Offset.Advance for a duration that is not
// strictly positive.
//
// It is a sentinel because the refusal is a SECURITY property rather than
// input validation, and a caller that swallows it has re-opened the hole. See
// Offset for what rewinding would buy an attacker.
var ErrNotForward = errors.New("clock: an offset clock only moves forward")

// Offset is a Clock that can be moved FORWARD of a base clock at runtime.
//
// It exists so a test can travel through a time-derived rule — a TOTP step, a
// session's idle deadline, a rate-limit window — instead of sleeping through
// it. Nothing in production may hold one: see cmd/api's clock control for the
// three locks that keep it out, and ADR-054 for why they are what they are.
//
// # Forward only, and why that is not a convenience
//
// Advance refuses a zero or negative duration. Moving time forward is time
// PASSING: a token expires, a lockout elapses, a TOTP step rolls over. Every
// one of those is a rule being enforced earlier, never skipped.
//
// Moving it backwards is the opposite. It would un-expire an expired
// verification token, restore a lockout that had already elapsed, and re-enter
// a TOTP step whose code somebody has already seen. A clock that can rewind is
// a general "skip the rules" switch wearing a clock's clothes, so this type
// does not have one — not behind a flag, not behind a second env var.
//
// The replay guard is unaffected either way, and deliberately so: it is keyed
// on (credential, step) in Postgres with ON CONFLICT DO NOTHING, so a spent
// step stays spent no matter what any clock says. Advancing past a step cannot
// un-spend it, and there is no path back to it.
//
// The zero value is not usable; use NewOffset.
type Offset struct {
	base Clock

	// ns is the offset in nanoseconds. Atomic because the control surface writes
	// it from an HTTP handler's goroutine while every request handler in the
	// process reads it.
	ns atomic.Int64
}

// NewOffset wraps a base clock with a movable offset, starting at zero.
//
// base is required: an Offset over nothing would report the zero instant, and a
// server whose clock reads year 1 fails in ways that look like anything except
// a nil clock.
func NewOffset(base Clock) *Offset {
	if base == nil {
		base = System{}
	}
	return &Offset{base: base}
}

// Now is the base clock plus the accumulated offset, in UTC.
func (o *Offset) Now() time.Time {
	return o.base.Now().Add(time.Duration(o.ns.Load())).UTC()
}

// Offset is how far ahead of the base clock this clock currently reads.
func (o *Offset) Offset() time.Duration { return time.Duration(o.ns.Load()) }

// Advance moves the clock forward by d and returns the new total offset.
//
// It refuses anything that is not strictly positive, with ErrNotForward. A
// caller wanting "no change" should read Offset instead — an Advance(0) that
// silently succeeded would make a rewind attempt look like a rounding error.
func (o *Offset) Advance(d time.Duration) (time.Duration, error) {
	if d <= 0 {
		return o.Offset(), fmt.Errorf("%w; %s would move it backwards or not at all",
			ErrNotForward, d)
	}
	return time.Duration(o.ns.Add(int64(d))), nil
}

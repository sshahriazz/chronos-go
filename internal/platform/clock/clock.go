// Package clock makes time injectable so tests are deterministic and workflow
// code stays honest (CONVENTIONS §10).
//
// Nothing outside this package may call time.Now. Two reasons:
//
//   - Temporal workflows must be deterministic; a wall-clock read breaks replay.
//   - Every timestamp we store is UTC (ADR-008), and a Clock that can only
//     return UTC removes the chance of storing a local time by accident.
package clock

import "time"

// Clock reports the current instant. Implementations always return UTC.
type Clock interface {
	Now() time.Time
}

// System reads the wall clock, normalised to UTC.
type System struct{}

func (System) Now() time.Time { return time.Now().UTC() }

// Fixed is a test clock. It does not advance unless told to.
type Fixed struct{ t time.Time }

// NewFixed pins the clock to an instant, normalised to UTC so a test that
// passes a local time still observes UTC behaviour.
func NewFixed(t time.Time) *Fixed { return &Fixed{t: t.UTC()} }

func (f *Fixed) Now() time.Time { return f.t }

// Advance moves the clock forward. Negative durations are allowed — clock skew
// and out-of-order events are things worth testing.
func (f *Fixed) Advance(d time.Duration) { f.t = f.t.Add(d) }

// Set jumps the clock to an instant.
func (f *Fixed) Set(t time.Time) { f.t = t.UTC() }

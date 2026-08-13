package projection

import (
	"context"
	"sync"
	"time"

	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// throttle paces a rebuild so it cannot starve the live system.
//
// A rebuild reads a link stream as fast as the server will serve it and writes
// through the SAME PostgreSQL pool the API and the live projectors share.
// Unthrottled — and batching made it a great deal faster — it is a self-inflicted
// load test against production, run at the moment someone is already fixing
// something.
//
// It paces the REBUILD path only. A projector catching up after downtime is not
// throttled: there the whole point is to become current, and slowing it down
// makes every read stale for longer.
//
// The rate is an AVERAGE, not a token bucket. It compares "events applied" to
// "events the limit allows by now" and sleeps the deficit, so a burst is
// permitted and then paid for. That is the right shape here: the cost being
// managed is sustained pressure on a shared pool, not instantaneous concurrency,
// which the shard count already bounds.
type throttle struct {
	perSecond int
	clk       clock.Clock

	mu      sync.Mutex
	started time.Time
	applied int64
}

// newThrottle returns nil when no limit is configured, so the unthrottled path
// costs a nil check rather than a lock.
func newThrottle(perSecond int, clk clock.Clock) *throttle {
	if perSecond <= 0 {
		return nil
	}
	return &throttle{perSecond: perSecond, clk: clk, started: clk.Now()}
}

// wait accounts for one applied event and sleeps if the replay is ahead of its
// budget. It returns false when the context ended while waiting.
func (t *throttle) wait(ctx context.Context) bool {
	if t == nil {
		return true
	}

	t.mu.Lock()
	t.applied++
	// The time this many events should have taken at the configured rate.
	budget := time.Duration(float64(t.applied) / float64(t.perSecond) * float64(time.Second))
	elapsed := t.clk.Now().Sub(t.started)
	t.mu.Unlock()

	deficit := budget - elapsed
	if deficit <= 0 {
		return true
	}
	// Sleeping per event would wake thousands of times a second for a sub-
	// millisecond deficit. Waiting only once it is worth waiting for keeps the
	// average honest and the syscall count low.
	if deficit < minThrottleSleep {
		return true
	}
	return sleep(ctx, deficit)
}

// minThrottleSleep is the smallest pause worth taking. Below it the timer costs
// more than the delay it introduces.
const minThrottleSleep = 2 * time.Millisecond

// throttled wraps a replay handler with pacing. It is applied at the READ side,
// so it bounds the whole pipeline — decode, apply and commit — rather than one
// stage of it.
func (r *Runner) throttled(h eventsourcing.Handler, t *throttle) eventsourcing.Handler {
	if t == nil {
		return h
	}
	return func(ctx context.Context, e eventsourcing.RecordedEvent) error {
		if err := h(ctx, e); err != nil {
			return err
		}
		if !t.wait(ctx) {
			return ctx.Err()
		}
		return nil
	}
}

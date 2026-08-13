package projection

import (
	"context"
	"fmt"

	"github.com/chronos/chronos-go/internal/platform/db"
)

// batch is the events waiting to share one transaction.
//
// It exists because a projector that is BEHIND pays one round trip per event,
// and that cost is per transaction rather than per statement: fifty events in
// one transaction cost one round trip, not fifty. What it must never do is span
// tenants — every statement runs under a scope set by SET LOCAL, so mixing two
// orgs in one transaction would project one org's event under the other's
// policy. Hence accepts: a scope change ends the batch.
//
// It holds decoded envelopes, so its memory is bounded by MaxCatchUpBatch times
// the largest payload — which is itself bounded by eventsourcing.MaxEventBytes.
type batch struct {
	events []Envelope
	scope  db.Tenant
}

func (b *batch) len() int { return len(b.events) }

// accepts reports whether an event with this scope may join the batch. An empty
// batch accepts anything and adopts the scope of what it is given.
func (b *batch) accepts(scope db.Tenant) bool {
	return len(b.events) == 0 || b.scope == scope
}

func (b *batch) add(env Envelope) {
	if len(b.events) == 0 {
		b.scope = ScopeOf(env.Meta)
	}
	b.events = append(b.events, env)
}

// last is the event whose position the checkpoint will name. Valid only when the
// batch is non-empty, which every caller checks first.
func (b *batch) last() Envelope { return b.events[len(b.events)-1] }

// reset empties the batch while keeping the allocation, so a catching-up
// projector allocates the slice once rather than once per batch.
func (b *batch) reset() {
	clear(b.events) // release the payload references; the array is reused
	b.events = b.events[:0]
	b.scope = db.Tenant{}
}

func (r *Runner) batchSize() int {
	if r.deps.CatchUpBatch <= 0 {
		return 1
	}
	return r.deps.CatchUpBatch
}

// flush applies every buffered event and the checkpoint that describes them in
// ONE transaction, then clears the buffer.
//
// The atomicity argument is identical to the single-event path and is the whole
// point: rows and checkpoint commit together, so a crash loses the batch as a
// unit and the projector reapplies it. Nothing is ever applied above a
// checkpoint that does not cover it.
//
// On failure the buffer is DROPPED rather than retried. The error stops the
// projector (ADR-019), the checkpoint still names the last committed batch, and
// a restart re-reads these events from the log — which is the only source that
// is allowed to be authoritative about them.
func (r *Runner) flush(ctx context.Context) error {
	n := r.pending.len()
	if n == 0 {
		return nil
	}

	last := r.pending.last()
	next := Checkpoint{
		Position:        last.Position,
		EventsProcessed: r.state.EventsProcessed + int64(n),
	}

	// Named so a failure points at the event that caused it rather than at the
	// batch it happened to be in.
	culprit := last
	started := r.deps.Clock.Now()

	// Replayable, not Durable, for the same reason the single-event path is:
	// everything written here is derived from the log (ADR-013), and the rows and
	// the checkpoint are lost together or not at all.
	err := r.deps.Batch.InTenantBatch(ctx, r.pending.scope, db.Replayable, func(w db.Writer) error {
		for _, env := range r.pending.events {
			if err := r.proj.Apply(ctx, w, env); err != nil {
				culprit = env
				return err
			}
		}
		r.deps.Checkpoints.Save(ctx, w, r.name, next, r.deps.Holder)
		return nil
	})
	if err != nil {
		r.pending.reset()
		r.deps.Metrics.Failed(r.name)
		return fmt.Errorf("%w: %s at %s#%d (in a batch of %d): %w",
			errApply, culprit.Type, culprit.Stream, culprit.Revision, n, err)
	}

	// One duration split across the batch. Reporting the whole batch time under
	// each event would make the histogram read as N slow events rather than one
	// transaction, and a per-event number is what the dashboards compare against
	// the unbatched path.
	per := r.deps.Clock.Now().Sub(started).Seconds() / float64(n)
	for range n {
		r.deps.Metrics.Applied(r.name, per)
	}
	r.deps.Metrics.Position(r.name, last.Position.Commit)
	r.state = next

	// Announce after the commit, never before — the same ordering the
	// single-event path keeps. Events buffered while behind are not live, so in
	// practice this announces nothing; it stays here so the rule holds if a
	// subscriber ever reports live without a batch boundary.
	for _, env := range r.pending.events {
		r.announce(ctx, env)
	}
	r.pending.reset()
	return nil
}

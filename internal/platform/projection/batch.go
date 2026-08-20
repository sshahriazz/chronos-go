package projection

import (
	"context"
	"errors"
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
	// batch it happened to be in. See attribution for why the obvious default —
	// the batch's last event — is the wrong answer far more often than the right
	// one.
	blame := attribution{events: r.pending.events}
	started := r.deps.Clock.Now()

	// Replayable, not Durable, for the same reason the single-event path is:
	// everything written here is derived from the log (ADR-013), and the rows and
	// the checkpoint are lost together or not at all.
	err := r.deps.Batch.InTenantBatch(ctx, r.pending.scope, db.Replayable, func(w db.Writer) error {
		blame.begin(w)
		for i, env := range r.pending.events {
			if err := r.proj.Apply(ctx, w, env); err != nil {
				blame.applyFailed(i)
				return err
			}
			blame.applied(i)
		}
		r.deps.Checkpoints.Save(ctx, w, r.name, next, r.deps.Holder)
		return nil
	})
	if err != nil {
		// BEFORE reset. reset() clears the envelope array in place to release
		// payload references, and attribution holds a slice over that same
		// array — reading it afterwards yields zeroed envelopes and an error
		// that names no event at all. Verified by making it happen: the message
		// read "apply failed:  at #0".
		culprit, known := blame.culprit(err)
		r.pending.reset()
		r.deps.Metrics.Failed(r.name)
		return fmt.Errorf("%w: %s at %s#%d%s (in a batch of %d): %w",
			errApply, culprit.Type, culprit.Stream, culprit.Revision,
			uncertain(known), n, err)
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

// ---------------------------------------------------------------------------
// attributing a batch failure to the event that caused it
// ---------------------------------------------------------------------------

// attribution maps a failed statement back to the event whose handler queued it.
//
// It exists because of a real hour of debugging. A batch failure used to be
// reported against `last`, the event that happened to close the batch, on the
// reasoning that Apply returns the error — but Apply does NOT return it.
// db.Writer.Exec QUEUES a statement and returns nothing; every statement in the
// batch is sent afterwards, in one round trip, and PostgreSQL's rejection
// surfaces from InTenantBatch long after every handler has returned nil. So the
// culprit stayed at its default and the message named an event that had done
// nothing wrong:
//
//	apply failed: identity.EmailVerificationRequested.v1 at user-usr_…#1
//	(in a batch of 48): postgres: batch statement 15 of 18
//	(…UpsertUser…): duplicate key value violates unique constraint
//
// Statement 15 belonged to a UserRegistered several events earlier. The name and
// the statement in one message contradicted each other, and the name is the half
// a reader believes.
//
// The mapping is recorded rather than guessed: the Writer reports how many
// statements it has queued (db.StatementCounter), so the range each event
// occupies is known exactly, and db.BatchStatementError carries the index of the
// one that failed on the same scale.
type attribution struct {
	events []Envelope

	// ends[i] is the queued-statement count immediately after events[i] was
	// applied, so events[i] owns [ends[i-1], ends[i]).
	ends []int

	// counter is nil when the Writer cannot report its position. Every
	// production Writer can; a test double need not, and the fallback is the old
	// behaviour rather than a failure.
	counter db.StatementCounter

	// failedAt is the index of the event whose Apply returned an error, or -1.
	// An error from Apply itself is unambiguous and outranks the statement map.
	failedAt int

	// start is the queued count before the first event was applied.
	start int
}

// begin starts recording against one batch's Writer.
func (a *attribution) begin(w db.Writer) {
	a.failedAt = -1
	a.ends = make([]int, 0, len(a.events))
	a.counter, _ = w.(db.StatementCounter)
	if a.counter != nil {
		// Not zero. InTenantBatch queues the tenant scope before the caller is
		// handed the Writer, so the first statement any event owns is not the
		// first statement in the batch — and a failure below this mark belongs
		// to the batch itself, not to an event.
		a.start = a.counter.Queued()
	}
}

// applied records where the event that just finished stopped queueing.
func (a *attribution) applied(i int) {
	if a.counter == nil {
		return
	}
	for len(a.ends) <= i {
		a.ends = append(a.ends, a.counter.Queued())
	}
}

// applyFailed records that Apply itself returned an error for this event.
func (a *attribution) applyFailed(i int) { a.failedAt = i }

// culprit reports the event to blame, and whether that attribution is certain.
//
// Uncertain means "no statement index was available" — a Writer that cannot
// count, or an error from somewhere other than a statement. The caller says so
// in the message rather than presenting a guess as a fact, because a confident
// wrong name is what made the original failure take an hour.
func (a *attribution) culprit(err error) (Envelope, bool) {
	if len(a.events) == 0 {
		return Envelope{}, false
	}
	if a.failedAt >= 0 && a.failedAt < len(a.events) {
		return a.events[a.failedAt], true
	}

	var batchErr *db.BatchStatementError
	if a.counter != nil && errors.As(err, &batchErr) && batchErr.Index >= a.start {
		for i, end := range a.ends {
			if batchErr.Index < end {
				return a.events[i], true
			}
		}
		// Past every event's range: the checkpoint statement, which belongs to
		// the batch rather than to any event.
		if len(a.ends) == len(a.events) {
			return a.events[len(a.events)-1], false
		}
	}
	return a.events[len(a.events)-1], false
}

// uncertain annotates a name the attribution could not establish.
func uncertain(known bool) string {
	if known {
		return ""
	}
	return " (or another event in this batch; the failing statement could not be attributed)"
}

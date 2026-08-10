package projection

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/realtime"
)

// Deps is what a Runner needs. Grouped into one struct so adding a dependency
// does not rewrite every call site, and so the composition root reads as a list
// of decisions rather than a positional argument soup.
type Deps struct {
	Subscriber eventsourcing.CatchUpSubscriber
	Codec      eventsourcing.Codec

	// Categories, when present, makes a rebuild read only this projection's own
	// aggregate types instead of scanning the whole log. Optional: without it a
	// rebuild falls back to $all, which is correct and much slower.
	Categories eventsourcing.CategoryReader

	// Types, when present, narrows a rebuild further still: a category stream
	// carries every type its aggregate emits, and a projection that wants one of
	// them reads and discards the rest. Applies only to a filter that selects on
	// whole event types and nothing else. Optional, like Categories.
	Types eventsourcing.TypeReader

	// Batch is the per-event path: one pipelined round trip per event.
	Batch db.BatchTX
	// TX is for the operations that are not per-event — loading a checkpoint,
	// and the reset-and-clear pair a rebuild runs once.
	TX db.SystemTX

	// Realtime announces changes to connected browsers. Optional: a projection
	// with no Emitter, or a deployment with no realtime service, simply does
	// not announce.
	Realtime realtime.Publisher

	Checkpoints Checkpoints
	Lease       Lease
	Clock       clock.Clock
	Log         *slog.Logger
	Metrics     Metrics

	// Holder identifies this process in the checkpoint row. Operational only —
	// mutual exclusion is the Lease, not this string.
	Holder string

	// LeaseRetry is how long to wait before trying again for the lease. Zero
	// takes the default.
	LeaseRetry time.Duration

	// SubscribeRetry is the backoff after a dropped subscription. Zero takes
	// the default.
	SubscribeRetry time.Duration

	// RebuildShards is how many workers a rebuild applies events through. One
	// (the default) is sequential.
	//
	// Sharding partitions by STREAM, never by revision range, so every event of
	// one aggregate is applied in order by one worker. It therefore trades away
	// ordering ACROSS aggregates — which a rebuild already gave up by reading a
	// link stream — and nothing else. See shardOf.
	//
	// Live consumption is never sharded: it must preserve the global commit
	// order the $all subscription exists to provide.
	RebuildShards int
}

const (
	defaultLeaseRetry     = 5 * time.Second
	defaultSubscribeRetry = 2 * time.Second
)

// Runner drives one projection.
//
// It is a single writer by construction: the Lease admits exactly one Runner
// per projection name across the whole fleet. Scaling the read side means
// adding projections, not copies of one (ARCHITECTURE §3.3).
type Runner struct {
	proj Projection
	deps Deps

	name string

	// state and resume are owned by the goroutine running consume. Nothing
	// else may read them: the checkpoint row in Postgres is the observable
	// position, and reading these from a health handler would be a data race.
	state  Checkpoint
	resume eventsourcing.StartFrom

	// live is written from the subscription goroutine and read by health
	// endpoints, so it is atomic rather than a plain bool.
	live atomic.Bool
}

func NewRunner(p Projection, deps Deps) *Runner {
	if deps.LeaseRetry <= 0 {
		deps.LeaseRetry = defaultLeaseRetry
	}
	if deps.SubscribeRetry <= 0 {
		deps.SubscribeRetry = defaultSubscribeRetry
	}
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	if deps.Clock == nil {
		deps.Clock = clock.System{}
	}
	if deps.Metrics == nil {
		deps.Metrics = noMetrics{}
	}
	deps.Log = deps.Log.With("projection", p.Name())
	return &Runner{proj: p, deps: deps, name: p.Name()}
}

// Run holds the lease and consumes the log until ctx is cancelled.
//
// It does not return an error for conditions that are expected in a running
// system — a lease held elsewhere, a dropped subscription — because those are
// not reasons to stop a process (ADR-010). It returns only when ctx ends, or
// when the projection itself rejects an event, which is a bug that must be
// loud.
func (r *Runner) Run(ctx context.Context) error {
	for {
		rel, held, err := r.deps.Lease.Acquire(ctx, r.name)
		switch {
		case err != nil:
			r.deps.Log.Warn("lease acquisition failed", "error", err)
		case !held:
			r.deps.Log.Debug("lease held elsewhere; standing by")
		default:
			err := r.consume(ctx)
			rel(context.WithoutCancel(ctx))
			// Any error that arrives with the context already ended is the
			// shutdown itself, whether it cancelled or timed out.
			if err != nil && ctx.Err() == nil {
				return err
			}
		}

		if !sleep(ctx, r.deps.LeaseRetry) {
			// ctx ended while standing by: an orderly stop, not a failure.
			return nil
		}
	}
}

// Live reports whether this projection has caught up to the head of the log.
//
// It is the honest answer to "is the read model current?", which no amount of
// checkpoint-watching gives you: a projector that has processed nothing looks
// identical whether the system is quiet or it is a day behind.
func (r *Runner) Live() bool { return r.live.Load() }

func (r *Runner) setLive(live bool) {
	if r.live.Swap(live) == live {
		return
	}
	r.deps.Metrics.Live(r.name, live)
	if live {
		r.deps.Log.Info("caught up to the head of the log")
		return
	}
	r.deps.Log.Warn("fell behind the head of the log")
}

// Rebuild empties the projection and restarts it from position zero.
//
// The reset and the checkpoint clear share one transaction, so a crash between
// them is impossible: either the projection is empty AND at zero, or neither
// happened. This is the operation that reactors deliberately do not have.
func (r *Runner) Rebuild(ctx context.Context) error {
	rel, held, err := r.deps.Lease.Acquire(ctx, r.name)
	if err != nil {
		return fmt.Errorf("projection %s: acquiring lease to rebuild: %w", r.name, err)
	}
	if !held {
		return fmt.Errorf("projection %s: cannot rebuild while another instance is running it", r.name)
	}
	defer rel(context.WithoutCancel(ctx))

	if err := r.deps.TX.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		if err := r.proj.Reset(ctx, q); err != nil {
			return fmt.Errorf("resetting: %w", err)
		}
		return r.deps.Checkpoints.Clear(ctx, q, r.name)
	}); err != nil {
		return fmt.Errorf("projection %s: rebuild: %w", r.name, err)
	}

	if err := r.rebuildFromLinkStreams(ctx); err != nil {
		return err
	}
	return r.consume(ctx)
}

// rebuildFromLinkStreams replays this projection's own slice of the log, picking
// the narrowest source the filter allows.
//
//	$et-<type>      when the filter names exactly one whole event type
//	$ce-<category>  when it names exactly one category
//	$all            otherwise, which is always correct and always slower
//
// $et- is preferred where it applies because it is strictly narrower: a category
// stream carries every type its aggregate emits, so a projection wanting one of
// them reads and discards the rest.
//
// "Exactly one" in both cases, and the restriction is not conservatism. Reading
// two link streams in sequence applies every event of the first before any of
// the second, so global commit order is lost — and a projection that joins
// across types would rebuild into a different state than it holds live. Merging
// them by commit position would fix it and is not worth the complexity until a
// projection actually needs it.
func (r *Runner) rebuildFromLinkStreams(ctx context.Context) error {
	filter := r.proj.Filter()

	if types, ok := filter.ExactTypes(); ok && len(types) == 1 && r.deps.Types != nil {
		return r.replay(ctx, "event type", types[0], func(h eventsourcing.Handler) error {
			return r.deps.Types.ReadEventType(ctx, types[0], h)
		})
	}

	if categories, ok := filter.Categories(); ok && len(categories) == 1 && r.deps.Categories != nil {
		category := categories[0]
		return r.replay(ctx, "category", string(category), func(h eventsourcing.Handler) error {
			return r.deps.Categories.ReadCategory(ctx, category, h)
		})
	}

	r.deps.Log.Info("rebuilding via $all",
		"reason", "the filter does not resolve to exactly one event type or category")
	return nil
}

// replay drains one link stream, falling back to $all if it is unavailable.
//
// The fallback is not silent and not fatal: a link stream is an optimisation
// over $all, and $all is always there. What makes the fallback SAFE is that
// consume resumes from the checkpoint this replay already advanced, so a partial
// read is finished rather than repeated.
func (r *Runner) replay(ctx context.Context, kind, name string, read func(eventsourcing.Handler) error) error {
	if r.deps.RebuildShards > 1 {
		return r.replaySharded(ctx, kind, name, read)
	}

	r.deps.Log.Info("rebuilding from the "+kind+" stream", kind, name)
	start := r.deps.Clock.Now()

	if err := read(r.handle); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, errApply) {
			// The projection rejected an event. That is not a reason to try a
			// slower source — it would reject the same event again.
			return err
		}
		r.deps.Log.Warn("link-stream read failed; continuing from $all",
			kind, name, "error", err)
		return nil
	}

	r.deps.Log.Info("replay complete", kind, name,
		"events", r.state.EventsProcessed,
		"elapsed", r.deps.Clock.Now().Sub(start).String())
	return nil
}

// consume subscribes from the stored checkpoint and applies events until the
// subscription drops or ctx ends.
func (r *Runner) consume(ctx context.Context) error {
	for {
		if err := r.loadCheckpoint(ctx); err != nil {
			return err
		}
		r.deps.Log.Info("subscribing",
			"from_beginning", r.resume.IsBeginning(),
			"from_commit", r.resume.Position().Commit,
			"events_processed", r.state.EventsProcessed)

		err := r.deps.Subscriber.SubscribeAll(ctx, r.resume, eventsourcing.SubscribeOptions{
			Filter:       r.proj.Filter(),
			OnLive:       func() { r.setLive(true) },
			OnBehind:     func() { r.setLive(false) },
			OnCheckpoint: r.skipTo,
		}, r.handle)
		switch {
		case err == nil, errors.Is(err, context.Canceled):
			return ctx.Err()
		case errors.Is(err, errApply):
			// The projection rejected an event. Retrying cannot help, and
			// skipping would build a read model that is wrong in a way nothing
			// detects. Stop and be loud.
			return err
		default:
			r.setLive(false)
			r.deps.Log.Warn("subscription dropped; reconnecting", "error", err)
			if !sleep(ctx, r.deps.SubscribeRetry) {
				return ctx.Err()
			}
		}
	}
}

func (r *Runner) loadCheckpoint(ctx context.Context) error {
	return r.deps.TX.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		cp, err := r.deps.Checkpoints.Load(ctx, q, r.name)
		if errors.Is(err, ErrNoCheckpoint) {
			// Never run, or just rebuilt. Start at the head of the log — which
			// is NOT the same as resuming after position zero.
			r.state, r.resume = Checkpoint{}, eventsourcing.FromBeginning()
			return nil
		}
		if err != nil {
			return fmt.Errorf("projection %s: loading checkpoint: %w", r.name, err)
		}
		r.state, r.resume = cp, eventsourcing.After(cp.Position)
		return nil
	})
}

// announce publishes a projection's realtime messages, AFTER its rows commit.
//
// Deliberately best-effort and deliberately last. A failed publish must not fail
// the projection: the rows are already durable, the browser recovers by reading
// them, and treating a missed toast as a projection error would stop a read
// model over a cosmetic failure (ADR-010).
//
// Nothing is announced while catching up. Replaying history to a connected
// browser would fire one notification per event that user ever received.
func (r *Runner) announce(ctx context.Context, env Envelope) {
	emitter, ok := r.proj.(Emitter)
	if !ok || r.deps.Realtime == nil || !env.Live {
		return
	}
	msgs := emitter.Emit(env)
	if len(msgs) == 0 {
		return
	}
	if err := r.deps.Realtime.PublishMany(ctx, msgs); err != nil {
		r.deps.Log.Warn("realtime announcement failed; the change is still in the read model",
			"event_type", env.Type, "messages", len(msgs), "error", err)
	}
}

// ScopeOf maps event metadata to a read-model tenant scope. This is the ONLY
// place the two vocabularies meet, so the kernel's event layer keeps no opinion
// about the read model and db.Tenant stays the single definition of a scope.
func ScopeOf(m eventsourcing.Metadata) db.Tenant {
	return db.Tenant{
		OrgID:       m.OrgID,
		WorkspaceID: m.WorkspaceID,
		Residency:   m.Residency,
	}
}

// errApply marks a failure that came from the projection itself, so consume can
// tell "the database moved" from "this projection is broken".
var errApply = errors.New("projection: apply failed")

// skipTo advances the stored position past a span the server has scanned and
// found nothing in.
//
// No rows are written and EventsProcessed does not move: nothing was projected.
// What moves is the resume point, and that is the whole value — a projection
// filtered to a quiet module otherwise never advances while the rest of the
// system writes, and re-scans the entire intervening log on every restart.
// Measured at 50k intervening events, that restart cost 866ms instead of 3ms,
// and it grows with the log forever.
//
// Safe because the server guarantees no MATCHING event lies between the last
// delivered one and this position. Resuming here therefore skips nothing this
// projection would have applied.
//
// It is written in its own system transaction rather than batched with rows,
// because by definition there are no rows to batch it with.
func (r *Runner) skipTo(ctx context.Context, p eventsourcing.Position) error {
	// Never move backwards. A server checkpoint can trail the last event already
	// applied — the checkpoint interval and event delivery are independent — and
	// rewinding the position would replay events this projection has processed.
	// Apply is idempotent, so that is not corruption, but it is silent repeated
	// work that would look like the bug this method fixes.
	if p.Commit <= r.state.Position.Commit {
		return nil
	}

	next := Checkpoint{Position: p, EventsProcessed: r.state.EventsProcessed}
	if err := r.deps.TX.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		w := &querierWriter{ctx: ctx, q: q}
		r.deps.Checkpoints.Save(ctx, w, r.name, next, r.deps.Holder)
		return w.err
	}); err != nil {
		// Deliberately fatal to the subscription rather than logged and dropped.
		// A checkpoint that silently fails to persist reproduces exactly the
		// behaviour this method exists to remove, with no signal at all.
		return fmt.Errorf("projection %s: recording scanned position %d: %w",
			r.name, p.Commit, err)
	}

	r.state = next
	r.deps.Metrics.Position(r.name, p.Commit)
	return nil
}

// querierWriter adapts a Querier to the queue-only Writer that Checkpoints.Save
// expects.
//
// Save queues rather than executes, because in the normal path it must land in
// the same batch as the rows it describes. Here there are no rows, so the queue
// is one statement deep and is executed immediately.
type querierWriter struct {
	ctx context.Context
	q   db.Querier
	err error
}

func (w *querierWriter) Exec(sql string, args ...any) {
	// Writer cannot return an error — it exists to queue into a batch, where
	// failures surface when the batch is sent. Here the statement runs
	// immediately, so the first failure is held and reported by the caller.
	if w.err != nil {
		return
	}
	if _, err := w.q.Exec(w.ctx, sql, args...); err != nil {
		w.err = err
	}
}

// handle applies one event and advances the checkpoint IN THE SAME
// TRANSACTION.
//
// That single property is what makes a projection rebuildable and restart-safe.
// If the rows commit but the checkpoint does not, the event is reapplied — which
// is why Apply must be idempotent. If the checkpoint commits but the rows do
// not, the event is lost forever and nothing ever notices. One transaction
// removes the second case entirely.
func (r *Runner) handle(ctx context.Context, e eventsourcing.RecordedEvent) error {
	// $all carries system streams — $metadata, stats, scavenge records. They are
	// not domain facts and decoding them is meaningless. The subscriber filters
	// them too; this holds for any other CatchUpSubscriber implementation.
	if e.IsSystem() {
		return nil
	}

	meta, err := r.decodeMeta(e)
	if err != nil {
		return fmt.Errorf("%w: %w", errApply, err)
	}
	env := Envelope{
		ID:       e.ID,
		Type:     e.Type,
		Stream:   e.Stream,
		Revision: e.Revision,
		Position: e.Position,
		Meta:     meta,
		Payload:  e.Payload,
		Live:     r.live.Load(),
	}

	next := Checkpoint{
		Position:        e.Position,
		EventsProcessed: r.state.EventsProcessed + 1,
	}

	started := r.deps.Clock.Now()

	// Replayable, not Durable: everything written here is derived from the log
	// (ADR-013). A crash can lose the last fraction of a second of commits, but
	// the rows and the checkpoint are in the SAME batch, so they are lost
	// together — the projection stays self-consistent and simply reapplies
	// those events on restart. Measured, this is 299 µs/event → 139 µs.
	if err := r.deps.Batch.InTenantBatch(ctx, ScopeOf(env.Meta), db.Replayable,
		func(w db.Writer) error {
			// The scope comes from the event's own metadata, so each event is
			// projected under the policy of the org that produced it. Events
			// with no org — system-wide facts — stay unscoped and may only
			// touch tables that carry no RLS.
			if err := r.proj.Apply(ctx, w, env); err != nil {
				return err
			}
			r.deps.Checkpoints.Save(ctx, w, r.name, next, r.deps.Holder)
			return nil
		}); err != nil {
		r.deps.Metrics.Failed(r.name)
		return fmt.Errorf("%w: %s at %s#%d: %w", errApply, e.Type, e.Stream, e.Revision, err)
	}

	r.deps.Metrics.Applied(r.name, r.deps.Clock.Now().Sub(started).Seconds())
	r.deps.Metrics.Position(r.name, e.Position.Commit)

	r.state = next
	r.announce(ctx, env)
	return nil
}

func (r *Runner) decodeMeta(e eventsourcing.RecordedEvent) (eventsourcing.Metadata, error) {
	meta, err := r.deps.Codec.UnmarshalMetadata(e.Metadata)
	if err != nil {
		return eventsourcing.Metadata{}, fmt.Errorf("metadata of %s at %s#%d: %w", e.Type, e.Stream, e.Revision, err)
	}
	return meta, nil
}

// sleep waits, reporting false if the context ended first. It returns a bool
// rather than an error because "the process is shutting down" is not a failure
// anyone should have to unwrap.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

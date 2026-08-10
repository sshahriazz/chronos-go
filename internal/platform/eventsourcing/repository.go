package eventsourcing

import (
	"context"
	"errors"
	"fmt"
)

// Repository loads and saves aggregates. It is the only thing that bridges the
// domain (typed events) and the store (encoded payloads), so aggregates never
// see a codec and the store never sees a domain type.
type Repository[T Root] struct {
	store     EventStore
	codec     Codec
	upcasters *UpcasterRegistry
	category  Category
	newFn     func() T

	snapshots     SnapshotStore
	snapshotEvery Revision
	onSnapshotErr func(stream StreamID, err error)
}

// Option configures a Repository.
type Option func(*repoOptions)

type repoOptions struct {
	snapshots     SnapshotStore
	snapshotEvery Revision
	onSnapshotErr func(stream StreamID, err error)
}

// WithSnapshots makes Load start from the latest snapshot instead of replaying
// the whole stream, and makes Save write a new one every `every` events.
//
// Snapshots are an optimisation and are treated as one throughout: a snapshot
// that cannot be read, decoded or restored is IGNORED and the aggregate is
// replayed from zero. The aggregate type must implement Snapshotter; if it does
// not, this is silently inert rather than an error, so a repository can be
// configured uniformly across aggregates that differ in whether they need it.
func WithSnapshots(s SnapshotStore, every Revision) Option {
	return func(o *repoOptions) {
		o.snapshots = s
		if every > 0 {
			o.snapshotEvery = every
		}
	}
}

// OnSnapshotError observes snapshots that were written or read unsuccessfully.
//
// There is no error return for these anywhere in the public API, by design — a
// failed snapshot must never fail a command — so this hook exists to keep the
// failure visible instead of silent.
func OnSnapshotError(fn func(stream StreamID, err error)) Option {
	return func(o *repoOptions) { o.onSnapshotErr = fn }
}

// NewRepository builds a repository for one aggregate type.
//
// newFn returns a zero-valued aggregate; the repository positions it before the
// first event so a never-persisted aggregate saves with NoStream.
func NewRepository[T Root](
	store EventStore,
	codec Codec,
	upcasters *UpcasterRegistry,
	category Category,
	newFn func() T,
	opts ...Option,
) *Repository[T] {
	o := repoOptions{snapshotEvery: SnapshotEvery}
	for _, apply := range opts {
		apply(&o)
	}
	return &Repository[T]{
		store: store, codec: codec, upcasters: upcasters,
		category: category, newFn: newFn,
		snapshots:     o.snapshots,
		snapshotEvery: o.snapshotEvery,
		onSnapshotErr: o.onSnapshotErr,
	}
}

// Load rebuilds an aggregate from its stream.
//
// A missing stream is NOT an error: it returns a new aggregate, which is what
// lets a caller treat "create" and "modify" as the same code path and rely on
// the append precondition to decide.
func (r *Repository[T]) Load(ctx context.Context, key string) (T, error) {
	agg := NewAggregate(r.newFn)

	stream, err := NewStreamID(r.category, key)
	if err != nil {
		return agg, err
	}

	// A snapshot only ever changes WHERE the replay starts. If anything about
	// it is unusable, from is zero and the result is identical to never having
	// had one — slower, never different.
	from := Revision(0)
	if rev, ok := r.restoreSnapshot(ctx, key, agg); ok {
		from = rev + 1
		positionAt(agg, rev)
	}

	recorded, err := r.store.ReadStream(ctx, stream, from)
	if err != nil {
		if isNotFound(err) {
			// No stream at all: only correct to return the aggregate as-is when
			// no snapshot claimed otherwise. A snapshot for a stream that does
			// not exist is corrupt, so fall back rather than trust it.
			if from > 0 {
				return r.loadWithoutSnapshot(ctx, stream)
			}
			return agg, nil
		}
		return agg, err
	}
	if len(recorded) == 0 {
		return agg, nil
	}

	events := make([]Event, 0, len(recorded))
	for _, rec := range recorded {
		// $all and stream reads can surface system events; a domain aggregate
		// must never try to decode one.
		if rec.IsSystem() {
			continue
		}
		e, err := r.decode(rec)
		if err != nil {
			return agg, fmt.Errorf("loading %s at revision %d: %w", stream, rec.Revision, err)
		}
		events = append(events, e)
	}

	rebuild(agg, events, recorded[len(recorded)-1].Revision)
	return agg, nil
}

// restoreSnapshot puts the aggregate into its snapshotted state, reporting the
// revision that state accounts for.
//
// Every failure path returns ok=false, including a snapshot whose type is no
// longer registered and one the aggregate refuses. That is the whole safety
// argument for snapshots: the worst outcome is a full replay.
func (r *Repository[T]) restoreSnapshot(ctx context.Context, key string, agg T) (Revision, bool) {
	if r.snapshots == nil {
		return 0, false
	}
	snapshotter, ok := any(agg).(Snapshotter)
	if !ok {
		return 0, false
	}

	stream, err := SnapshotStreamID(r.category, key)
	if err != nil {
		return 0, false
	}

	rec, found, err := r.snapshots.LoadSnapshot(ctx, stream)
	if err != nil {
		r.snapshotFailed(stream, fmt.Errorf("reading snapshot: %w", err))
		return 0, false
	}
	if !found {
		return 0, false
	}

	meta, err := r.codec.UnmarshalMetadata(rec.Metadata)
	if err != nil {
		r.snapshotFailed(stream, fmt.Errorf("snapshot metadata: %w", err))
		return 0, false
	}
	if meta.SnapshotRevision < 0 {
		return 0, false
	}

	e, err := r.decode(rec)
	if err != nil {
		// The usual cause is a snapshot type that was renamed or retired. It is
		// not a failure — history is intact and replay produces the truth.
		r.snapshotFailed(stream, fmt.Errorf("decoding snapshot: %w", err))
		return 0, false
	}
	if err := snapshotter.Restore(e); err != nil {
		r.snapshotFailed(stream, fmt.Errorf("restoring snapshot: %w", err))
		return 0, false
	}
	return meta.SnapshotRevision, true
}

// loadWithoutSnapshot is the fallback when a snapshot turned out to describe a
// stream that is not there.
func (r *Repository[T]) loadWithoutSnapshot(ctx context.Context, stream StreamID) (T, error) {
	agg := NewAggregate(r.newFn)
	recorded, err := r.store.ReadStream(ctx, stream, 0)
	if err != nil {
		if isNotFound(err) {
			return agg, nil
		}
		return agg, err
	}
	if len(recorded) == 0 {
		return agg, nil
	}
	events, err := r.decodeAll(stream, recorded)
	if err != nil {
		return agg, err
	}
	rebuild(agg, events, recorded[len(recorded)-1].Revision)
	return agg, nil
}

func (r *Repository[T]) decodeAll(stream StreamID, recorded []RecordedEvent) ([]Event, error) {
	events := make([]Event, 0, len(recorded))
	for _, rec := range recorded {
		if rec.IsSystem() {
			continue
		}
		e, err := r.decode(rec)
		if err != nil {
			return nil, fmt.Errorf("loading %s at revision %d: %w", stream, rec.Revision, err)
		}
		events = append(events, e)
	}
	return events, nil
}

func (r *Repository[T]) snapshotFailed(stream StreamID, err error) {
	if r.onSnapshotErr != nil {
		r.onSnapshotErr(stream, err)
	}
}

// maybeSnapshot writes a snapshot when enough events have accumulated since the
// last one.
//
// It returns nothing. A snapshot that fails to write must not fail the command
// that triggered it: the events are already durable, the aggregate is correct,
// and the only consequence is that the next load is slower.
func (r *Repository[T]) maybeSnapshot(ctx context.Context, key string, agg T, at Revision, meta Metadata) {
	if r.snapshots == nil || r.snapshotEvery <= 0 {
		return
	}
	snapshotter, ok := any(agg).(Snapshotter)
	if !ok {
		return
	}
	// Snapshot when the revision crosses a multiple of the interval. Computed
	// from the revision rather than a counter so it holds no matter how many
	// events one command appended, or which process appended them.
	if at/r.snapshotEvery == (at-Revision(len(agg.Uncommitted())))/r.snapshotEvery {
		return
	}

	stream, err := SnapshotStreamID(r.category, key)
	if err != nil {
		return
	}

	state := snapshotter.Snapshot()
	if state == nil {
		return
	}
	meta.SnapshotRevision = at
	if meta.SchemaVersion == 0 && r.upcasters != nil {
		if v, ok := r.upcasters.CurrentVersion(state.EventType()); ok {
			meta.SchemaVersion = v
		}
	}

	// A deterministic id keyed by stream and revision makes a retried snapshot
	// collapse into the existing one instead of duplicating.
	err = r.snapshots.SaveSnapshot(ctx, stream, PendingEvent{
		ID:    DeriveEventID(string(stream), int(at)),
		Event: state,
		Meta:  meta,
	})
	if err != nil {
		r.snapshotFailed(stream, fmt.Errorf("writing snapshot at %d: %w", at, err))
	}
}

// decode applies the upcaster chain before handing the payload to the codec, so
// the domain only ever sees the current schema version (ADR-029).
func (r *Repository[T]) decode(rec RecordedEvent) (Event, error) {
	payload := rec.Payload

	if r.upcasters != nil {
		meta, err := r.codec.UnmarshalMetadata(rec.Metadata)
		if err != nil {
			return nil, err
		}
		upcasted, err := r.upcasters.Apply(rec.Type, meta.SchemaVersion, payload)
		if err != nil {
			return nil, err
		}
		payload = upcasted
	}
	return r.codec.Unmarshal(rec.Type, payload)
}

// Save appends the aggregate's uncommitted events under the concurrency
// precondition implied by the version it was loaded at.
//
// idempotencyKey derives deterministic event ids, so a retried command produces
// byte-identical ids and the store collapses the duplicate itself
// (EVENT-SOURCING §3). It must be stable across retries of the same command.
func (r *Repository[T]) Save(
	ctx context.Context,
	key string,
	agg T,
	idempotencyKey string,
	meta Metadata,
) (AppendResult, error) {
	pending := agg.Uncommitted()
	if len(pending) == 0 {
		return AppendResult{}, nil
	}

	stream, err := NewStreamID(r.category, key)
	if err != nil {
		return AppendResult{}, err
	}

	events := make([]PendingEvent, 0, len(pending))
	for i, e := range pending {
		m := meta
		if m.SchemaVersion == 0 && r.upcasters != nil {
			if v, ok := r.upcasters.CurrentVersion(e.EventType()); ok {
				m.SchemaVersion = v
			}
		}
		events = append(events, PendingEvent{
			ID:    DeriveEventID(idempotencyKey, i),
			Event: e,
			Meta:  m,
		})
	}

	res, err := r.store.Append(ctx, stream, ExpectedFor(agg), events)
	if err != nil {
		return AppendResult{}, err
	}

	// After the append, never before: a snapshot of state that failed to
	// persist would describe a history that does not exist.
	r.maybeSnapshot(ctx, key, agg, res.Revision, meta)

	// Only clear once the append is durable: clearing earlier would lose the
	// events if the caller retries after a transient failure.
	agg.ClearUncommitted()
	agg.base().version = res.Revision
	return res, nil
}

func isNotFound(err error) bool { return errors.Is(err, ErrStreamNotFound) }

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
) *Repository[T] {
	return &Repository[T]{
		store: store, codec: codec, upcasters: upcasters,
		category: category, newFn: newFn,
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

	// Only clear once the append is durable: clearing earlier would lose the
	// events if the caller retries after a transient failure.
	agg.ClearUncommitted()
	agg.base().version = res.Revision
	return res, nil
}

func isNotFound(err error) bool { return errors.Is(err, ErrStreamNotFound) }

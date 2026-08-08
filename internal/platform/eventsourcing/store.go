package eventsourcing

import "context"

// AppendResult reports where an append landed. The Position is the consistency
// token handed back to clients for read-your-writes (access.md §6.3).
type AppendResult struct {
	Revision Revision
	Position Position
}

// EventStore is the append-and-read port. Declared here, in the kernel;
// implemented by an adapter (ADR-001), so no domain ever sees a driver.
type EventStore interface {
	// Append writes events with an optimistic-concurrency precondition,
	// returning ErrWrongExpectedRevision on mismatch.
	Append(ctx context.Context, stream StreamID, expected ExpectedRevision, events []PendingEvent) (AppendResult, error)

	// ReadStream reads forwards from the given revision. Returns
	// ErrStreamNotFound when the stream does not exist.
	ReadStream(ctx context.Context, stream StreamID, from Revision) ([]RecordedEvent, error)
}

// SubscriptionFilter narrows a global subscription server-side.
//
// Category streams ($ce-) are unavailable to us: they require the $by_category
// system projection, which is off by design (verified — reading one returns
// 404). So every subscriber reads $all with a filter, which also buys global
// commit ordering across aggregates.
type SubscriptionFilter struct {
	// StreamPrefixes matches on stream name, e.g. "organization-".
	StreamPrefixes []string
	// EventTypePrefixes matches on event type.
	EventTypePrefixes []string
}

// Handler processes one event. Returning an error stops a projector and parks
// the event for a reactor.
type Handler func(ctx context.Context, e RecordedEvent) error

// CatchUpSubscriber streams $all from a caller-held position.
//
// This is the PROJECTOR transport: the checkpoint is ours, committed in the
// same transaction as the rows it describes, which is what makes a projection
// rebuildable from zero (ADR-019).
type CatchUpSubscriber interface {
	SubscribeAll(ctx context.Context, from Position, filter SubscriptionFilter, h Handler) error
}

// PersistentSubscriber consumes a server-managed subscription.
//
// This is the REACTOR transport: KurrentDB holds the checkpoint and provides
// ack/nack with a parking queue. There is no rebuild API to call by accident,
// which makes "reactors are never replayed" structural rather than a
// convention (ADR-019).
type PersistentSubscriber interface {
	Consume(ctx context.Context, group string, filter SubscriptionFilter, h Handler) error
}

// Codec serializes domain events. Implemented by an adapter, so this package
// imports no serialization library and domain types carry no wire tags.
type Codec interface {
	Marshal(Event) ([]byte, error)
	Unmarshal(eventType string, payload []byte) (Event, error)
	MarshalMetadata(Metadata) ([]byte, error)
	UnmarshalMetadata([]byte) (Metadata, error)
}

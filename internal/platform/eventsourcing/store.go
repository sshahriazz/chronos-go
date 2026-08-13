package eventsourcing

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

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

// StreamAppend is one stream's part of an atomic multi-stream append.
type StreamAppend struct {
	Stream   StreamID
	Expected ExpectedRevision
	Events   []PendingEvent
}

// MultiAppender writes to several streams in ONE atomic operation: every
// precondition holds and every event lands, or nothing does.
//
// # This does not relax the aggregate boundary
//
// One aggregate is still one stream and one consistency boundary (ADR §2). If an
// invariant spans two aggregates, it belongs in one aggregate or it is a process
// — and a process is a Temporal workflow (ADR-017). Reaching for this to enforce
// a cross-aggregate rule reintroduces exactly the coupling that rule prevents,
// and it will not scale past one server.
//
// # What it IS for
//
// Pairing a claim with the thing that claims it. Registration must reserve
// `reservation_email-<hex(HMAC(k_res, email))>` with NoStream AND create
// `user-<id>` with NoStream. The reservation value is HMACed rather than the
// raw address: a stream name is permanent, appears in the $streams index and in
// category streams, and has no ciphertext for erasure to destroy (ADR-048). As two appends, a crash between them leaves a reservation
// nobody owns, which is why the pattern needed compensation or a workflow. As
// one append, the gap does not exist.
//
// Verified against the running server: failing one stream's precondition rolled
// the other stream's events back — nothing was written.
type MultiAppender interface {
	AppendToMany(ctx context.Context, appends []StreamAppend) ([]AppendResult, error)
}

// Event size limits.
//
// KurrentDB caps an APPEND at roughly 1 MiB by default, and the cap counts the
// whole append rather than one event, so a command emitting several events has
// less headroom than the number below suggests. MaxEventBytes is deliberately
// under the server's limit: being refused by our own code names the problem,
// while being refused by the server surfaces as a generic write failure in the
// middle of a command that has already reserved uniqueness.
//
// The real answer to a large payload is not a larger limit. Bytes go to
// SeaweedFS and the event carries a reference (EVENT-SOURCING §10) — an event is
// a fact about what happened, not a container for the thing it happened to.
const (
	// MaxEventBytes is the hard ceiling on one event's encoded payload.
	MaxEventBytes = 768 << 10 // 768 KiB

	// LargeEventBytes is the point at which an event is worth complaining about
	// while still writing it. Throughput on the log is a function of payload
	// size, and an event this big is nearly always a blob that belongs in object
	// storage or a projection that belongs in a read model.
	LargeEventBytes = 50 << 10 // 50 KiB
)

// ErrEventTooLarge is returned instead of attempting an append that the server
// would reject, or that would leave no room for the events beside it.
var ErrEventTooLarge = errors.New("eventsourcing: event payload is too large")

// CheckEventSize reports whether an encoded payload may be appended, and whether
// it is large enough to be worth reporting.
//
// It lives in the kernel so both append paths — single-stream and multi-stream —
// share one limit, and so the limit is stated where the rules are rather than
// inside a driver.
func CheckEventSize(eventType string, payload []byte) (large bool, err error) {
	if len(payload) > MaxEventBytes {
		return true, fmt.Errorf("%w: %s is %d bytes, over the %d-byte limit; "+
			"put the bytes in object storage and reference them from the event",
			ErrEventTooLarge, eventType, len(payload), MaxEventBytes)
	}
	return len(payload) > LargeEventBytes, nil
}

// SubscriptionFilter narrows a global subscription server-side.
//
// LIVE subscriptions read $all with this filter, which buys global commit
// ordering across aggregates — the property a projection joining two aggregate
// types depends on.
//
// REBUILDS do not need that ordering within a single category, so they read the
// link streams instead and skip the rest of the log entirely: $ce-<category> via
// Categories, $et-<type> via ExactTypes. Both are maintained by the built-in
// system projections and require RUN_PROJECTIONS=System.
//
// An earlier version of this comment stated that $ce- was unavailable, citing a
// verified 404. The 404 was real; its cause was our own compose file setting
// RUN_PROJECTIONS=None, so the note documented a misconfiguration as a property
// of the server. Enabling System made the streams work and the rebuild 14.8x
// faster.
type SubscriptionFilter struct {
	// StreamPrefixes matches on stream name, e.g. "organization-".
	StreamPrefixes []string
	// EventTypePrefixes matches on event type.
	EventTypePrefixes []string

	// EventTypes matches WHOLE event types, e.g. "notification.Created.v1".
	//
	// Distinct from EventTypePrefixes because the difference is not cosmetic. A
	// prefix cannot name a $et- stream — "notification.Created.v1" as a prefix
	// also matches "notification.Created.v10" — so only an exact type can use
	// the type stream on rebuild. Declaring the intent here is what makes that
	// choice available.
	EventTypes []string
}

// ErrAmbiguousFilter marks a filter that selects on more than one dimension.
var ErrAmbiguousFilter = errors.New("eventsourcing: subscription filter mixes selectors")

// Validate rejects a filter the server cannot express.
//
// A KurrentDB filter is EITHER a stream filter OR an event-type filter, never
// both. A filter naming stream prefixes and event types therefore has to lose
// one of them, and the loss is silent: the subscription runs, the projection
// looks healthy, and the events it declared but never received simply never
// appear in the read model. Nothing detects that — not a test, not a metric, not
// a checkpoint, because the checkpoint advances perfectly well over events the
// filter excluded.
//
// So it is refused at startup instead. A projection that genuinely needs two
// dimensions must widen to one of them and discard the rest in Apply, which is
// correct and merely wasteful — the opposite trade to the one silence makes.
//
// An EMPTY filter is valid: it means "every domain event", which the subscriber
// renders as KurrentDB's exclude-system filter.
func (f SubscriptionFilter) Validate() error {
	selectors := 0
	if len(f.StreamPrefixes) > 0 {
		selectors++
	}
	if len(f.EventTypePrefixes) > 0 {
		selectors++
	}
	if len(f.EventTypes) > 0 {
		selectors++
	}
	if selectors > 1 {
		return fmt.Errorf("%w: stream_prefixes=%d event_type_prefixes=%d event_types=%d; "+
			"a KurrentDB filter matches streams OR event types, so one of these would be "+
			"dropped and the events it selects would never arrive",
			ErrAmbiguousFilter, len(f.StreamPrefixes), len(f.EventTypePrefixes), len(f.EventTypes))
	}

	for _, group := range [][]string{f.StreamPrefixes, f.EventTypePrefixes, f.EventTypes} {
		for _, v := range group {
			if v == "" {
				// An empty prefix matches everything, which makes the filter a lie
				// rather than a narrowing.
				return fmt.Errorf("%w: an empty selector matches every event", ErrAmbiguousFilter)
			}
			if strings.HasPrefix(v, "$") {
				return fmt.Errorf("%w: %q selects system streams, which no consumer may handle",
					ErrAmbiguousFilter, v)
			}
		}
	}
	return nil
}

// ExactTypes reports the whole event types this filter selects, when types are
// the ONLY thing it selects on.
//
// Mixing selectors reports ok=false: a filter that also names stream prefixes
// selects a set no single $et- stream contains, and rebuilding from one would
// silently drop the rest.
func (f SubscriptionFilter) ExactTypes() ([]string, bool) {
	if len(f.EventTypes) == 0 {
		return nil, false
	}
	if len(f.StreamPrefixes) > 0 || len(f.EventTypePrefixes) > 0 {
		return nil, false
	}
	for _, t := range f.EventTypes {
		if t == "" || strings.HasPrefix(t, "$") {
			return nil, false
		}
	}
	return f.EventTypes, true
}

// Categories reports the categories this filter selects, when every prefix is a
// whole category of the form "<category>-".
//
// This is what lets a rebuild read category streams instead of scanning the
// entire log — measured at 14.8x on a projection wanting 5% of the events. A
// filter that cannot be expressed as whole categories reports ok=false and the
// caller falls back to $all, which is always correct and always slower.
func (f SubscriptionFilter) Categories() ([]Category, bool) {
	if len(f.StreamPrefixes) == 0 || len(f.EventTypePrefixes) > 0 || len(f.EventTypes) > 0 {
		return nil, false
	}
	out := make([]Category, 0, len(f.StreamPrefixes))
	for _, p := range f.StreamPrefixes {
		if len(p) < 2 || p[len(p)-1] != '-' {
			return nil, false
		}
		name := p[:len(p)-1]
		if strings.ContainsRune(name, '-') || strings.HasPrefix(name, "$") {
			return nil, false
		}
		out = append(out, Category(name))
	}
	return out, true
}

// CategoryReader reads every event of one aggregate type, in log order.
//
// Backed by KurrentDB's $ce- streams, which the $by_category system projection
// maintains. They are available only when the server runs with
// RUN_PROJECTIONS=System — a setting that enables the built-in NATIVE
// projections and no JavaScript.
type CategoryReader interface {
	ReadCategory(ctx context.Context, category Category, h Handler) error
}

// TypeReader reads every event of one exact event type, in log order.
//
// Backed by $et- streams, maintained by the $by_event_type system projection.
// Narrower than a category stream and correspondingly cheaper: a category
// carries every type its aggregate emits, so a projection that wants one of them
// reads and discards the rest.
//
// It applies only to a filter that selects on whole event types and nothing else
// — see SubscriptionFilter.ExactTypes.
type TypeReader interface {
	ReadEventType(ctx context.Context, eventType string, h Handler) error
}

// Deleter removes a stream. This is the mechanism behind erasure that must
// destroy events rather than re-encrypt them.
type Deleter interface {
	// SoftDelete makes a stream unreadable and allows the next scavenge to
	// reclaim it. The stream name can be written to again afterwards.
	SoftDelete(ctx context.Context, stream StreamID) error

	// Tombstone deletes a stream PERMANENTLY. The name can never be reused and
	// the operation cannot be undone — writing to it again is an error forever.
	// Reserved for erasure that must leave no possibility of resurrection.
	Tombstone(ctx context.Context, stream StreamID) error
}

// Handler processes one event. Returning an error stops a projector and parks
// the event for a reactor.
type Handler func(ctx context.Context, e RecordedEvent) error

// StartFrom names where a $all subscription begins.
//
// It exists because a Position alone cannot express the difference between
// "this projector has never run" and "this projector's checkpoint is at
// position zero". Both are the zero Position, and treating the second as the
// first silently replays the ENTIRE log — not a double-apply, a full rebuild
// nobody asked for. Whether a real event can land at position zero depends on
// how the server was bootstrapped, which is not a property worth betting on.
//
// It is a value type with no pointer inside, so passing one allocates nothing.
type StartFrom struct {
	pos      Position
	resuming bool
}

// FromBeginning starts at the first event in the log. This is what a projector
// with no checkpoint does, and what a rebuild does.
func FromBeginning() StartFrom { return StartFrom{} }

// After resumes strictly after a position — the event at p is NOT redelivered.
func After(p Position) StartFrom { return StartFrom{pos: p, resuming: true} }

// IsBeginning reports whether this starts at the FIRST event in the log, rather
// than resuming from a stored position. It is the opposite end of the log from
// "live", which is what a caught-up subscription reaches.
func (s StartFrom) IsBeginning() bool { return !s.resuming }

// Position is the resume point, meaningful only when IsBeginning is false.
func (s StartFrom) Position() Position { return s.pos }

// SubscribeOptions configures a catch-up subscription.
//
// OnLive and OnBehind are how a projector knows whether it is CAUGHT UP or
// still replaying. Without them "no events arrived recently" is ambiguous
// between an idle system and a projector hours behind, and a readiness probe
// cannot tell the difference — it reports healthy either way.
type SubscribeOptions struct {
	Filter SubscriptionFilter

	// OnLive fires when the subscription reaches the head of the log.
	//
	// It takes a context and returns an error for the same reason OnCheckpoint
	// does: reaching the head is the moment a consumer that has been buffering
	// work while behind must commit it, and a commit that fails must stop the
	// subscription rather than be swallowed inside a callback that cannot
	// report.
	OnLive func(context.Context) error

	// OnBehind fires when it falls behind again.
	OnBehind func()

	// OnCheckpoint fires with a position the server has scanned past WITHOUT
	// finding anything that matches the filter. It is a resume point, not an
	// event: no event was delivered and none was skipped.
	//
	// Ignoring it is the difference between a restart costing O(1) and a restart
	// costing O(size of the whole log). A filtered subscription only ever
	// advances a caller-held checkpoint when a matching event arrives, so a
	// projection interested in a quiet module never advances at all while the
	// rest of the system writes — and on every restart the server re-scans
	// everything since its last MATCH. Measured against the running server at
	// 50k intervening events: 866ms to reach live from the last match, 3ms from
	// the checkpoint offered here.
	//
	// It returns an error so the caller can refuse to advance — persisting a
	// position is a write, and a failed write must stop the subscription rather
	// than be silently dropped.
	OnCheckpoint func(context.Context, Position) error
}

// CatchUpSubscriber streams $all from a caller-held position.
//
// This is the PROJECTOR transport: the checkpoint is ours, committed in the
// same transaction as the rows it describes, which is what makes a projection
// rebuildable from zero (ADR-019).
type CatchUpSubscriber interface {
	SubscribeAll(ctx context.Context, from StartFrom, opts SubscribeOptions, h Handler) error
}

// ErrPoison marks an event this consumer can NEVER handle — a malformed
// payload, a command for a tenant that no longer exists, a type it does not
// understand. Returning it parks the event immediately instead of burning ten
// redeliveries on something that cannot succeed.
//
// Any other error means "try again": a provider timeout, a database blip.
var ErrPoison = errors.New("eventsourcing: event cannot be handled")

// GroupStats describes a reactor's queue. Parked is the number that matters:
// it counts events that failed every retry and are now waiting for a human.
type GroupStats struct {
	Group              string
	InFlight           int64
	Unacked            int64
	Parked             int64
	ProcessedSinceLast int64
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

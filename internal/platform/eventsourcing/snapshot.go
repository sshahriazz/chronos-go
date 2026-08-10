package eventsourcing

import (
	"context"
	"time"
)

// Snapshotter is an aggregate that can save and restore its own state.
//
// Implementing it is optional. An aggregate that does not is loaded by replaying
// its whole stream, which is correct but gets linearly slower forever — a
// long-lived organization replays fifty thousand events to change one field.
//
// A snapshot is an ordinary domain Event, not a new serialization path. That is
// what keeps the domain free of wire concerns (ADR-001): the snapshot type is a
// plain struct registered with the codec like any other event, the adapter
// encodes it, and the upcaster chain applies to it unchanged (ADR-029).
type Snapshotter interface {
	Root

	// Snapshot returns an event carrying COMPLETE state. Anything omitted is
	// silently lost for every load that starts from this snapshot, so a partial
	// snapshot is worse than none.
	Snapshot() Event

	// Restore rebuilds state from an event previously returned by Snapshot.
	//
	// Returning an error is safe and expected: after a schema change, an old
	// snapshot should be REJECTED here, and the repository falls back to
	// replaying from zero. Degrading to slow is always allowed; degrading to
	// wrong is not.
	Restore(Event) error
}

// SnapshotEvery is how many events pass between snapshots.
//
// The cost of a snapshot is one append; the cost of not having one is replaying
// every event since the last. 100 keeps a worst-case load under a hundred events
// while adding roughly one percent to append volume.
const SnapshotEvery Revision = 100

// SnapshotCategory is where snapshots for a category are written.
//
// A separate stream, not the aggregate's own, for three reasons: the aggregate
// stream stays a pure record of what happened; snapshots can be discarded and
// regenerated without touching history; and the snapshot stream can carry
// `$maxCount = 1` so old snapshots are scavenged automatically.
//
// The suffix has no dash, so `organizationSnapshot-org_1` is its own category
// and is NOT matched by a projector filtering on the prefix `organization-`.
func SnapshotCategory(c Category) Category { return c + "Snapshot" }

// SnapshotStreamID names the snapshot stream for an aggregate.
func SnapshotStreamID(category Category, key string) (StreamID, error) {
	return NewStreamID(SnapshotCategory(category), key)
}

// SnapshotStore reads and writes aggregate snapshots.
//
// Separate from EventStore because a snapshot is not history: losing every
// snapshot in the system costs time and nothing else, so this port is allowed
// to fail in ways EventStore is not.
type SnapshotStore interface {
	// LoadSnapshot returns the most recent snapshot for a stream. found=false
	// means there is none, which is not an error.
	LoadSnapshot(ctx context.Context, stream StreamID) (rec RecordedEvent, found bool, err error)

	// SaveSnapshot writes a snapshot, replacing any earlier one.
	SaveSnapshot(ctx context.Context, stream StreamID, e PendingEvent) error
}

// Retention is a stream's server-side retention policy.
//
// KurrentDB enforces these itself; without them every stream grows forever.
// Session streams, audit trails and snapshot streams all need bounding, and
// TruncateBefore is the mechanism behind erasure that must remove events rather
// than re-encrypt them.
type Retention struct {
	// MaxCount keeps only the last N events. Zero means unbounded.
	MaxCount uint64

	// MaxAge discards events older than this. Zero means unbounded.
	MaxAge time.Duration

	// TruncateBefore marks every event below this revision as scavengeable.
	// Zero means nothing is truncated.
	TruncateBefore Revision
}

// IsZero reports whether the policy constrains anything.
func (r Retention) IsZero() bool {
	return r.MaxCount == 0 && r.MaxAge == 0 && r.TruncateBefore == 0
}

// StreamAdmin manages per-stream metadata.
//
// Retention is a property of the log, so it belongs to the store rather than to
// a cleanup job in Go: a server that enforces it needs no coordination, cannot
// fall behind, and keeps working when every application instance is down.
type StreamAdmin interface {
	SetRetention(ctx context.Context, stream StreamID, r Retention) error
	Retention(ctx context.Context, stream StreamID) (Retention, error)
}

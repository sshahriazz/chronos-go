package eventsourcing

import (
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/google/uuid"
)

// Event is a domain fact. Implementations live in a module's domain package and
// are plain Go structs — no tags, no wire concerns (ADR-001).
//
// EventType is the persisted discriminator and is permanent: it appears in
// every stored event forever. Format: "<module>.<Name>.v<N>".
type Event interface {
	EventType() string
}

// Metadata travels alongside every event. It carries no personal data — only
// SubjectID pseudonyms (ADR-002), because the log is immutable and erasure
// works by destroying a key, not by rewriting history.
type Metadata struct {
	// SchemaVersion drives the upcaster chain (ADR-029).
	SchemaVersion int

	// OccurredAt is always UTC (ADR-008).
	OccurredAt time.Time

	// OrgID is the tenant scope, present on every tenant-scoped event.
	OrgID string

	// WorkspaceID scopes the event to a workspace within the org, and is empty
	// for org-level facts.
	//
	// It rides in metadata rather than being derived from the stream because
	// every workspace-owned read model has an RLS policy that checks BOTH
	// columns (ADR-020), and a projector must be able to scope itself from the
	// event alone — without a lookup that could return a stale answer, or none
	// at all during a rebuild.
	WorkspaceID string

	// Residency tags the region even while there is only one (ADR-035).
	Residency string

	// SubjectIDs are the data subjects this event concerns — pseudonyms only.
	SubjectIDs []string

	// ActorID is who CAUSED the event, as a pseudonym. It is often one of the
	// SubjectIDs and often not: an admin revoking someone else's access is the
	// actor, the other person is the subject.
	//
	// It exists because "notify the actor" and "notify the subject" are
	// different audiences, and guessing that the actor is the first subject
	// sends security mail to the wrong person — a worse outcome than sending
	// none (NOTIFICATIONS §4).
	ActorID string

	// CorrelationID groups everything caused by one originating request.
	CorrelationID string

	// CausationID is the event or command that directly produced this one.
	CausationID string

	// SnapshotRevision is the aggregate revision a SNAPSHOT represents, and is
	// zero on ordinary events.
	//
	// It lives in metadata rather than in the snapshot payload because it is
	// bookkeeping about the log, not a fact about the business. Without it a
	// snapshot cannot say which events it already accounts for, and restoring
	// from one would either replay events twice or skip them.
	SnapshotRevision Revision
}

// PendingEvent is an event ready to append: the domain fact plus its metadata
// and the deterministic identifier that makes appends idempotent.
type PendingEvent struct {
	ID    ids.EventID
	Event Event
	Meta  Metadata
}

// RecordedEvent is an event read back from the store. Payload and metadata are
// still encoded: decoding is the codec's job, so this package never imports a
// serialization library.
type RecordedEvent struct {
	ID        ids.EventID
	Type      string
	Stream    StreamID
	Revision  Revision
	Position  Position
	Payload   []byte
	Metadata  []byte
	CreatedAt time.Time
}

// IsSystem reports whether this came from a system or metadata stream.
// Verified: $all carries them, so every subscriber must filter.
func (r RecordedEvent) IsSystem() bool {
	return r.Stream.IsSystem() || len(r.Type) > 0 && r.Type[0] == '$'
}

// eventIDNamespace is a fixed UUIDv5 namespace for this system. It never
// changes: changing it would make previously-derived identifiers unreachable
// and break the idempotency guarantee below.
var eventIDNamespace = uuid.MustParse("6f1e5d3a-2c47-5a9b-8e10-3f7c9d24b5a1")

// DeriveEventID produces a deterministic identifier from a command's
// idempotency key and the event's index within that command.
//
// This is the second idempotency layer (EVENT-SOURCING §3). The gate stops
// duplicate *work*; this stops duplicate *events* when a crash lands between
// the gate and the append. Verified behaviour: re-appending the same event id
// at the same expected revision is accepted and does NOT duplicate.
//
// It must be deterministic, so it must not use randomness or the clock.
func DeriveEventID(idempotencyKey string, seq int) ids.EventID {
	name := idempotencyKey + ":" + itoa(seq)
	u := uuid.NewSHA1(eventIDNamespace, []byte(name))
	return ids.FromUUID[ids.Event](u)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		b[n] = '-'
	}
	return string(b[n:])
}

// EventTypeOf is a small helper for building type names consistently.
func EventTypeOf(module, name string, version int) string {
	return fmt.Sprintf("%s.%s.v%d", module, name, version)
}

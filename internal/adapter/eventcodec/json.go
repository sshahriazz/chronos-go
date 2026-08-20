// Package eventcodec serializes domain events.
//
// It lives in the adapter layer because serialization is a wire concern: a
// domain type carrying json tags has let a wire format dictate a business rule
// (ADR-001). Domain events are plain structs, and the mapping from stored type
// name to Go type lives here.
//
// # Why this file is the one to be careful with
//
// An event log is append-only and permanent. Every other format in this
// codebase can be changed by deploying a new binary; this one has to decode
// bytes written by every binary that ever ran, forever. Three consequences run
// through the design:
//
//   - Reading is TOLERANT of unknown fields and STRICT about everything else. A
//     newer producer adds a field, and during a rolling deploy the older binary
//     must keep working — but a payload that is corrupt, duplicated or of the
//     wrong type must stop the projector rather than silently produce a
//     half-populated event.
//   - Both stored shapes decode forever. The metadata format changed to
//     all-strings (ADR-044); the typed shape that preceded it is not a migration
//     to finish, it is a shape that exists for the life of the log.
//   - The registry is written once at wiring and read on every event after. It
//     is copy-on-write so the read path is a single atomic load, because a
//     sharded rebuild decodes on N goroutines at once and a shared lock there is
//     N cores contending on one cache line.
package eventcodec

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// JSON is a registry-backed JSON codec.
//
// Every event type must be registered at startup. An unregistered type on read
// is a hard error rather than a silent skip: skipping would let a projector
// quietly ignore facts it does not understand and build a read model that is
// wrong in a way nothing detects.
type JSON struct {
	// table is the read path, and it is never mutated in place.
	//
	// An atomic load rather than a mutex because this is read once per EVENT and
	// written a few dozen times at wiring. sync.RWMutex.RLock is an atomic
	// read-modify-write on one shared word, so a rebuild running N shard workers
	// (ADR-044) has N cores invalidating each other's cache line on every single
	// event. A pointer that is never written after startup stays valid in every
	// core's cache.
	table atomic.Pointer[table]

	// writes serialises registration. It is never taken on the read path.
	writes sync.Mutex

	// frozen closes the registry. Registering after the first event has been
	// decoded is a real bug — a projector that started earlier already failed on
	// those types — and it is invisible without this.
	frozen atomic.Bool

	upcasters *eventsourcing.UpcasterRegistry
}

// table is one immutable snapshot of the registry.
type table struct {
	factories map[string]func() eventsourcing.Event

	// names is precomputed and sorted, so Types() allocates nothing and cannot
	// disagree with factories.
	names []string
}

func NewJSON(up *eventsourcing.UpcasterRegistry) *JSON {
	c := &JSON{upcasters: up}
	c.table.Store(&table{factories: map[string]func() eventsourcing.Event{}})
	return c
}

// Register associates a stored event type with a constructor for its Go type.
//
// Prefer the generic Register below: this form requires the caller to repeat
// the event type string, and a typo in it produces a codec that decodes
// nothing while looking perfectly correct.
func (c *JSON) Register(eventType string, newFn func() eventsourcing.Event) {
	c.register(eventType, newFn)
}

// Freeze closes the registry.
//
// Called by the composition root once every module has registered. After it, a
// late registration panics at the call site instead of producing a codec whose
// behaviour depends on when a package happened to initialise — a projector that
// started before the registration already treated those events as unknown and
// stopped, and nothing connects that failure to the cause.
//
// Optional: a codec that is never frozen still works. Freezing is what turns a
// wiring mistake into a stack trace.
func (c *JSON) Freeze() { c.frozen.Store(true) }

// Frozen reports whether the registry is closed, so the composition root can be
// asserted rather than assumed.
func (c *JSON) Frozen() bool { return c.frozen.Load() }

func (c *JSON) register(eventType string, newFn func() eventsourcing.Event) {
	if eventType == "" {
		panic("eventcodec: refusing to register an empty event type")
	}
	if newFn == nil {
		panic(fmt.Sprintf("eventcodec: %q registered with a nil constructor", eventType))
	}
	if c.frozen.Load() {
		panic(fmt.Sprintf("eventcodec: %q registered after the codec was frozen; anything "+
			"already consuming the log treated it as an unknown type and stopped", eventType))
	}

	c.writes.Lock()
	defer c.writes.Unlock()

	old := c.table.Load()
	if _, dup := old.factories[eventType]; dup {
		panic(fmt.Sprintf("eventcodec: %q is already registered", eventType))
	}

	// Copy on write. Mutating the live map would be a data race against every
	// in-flight decode, and the race detector only catches it if a test happens
	// to register while decoding.
	next := &table{factories: make(map[string]func() eventsourcing.Event, len(old.factories)+1)}
	maps.Copy(next.factories, old.factories)
	next.factories[eventType] = newFn
	next.names = append(slices.Clone(old.names), eventType)
	slices.Sort(next.names)

	c.table.Store(next)
}

// Register binds an event type to the codec, deriving both the stored type name
// and the constructor from T:
//
//	eventcodec.Register[identity.UserRegistered](codec)
//
// There is nothing left to get wrong — no string to mistype, no factory that
// can return the wrong type. It panics on a duplicate registration, at wiring
// time, because the alternative is one event type silently shadowing another.
func Register[T any, PT eventsourcing.EventPtr[T]](c *JSON) {
	eventType := eventsourcing.TypeOf[T, PT]()
	c.register(eventType, func() eventsourcing.Event { return PT(new(T)) })
}

// Types lists every registered event type, sorted.
//
// This is what makes the notification catalogue verifiable: every type the
// system can DECODE must have a notification decision recorded against it, and
// a test compares the two lists (notify.Catalogue.Verify).
func (c *JSON) Types() []string {
	return slices.Clone(c.table.Load().names)
}

// Marshal encodes an event payload.
//
// Deterministic, via the codec kernel: the same event must produce the same
// bytes every time, or a replay writing an event a second time would store a
// different document for the same fact.
func (c *JSON) Marshal(e eventsourcing.Event) ([]byte, error) {
	b, err := codec.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("eventcodec: marshal %s: %w", e.EventType(), err)
	}
	return b, nil
}

// Unmarshal decodes a stored payload into its registered Go type.
//
// TOLERANT of unknown members, and only here. A payload written by a newer
// producer carries fields this binary has never heard of, and during a rolling
// deploy both versions are running — rejecting the unknown field would stop a
// projector on an event that is perfectly valid (ADR-029).
//
// Everything else is still strict. A duplicate member, a wrong type, a truncated
// document: all errors, because those are corruption rather than evolution, and
// a projector that half-decodes an event builds a read model that is wrong with
// nothing detecting it.
func (c *JSON) Unmarshal(eventType string, payload []byte) (eventsourcing.Event, error) {
	newFn, ok := c.table.Load().factories[eventType]
	if !ok {
		return nil, fmt.Errorf("eventcodec: no type registered for %q", eventType)
	}
	e := newFn()
	if err := codec.IntoTolerant(payload, e); err != nil {
		return nil, fmt.Errorf("eventcodec: unmarshal %s: %w", eventType, err)
	}
	return e, nil
}

// MarshalMetadata writes the on-disk metadata shape.
//
// Every value is a STRING, including the two that are conceptually numbers and
// the one that is a list. That is not a style choice: KurrentDB's v2 append APIs
// — MultiStreamAppend and AppendRecords — carry metadata as map<string,string>
// and reject anything else outright. Writing typed JSON here would leave those
// APIs permanently unusable, and with them the atomic reserve-and-create that
// registration needs (ADR-044).
//
// UnmarshalMetadata reads both shapes, so events written before this change
// remain readable forever.
func (c *JSON) MarshalMetadata(m eventsourcing.Metadata) ([]byte, error) {
	// A STRUCT of strings, not a map[string]string. The constraint is on the
	// JSON — a flat object whose values are all strings — and nothing requires
	// marshalling from a map. Measured: the map form cost 1554 ns and 15 allocs
	// against 718 ns and 4 for a struct, because a map adds a hash table and
	// forces the encoder to sort the keys on every append.
	w := stringMetadata{
		SchemaVersion: strconv.Itoa(m.SchemaVersion),
		OccurredAt:    m.OccurredAt.UTC().Format(time.RFC3339Nano),
		OrgID:         m.OrgID,
		WorkspaceID:   m.WorkspaceID,
		Residency:     m.Residency,
		ActorID:       m.ActorID,
		CorrelationID: m.CorrelationID,
		CausationID:   m.CausationID,
	}
	if m.SnapshotRevision != 0 {
		w.SnapshotRevision = strconv.FormatInt(int64(m.SnapshotRevision), 10)
	}
	if len(m.SubjectIDs) > 0 {
		// Comma-separated rather than JSON-in-a-string: a SubjectID is a prefixed
		// ULID — Crockford base32 with a '_' separator (ADR-030) — so a comma
		// cannot occur and the encoding stays readable to an operator looking at
		// raw metadata.
		//
		// The type is []string, though, and nothing upstream forces its entries
		// to be well-formed. An entry carrying a comma would decode as TWO
		// subjects, silently widening who this event concerns — which is what
		// drives erasure and notification targeting. Refused rather than escaped:
		// there is no legitimate value with a comma in it, so this can only be a
		// bug, and it should surface at the write rather than at the read.
		for _, id := range m.SubjectIDs {
			if strings.ContainsRune(id, subjectSeparator) {
				return nil, fmt.Errorf(
					"eventcodec: subject id %q contains %q, which is the separator "+
						"metadata encodes subject ids with; it would decode as two subjects",
					id, string(subjectSeparator))
			}
			if id == "" {
				return nil, fmt.Errorf("eventcodec: an empty subject id cannot be encoded")
			}
		}
		w.SubjectIDs = strings.Join(m.SubjectIDs, string(subjectSeparator))
	}
	return codec.Marshal(w)
}

// stringMetadata is the ON-DISK shape: a flat JSON object whose every value is a
// string.
//
// It is a struct rather than a map[string]string because the requirement is on
// the JSON, not on the Go type — and the map form cost 1554 ns and 15 allocs per
// append against 718 ns and 4 here. Keeping it a struct also means a field can
// never be added without appearing in this list, which is what the reflection
// guards in the tests check.
//
// omitempty everywhere except the two fields every event carries, so an absent
// value is absent rather than an empty string that reads as "set to nothing".
type stringMetadata struct {
	SchemaVersion    string `json:"schemaVersion"`
	OccurredAt       string `json:"occurredAt"`
	OrgID            string `json:"orgId,omitempty"`
	WorkspaceID      string `json:"workspaceId,omitempty"`
	Residency        string `json:"residency,omitempty"`
	SubjectIDs       string `json:"subjectIds,omitempty"`
	ActorID          string `json:"actorId,omitempty"`
	CorrelationID    string `json:"$correlationId,omitempty"`
	CausationID      string `json:"$causationId,omitempty"`
	SnapshotRevision string `json:"snapshotRevision,omitempty"`
}

// UnmarshalMetadata reads either stored shape.
//
// Tolerant of unknown members for the same reason payloads are: KurrentDB's own
// tooling and a newer producer both add keys we do not model, and metadata that
// cannot be read parks the event.
func (c *JSON) UnmarshalMetadata(b []byte) (eventsourcing.Metadata, error) {
	if len(b) == 0 {
		return eventsourcing.Metadata{}, nil
	}
	w, err := codec.Tolerant[wireMetadata](b)
	if err != nil {
		return eventsourcing.Metadata{}, fmt.Errorf("eventcodec: unmarshal metadata: %w", err)
	}
	m := eventsourcing.Metadata{
		SchemaVersion:    int(w.SchemaVersion),
		OrgID:            w.OrgID,
		WorkspaceID:      w.WorkspaceID,
		Residency:        w.Residency,
		SubjectIDs:       []string(w.SubjectIDs),
		ActorID:          w.ActorID,
		CorrelationID:    w.CorrelationID,
		CausationID:      w.CausationID,
		SnapshotRevision: eventsourcing.Revision(w.SnapshotRevision),
	}
	if w.OccurredAt != "" {
		t, err := parseUTC(w.OccurredAt)
		if err != nil {
			return eventsourcing.Metadata{}, err
		}
		m.OccurredAt = t
	}
	return m, nil
}

// wireMetadata is the on-disk shape, kept separate from the kernel type so the
// kernel carries no json tags and renaming a Go field can never silently change
// what is already stored.
//
// Causation uses KurrentDB's reserved names so its own tooling can follow a
// chain without knowing anything about us.
type wireMetadata struct {
	SchemaVersion flexInt     `json:"schemaVersion"`
	OccurredAt    string      `json:"occurredAt"`
	OrgID         string      `json:"orgId,omitempty"`
	WorkspaceID   string      `json:"workspaceId,omitempty"`
	Residency     string      `json:"residency,omitempty"`
	SubjectIDs    flexStrings `json:"subjectIds,omitempty"`
	ActorID       string      `json:"actorId,omitempty"`
	CorrelationID string      `json:"$correlationId,omitempty"`
	CausationID   string      `json:"$causationId,omitempty"`
	// SnapshotRevision is set only on snapshots.
	SnapshotRevision flexInt `json:"snapshotRevision,omitempty"`
}

// subjectSeparator joins subject ids inside the single metadata string they
// share. A prefixed ULID cannot contain it (ADR-030), and MarshalMetadata
// refuses any value that does.
const subjectSeparator = ','

// flexInt reads a number OR a numeric string.
//
// The stored format changed to all-strings so KurrentDB's v2 append APIs would
// accept it (ADR-044). Events written before that carry real JSON numbers and
// must keep decoding — an event log is append-only, so "the old shape" is not a
// migration to finish but a shape that exists forever.
//
// It implements UnmarshalJSON([]byte), which BOTH encoding/json v1 and v2
// honour. The v2-native UnmarshalJSONFrom would avoid a copy, but it exists only
// under v2 — and a type on the read path of a permanent log should not be
// decodable by exactly one library version.
type flexInt int64

func (f *flexInt) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '"' {
		s, err := unquote(b)
		if err != nil {
			return err
		}
		if s == "" {
			return nil
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return fmt.Errorf("eventcodec: %q is not a number: %w", s, err)
		}
		*f = flexInt(n)
		return nil
	}
	n, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		return fmt.Errorf("eventcodec: %q is not a number: %w", b, err)
	}
	*f = flexInt(n)
	return nil
}

// flexStrings reads a JSON array OR a comma-separated string, for the same
// reason as flexInt.
type flexStrings []string

func (f *flexStrings) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '"' {
		s, err := unquote(b)
		if err != nil {
			return err
		}
		if s == "" {
			return nil
		}
		*f = strings.Split(s, string(subjectSeparator))
		return nil
	}
	out, err := codec.Tolerant[[]string](b)
	if err != nil {
		return err
	}
	*f = out
	return nil
}

// unquote reads a JSON string value.
//
// Both callers have already established that b starts with '"', so there is no
// kind check here — re-deriving it would need the low-level jsontext package,
// and the whole point of routing every decode through the codec kernel is that
// one package knows which JSON library this codebase is on (ADR-047).
func unquote(b []byte) (string, error) {
	var s string
	if err := codec.Into(b, &s); err != nil {
		return "", fmt.Errorf("eventcodec: %q is not a JSON string: %w", b, err)
	}
	return s, nil
}

// parseUTC accepts RFC 3339 and normalises to UTC. Storage is always UTC
// (ADR-008); a value stored with another offset is data we did not write, so it
// is converted rather than trusted.
func parseUTC(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("eventcodec: invalid timestamp %q: %w", s, err)
	}
	return t.UTC(), nil
}

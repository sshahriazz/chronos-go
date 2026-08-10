// Package eventcodec serializes domain events.
//
// It lives in the adapter layer because serialization is a wire concern: a
// domain type carrying json tags has let a wire format dictate a business rule
// (ADR-001). Domain events are plain structs, and the mapping from stored type
// name to Go type lives here.
package eventcodec

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// JSON is a registry-backed JSON codec.
//
// Every event type must be registered at startup. An unregistered type on read
// is a hard error rather than a silent skip: skipping would let a projector
// quietly ignore facts it does not understand and build a read model that is
// wrong in a way nothing detects.
type JSON struct {
	mu        sync.RWMutex
	factories map[string]func() eventsourcing.Event
	upcasters *eventsourcing.UpcasterRegistry
}

func NewJSON(up *eventsourcing.UpcasterRegistry) *JSON {
	return &JSON{
		factories: make(map[string]func() eventsourcing.Event),
		upcasters: up,
	}
}

// Register associates a stored event type with a constructor for its Go type.
//
// Prefer the generic Register below: this form requires the caller to repeat
// the event type string, and a typo in it produces a codec that decodes
// nothing while looking perfectly correct.
func (c *JSON) Register(eventType string, newFn func() eventsourcing.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.factories[eventType] = newFn
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

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, dup := c.factories[eventType]; dup {
		panic(fmt.Sprintf("eventcodec: %q is already registered", eventType))
	}
	c.factories[eventType] = func() eventsourcing.Event { return PT(new(T)) }
}

// Types lists every registered event type, sorted.
//
// This is what makes the notification catalogue verifiable: every type the
// system can DECODE must have a notification decision recorded against it, and
// a test compares the two lists (notify.Catalogue.Verify).
func (c *JSON) Types() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, 0, len(c.factories))
	for t := range c.factories {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func (c *JSON) Marshal(e eventsourcing.Event) ([]byte, error) {
	return json.Marshal(e)
}

func (c *JSON) Unmarshal(eventType string, payload []byte) (eventsourcing.Event, error) {
	c.mu.RLock()
	newFn, ok := c.factories[eventType]
	c.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("eventcodec: no type registered for %q", eventType)
	}
	e := newFn()
	if err := json.Unmarshal(payload, e); err != nil {
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
	// forces encoding/json to sort the keys on every append.
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
	return json.Marshal(w)
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

func (c *JSON) UnmarshalMetadata(b []byte) (eventsourcing.Metadata, error) {
	if len(b) == 0 {
		return eventsourcing.Metadata{}, nil
	}
	var w wireMetadata
	if err := json.Unmarshal(b, &w); err != nil {
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
type flexInt int64

func (f *flexInt) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
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
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return err
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
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		if s == "" {
			return nil
		}
		*f = strings.Split(s, ",")
		return nil
	}
	var out []string
	if err := json.Unmarshal(b, &out); err != nil {
		return err
	}
	*f = out
	return nil
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

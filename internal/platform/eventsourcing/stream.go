// Package eventsourcing is the write-side kernel: streams, aggregates, the
// event envelope and the ports an event store must satisfy.
//
// Every rule here was verified against the running KurrentDB — see
// docs/evidence/kurrentdb-semantics-probe.py and docs/EVENT-SOURCING.md.
// Nothing in this package knows what an organization is, and nothing in it
// imports a driver.
package eventsourcing

import (
	"errors"
	"fmt"
	"strings"
)

// Category groups streams of the same aggregate type. KurrentDB derives it from
// everything before the FIRST dash, so it is a property of the name rather than
// something we choose independently.
type Category string

// StreamID names a single aggregate's stream: "<category>-<id>".
type StreamID string

var (
	ErrEmptyCategory   = errors.New("eventsourcing: category is empty")
	ErrEmptyStreamKey  = errors.New("eventsourcing: stream key is empty")
	ErrDashInCategory  = errors.New("eventsourcing: category must not contain '-'")
	ErrDashInStreamKey = errors.New("eventsourcing: stream key must not contain '-'")
	ErrSystemStream    = errors.New("eventsourcing: '$' is reserved for system streams")
)

// NewStreamID builds "<category>-<key>".
//
// The key must not contain a dash: KurrentDB would then read the category as
// only the part before it, silently filing the stream under the wrong category
// and breaking every prefix-filtered subscription. Prefixed public identifiers
// use '_' precisely so they are safe here (ADR-030).
func NewStreamID(category Category, key string) (StreamID, error) {
	switch {
	case category == "":
		return "", ErrEmptyCategory
	case key == "":
		return "", ErrEmptyStreamKey
	case strings.Contains(string(category), "-"):
		return "", fmt.Errorf("%w: %q", ErrDashInCategory, category)
	case strings.Contains(key, "-"):
		return "", fmt.Errorf("%w: %q", ErrDashInStreamKey, key)
	case strings.HasPrefix(string(category), "$"), strings.HasPrefix(key, "$"):
		return "", ErrSystemStream
	}
	return StreamID(string(category) + "-" + key), nil
}

// MustStreamID is for tests and constants.
func MustStreamID(category Category, key string) StreamID {
	s, err := NewStreamID(category, key)
	if err != nil {
		panic(err)
	}
	return s
}

// Category reports the stream's category — everything before the first dash,
// matching KurrentDB's own rule.
func (s StreamID) Category() Category {
	if i := strings.IndexByte(string(s), '-'); i >= 0 {
		return Category(s[:i])
	}
	return Category(s)
}

// Key reports the identifier portion.
func (s StreamID) Key() string {
	if i := strings.IndexByte(string(s), '-'); i >= 0 {
		return string(s[i+1:])
	}
	return ""
}

// IsSystem reports whether this is a KurrentDB system stream.
//
// Verified: $all carries system and metadata streams ($$-prefixed). A projector
// that does not exclude them will try to deserialize $metadata as a domain
// event on its very first run.
func (s StreamID) IsSystem() bool { return strings.HasPrefix(string(s), "$") }

func (s StreamID) String() string { return string(s) }

// Position is a location in the global $all stream. KurrentDB reports a pair,
// and checkpoints must store both.
type Position struct {
	Commit  uint64
	Prepare uint64
}

// Start is the beginning of $all — where a projection rebuild begins.
var Start = Position{}

func (p Position) IsStart() bool { return p == Start }

// After reports whether p is strictly later than other.
func (p Position) After(other Position) bool {
	if p.Commit != other.Commit {
		return p.Commit > other.Commit
	}
	return p.Prepare > other.Prepare
}

// AtOrAfter reports whether p has reached other — the comparison a consistency
// token performs against a projector checkpoint.
func (p Position) AtOrAfter(other Position) bool { return p == other || p.After(other) }

func (p Position) String() string { return fmt.Sprintf("%d/%d", p.Commit, p.Prepare) }

// Revision is a position within one stream. The first event is 0.
type Revision int64

// ExpectedRevision expresses the optimistic-concurrency precondition for an
// append. A mismatch is rejected by the server — that rejection IS the
// aggregate consistency boundary (verified).
type ExpectedRevision struct {
	kind     revisionKind
	revision Revision
}

type revisionKind uint8

const (
	revisionAny revisionKind = iota
	revisionNoStream
	revisionStreamExists
	revisionExact
)

// NoStream requires that the stream does not yet exist. This is what makes
// aggregate creation atomic — and what makes a uniqueness reservation work,
// because the second caller to claim a name is rejected.
func NoStream() ExpectedRevision { return ExpectedRevision{kind: revisionNoStream} }

// StreamExists requires the stream to be present, without pinning a revision.
func StreamExists() ExpectedRevision { return ExpectedRevision{kind: revisionStreamExists} }

// AnyRevision disables the concurrency check. Use sparingly: it also weakens
// the store's idempotency guarantee, which is scoped to the expected revision.
func AnyRevision() ExpectedRevision { return ExpectedRevision{kind: revisionAny} }

// AtRevision requires the stream's last event to be exactly r.
func AtRevision(r Revision) ExpectedRevision {
	return ExpectedRevision{kind: revisionExact, revision: r}
}

func (e ExpectedRevision) IsAny() bool          { return e.kind == revisionAny }
func (e ExpectedRevision) IsNoStream() bool     { return e.kind == revisionNoStream }
func (e ExpectedRevision) IsStreamExists() bool { return e.kind == revisionStreamExists }
func (e ExpectedRevision) Exact() (Revision, bool) {
	return e.revision, e.kind == revisionExact
}

func (e ExpectedRevision) String() string {
	switch e.kind {
	case revisionNoStream:
		return "no_stream"
	case revisionStreamExists:
		return "stream_exists"
	case revisionExact:
		return fmt.Sprintf("exact(%d)", e.revision)
	default:
		return "any"
	}
}

// ErrWrongExpectedRevision is returned when the precondition fails. It is
// expected under concurrency: reload, re-decide and retry.
var ErrWrongExpectedRevision = errors.New("eventsourcing: wrong expected revision")

// ErrStreamNotFound is returned when reading a stream that does not exist.
var ErrStreamNotFound = errors.New("eventsourcing: stream not found")

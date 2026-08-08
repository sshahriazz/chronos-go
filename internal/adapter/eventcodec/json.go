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
func (c *JSON) Register(eventType string, newFn func() eventsourcing.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.factories[eventType] = newFn
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

func (c *JSON) MarshalMetadata(m eventsourcing.Metadata) ([]byte, error) {
	return json.Marshal(wireMetadata{
		SchemaVersion: m.SchemaVersion,
		OccurredAt:    m.OccurredAt.UTC().Format(time.RFC3339Nano),
		OrgID:         m.OrgID,
		Residency:     m.Residency,
		SubjectIDs:    m.SubjectIDs,
		CorrelationID: m.CorrelationID,
		CausationID:   m.CausationID,
	})
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
		SchemaVersion: w.SchemaVersion,
		OrgID:         w.OrgID,
		Residency:     w.Residency,
		SubjectIDs:    w.SubjectIDs,
		CorrelationID: w.CorrelationID,
		CausationID:   w.CausationID,
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
	SchemaVersion int      `json:"schemaVersion"`
	OccurredAt    string   `json:"occurredAt"`
	OrgID         string   `json:"orgId,omitempty"`
	Residency     string   `json:"residency,omitempty"`
	SubjectIDs    []string `json:"subjectIds,omitempty"`
	CorrelationID string   `json:"$correlationId,omitempty"`
	CausationID   string   `json:"$causationId,omitempty"`
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

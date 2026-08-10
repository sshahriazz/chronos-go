package eventcodec_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// Metadata encoding is on the hot path twice over: once per append, and once per
// event on every projector and reactor. ADR-044 changed it from a typed struct
// to a flat map[string]string, which trades allocations for compatibility with
// KurrentDB's v2 append APIs. These measure what that trade cost.

func benchMetadata() eventsourcing.Metadata {
	return eventsourcing.Metadata{
		SchemaVersion: 1,
		OccurredAt:    time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
		OrgID:         "org_01H8XG5N2QK7VB3C9WPYZR4TFM",
		WorkspaceID:   "ws_01H8XG5N2QK7VB3C9WPYZR4TFN",
		Residency:     "eu",
		SubjectIDs:    []string{"sub_01H8XG5N2QK7VB3C9WPYZR4TFP"},
		ActorID:       "usr_01H8XG5N2QK7VB3C9WPYZR4TFQ",
		CorrelationID: "cor_01H8XG5N2QK7VB3C9WPYZR4TFR",
	}
}

func BenchmarkMarshalMetadata(b *testing.B) {
	c := codec()
	m := benchMetadata()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := c.MarshalMetadata(m); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnmarshalMetadata(b *testing.B) {
	c := codec()
	raw, err := c.MarshalMetadata(benchMetadata())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := c.UnmarshalMetadata(raw); err != nil {
			b.Fatal(err)
		}
	}
}

// The shape events written before ADR-044 carry. Both shapes decode forever, so
// both are worth measuring — a projector rebuilding old history reads this one.
func BenchmarkUnmarshalMetadataLegacyShape(b *testing.B) {
	c := codec()
	raw := []byte(`{"schemaVersion":1,"occurredAt":"2026-08-10T12:00:00Z",` +
		`"orgId":"org_01H8XG5N2QK7VB3C9WPYZR4TFM","workspaceId":"ws_01H8XG5N2QK7VB3C9WPYZR4TFN",` +
		`"residency":"eu","subjectIds":["sub_01H8XG5N2QK7VB3C9WPYZR4TFP"],` +
		`"actorId":"usr_01H8XG5N2QK7VB3C9WPYZR4TFQ"}`)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := c.UnmarshalMetadata(raw); err != nil {
			b.Fatal(err)
		}
	}
}

// typedMetadata is the pre-ADR-044 encoding, kept ONLY as a benchmark baseline
// so the cost of the flat-string format is a measured number rather than a
// guess. It is not used to write anything.
type typedMetadata struct {
	SchemaVersion int      `json:"schemaVersion"`
	OccurredAt    string   `json:"occurredAt"`
	OrgID         string   `json:"orgId,omitempty"`
	WorkspaceID   string   `json:"workspaceId,omitempty"`
	Residency     string   `json:"residency,omitempty"`
	SubjectIDs    []string `json:"subjectIds,omitempty"`
	ActorID       string   `json:"actorId,omitempty"`
	CorrelationID string   `json:"$correlationId,omitempty"`
}

func BenchmarkMarshalMetadataTypedBaseline(b *testing.B) {
	m := benchMetadata()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := json.Marshal(typedMetadata{
			SchemaVersion: m.SchemaVersion,
			OccurredAt:    m.OccurredAt.Format(time.RFC3339Nano),
			OrgID:         m.OrgID,
			WorkspaceID:   m.WorkspaceID,
			Residency:     m.Residency,
			SubjectIDs:    m.SubjectIDs,
			ActorID:       m.ActorID,
			CorrelationID: m.CorrelationID,
		}); err != nil {
			b.Fatal(err)
		}
	}
}

var _ = eventcodec.NewJSON

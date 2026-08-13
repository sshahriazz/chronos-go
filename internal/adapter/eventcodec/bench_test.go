package eventcodec_test

import (
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	jsoncodec "github.com/chronos/chronos-go/internal/platform/codec"
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
		if _, err := jsoncodec.Marshal(typedMetadata{
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

// ---------------------------------------------------------------------------
// Payload and concurrency
// ---------------------------------------------------------------------------
//
// Metadata is only half the per-event cost. The payload is decoded once per
// event per consumer, and a rebuild decodes on N goroutines at once (ADR-044) —
// so the number that matters for a rebuild is the PARALLEL one, not the serial
// one. A registry read that scales badly does not show up in a single-threaded
// benchmark at all.

func benchPayload() []byte {
	c := benchCodec()
	b, err := c.Marshal(&benchEvent{
		ID:       "evt_01H8XG5N2QK7VB3C9WPYZR4TFM",
		Subject:  "sub_01H8XG5N2QK7VB3C9WPYZR4TFP",
		Name:     "a reasonably typical event payload",
		Count:    42,
		Flag:     true,
		Tags:     []string{"alpha", "beta", "gamma"},
		Occurred: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
		Extra:    map[string]string{"k1": "v1", "k2": "v2"},
	})
	if err != nil {
		panic(err)
	}
	return b
}

func benchCodec() *eventcodec.JSON {
	c := eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry())
	eventcodec.Register[benchEvent](c)
	c.Freeze()
	return c
}

func BenchmarkMarshalPayload(b *testing.B) {
	c := benchCodec()
	e := &benchEvent{
		ID: "evt_01H8XG5N2QK7VB3C9WPYZR4TFM", Subject: "sub_01H8XG5N2QK7VB3C9WPYZR4TFP",
		Name: "a reasonably typical event payload", Count: 42, Flag: true,
		Tags:     []string{"alpha", "beta", "gamma"},
		Occurred: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
		Extra:    map[string]string{"k1": "v1", "k2": "v2"},
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.Marshal(e); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnmarshalPayload(b *testing.B) {
	c := benchCodec()
	payload := benchPayload()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.Unmarshal("bench.event", payload); err != nil {
			b.Fatal(err)
		}
	}
}

// The rebuild-shaped benchmark: N goroutines decoding at once.
//
// This is where a mutex-guarded registry shows its cost — RLock is an atomic
// read-modify-write on one shared word, so every core invalidates the others'
// cache line on every single event, and the serial benchmark above never sees it.
func BenchmarkUnmarshalPayloadParallel(b *testing.B) {
	c := benchCodec()
	payload := benchPayload()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := c.Unmarshal("bench.event", payload); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkUnmarshalMetadataParallel(b *testing.B) {
	c := benchCodec()
	raw, err := c.MarshalMetadata(benchMetadata())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := c.UnmarshalMetadata(raw); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Types() is read by the notification-catalogue check and by anything listing
// what the system understands. It must not be on any hot path, but it also must
// not be quadratic.
func BenchmarkTypes(b *testing.B) {
	c := benchCodec()
	b.ReportAllocs()
	for b.Loop() {
		_ = c.Types()
	}
}

type benchEvent struct {
	ID       string            `json:"id"`
	Subject  string            `json:"subject"`
	Name     string            `json:"name"`
	Count    int               `json:"count"`
	Flag     bool              `json:"flag"`
	Tags     []string          `json:"tags"`
	Occurred time.Time         `json:"occurred"`
	Extra    map[string]string `json:"extra"`
}

func (*benchEvent) EventType() string { return "bench.event" }

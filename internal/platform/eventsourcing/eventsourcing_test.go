package eventsourcing_test

import (
	"errors"
	"strings"
	"testing"

	es "github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// ---- streams -------------------------------------------------------------

// KurrentDB derives the category from everything before the FIRST dash. A dash
// in the key silently files the stream under the wrong category and breaks
// every prefix-filtered subscription — so it must be rejected at construction.
func TestNewStreamID_RejectsDashInKey(t *testing.T) {
	if _, err := es.NewStreamID("organization", "01H8-XG5N"); !errors.Is(err, es.ErrDashInStreamKey) {
		t.Fatalf("got %v want ErrDashInStreamKey", err)
	}
	// Our prefixed public ids use '_', precisely so they are safe here.
	if _, err := es.NewStreamID("organization", "org_01H8XG5N2QK7VB3C9WPYZR4TFM"); err != nil {
		t.Fatalf("underscore-prefixed id must be valid: %v", err)
	}
}

func TestStreamID_CategoryAndKey(t *testing.T) {
	s := es.MustStreamID("workspace", "ws_01H8XG5N")
	if got := s.Category(); got != "workspace" {
		t.Errorf("category: got %q want workspace", got)
	}
	if got := s.Key(); got != "ws_01H8XG5N" {
		t.Errorf("key: got %q want ws_01H8XG5N", got)
	}
}

func TestNewStreamID_Rejects(t *testing.T) {
	for name, fn := range map[string]func() (es.StreamID, error){
		"empty category":  func() (es.StreamID, error) { return es.NewStreamID("", "k") },
		"empty key":       func() (es.StreamID, error) { return es.NewStreamID("c", "") },
		"dash in cat":     func() (es.StreamID, error) { return es.NewStreamID("a-b", "k") },
		"system category": func() (es.StreamID, error) { return es.NewStreamID("$all", "k") },
		"system key":      func() (es.StreamID, error) { return es.NewStreamID("c", "$meta") },
	} {
		if _, err := fn(); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

// $all carries system and metadata streams — verified against the server. Every
// subscriber must exclude them or it will try to decode $metadata as a domain
// event on its first run.
func TestIsSystem(t *testing.T) {
	if !es.StreamID("$$organization-abc").IsSystem() {
		t.Error("metadata stream must be detected")
	}
	if !es.StreamID("$all").IsSystem() {
		t.Error("system stream must be detected")
	}
	if es.StreamID("organization-abc").IsSystem() {
		t.Error("domain stream must not be flagged as system")
	}
}

// ---- positions -----------------------------------------------------------

func TestPosition_Ordering(t *testing.T) {
	a := es.Position{Commit: 100, Prepare: 100}
	b := es.Position{Commit: 100, Prepare: 101}
	c := es.Position{Commit: 101, Prepare: 0}

	if !b.After(a) {
		t.Error("prepare breaks the tie when commit is equal")
	}
	if !c.After(b) {
		t.Error("commit dominates prepare")
	}
	if a.After(a) {
		t.Error("a position is not after itself")
	}
	if !a.AtOrAfter(a) {
		t.Error("AtOrAfter must include equality — a checkpoint that has exactly reached a token has caught up")
	}
	if !es.Start.IsStart() {
		t.Error("Start must report IsStart")
	}
}

// ---- expected revision ---------------------------------------------------

func TestExpectedRevision(t *testing.T) {
	if !es.NoStream().IsNoStream() {
		t.Error("NoStream")
	}
	if !es.AnyRevision().IsAny() {
		t.Error("Any")
	}
	if !es.StreamExists().IsStreamExists() {
		t.Error("StreamExists")
	}
	r, ok := es.AtRevision(7).Exact()
	if !ok || r != 7 {
		t.Errorf("Exact: got (%d,%v) want (7,true)", r, ok)
	}
	if _, ok := es.NoStream().Exact(); ok {
		t.Error("NoStream is not an exact revision")
	}
}

// ---- deterministic event ids --------------------------------------------

// The second idempotency layer: a retried command must produce byte-identical
// event ids so the store collapses the duplicate itself (verified behaviour).
func TestDeriveEventID_IsDeterministic(t *testing.T) {
	a := es.DeriveEventID("idem-key-123", 0)
	b := es.DeriveEventID("idem-key-123", 0)
	if a != b {
		t.Fatalf("same input must derive the same id: %s != %s", a, b)
	}
	if a.IsZero() {
		t.Fatal("derived id must not be zero")
	}
	if !strings.HasPrefix(a.String(), "evt_") {
		t.Errorf("derived id must carry the event prefix, got %s", a)
	}
}

func TestDeriveEventID_DistinctPerSequence(t *testing.T) {
	seen := map[string]bool{}
	for i := range 5 {
		id := es.DeriveEventID("same-key", i).String()
		if seen[id] {
			t.Fatalf("sequence %d collided: %s", i, id)
		}
		seen[id] = true
	}
}

func TestDeriveEventID_DistinctPerKey(t *testing.T) {
	if es.DeriveEventID("key-a", 0) == es.DeriveEventID("key-b", 0) {
		t.Fatal("different idempotency keys must derive different ids")
	}
}

func TestEventTypeOf(t *testing.T) {
	if got := es.EventTypeOf("workspace", "MemberInvited", 2); got != "workspace.MemberInvited.v2" {
		t.Fatalf("got %q", got)
	}
}

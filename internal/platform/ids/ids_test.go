package ids_test

import (
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// fixed inputs so every test is deterministic (CONVENTIONS §10).
// The entropy source must never exhaust — a bounded reader made an earlier
// version of this test fail for reasons that had nothing to do with ids.
var at = time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)

type constEntropy byte

func (c constEntropy) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(c)
	}
	return len(p), nil
}

var ent = constEntropy(0x01)

func TestString_CarriesTheTypePrefix(t *testing.T) {
	id := ids.New[ids.Org](at, ent)
	if got := id.String(); !strings.HasPrefix(got, "org_") {
		t.Fatalf("want org_ prefix, got %q", got)
	}
	// ADR-030: the prefix uses '_' so it never becomes a KurrentDB category,
	// which is everything before the first '-' (EVENT-SOURCING §2).
	if strings.Contains(id.String(), "-") {
		t.Fatalf("id must not contain '-', got %q", id.String())
	}
}

func TestParse_RoundTrips(t *testing.T) {
	orig := ids.New[ids.Workspace](at, ent)
	got, err := ids.Parse[ids.Workspace](orig.String())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != orig {
		t.Fatalf("round trip: got %v want %v", got, orig)
	}
}

// The point of ADR-030: a wrong-type id is a validation error at the boundary,
// not a mysterious not-found three layers down.
func TestParse_RejectsTheWrongPrefix(t *testing.T) {
	ws := ids.New[ids.Workspace](at, ent).String()
	if _, err := ids.Parse[ids.Org](ws); err == nil {
		t.Fatal("parsing a workspace id as an org id must fail")
	}
}

func TestParse_RejectsMalformed(t *testing.T) {
	for _, s := range []string{
		"", "org", "org_", "_01H8XG5N2QK7VB3C9WPYZR4TFM",
		"org_not-a-ulid", "org_01H8XG5N2QK7VB3C9WPYZR4TF", // too short
	} {
		if _, err := ids.Parse[ids.Org](s); err == nil {
			t.Errorf("expected %q to be rejected", s)
		}
	}
}

func TestZero(t *testing.T) {
	var z ids.OrgID
	if !z.IsZero() {
		t.Fatal("zero value must report IsZero")
	}
	if s := z.String(); s != "" {
		t.Fatalf("zero id must render empty, got %q", s)
	}
	if id := ids.New[ids.Org](at, ent); id.IsZero() {
		t.Fatal("generated id must not be zero")
	}
}

func TestTime_IsRecoverableAndUTC(t *testing.T) {
	id := ids.New[ids.Org](at, ent)
	got := id.Time()
	if !got.Equal(at) {
		t.Fatalf("timestamp: got %v want %v", got, at)
	}
	if got.Location() != time.UTC {
		t.Fatalf("ADR-008: timestamps are UTC, got %v", got.Location())
	}
}

func TestOrdering_IsChronological(t *testing.T) {
	early := ids.New[ids.Org](at, ent)
	later := ids.New[ids.Org](at.Add(time.Hour), ent)
	if early.String() >= later.String() {
		t.Fatalf("ULIDs must sort chronologically: %q !< %q", early, later)
	}
}

func TestJSON_UsesThePrefixedForm(t *testing.T) {
	type payload struct {
		Org ids.OrgID `json:"org"`
	}
	in := payload{Org: ids.New[ids.Org](at, ent)}
	b, err := codec.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := `{"org":"` + in.Org.String() + `"}`; string(b) != want {
		t.Fatalf("json: got %s want %s", b, want)
	}
	// Strict: an id document is ours end to end, so an unrecognised member is a
	// typo rather than a newer producer's field.
	out, err := codec.Unmarshal[payload](b)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Org != in.Org {
		t.Fatalf("json round trip: got %v want %v", out.Org, in.Org)
	}
}

func TestJSON_RejectsTheWrongType(t *testing.T) {
	var out struct {
		Org ids.OrgID `json:"org"`
	}
	ws := ids.New[ids.Workspace](at, ent).String()
	if err := codec.Into([]byte(`{"org":"`+ws+`"}`), &out); err == nil {
		t.Fatal("unmarshalling a workspace id into an OrgID must fail")
	}
}

// Every registered prefix must be unique, or Parse cannot tell types apart.
func TestPrefixes_AreUniqueAndWellFormed(t *testing.T) {
	seen := map[string]string{}
	for name, p := range ids.Registry() {
		if p == "" {
			t.Errorf("%s has an empty prefix", name)
		}
		if strings.ContainsAny(p, "_-") {
			t.Errorf("%s prefix %q must not contain '_' or '-'", name, p)
		}
		if prev, dup := seen[p]; dup {
			t.Errorf("prefix %q used by both %s and %s", p, prev, name)
		}
		seen[p] = name
	}
	if len(seen) < 8 {
		t.Fatalf("expected the full registry, got %d entries", len(seen))
	}
}

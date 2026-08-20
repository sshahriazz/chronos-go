package eventcodec_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	jsoncodec "github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

func codec() *eventcodec.JSON {
	return eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry())
}

// Metadata is written as map[string]string because KurrentDB's v2 append APIs
// carry it that way and reject anything else. A typed value here makes
// MultiStreamAppend permanently unusable (ADR-044).
func TestMetadataIsWrittenAsFlatStrings(t *testing.T) {
	raw, err := codec().MarshalMetadata(eventsourcing.Metadata{
		SchemaVersion:    3,
		OccurredAt:       time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
		OrgID:            "org_1",
		SubjectIDs:       []string{"sub_a", "sub_b"},
		SnapshotRevision: 17,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// The exact check the SDK performs before it will send anything.
	flat, err := jsoncodec.Unmarshal[map[string]string](raw)
	if err != nil {
		t.Fatalf("metadata is not a map[string]string, so every v2 append will be "+
			"rejected before it leaves this process: %v\nraw: %s", err, raw)
	}
	for k, want := range map[string]string{
		"schemaVersion":    "3",
		"orgId":            "org_1",
		"subjectIds":       "sub_a,sub_b",
		"snapshotRevision": "17",
	} {
		if flat[k] != want {
			t.Errorf("%s = %q, want %q", k, flat[k], want)
		}
	}
	// Absent values must not appear at all, rather than as empty strings that
	// read as "set to nothing".
	if _, present := flat["workspaceId"]; present {
		t.Error("an unset field was written as an empty string")
	}
}

// Events written before the format changed carry real JSON numbers and a real
// array. An event log is append-only, so the old shape is not a migration to
// finish — it exists forever and must decode forever.
func TestMetadataReadsTheOldTypedShape(t *testing.T) {
	old := []byte(`{
		"schemaVersion": 2,
		"occurredAt": "2026-08-01T09:30:00Z",
		"orgId": "org_old",
		"workspaceId": "ws_old",
		"subjectIds": ["sub_x","sub_y"],
		"snapshotRevision": 42
	}`)

	m, err := codec().UnmarshalMetadata(old)
	if err != nil {
		t.Fatalf("metadata written before ADR-044 no longer decodes, so every event in "+
			"the log before that change is unreadable: %v", err)
	}
	if m.SchemaVersion != 2 {
		t.Errorf("schemaVersion = %d, want 2", m.SchemaVersion)
	}
	if m.SnapshotRevision != 42 {
		t.Errorf("snapshotRevision = %d, want 42", m.SnapshotRevision)
	}
	if len(m.SubjectIDs) != 2 || m.SubjectIDs[0] != "sub_x" || m.SubjectIDs[1] != "sub_y" {
		t.Errorf("subjectIds = %v, want [sub_x sub_y]", m.SubjectIDs)
	}
	if m.OrgID != "org_old" || m.WorkspaceID != "ws_old" {
		t.Errorf("scope lost: org=%q workspace=%q", m.OrgID, m.WorkspaceID)
	}
	if !m.OccurredAt.Equal(time.Date(2026, 8, 1, 9, 30, 0, 0, time.UTC)) {
		t.Errorf("occurredAt = %s", m.OccurredAt)
	}
}

// And the new shape must round-trip, or the format change breaks the present
// while preserving the past.
func TestMetadataRoundTrips(t *testing.T) {
	c := codec()
	want := eventsourcing.Metadata{
		SchemaVersion:    1,
		OccurredAt:       time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
		OrgID:            "org_1",
		WorkspaceID:      "ws_1",
		Residency:        "eu",
		SubjectIDs:       []string{"sub_a"},
		ActorID:          "usr_1",
		CorrelationID:    "cor_1",
		CausationID:      "cau_1",
		SnapshotRevision: 9,
	}

	raw, err := c.MarshalMetadata(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := c.UnmarshalMetadata(raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.SchemaVersion != want.SchemaVersion || got.OrgID != want.OrgID ||
		got.WorkspaceID != want.WorkspaceID || got.Residency != want.Residency ||
		got.ActorID != want.ActorID || got.CorrelationID != want.CorrelationID ||
		got.CausationID != want.CausationID || got.SnapshotRevision != want.SnapshotRevision {
		t.Fatalf("round trip changed the metadata:\n got %+v\nwant %+v", got, want)
	}
	if len(got.SubjectIDs) != 1 || got.SubjectIDs[0] != "sub_a" {
		t.Fatalf("subjectIds = %v", got.SubjectIDs)
	}
	if !got.OccurredAt.Equal(want.OccurredAt) {
		t.Fatalf("occurredAt %s != %s", got.OccurredAt, want.OccurredAt)
	}
}

// Empty metadata is legitimate — a system-wide fact has no tenant — and must not
// become an error or a phantom subject.
func TestMetadataEmptyValues(t *testing.T) {
	c := codec()
	m, err := c.UnmarshalMetadata(nil)
	if err != nil {
		t.Fatalf("empty metadata: %v", err)
	}
	if m.SchemaVersion != 0 || len(m.SubjectIDs) != 0 {
		t.Fatalf("got %+v", m)
	}

	m, err = c.UnmarshalMetadata([]byte(`{"schemaVersion":"","subjectIds":"","snapshotRevision":""}`))
	if err != nil {
		t.Fatalf("empty strings must decode as absent, got %v", err)
	}
	if m.SchemaVersion != 0 || len(m.SubjectIDs) != 0 || m.SnapshotRevision != 0 {
		t.Fatalf("empty strings decoded as values: %+v", m)
	}
}

func TestMetadataRejectsNonNumericVersion(t *testing.T) {
	if _, err := codec().UnmarshalMetadata([]byte(`{"schemaVersion":"one"}`)); err == nil {
		t.Fatal("a non-numeric schemaVersion must be an error, not a silent zero")
	}
}

// ---------------------------------------------------------------------------
// future-proofing
// ---------------------------------------------------------------------------

// metadataWireKeys maps every field of eventsourcing.Metadata to the key it is
// written under. Adding a field to Metadata without adding it here FAILS the
// tests below.
//
// That is the point. The flat-string format is a constraint imposed by
// KurrentDB's v2 append APIs, and the way it would be broken is not by editing
// MarshalMetadata deliberately — it is by adding an ordinary typed field months
// from now and never running a multi-stream append until much later. A map that
// must be updated by hand turns that into a failing test at the moment the field
// is added.
var metadataWireKeys = map[string]string{
	"SchemaVersion":    "schemaVersion",
	"OccurredAt":       "occurredAt",
	"OrgID":            "orgId",
	"WorkspaceID":      "workspaceId",
	"Residency":        "residency",
	"SubjectIDs":       "subjectIds",
	"ActorID":          "actorId",
	"CorrelationID":    "$correlationId",
	"CausationID":      "$causationId",
	"SnapshotRevision": "snapshotRevision",
}

// A new field on Metadata must be deliberately accounted for.
func TestEveryMetadataFieldIsAccountedFor(t *testing.T) {
	typ := reflect.TypeFor[eventsourcing.Metadata]()
	for field := range typ.Fields() {
		name := field.Name
		if _, known := metadataWireKeys[name]; !known {
			t.Fatalf("Metadata.%s is new and has no entry in metadataWireKeys.\n\n"+
				"Event metadata is written as map[string]string because KurrentDB's v2 "+
				"append APIs reject anything else (ADR-044). Add %s to MarshalMetadata as "+
				"a STRING, to UnmarshalMetadata, and to metadataWireKeys.", name, name)
		}
	}
	if got, want := typ.NumField(), len(metadataWireKeys); got != want {
		t.Fatalf("Metadata has %d fields but %d are mapped", got, want)
	}
}

// Whatever the fields are, the encoded form must remain a flat map of strings.
// This is the exact check the KurrentDB SDK performs before it will send a v2
// append, so a failure here is a failure to write at all.
func TestMetadataStaysFlatWithEveryFieldPopulated(t *testing.T) {
	m := populatedMetadata(t)

	raw, err := codec().MarshalMetadata(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	flat, err := jsoncodec.Unmarshal[map[string]string](raw)
	if err != nil {
		t.Fatalf("metadata is no longer a flat map[string]string, so MultiStreamAppend "+
			"and AppendRecords will both reject every write:\n%v\nraw: %s", err, raw)
	}

	// And nothing may be silently dropped: a field that is set but never written
	// loses data with no error anywhere.
	for field, key := range metadataWireKeys {
		if _, present := flat[key]; !present {
			t.Errorf("Metadata.%s was set but %q is absent from the encoded metadata: "+
				"the value is silently discarded on every append", field, key)
		}
	}
}

// A populated value must survive the round trip. Catches a field that is written
// but never read back.
func TestEveryPopulatedFieldSurvivesTheRoundTrip(t *testing.T) {
	c := codec()
	m := populatedMetadata(t)

	raw, err := c.MarshalMetadata(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := c.UnmarshalMetadata(raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	before := reflect.ValueOf(m)
	after := reflect.ValueOf(got)
	typ := before.Type()
	for i := range typ.NumField() {
		name := typ.Field(i).Name
		if reflect.DeepEqual(before.Field(i).Interface(), after.Field(i).Interface()) {
			continue
		}
		// time.Time compares by wall clock and monotonic reading; compare by value.
		if t0, ok := before.Field(i).Interface().(time.Time); ok {
			if t1, ok2 := after.Field(i).Interface().(time.Time); ok2 && t0.Equal(t1) {
				continue
			}
		}
		t.Errorf("Metadata.%s did not survive the round trip: wrote %v, read %v",
			name, before.Field(i).Interface(), after.Field(i).Interface())
	}
}

// An id carrying the separator would decode as two subjects, silently widening
// who the event concerns — which is what drives erasure and notification
// targeting. It must fail at the write.
func TestSubjectIDWithSeparatorIsRefused(t *testing.T) {
	_, err := codec().MarshalMetadata(eventsourcing.Metadata{
		SchemaVersion: 1,
		SubjectIDs:    []string{"sub_a,sub_b"},
	})
	if err == nil {
		t.Fatal("a subject id containing the separator must be refused: it would decode " +
			"as two subjects and widen who this event concerns")
	}
	if _, err := codec().MarshalMetadata(eventsourcing.Metadata{
		SchemaVersion: 1, SubjectIDs: []string{""},
	}); err == nil {
		t.Fatal("an empty subject id must be refused")
	}
}

// populatedMetadata builds a Metadata with every field non-zero, via reflection,
// so a newly added field is populated automatically rather than silently skipped
// by a hand-written literal.
func populatedMetadata(t *testing.T) eventsourcing.Metadata {
	t.Helper()
	var m eventsourcing.Metadata
	v := reflect.ValueOf(&m).Elem()
	typ := v.Type()

	for i := range typ.NumField() {
		f := v.Field(i)
		name := typ.Field(i).Name
		switch {
		case name == "SubjectIDs":
			f.Set(reflect.ValueOf([]string{"sub_a", "sub_b"}))
		case f.Type() == reflect.TypeFor[time.Time]():
			f.Set(reflect.ValueOf(time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)))
		case f.Kind() == reflect.String:
			f.SetString("v_" + name)
		case f.CanInt():
			f.SetInt(7)
		case f.CanUint():
			f.SetUint(7)
		default:
			t.Fatalf("Metadata.%s is a %s, which has no flat-string encoding. "+
				"Metadata must stay expressible as map[string]string (ADR-044).",
				name, f.Kind())
		}
	}
	return m
}

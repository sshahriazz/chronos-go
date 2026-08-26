package domain_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/operator/contract"
	"github.com/chronos/chronos-go/internal/operator/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

func newEntry() *domain.AuditEntry {
	return eventsourcing.NewAggregate(domain.NewAuditEntry)
}

// TestAPersonalDataAccessCannotBeRecordedWithoutAJustification is the single
// most important assertion in this package.
//
// operator.md §4 permits reading a person's data "only on explicit, justified
// access". The justification is what makes the access lawful — so a record of
// the access WITHOUT it documents that a rule was followed while omitting the
// only evidence that it was.
//
// It is enforced three times over: protovalidate at the edge with a useful
// message, this aggregate, and the database's own CHECK constraint. Each layer
// catches a different mistake — a client bug, a second caller added later, and
// a projector bug respectively — and this is the one that holds for a caller
// nobody has written yet.
func TestAPersonalDataAccessCannotBeRecordedWithoutAJustification(t *testing.T) {
	valid := contract.OperatorViewedPersonalData{
		OperatorID:      "opr_1",
		SubjectID:       "subj_op",
		TargetSubjectID: "subj_target",
		OrgID:           "org_1",
		Fields:          []string{"email"},
		Reason:          "ticket 4711: the customer cannot receive mail",
		Method:          "/chronos.operator.v1.OperatorService/RevealPersonalData",
		ViewedAt:        at,
	}

	t.Run("with a reason it records", func(t *testing.T) {
		e := newEntry()
		if err := e.RecordPersonalDataView(valid); err != nil {
			t.Fatalf("a justified access was refused: %v", err)
		}
		if len(e.Uncommitted()) != 1 {
			t.Fatalf("recorded %d events", len(e.Uncommitted()))
		}
	})

	t.Run("with no reason it refuses", func(t *testing.T) {
		bad := valid
		bad.Reason = ""

		e := newEntry()
		err := e.RecordPersonalDataView(bad)
		if err == nil {
			t.Fatal("an unjustified personal-data access was recorded")
		}
		if !strings.Contains(err.Error(), "justification") {
			t.Errorf("refused for the wrong reason: %v", err)
		}
		if len(e.Uncommitted()) != 0 {
			t.Error("a refused access still recorded an event")
		}
	})

	t.Run("with no fields it refuses", func(t *testing.T) {
		// An empty field list would have to mean "everything", and "everything"
		// is the default that makes a justified-access rule meaningless.
		bad := valid
		bad.Fields = nil

		e := newEntry()
		if err := e.RecordPersonalDataView(bad); err == nil {
			t.Fatal("an access recording no fields was accepted")
		}
	})

	t.Run("with no target it refuses", func(t *testing.T) {
		bad := valid
		bad.TargetSubjectID = ""

		e := newEntry()
		if err := e.RecordPersonalDataView(bad); err == nil {
			t.Fatal("an access naming nobody was accepted")
		}
	})
}

// TestAViewNeedsTheMethodButNotAnOrg is the asymmetry the list view depends on.
//
// A page of the directory is an aggregate over MANY tenants, so naming one of
// them would be false — the audit entry for a list correctly has no org. What it
// must have is the method, because the audit's unit is the action.
func TestAViewNeedsTheMethodButNotAnOrg(t *testing.T) {
	t.Run("a list names no org and is accepted", func(t *testing.T) {
		e := newEntry()
		err := e.RecordView(contract.OperatorViewedCustomer{
			OperatorID: "opr_1",
			SubjectID:  "subj_op",
			Method:     "/chronos.operator.v1.OperatorService/ListCustomers",
			ViewedAt:   at,
		})
		if err != nil {
			t.Fatalf("a list view was refused for naming no org: %v", err)
		}
	})

	t.Run("a view with no method is refused", func(t *testing.T) {
		e := newEntry()
		err := e.RecordView(contract.OperatorViewedCustomer{
			OperatorID: "opr_1",
			SubjectID:  "subj_op",
			OrgID:      "org_1",
			ViewedAt:   at,
		})
		if err == nil {
			t.Fatal("a view recording no method was accepted")
		}
	})

	t.Run("a view with no operator is refused", func(t *testing.T) {
		e := newEntry()
		err := e.RecordView(contract.OperatorViewedCustomer{
			Method:   "/chronos.operator.v1.OperatorService/GetCustomer",
			ViewedAt: at,
		})
		if err == nil {
			t.Fatal("a view attributable to nobody was accepted")
		}
	})
}

// TestAnEntryRecordsExactlyOnce guards the one-stream-per-entry design.
//
// Each audit stream holds one event. A second record on the same aggregate
// would append to a stream that already has one, which the appender's
// single-event assertion would then reject — better to refuse at the aggregate,
// where the message says what happened.
func TestAnEntryRecordsExactlyOnce(t *testing.T) {
	e := newEntry()
	if err := e.RecordSignIn(contract.OperatorSignedIn{
		OperatorID: "opr_1", SubjectID: "subj_op", SessionID: "opsess_1", SignedInAt: at,
	}); err != nil {
		t.Fatalf("recording: %v", err)
	}

	// Replayed, so `recorded` comes from the EVENT rather than from the
	// in-memory flag the first call set.
	replayed := newEntry()
	for _, ev := range e.Uncommitted() {
		replayed.Apply(ev)
	}
	if !replayed.Recorded() {
		t.Fatal("an entry did not read as recorded after replay")
	}

	err := replayed.RecordView(contract.OperatorViewedCustomer{
		OperatorID: "opr_1", SubjectID: "subj_op", Method: "x", ViewedAt: at,
	})
	if err == nil {
		t.Fatal("a second action was recorded onto an entry that already holds one")
	}
}

// TestASignInRecordNeedsBothIdentifiers.
//
// The session id is what links the audit entry to the bearer that was issued,
// and an entry without it cannot answer "which session did this operator have
// when they read that customer" — which is the first question an incident asks.
func TestASignInRecordNeedsBothIdentifiers(t *testing.T) {
	for _, tc := range []struct {
		name string
		ev   contract.OperatorSignedIn
	}{
		{"no operator", contract.OperatorSignedIn{SessionID: "opsess_1", SignedInAt: at}},
		{"no session", contract.OperatorSignedIn{OperatorID: "opr_1", SignedInAt: at}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := newEntry().RecordSignIn(tc.ev); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// TestEveryAuditInstantIsUTC is the invariant CLAUDE.md states plainly, applied
// to the one table somebody may one day have to use as evidence.
func TestEveryAuditInstantIsUTC(t *testing.T) {
	local := time.FixedZone("UTC+6", 6*3600)
	when := time.Date(2026, 8, 26, 15, 0, 0, 0, local)

	t.Run("sign in", func(t *testing.T) {
		e := newEntry()
		if err := e.RecordSignIn(contract.OperatorSignedIn{
			OperatorID: "opr_1", SessionID: "opsess_1", SignedInAt: when,
		}); err != nil {
			t.Fatal(err)
		}
		got := e.Uncommitted()[0].(*contract.OperatorSignedIn).SignedInAt
		assertUTC(t, got, when)
	})

	t.Run("sign out", func(t *testing.T) {
		e := newEntry()
		if err := e.RecordSignOut(contract.OperatorSignedOut{
			OperatorID: "opr_1", SessionID: "opsess_1", SignedOutAt: when,
		}); err != nil {
			t.Fatal(err)
		}
		got := e.Uncommitted()[0].(*contract.OperatorSignedOut).SignedOutAt
		assertUTC(t, got, when)
	})

	t.Run("view", func(t *testing.T) {
		e := newEntry()
		if err := e.RecordView(contract.OperatorViewedCustomer{
			OperatorID: "opr_1", Method: "x", ViewedAt: when,
		}); err != nil {
			t.Fatal(err)
		}
		got := e.Uncommitted()[0].(*contract.OperatorViewedCustomer).ViewedAt
		assertUTC(t, got, when)
	})

	t.Run("personal data", func(t *testing.T) {
		e := newEntry()
		if err := e.RecordPersonalDataView(contract.OperatorViewedPersonalData{
			OperatorID: "opr_1", TargetSubjectID: "subj_t", Fields: []string{"email"},
			Reason: "ticket 4711", Method: "x", ViewedAt: when,
		}); err != nil {
			t.Fatal(err)
		}
		got := e.Uncommitted()[0].(*contract.OperatorViewedPersonalData).ViewedAt
		assertUTC(t, got, when)
	})
}

func assertUTC(t *testing.T, got, want time.Time) {
	t.Helper()
	if got.Location() != time.UTC {
		t.Errorf("recorded in %v, not UTC", got.Location())
	}
	if !got.Equal(want) {
		t.Errorf("the instant moved: %v vs %v", got, want)
	}
}

// TestNoAuditEventCarriesAnAddress is ADR-002 applied to this stream, in BOTH
// directions.
//
// The tenant side is obvious. The operator side is the one that is easy to get
// wrong: an operator is a natural person too, their work address is personal
// data, and operator.md §5 requires these records to be retained beyond their
// employment. An audit log holding employee addresses forever is a retention
// problem wearing an audit badge.
//
// This asserts on the STRUCT SHAPE rather than on a value, because the failure
// it guards is somebody adding a field — and a value test would pass on the day
// the field was added and empty.
func TestNoAuditEventCarriesAnAddress(t *testing.T) {
	forbidden := []string{"email", "address", "name", "phone", "avatar"}

	for _, ev := range []eventsourcing.Event{
		&contract.OperatorSignedIn{},
		&contract.OperatorSignedOut{},
		&contract.OperatorViewedCustomer{},
		&contract.OperatorViewedPersonalData{},
		&contract.OperatorProvisioned{},
		&contract.OperatorRoleChanged{},
		&contract.OperatorDisabled{},
		&contract.OperatorCredentialEnrolled{},
	} {
		t.Run(ev.EventType(), func(t *testing.T) {
			for _, field := range fieldNames(ev) {
				lower := strings.ToLower(field)
				for _, bad := range forbidden {
					if strings.Contains(lower, bad) {
						t.Errorf("%s.%s looks like personal data.\n\n"+
							"ADR-002: personal data never enters an event. The audit log stores "+
							"SubjectID pseudonyms only, which is what lets a record survive "+
							"erasure as a non-identifying fact — 'operator opr_… viewed billing "+
							"for org_… at T' stays true and provable while the erased person is "+
							"no longer identifiable from it.", ev.EventType(), field)
					}
				}
			}
		})
	}
}

// fieldNames reports the exported field names of an event struct.
func fieldNames(ev any) []string {
	v := reflect.ValueOf(ev)
	for v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}
	t := v.Type()
	out := make([]string, 0, t.NumField())
	for i := range t.NumField() {
		out = append(out, t.Field(i).Name)
	}
	return out
}

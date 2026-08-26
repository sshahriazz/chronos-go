package domain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/contract"
	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

var correctedAt = time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC)

func newRectification() *domain.Rectification {
	return eventsourcing.NewAggregate(domain.NewRectification)
}

// TestACorrectionRecordsTHATTheRightWasExercisedAndNotTheValues.
//
// ADR-002, at the point it is most tempting to break. The natural payload for
// this event is "corrected from X to Y", and it would put BOTH versions of
// somebody's name permanently in the log — the old one being precisely the value
// they have just told us is wrong about them.
//
// The event carries FIELD NAMES. This asserts the names are there and that
// nothing else is, by checking the only string field on the payload against the
// closed set.
func TestACorrectionRecordsFieldNamesAndNoValues(t *testing.T) {
	r := newRectification()

	if err := r.Correct("subj_1", "subj_1",
		[]domain.CorrectableField{domain.CorrectDisplayName, domain.CorrectTimezone},
		correctedAt); err != nil {
		t.Fatalf("correcting: %v", err)
	}

	events := r.Uncommitted()
	if len(events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(events))
	}
	ev, ok := events[0].(*contract.PersonalDataCorrected)
	if !ok {
		t.Fatalf("recorded %T", events[0])
	}

	if len(ev.Fields) != 2 {
		t.Fatalf("the event names %v, want both corrected fields", ev.Fields)
	}
	for _, name := range ev.Fields {
		if !domain.CorrectableField(name).Valid() {
			t.Errorf("the event carries %q, which is not a field name from the closed "+
				"set. A value has reached the event log, where ADR-002 says one may "+
				"never go", name)
		}
	}
	if !ev.CorrectedAt.Equal(correctedAt) || ev.CorrectedAt.Location() != time.UTC {
		t.Errorf("recorded at %v; all times are UTC (ADR-008)", ev.CorrectedAt)
	}
}

// TestTheFIELDORDERIsTheSchemaS, not the caller's.
//
// The names reach the event, the response and eventually a report. If the order
// depended on how a caller assembled the slice, two identical corrections would
// look different in the log — and "did this person correct the same thing twice"
// is a question somebody eventually asks of it.
func TestTheFieldOrderIsStable(t *testing.T) {
	a := newRectification()
	if err := a.Correct("subj_1", "subj_1",
		[]domain.CorrectableField{domain.CorrectDisplayName, domain.CorrectLocale},
		correctedAt); err != nil {
		t.Fatal(err)
	}
	b := newRectification()
	if err := b.Correct("subj_1", "subj_1",
		[]domain.CorrectableField{domain.CorrectDisplayName, domain.CorrectLocale},
		correctedAt); err != nil {
		t.Fatal(err)
	}

	first := a.Uncommitted()[0].(*contract.PersonalDataCorrected)
	second := b.Uncommitted()[0].(*contract.PersonalDataCorrected)
	if strings.Join(first.Fields, ",") != strings.Join(second.Fields, ",") {
		t.Errorf("two identical corrections recorded %v and %v", first.Fields, second.Fields)
	}
}

// TestCorrectingTwiceRecordsTWICE — the opposite of Restriction, on purpose.
//
// A restriction is a STATE: asking for it twice asks for something that already
// holds, so the second call records nothing. A correction is an EVENT in a
// person's history, and there is no state for the second one to already be in.
//
// The concrete case is somebody correcting a field to the same value again
// because the first attempt appeared not to work. Article 12(3)'s clock runs
// from REQUESTS, so collapsing the second would lose a request that was made.
func TestCorrectingTwiceRecordsTwice(t *testing.T) {
	r := newRectification()
	fields := []domain.CorrectableField{domain.CorrectDisplayName}

	if err := r.Correct("subj_1", "subj_1", fields, correctedAt); err != nil {
		t.Fatal(err)
	}
	first := r.Uncommitted()

	replayed := newRectification()
	for _, e := range first {
		replayed.Apply(e)
	}
	if err := replayed.Correct("subj_1", "subj_1", fields, correctedAt.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := len(replayed.Uncommitted()); n != 1 {
		t.Fatalf("a second correction recorded %d events; a person told us twice and the "+
			"log remembers once", n)
	}
	if replayed.Corrections() != 2 {
		t.Errorf("the aggregate counts %d corrections after two, so the Article 12(3) "+
			"history is short", replayed.Corrections())
	}
	if !replayed.LastCorrectedAt().Equal(correctedAt.Add(time.Hour)) {
		t.Errorf("the last correction is dated %v; unlike a restriction's instant, this "+
			"one MOVES — it is the latest request, not the first", replayed.LastCorrectedAt())
	}
}

// TestACorrectionNamingNoFieldIsRefused.
//
// An event asserting that a statutory right was exercised over no data is
// evidence of nothing, and it would sit in the log looking like a request that
// was answered.
func TestACorrectionNamingNoFieldIsRefused(t *testing.T) {
	r := newRectification()
	err := r.Correct("subj_1", "subj_1", nil, correctedAt)
	if err == nil {
		t.Fatal("a correction over no fields was recorded")
	}
	if len(r.Uncommitted()) != 0 {
		t.Error("it recorded an event anyway")
	}
}

// TestAFieldNamedTwiceIsRefusedRatherThanDeduplicated.
//
// A request naming one field twice was built by something that lost track of
// what it was sending. Silently collapsing it would record a correction the
// caller cannot reconcile with the request it made — and the caller here is
// eventually a client we did not write.
func TestAFieldNamedTwiceIsRefused(t *testing.T) {
	r := newRectification()
	err := r.Correct("subj_1", "subj_1", []domain.CorrectableField{
		domain.CorrectLocale, domain.CorrectLocale,
	}, correctedAt)
	if err == nil {
		t.Fatal("a correction naming one field twice was accepted")
	}
	if !strings.Contains(err.Error(), "twice") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// TestAnUnknownFieldIsRefused.
//
// The closed set is what keeps the vocabulary in the event log enumerable. A
// field name nothing recognises is one no later reader can act on, and it would
// travel to whichever module was asked to correct it.
func TestAnUnknownFieldIsRefused(t *testing.T) {
	r := newRectification()
	if err := r.Correct("subj_1", "subj_1",
		[]domain.CorrectableField{"email"}, correctedAt); err == nil {
		t.Fatal("a correction of a field outside the closed set was recorded")
	}
}

// TestTheEmailRefusalIsNamedAndCarriesItsReason.
//
// The decision this aggregate exists to hold. identity.md §12 owns the email
// change: a token to the new address proves the mailbox can be read, a revert
// token to the old one gives a way back, and a window bounds it. A rectification
// path for `email` would move the login identifier — and the account-recovery
// route with it — on one authenticated call with none of that proof.
//
// The refusal is asserted rather than left as a comment, because "the schema has
// no email field" is a decision nobody can see. This makes it a named error with
// its reason attached, so the day somebody adds the field they get this answer
// instead of a generic one.
func TestTheEmailRefusalIsNamedAndCarriesItsReason(t *testing.T) {
	if domain.ErrEmailNotRectifiable == nil {
		t.Fatal("there is no named refusal for correcting an email address, so the " +
			"decision to route it through identity's verified flow exists only in a " +
			"comment")
	}
	msg := domain.ErrEmailNotRectifiable.Error()
	for _, want := range []string{"identity", "login identifier", "recovery"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not mention %q, so it does not say where the "+
				"verified path is or why this one is closed: %q", want, msg)
		}
	}
	if domain.CorrectableField("email").Valid() {
		t.Error("`email` is in the correctable set, so rectification IS a second, " +
			"unverified path to change a login identifier")
	}
}

// TestACorrectionNeedsBothASubjectAndAnActor.
//
// The actor is who exercised the right. An event with no actor cannot answer
// "who asked for this", which is the first question about any correction that
// turns out to have been wrong.
func TestACorrectionNeedsBothASubjectAndAnActor(t *testing.T) {
	fields := []domain.CorrectableField{domain.CorrectDisplayName}
	if err := newRectification().Correct("", "subj_1", fields, correctedAt); err == nil {
		t.Error("a correction with no subject was recorded")
	}
	if err := newRectification().Correct("subj_1", "", fields, correctedAt); err == nil {
		t.Error("a correction with no actor was recorded")
	}
}

// TestTheFieldBoundMatchesTheClosedSet.
//
// MaxCorrectedFields exists so a request naming more fields than exist is
// refused as a repeat rather than processed. That reasoning only holds while the
// number IS the size of the set: adding a fourth correctable field without
// bumping the bound would refuse a caller who legitimately named all four, and
// the error would tell them one is repeated when none is.
func TestTheFieldBoundMatchesTheClosedSet(t *testing.T) {
	if got := len(domain.CorrectableFields()); got != domain.MaxCorrectedFields {
		t.Fatalf("%d fields are correctable and the per-request bound is %d. A caller "+
			"naming every field they may correct is now refused, and told that one is "+
			"repeated when none is", got, domain.MaxCorrectedFields)
	}
	for _, f := range domain.CorrectableFields() {
		if !f.Valid() {
			t.Errorf("%q is in the set and does not validate against it", f)
		}
	}
}

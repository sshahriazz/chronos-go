package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/compliance/app"
	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
)

// recordingRecords answers the conditional classes with a fixed answer, and
// remembers what it was asked.
//
// `asked` is the assertion that matters in the first test below: the whole point
// of the resolver is that it CONSULTS something, and a resolver that returned the
// full list without asking would pass every other assertion here.
type recordingRecords struct {
	has   bool
	err   error
	asked []domain.DataClass
}

func (r *recordingRecords) HasRecords(
	_ context.Context, _ string, class domain.DataClass,
) (bool, error) {
	r.asked = append(r.asked, class)
	return r.has, r.err
}

func newExemptions(t *testing.T, records app.RetainedRecords) *app.Exemptions {
	t.Helper()
	e, err := app.NewExemptions(app.ExemptionsDeps{Records: records})
	if err != nil {
		t.Fatalf("building the resolver: %v", err)
	}
	return e
}

// TestAConditionalExemptionIsASKED, not assumed.
//
// This is the difference between the resolver and the package-level []string it
// replaced. The old list named invoices for everybody because nothing could ask;
// this one asks, and a subject with no invoices is not told we keep theirs.
//
// If this test were deleted, every other assertion in this file would still pass
// against a resolver that returned domain.RetentionExemptions() unchanged.
func TestAConditionalExemptionIsAsked(t *testing.T) {
	records := &recordingRecords{has: true}
	newExemptions(t, records).For(context.Background(), "subj_1")

	if len(records.asked) == 0 {
		t.Fatal("no data class was resolved against the subject, so the exemptions are " +
			"asserted rather than consulted — which is the static list this replaced")
	}
	for _, class := range records.asked {
		policy, err := domain.RetentionPolicyFor(class)
		if err != nil {
			t.Fatalf("asked about %q, which is not in the schedule: %v", class, err)
		}
		if !policy.Conditional {
			t.Errorf("asked whether the subject has records in %q, which applies to "+
				"everybody. A round trip per erasure to learn something already known "+
				"is a cost with no answer attached", class)
		}
	}
}

// TestASubjectWithNoInvoicesIsNotToldTheirInvoicesAreKept.
//
// The specific wrong the port exists to prevent: a person who never paid us
// anything, told in their erasure confirmation that their invoices are retained
// for up to ten years under tax law. It is a false statement about their data,
// made in the one message they cannot reply to.
func TestASubjectWithNoInvoicesIsNotToldTheirInvoicesAreKept(t *testing.T) {
	got := newExemptions(t, &recordingRecords{has: false}).For(context.Background(), "subj_1")

	for _, p := range got {
		if p.Conditional {
			t.Errorf("%q was stated for a subject who holds no records in it", p.Class)
		}
	}
	if len(got) == 0 {
		t.Fatal("no exemptions at all. The event log and the operator audit trail survive " +
			"every erasure and apply to everybody, so an empty answer means the " +
			"unconditional classes were dropped along with the conditional ones")
	}
}

// TestAnUnanswerableExemptionIsSTATED.
//
// The failure direction, and it is the opposite of this codebase's usual
// fail-closed instinct — deliberately. Omitting a class we cannot rule out
// implies total deletion when tax records may survive, which compliance.md §7
// names as a misleading statement about processing. Stating one that does not
// apply is a smaller wrong, so an unreachable billing store resolves towards
// saying more rather than less.
func TestAnUnanswerableExemptionIsStated(t *testing.T) {
	records := &recordingRecords{err: errors.New("billing is unreachable")}
	got := newExemptions(t, records).For(context.Background(), "subj_1")

	var stated bool
	for _, p := range got {
		if p.Class == domain.ClassInvoices {
			stated = true
		}
	}
	if !stated {
		t.Fatalf("an unreadable billing store dropped the invoice exemption, so the "+
			"confirmation would imply total deletion while tax records may survive. Got %v",
			classes(got))
	}
}

// TestTheResolverCannotFailAnErasure.
//
// A statutory right with a one-month clock must not be blocked because a store
// was briefly unreachable while we worked out what sentence to put in the
// confirmation. The erasure is the obligation; this is the statement about it.
//
// Expressed as a type property — For returns no error — and asserted here so
// that widening the signature later is a deliberate decision rather than a
// refactor.
func TestTheResolverCannotFailAnErasure(t *testing.T) {
	records := &recordingRecords{err: errors.New("everything is down")}
	got := newExemptions(t, records).For(context.Background(), "subj_1")

	if len(got) < 2 {
		t.Fatalf("a total outage produced %d exemptions; the unconditional ones need no "+
			"lookup and must survive it", len(got))
	}
}

// TestTheResolverRefusesToBuildWithoutARecordsPort.
//
// A nil port could reasonably mean "include every conditional class", which is
// the safe direction and is what a failure already produces. It is refused
// anyway, because that reading makes "we chose to be over-inclusive" and
// "somebody forgot to wire this" indistinguishable — and the second is what a
// composition root ships when a dependency is optional.
func TestTheResolverRefusesToBuildWithoutARecordsPort(t *testing.T) {
	_, err := app.NewExemptions(app.ExemptionsDeps{})
	if err == nil {
		t.Fatal("a resolver was built with no records port, so the deliberate " +
			"over-inclusive answer is indistinguishable from a forgotten dependency")
	}
	if !strings.Contains(err.Error(), "AssumeRecordsExist") {
		t.Errorf("the refusal does not point at the honest placeholder: %v", err)
	}
}

// TestTheHonestPlaceholderIsOverInclusive.
//
// AssumeRecordsExist is no longer what the roots wire — RecordsByClass is — but
// it is still the correct reader for a process with no billing read side. This
// asserts it errs in the safe direction rather than trusting its name.
func TestTheHonestPlaceholderIsOverInclusive(t *testing.T) {
	got := newExemptions(t, app.AssumeRecordsExist{}).For(context.Background(), "subj_1")

	if len(got) != len(domain.RetentionExemptions()) {
		t.Fatalf("the placeholder produced %d of %d exemptions; it exists to state every "+
			"one, so anything less is under-inclusion by a component named for the "+
			"opposite", len(got), len(domain.RetentionExemptions()))
	}
}

func classes(policies []domain.RetentionPolicy) []domain.DataClass {
	out := make([]domain.DataClass, 0, len(policies))
	for _, p := range policies {
		out = append(out, p.Class)
	}
	return out
}

// ---------------------------------------------------------------------------
// The router
// ---------------------------------------------------------------------------

// invoiceAnswer is a billing read side with a fixed answer.
type invoiceAnswer struct {
	has bool
	err error
}

func (a invoiceAnswer) HasInvoices(context.Context, string) (bool, error) {
	return a.has, a.err
}

// TestASubjectWithNoInvoicesIsNotToldTheirInvoicesAreRetained is the whole
// point of replacing the placeholder.
//
// Most subjects are in this case: a trial that never converted has no invoice
// anywhere, and the confirmation used to tell every one of them that invoice
// data may be kept about them for seven to ten years.
func TestASubjectWithNoInvoicesIsNotToldTheirInvoicesAreRetained(t *testing.T) {
	records, err := app.NewRecordsByClass(invoiceAnswer{has: false})
	if err != nil {
		t.Fatalf("NewRecordsByClass: %v", err)
	}

	got := classes(newExemptions(t, records).For(context.Background(), "subj_1"))
	for _, c := range got {
		if c == domain.ClassInvoices {
			t.Fatal("a subject with no invoices anywhere was told invoice data may be " +
				"retained about them; that is a false statement about their data, and " +
				"the reader exists to prevent exactly it")
		}
	}
	if len(got) == 0 {
		t.Fatal("no exemptions at all; the unconditional classes must still be stated")
	}
}

// TestASubjectWithInvoicesIsToldSo is the other direction, and it is the one
// that matters legally: Article 17(3)(b) retention that is not disclosed is the
// misleading answer compliance.md §7 names.
func TestASubjectWithInvoicesIsToldSo(t *testing.T) {
	records, err := app.NewRecordsByClass(invoiceAnswer{has: true})
	if err != nil {
		t.Fatalf("NewRecordsByClass: %v", err)
	}

	got := classes(newExemptions(t, records).For(context.Background(), "subj_1"))
	if !containsClass(got, domain.ClassInvoices) {
		t.Fatal("a subject who appears on an invoice was NOT told their invoice data is " +
			"retained, so the confirmation implies a total deletion that did not happen")
	}
}

// TestAnUnreachableBillingStillStatesTheClass.
//
// The resolver's rule, exercised through the router: an error is not "no
// records". A statutory right with a one-month clock must not be blocked
// because billing was briefly unreachable, and the statement must not shrink
// either.
func TestAnUnreachableBillingStillStatesTheClass(t *testing.T) {
	records, err := app.NewRecordsByClass(invoiceAnswer{err: errors.New("pool exhausted")})
	if err != nil {
		t.Fatalf("NewRecordsByClass: %v", err)
	}

	got := classes(newExemptions(t, records).For(context.Background(), "subj_1"))
	if !containsClass(got, domain.ClassInvoices) {
		t.Fatal("billing failed to answer and the invoice class was dropped; an " +
			"unanswerable question must resolve towards saying more, not less")
	}
}

// TestEveryConditionalClassIsEitherAnsweredOrNamed is the guard on the router
// itself.
//
// A class added to the schedule with `Conditional: true` and no reader falls to
// the router's default, which states it for everybody — the old placeholder's
// behaviour, restored quietly for one class. `Unanswered` is derived from the
// schedule, so this test names exactly which classes are in that state and
// fails when a new one joins them.
//
// The breach register is expected here: it does not exist, so nothing can be
// asked about it.
func TestEveryConditionalClassIsEitherAnsweredOrNamed(t *testing.T) {
	records, err := app.NewRecordsByClass(invoiceAnswer{})
	if err != nil {
		t.Fatalf("NewRecordsByClass: %v", err)
	}

	want := []domain.DataClass{domain.ClassBreachRecords}
	got := records.Unanswered()

	if len(got) != len(want) {
		t.Fatalf("the router cannot answer %v; it is expected to be unable to answer only "+
			"%v.\n\nA conditional class with no reader is stated for every subject, "+
			"which is the placeholder's behaviour restored for one class. Either give "+
			"it a reader or add it here deliberately.", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("unanswered class %d is %q, want %q", i, got[i], want[i])
		}
	}
}

// TestTheRouterRefusesToBuildWithoutBilling.
//
// The same argument NewExemptions makes for its own port: a nil would silently
// restore "state invoices for everybody", and a deliberate over-statement and a
// forgotten dependency would be indistinguishable.
func TestTheRouterRefusesToBuildWithoutBilling(t *testing.T) {
	if _, err := app.NewRecordsByClass(nil); err == nil {
		t.Fatal("a router was built with no billing reader, so every erasure would state " +
			"invoice retention for subjects who have none and nothing would say why")
	}
}

func containsClass(list []domain.DataClass, want domain.DataClass) bool {
	for _, c := range list {
		if c == want {
			return true
		}
	}
	return false
}

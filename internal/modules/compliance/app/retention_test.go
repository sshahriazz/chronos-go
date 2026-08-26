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
// AssumeRecordsExist is what both composition roots wire today, because nothing
// can ask billing whether a subject appears on an invoice. This asserts it errs
// in the safe direction rather than trusting its name.
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

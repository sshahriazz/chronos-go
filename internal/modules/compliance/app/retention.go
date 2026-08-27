package app

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
)

// RetainedRecords answers, for one CONDITIONAL data class, whether this subject
// actually has records in it (domain.RetentionPolicy.Conditional).
//
// # Declared here, satisfied by whoever owns the records
//
// compliance owns the retention POLICY and none of the data it describes
// (compliance.md §15). Only billing can say whether a person appears on an
// invoice; only the breach register can say whether they were involved in an
// incident. So this is a port, satisfied at the composition root, exactly as
// AccountErasure is.
//
// # An error is not "no records"
//
// The caller treats a failure to answer as a reason to INCLUDE the class. That
// is the opposite of this codebase's usual fail-closed instinct and it is the
// same direction: the dangerous outcome here is telling somebody their data is
// gone when it is not, so an unanswerable question resolves towards saying more
// rather than less.
type RetainedRecords interface {
	HasRecords(ctx context.Context, subjectID string, class domain.DataClass) (bool, error)
}

// Exemptions resolves what an erasure leaves behind, for one subject.
//
// # It replaced a hand-written list of sentences
//
// The erasure used to carry a package-level `[]string`. It was honest about
// being static — the comment said so — and static was the problem: nothing
// compared it to compliance.md §7, nothing could enumerate it, and adding a data
// class with a statutory retention would have left the confirmation saying what
// it always said while a new category of record quietly survived.
//
// What this adds is not more sentences. It is that the sentences are DERIVED
// from the schedule, and that the classes which apply only to some people are
// asked about rather than asserted.
type Exemptions struct {
	records RetainedRecords
	log     *slog.Logger
}

// ExemptionsDeps is what Exemptions needs.
type ExemptionsDeps struct {
	// Records answers the conditional classes. REQUIRED — see NewExemptions.
	Records RetainedRecords

	Log *slog.Logger
}

// NewExemptions builds the resolver.
//
// The records port is REQUIRED even though its absence would be survivable: a
// nil port could reasonably mean "include every conditional class", which is the
// safe direction and is what a failure already produces. It is required anyway,
// because that reading makes the difference between "we decided to be
// over-inclusive" and "somebody forgot to wire this" invisible — and the second
// is what a composition root ships when a dependency is optional. The
// over-inclusive answer is available deliberately, as AssumeRecordsExist, which
// says in its own name what it is doing.
func NewExemptions(d ExemptionsDeps) (*Exemptions, error) {
	if d.Records == nil {
		return nil, fmt.Errorf("compliance: a retained-records reader is required; the " +
			"conditional exemptions (invoices, breach records) do not apply to everybody, " +
			"and a resolver with no way to ask would state them for people who have none. " +
			"Wire AssumeRecordsExist if nothing can answer yet — it says so in its name")
	}
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	return &Exemptions{records: d.Records, log: log}, nil
}

// For returns the retention exemptions that apply to one subject.
//
// # It cannot fail, and that is deliberate rather than lazy
//
// There is no failure of this resolver that should stop an erasure. A statutory
// right with a one-month clock must not be blocked because billing was briefly
// unreachable while we worked out what sentence to put in the confirmation — the
// erasure is the obligation, and this is the statement about it.
//
// So every unanswerable question resolves in the over-inclusive direction and is
// LOGGED. The log line is what makes the degradation visible: a resolver quietly
// naming every conditional class on every erasure, because one port has been
// erroring for a month, is otherwise indistinguishable from correct behaviour.
func (e *Exemptions) For(ctx context.Context, subjectID string) []domain.RetentionPolicy {
	all := domain.RetentionExemptions()
	out := make([]domain.RetentionPolicy, 0, len(all))

	for _, policy := range all {
		if !policy.Conditional {
			// Applies to everybody who ever used the system: the event log and
			// the operator audit trail. Nothing to ask.
			out = append(out, policy)
			continue
		}

		has, err := e.records.HasRecords(ctx, subjectID, policy.Class)
		switch {
		case err != nil:
			// INCLUDED. See the doc comment: implying total deletion when tax
			// records survive is the misleading statement compliance.md §7 names,
			// and it is the wrong that an omission produces.
			e.log.WarnContext(ctx,
				"a conditional retention exemption could not be resolved and is being "+
					"stated anyway",
				"subject_id", subjectID, "data_class", string(policy.Class), "error", err)
			out = append(out, policy)
		case has:
			out = append(out, policy)
		default:
			// The subject genuinely has no records in this class. Saying their
			// invoices are retained would be a false statement about their data,
			// and this is the case the port exists to catch.
			e.log.DebugContext(ctx, "a retention exemption does not apply to this subject",
				"subject_id", subjectID, "data_class", string(policy.Class))
		}
	}
	return out
}

// InvoiceRecords is billing's half of the question: does this person appear on
// an invoice we are required to keep?
//
// Declared as its own one-method port rather than as a `RetainedRecords` that
// ignores the class it is handed. A reader that accepted `class` and answered
// the same way regardless would be a reader nothing stops from being wired for
// the breach register.
type InvoiceRecords interface {
	HasInvoices(ctx context.Context, subjectID string) (bool, error)
}

// RecordsByClass routes each conditional class to whoever can answer it, and
// states the rest.
//
// # This replaced AssumeRecordsExist at the composition roots
//
// The schedule has two conditional classes. Billing can now answer one of them
// — `SubjectHasRetainedInvoices` joins `invoice_view` to `org_member_index`, so
// a person whose organizations were never invoiced is no longer told that
// invoice data may be retained about them. That is most people: every trial
// that never converted.
//
// The other, the breach register, cannot be answered because the register does
// not exist. It is STATED, unconditionally, and `Unanswered` names which class
// that is doing — so the over-statement is scoped to one named class instead of
// being the behaviour of the whole resolver.
//
// # Why an unknown conditional class is stated too
//
// A class added to the schedule with `Conditional: true` and no reader here
// falls to the default, which states it and records the class in `Unanswered`.
// That is the safe direction, and the test
// TestEveryConditionalClassIsEitherAnsweredOrNamed fails on it — so the
// omission is visible in CI rather than discovered in somebody's erasure
// confirmation.
type RecordsByClass struct {
	invoices InvoiceRecords
}

var _ RetainedRecords = (*RecordsByClass)(nil)

// NewRecordsByClass builds the router.
//
// The invoice reader is REQUIRED, for the reason NewExemptions requires its
// port: a nil would silently restore the old behaviour for the one class that
// can now be answered, and "we decided to over-state" would become
// indistinguishable from "somebody forgot to wire billing".
func NewRecordsByClass(invoices InvoiceRecords) (*RecordsByClass, error) {
	if invoices == nil {
		return nil, fmt.Errorf("compliance: a retained-invoice reader is required; " +
			"without it every erasure confirmation states that invoice data may be " +
			"retained, including for the majority of subjects whose organizations were " +
			"never invoiced")
	}
	return &RecordsByClass{invoices: invoices}, nil
}

// HasRecords answers one class.
func (r *RecordsByClass) HasRecords(
	ctx context.Context, subjectID string, class domain.DataClass,
) (bool, error) {
	switch class {
	case domain.ClassInvoices:
		return r.invoices.HasInvoices(ctx, subjectID)
	default:
		// STATED. See Unanswered for which classes reach here and why.
		return true, nil
	}
}

// Unanswered is every conditional class this router cannot actually ask about.
//
// Derived from the schedule and the switch above rather than written out, so it
// cannot claim to cover a class the switch does not.
func (r *RecordsByClass) Unanswered() []domain.DataClass {
	var out []domain.DataClass
	for _, p := range domain.RetentionExemptions() {
		if !p.Conditional {
			continue
		}
		if p.Class == domain.ClassInvoices {
			continue
		}
		out = append(out, p.Class)
	}
	return out
}

// AssumeRecordsExist answers every conditional class with "yes".
//
// # No longer what the composition roots wire
//
// It was, and its own doc said so. The roots now wire RecordsByClass, which
// asks billing about invoices and states the rest — so the over-statement is
// scoped to the classes nothing can answer instead of being the behaviour of
// the whole resolver.
//
// It is kept because it is still the correct thing to hand a process that has
// no billing read side at all, and because the tests that assert the
// over-inclusive direction need a reader that takes it unconditionally. It is
// named so that a root wiring it cannot pretend to be doing anything else.
type AssumeRecordsExist struct{}

var _ RetainedRecords = AssumeRecordsExist{}

// HasRecords always answers yes.
func (AssumeRecordsExist) HasRecords(
	context.Context, string, domain.DataClass,
) (bool, error) {
	return true, nil
}

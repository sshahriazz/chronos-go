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

// AssumeRecordsExist answers every conditional class with "yes".
//
// # It is the honest placeholder, and it is named so it cannot hide
//
// Nothing in this build can ask billing whether a subject appears on an invoice:
// `invoice_view` is keyed by organization, and the person-to-invoice link would
// be a membership join through a billing contact this system does not record.
// The breach register does not exist at all.
//
// So the conditional classes are stated for everybody. That is over-inclusive in
// the safe direction — a person with no invoices is told invoices may be
// retained, which is a smaller wrong than a person with invoices being told
// everything is gone — and it is wired at the composition root rather than
// buried behind a nil check, so replacing it is a one-line change at the place
// that decides.
type AssumeRecordsExist struct{}

var _ RetainedRecords = AssumeRecordsExist{}

// HasRecords always answers yes.
func (AssumeRecordsExist) HasRecords(
	context.Context, string, domain.DataClass,
) (bool, error) {
	return true, nil
}

package domain

import (
	"fmt"
	"slices"
)

// ---------------------------------------------------------------------------
// The retention schedule (compliance.md §7), as data rather than as prose
// ---------------------------------------------------------------------------
//
// §7 publishes a table: per data class, how long it is kept and what happens to
// it when somebody exercises Article 17. Until this file existed, nothing read
// that table. The erasure carried a hand-written `[]string` of sentences, the
// confirmation printed it, and the export manifest printed the same one — three
// copies of a policy nobody could enumerate, compare against §7, or test.
//
// The failure that shape invites is specific and quiet. Add a data class with a
// statutory retention — a breach register, an audit trail — and the erasure
// confirmation keeps saying what it always said. The person is told their data
// is gone, some of it is not, and the discrepancy surfaces during a supervisory
// authority's questions rather than in review.
//
// So the table is here, it is the whole of §7 including the classes that are
// NOT retained, and the erasure consults it.
//
// # Why the classes that are erased are in the table too
//
// Two reasons, and the second is the one that matters. Enumerating only the
// exemptions makes "is this class exempt?" unanswerable for a class nobody
// listed — absence would mean both "erased" and "forgotten about", which is
// exactly the ambiguity the notification catalogue's `Silent` entries exist to
// remove. And compliance.md §16's test plan asks for "invoices survive erasure;
// session logs do not", which is a statement about two rows of one table and
// cannot be made against a list of one kind of row.

// DataClass names one category of data this system retains on its own schedule.
//
// A closed set, in the source, so "what do we keep and for how long" is
// answerable by reading a Go file rather than by asking somebody. The strings
// are PERMANENT: they reach the data subject in an erasure confirmation and an
// export manifest, and a bundle a person downloaded last year must still mean
// what it said.
type DataClass string

const (
	// ClassSessionLogs is authentication and session history: sign-ins, device
	// records, token issuance. Erased with the subject.
	ClassSessionLogs DataClass = "session_and_auth_logs"

	// ClassNotificationDelivery is what was sent and whether it arrived. Erased
	// with the subject.
	ClassNotificationDelivery DataClass = "notification_delivery"

	// ClassInvoices is invoices and tax records. THE exemption that surprises
	// people (§7): tax law requires their retention, so erasure minimises them
	// to what the obligation needs and keeps them.
	ClassInvoices DataClass = "invoices_and_tax_records"

	// ClassOperatorAudit is the operator plane's record of who looked at what
	// (operator.md §5). Survives as a pseudonym: the entry stays, and the key
	// that could resolve it to a person is destroyed.
	ClassOperatorAudit DataClass = "operator_audit"

	// ClassBreachRecords is the Article 33 register. Retained for seven years
	// because a supervisory authority may ask about an incident long after
	// everybody involved has left.
	ClassBreachRecords DataClass = "breach_records"

	// ClassEventLog is the append-only log itself. It is not deleted and cannot
	// be: it is what every projection is rebuilt from (ADR-013). Erasure
	// pseudonymises it by destroying the key, which is the whole of ADR-002.
	ClassEventLog DataClass = "event_log"
)

// Disposition is what an erasure does to a data class.
type Disposition string

const (
	// DispositionErased means the class goes with the erasure. Nothing about
	// this subject survives in it.
	DispositionErased Disposition = "erased"

	// DispositionPseudonymised means the records survive and become unreadable:
	// the rows keep a pseudonym, and the key that resolved it is destroyed.
	//
	// It is NOT the same as retained, and telling somebody the two are the same
	// would be false in both directions. Pseudonymised data cannot be read back
	// to them or to us; retained data can.
	DispositionPseudonymised Disposition = "pseudonymised"

	// DispositionRetained means the records survive READABLE, under a legal
	// obligation that overrides the erasure request. This is the disposition
	// Article 17(3) exists for, and the one a confirmation must never imply
	// away.
	DispositionRetained Disposition = "retained"
)

// Retained reports whether a class survives an erasure in any form.
//
// Both non-erased dispositions count. A pseudonymised operator audit entry is
// not readable, and it is still a record about a person that outlives their
// request — which is a fact the confirmation has to state rather than round
// down to "everything is gone".
func (d Disposition) Retained() bool { return d != DispositionErased }

// RetentionPolicy is one row of compliance.md §7's table.
//
// It carries no personal data and never can: it is a statement about a CLASS,
// identical for every subject. What varies per subject is only whether the class
// applies to them at all — see Conditional.
type RetentionPolicy struct {
	// Class is which category this is about.
	Class DataClass

	// Period is how long the class is kept, in the words §7 uses. A sentence
	// rather than a duration, because "7–10 years, statutory" is a range that
	// depends on jurisdiction and rendering it as a single number would be a
	// precision this system does not have.
	Period string

	// Disposition is what an erasure does to it.
	Disposition Disposition

	// LegalBasis is the article permitting the retention. Empty when the class
	// is erased, because there is nothing to justify.
	//
	// It is stated to the DATA SUBJECT, which is the point of the field:
	// compliance.md §7 requires the DSAR response to say what is retained and
	// why, "rather than implying total deletion", and "why" under the GDPR means
	// an article and not a business reason.
	LegalBasis string

	// Reason is one sentence the person reads. Written for them, not for us: it
	// explains the retention in terms of what it means for their data, and it
	// names no internal system.
	Reason string

	// Conditional reports whether this class applies only to subjects who
	// actually have records in it.
	//
	// # Why the distinction exists, and which way it fails
	//
	// Everybody who ever used this system appears in the event log and may
	// appear in an operator audit entry, so those two are unconditional. Not
	// everybody has an invoice, and almost nobody appears in a breach record —
	// telling a person with no invoices that their invoices are retained is a
	// statement about their data that is not true.
	//
	// The resolution is asked of the module that holds the records, and when
	// that question cannot be answered the class is INCLUDED. Over-inclusion
	// tells somebody their invoices may be retained when they have none;
	// under-inclusion implies total deletion when tax records survive, which is
	// the misleading statement §7 names. The first is a smaller wrong and it is
	// the direction this fails in.
	Conditional bool
}

// retentionSchedule is compliance.md §7's table, in its order.
//
// Unexported and copied on read: a caller that could append to this would be
// changing the published retention policy of a running system by assigning to a
// slice, and the erasure confirmation is downstream of it.
var retentionSchedule = []RetentionPolicy{
	{
		Class:       ClassSessionLogs,
		Period:      "90 days",
		Disposition: DispositionErased,
		Reason: "your sign-in history and device records are destroyed with the rest of " +
			"your account",
	},
	{
		Class:       ClassNotificationDelivery,
		Period:      "180 days",
		Disposition: DispositionErased,
		Reason: "the record of what we sent you, and whether it arrived, is destroyed " +
			"with the rest of your account",
	},
	{
		Class:       ClassInvoices,
		Period:      "7–10 years, depending on jurisdiction",
		Disposition: DispositionRetained,
		LegalBasis:  "GDPR Article 17(3)(b) — compliance with a legal obligation (tax law)",
		Reason: "invoices and tax records are kept because tax law requires it. They are " +
			"reduced to what that obligation needs and nothing more, and they are not " +
			"used for anything else",
		Conditional: true,
	},
	{
		Class:       ClassOperatorAudit,
		Period:      "7 years",
		Disposition: DispositionPseudonymised,
		LegalBasis: "GDPR Article 17(3)(b) — compliance with a legal obligation " +
			"(our own auditability)",
		Reason: "the record of which of our staff accessed an account is kept, but only " +
			"as a code. The key that could turn that code back into you is destroyed, " +
			"so the entry no longer identifies anybody",
	},
	{
		Class:       ClassBreachRecords,
		Period:      "7 years",
		Disposition: DispositionRetained,
		LegalBasis:  "GDPR Article 17(3)(b) — compliance with a legal obligation (Article 33)",
		Reason: "if a security incident ever affected your data, the record of that " +
			"incident is kept so a supervisory authority can ask about it",
		Conditional: true,
	},
	{
		Class:       ClassEventLog,
		Period:      "indefinite",
		Disposition: DispositionPseudonymised,
		Reason: "the history of what happened in the system is not rewritten. It refers " +
			"to you only by a code, and destroying your key is what makes that code " +
			"resolve to nothing — permanently, everywhere, at once",
	},
}

// RetentionSchedule returns compliance.md §7's table, every class.
//
// A copy, for the reason above. The slice is small and read once per erasure, so
// the allocation is not worth reasoning about; the alternative is a package
// variable any caller can rewrite.
func RetentionSchedule() []RetentionPolicy { return slices.Clone(retentionSchedule) }

// RetentionExemptions returns the classes that SURVIVE an erasure.
//
// This is what a confirmation and an export manifest state. It is derived from
// the schedule rather than written twice, so a class whose disposition changes
// moves between the two answers by editing one field.
func RetentionExemptions() []RetentionPolicy {
	out := make([]RetentionPolicy, 0, len(retentionSchedule))
	for _, p := range retentionSchedule {
		if p.Disposition.Retained() {
			out = append(out, p)
		}
	}
	return out
}

// RetentionPolicyFor returns one class's policy.
//
// An unknown class is an ERROR rather than a zero value. A zero RetentionPolicy
// has an empty disposition, which `Retained` reports as true — so a typo'd class
// would silently become an exemption with no period, no basis and no sentence,
// and the person would be told something survived without being told what.
func RetentionPolicyFor(class DataClass) (RetentionPolicy, error) {
	for _, p := range retentionSchedule {
		if p.Class == class {
			return p, nil
		}
	}
	return RetentionPolicy{}, fmt.Errorf(
		"compliance: %q is not a data class in the retention schedule (compliance.md §7)",
		class)
}

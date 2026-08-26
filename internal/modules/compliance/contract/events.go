// Package contract is compliance's public event surface.
package contract

import "time"

// ProcessingRestricted records that a data subject invoked Article 18.
//
// # What restriction is, and what it is not
//
// It is NOT deletion and NOT deactivation. Article 18 exists for the case where
// somebody disputes what is held about them but does not want it destroyed while
// the dispute runs: storage continues, and everything else stops. The account
// keeps working, the projections keep building, the log keeps its history — and
// the subject stops being contacted or otherwise processed.
//
// compliance.md §6: "projectors continue, but reactors skip the subject — no
// email, no push, no export, no profiling."
//
// # The reason is not carried
//
// A restriction's justification is the subject's own account of a dispute, which
// is free text a person wrote about themselves. It belongs in a support system,
// not in a permanent replicated log (ADR-002) — and nothing in this system
// branches on it, so storing it would be keeping personal data to satisfy
// nobody's question.
type ProcessingRestricted struct {
	SubjectID string

	// ActorID is who invoked it. Normally the subject; an operator when the
	// request arrived out of band.
	ActorID string

	RestrictedAt time.Time
}

func (*ProcessingRestricted) EventType() string { return "compliance.ProcessingRestricted.v1" }

// ProcessingRestrictionLifted records that processing may resume.
//
// The dispute is settled, or the subject withdrew the restriction. Nothing was
// lost while it stood, which is the whole point of Article 18 as distinct from
// Article 17.
type ProcessingRestrictionLifted struct {
	SubjectID string

	ActorID string

	LiftedAt time.Time
}

func (*ProcessingRestrictionLifted) EventType() string {
	return "compliance.ProcessingRestrictionLifted.v1"
}

// ---------------------------------------------------------------------------
// Data export (Articles 15 and 20, compliance.md §5)
// ---------------------------------------------------------------------------

// DataExportRequested records that a subject asked for a copy of their data.
//
// # It is a compliance record before it is a job ticket
//
// Article 15 gives a controller one month to answer, and "when did they ask"
// is the question that starts that clock. The workflow the request triggers is
// how the answer gets built; THIS is the evidence that the right was exercised,
// and it outlives every workflow history and every bundle the request produces.
//
// # No address, no field list, no bundle contents
//
// The pseudonym only (ADR-002). What the export CONTAINS is the vault's answer
// at the moment the workflow reads it — putting any of it here would write the
// person's personal data permanently into the log, which is the one thing an
// export must not do on its way to giving them a copy.
type DataExportRequested struct {
	SubjectID string

	// ExportID names this request, and is what the subject polls with. Prefixed
	// (ADR-030) and unguessable, because it is the handle a later call uses to
	// mint download URLs.
	ExportID string

	RequestedAt time.Time
}

func (*DataExportRequested) EventType() string { return "compliance.DataExportRequested.v1" }

// DataExportCompleted records that the bundle exists and can be fetched.
//
// The manifest's KEY, not its contents. An object key carries no business
// meaning by construction (CLAUDE.md) and lives under the subject's own prefix,
// so recording it says where the answer is without saying what it says — and
// erasure removes the object the key names by the traversal it already performs.
type DataExportCompleted struct {
	SubjectID string
	ExportID  string

	// ManifestKey is the JSON bundle describing everything included.
	ManifestKey string

	// ObjectCount is how many stored objects the manifest references. Reported
	// because "your export is ready" and "your export is ready and it found none
	// of your files" are different answers, and only this number distinguishes
	// them.
	ObjectCount int

	CompletedAt time.Time
}

func (*DataExportCompleted) EventType() string { return "compliance.DataExportCompleted.v1" }

// DataExportFailed records that the bundle could not be produced.
//
// # It is recorded rather than retried forever
//
// The workflow retries on its own for as long as retrying can help. This is what
// it appends when it has stopped: a subject who asked for their data and got
// nothing must be able to see that, and a controller who owes an answer within a
// month must be able to find the requests that produced none.
//
// The reason is a SHORT MACHINE STRING, never the underlying error. An object
// store's error names a bucket, a key and an endpoint; a vault's can name a key
// id. None of that belongs in a permanent log, and none of it means anything to
// the person who asked.
type DataExportFailed struct {
	SubjectID string
	ExportID  string

	Reason   string
	FailedAt time.Time
}

func (*DataExportFailed) EventType() string { return "compliance.DataExportFailed.v1" }

// Failure reasons. Stored in the event, so they are permanent strings rather
// than an enum whose meaning depends on ordering in a Go file.
const (
	// ExportFailedUnreadable is the vault or the object store refusing to answer
	// after the workflow exhausted its retries.
	ExportFailedUnreadable = "source_unreadable"

	// ExportFailedTooManyObjects is a subject holding more objects than one
	// export is allowed to enumerate. Its own reason because the remedy is an
	// operator's, not a retry's.
	ExportFailedTooManyObjects = "too_many_objects"

	// ExportFailedRestricted is Article 18 standing in front of Article 15.
	// compliance.md §6: a restricted subject is not processed, and building an
	// export is processing.
	ExportFailedRestricted = "processing_restricted"
)

// ---------------------------------------------------------------------------
// Legal holds (compliance.md §4 step 2, §7)
// ---------------------------------------------------------------------------

// LegalHoldPlaced suspends erasure and retention purges for one subject.
//
// # A held erasure is DEFERRED, not refused
//
// compliance.md §7 is explicit: "a held subject's erasure request is deferred,
// not refused, and executes automatically when the hold lifts". That is the
// only reading that survives both obligations at once — Article 17 gives the
// person a right the controller cannot decline, and a litigation hold is a
// legal duty the controller cannot ignore. Deferring honours the first as soon
// as the second releases.
//
// It follows that placing a hold is not the end of anything. The request stays
// live, its statutory clock keeps whatever meaning it had, and LegalHoldLifted
// is what resumes it.
//
// # The OWNER, and why it is an operator
//
// §7: holds carry "a recorded justification and an owner". A hold with no owner
// is one nobody can be asked about; one placed by "the system" is one nobody
// decided. Only an operator can place one (operator.md §7 puts it beside the
// other operator writes), so the owner is an operator id — a pseudonymous
// identifier for a member of our staff.
type LegalHoldPlaced struct {
	SubjectID string

	// PlacedBy is the operator id of whoever placed it.
	//
	// Not a SubjectID: an operator's pseudonym identifies them in the operator
	// plane's own audit log, and this event lives on the TENANT's log where
	// that pseudonym means nothing. The operator id is the stable handle across
	// both.
	PlacedBy string

	// Matter is a REFERENCE, not a narrative: "litigation 2026-4711",
	// "regulator request DPA-88".
	//
	// # Why the full justification is not here
	//
	// ADR-002 keeps free text out of the event log because it is where personal
	// data hides, and a hold's justification is prose about a legal matter that
	// very often names people — the opposing party, a complainant, a
	// third party who is not the subject of this stream at all.
	//
	// The narrative IS recorded, verbatim, in operator_audit_log, which is
	// access-controlled and retained on its own schedule. This carries the
	// handle that joins the two, so "why is this subject held" is answerable
	// without the tenant's permanent log holding the answer.
	Matter string

	PlacedAt time.Time
}

func (*LegalHoldPlaced) EventType() string { return "compliance.LegalHoldPlaced.v1" }

// LegalHoldLifted releases a subject, and resumes any deferred erasure.
//
// The resumption is automatic (§7) and is a reactor's job rather than this
// event's: lifting a hold and re-running an erasure are separate failures with
// separate retries, and coupling them would make a transient vault error look
// like a hold that did not lift.
type LegalHoldLifted struct {
	SubjectID string

	// LiftedBy is the operator who released it. A hold that lapsed on its own
	// would be a hold with a timer, and §7 gives it none — somebody decides a
	// matter is closed.
	LiftedBy string

	LiftedAt time.Time
}

func (*LegalHoldLifted) EventType() string { return "compliance.LegalHoldLifted.v1" }

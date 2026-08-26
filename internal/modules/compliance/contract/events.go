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

// ---------------------------------------------------------------------------
// Deferral (Article 12(4), compliance.md §4 step 2)
// ---------------------------------------------------------------------------

// ErasureDeferred records that a request could not be acted on yet, and that
// the person was told.
//
// # It exists because Article 12(4) requires an ANSWER, not just a delay
//
// "If the controller does not take action on the request of the data subject,
// the controller shall inform the data subject without delay and at the latest
// within one month of receipt of the request of the reasons for not taking
// action."
//
// Legal holds made deferral reachable for the first time. Before them the
// erasure either ran or failed, and a failure was a retry — so there was no
// state in which we were deliberately not acting, and nothing to answer for.
//
// This event is that answer's trigger and its evidence. The notification
// catalogue turns it into mail; the log keeps the record that the mail was owed
// and when.
//
// # It carries NO MATTER, and that is the whole difficulty of this message
//
// The hold's own event names the matter. This one must not, because this one is
// what reaches the subject — and naming the matter would tell somebody they are
// under investigation, at the moment when telling them is most damaging.
//
// What is disclosable is the GROUND: Article 17(3)(e), processing necessary for
// the establishment, exercise or defence of legal claims. That is a legal basis
// rather than a fact about their case, it is what 12(4) actually asks for, and
// it is the same sentence for everybody.
//
// The distinction that makes this lawful rather than tipping off is that it
// answers THEIR REQUEST. We are not announcing a decision we took about them;
// we are replying to something they asked for, which is an obligation they
// triggered.
type ErasureDeferred struct {
	SubjectID string

	// DeferredAt is when we first could not act. The 12(4) clock is one month
	// from the REQUEST rather than from here, so this is not the deadline — it
	// is the evidence that the answer was sent without delay once the reason
	// arose.
	DeferredAt time.Time
}

func (*ErasureDeferred) EventType() string { return "compliance.ErasureDeferred.v1" }

// ErasureResumed records that the obstacle cleared and the request is live
// again.
//
// It notifies nobody. The person was told the erasure was deferred and would
// complete automatically; what reaches them next is the erasure's own
// confirmation, which is the message that actually matters. Mail saying "we
// have resumed" followed minutes later by "we have finished" is two messages
// for one event.
//
// It is recorded because the deferral was, and a window with an opening and no
// close is one somebody has to reconstruct from timestamps.
type ErasureResumed struct {
	SubjectID string

	ResumedAt time.Time
}

func (*ErasureResumed) EventType() string { return "compliance.ErasureResumed.v1" }

// ---------------------------------------------------------------------------
// Rectification (Article 16, compliance.md §3 and §6)
// ---------------------------------------------------------------------------

// PersonalDataCorrected records that a data subject exercised Article 16.
//
// # It records the RIGHT, not the write
//
// The value itself is changed by whichever module owns the field —
// `profile.ProfileUpdated.v1` is appended by the same call, from profile's own
// stream, because compliance does not write another module's data
// (compliance.md §15). So there are two events for one request, and they say
// different things.
//
// `ProfileUpdated` says a profile changed. This says a person told us what we
// hold about them is INACCURATE and required its correction — which is a
// statutory request with Article 12(3)'s one-month clock attached and
// Article 19's duty to pass the correction on to whoever the data was disclosed
// to. A controller asked to evidence its Article 16 handling cannot answer with
// a list of settings saves, and could not tell one from the other if this event
// did not exist.
//
// # No values, and not even a before-and-after
//
// ADR-002. The fields are named; what they said is in the vault, which is the
// only place personal data may live. A "corrected from X to Y" payload is the
// most natural shape for this event and the most damaging: it would put BOTH
// versions of somebody's name permanently in the log, and the old one is
// precisely the value they have just told us is wrong about them.
//
// compliance.md §6: "a correction is a new event, and the projection reflects
// the corrected value. The historical record remains truthful: it recorded what
// we believed at the time, and when we learned otherwise." The learning is what
// this event is.
type PersonalDataCorrected struct {
	SubjectID string

	// Fields names what the subject asked to have corrected, in the request's
	// own vocabulary — `display_name`, `locale`, `timezone`.
	//
	// # Named, not diffed, and it is the ASSERTION rather than the delta
	//
	// A field appears here because the person said it was wrong, not because the
	// stored value turned out to differ. Those come apart when somebody corrects
	// a field to what it already said — a re-submitted form, a value we had
	// fixed from another source — and Article 16 was still exercised in that
	// case. Recording only the delta would lose the request, which is the thing
	// with a statutory clock on it.
	//
	// The names are the WIRE vocabulary rather than the vault's own field names
	// deliberately: this event is read by whoever answers a data subject's
	// question about their own request, and "display_name" is the word they were
	// shown. The mapping to a vault field is an implementation detail that has
	// already changed once.
	Fields []string

	// ActorID is who asked. Always the subject today — the endpoint takes no
	// subject and cannot — and carried anyway so that an operator-assisted
	// correction, when one exists, is distinguishable from a self-service one
	// without an upcaster.
	ActorID string

	CorrectedAt time.Time
}

func (*PersonalDataCorrected) EventType() string { return "compliance.PersonalDataCorrected.v1" }

// ---------------------------------------------------------------------------
// Objection (Article 21, compliance.md §3)
// ---------------------------------------------------------------------------

// ProcessingObjected records that a data subject objected to one purpose.
//
// # Why this is not ProcessingRestricted with a narrower blast radius
//
// The two rights are different in kind, and the difference is observable rather
// than doctrinal.
//
// Article 18 restriction is TOTAL and TEMPORARY. It halts everything except
// storage — transactional receipts included — while a dispute about the data
// runs, and it ends when the dispute is settled. Article 21 objection is
// PER-PURPOSE and open-ended: the account keeps working, receipts and
// verification links keep arriving, and exactly one purpose stops until the
// person withdraws the objection.
//
// They also differ in who may end them. A restriction can be lifted by either
// side once the dispute is resolved. An objection binds the controller until its
// AUTHOR releases it, which is why it is a separate record from a notification
// preference — a preference is a setting we may reasonably re-solicit, and this
// is not.
//
// If this event ever came to mean "stop everything", it would be a duplicate of
// ProcessingRestricted and should be deleted rather than kept as a synonym.
//
// # No reason field
//
// Article 21(1) requires the objection to be "on grounds relating to his or her
// particular situation", so there is an obvious place to put one. It is
// deliberately absent, for ProcessingRestricted's reason: a person's account of
// their own situation is free text about themselves, which ADR-002 keeps out of
// a permanent replicated log, and nothing here branches on it.
//
// The absence is only tenable because the controller's override is not
// implemented — see the RPC. An override needs the grounds to weigh against,
// and building one means finding somewhere other than this event to keep them.
type ProcessingObjected struct {
	SubjectID string

	// Purpose is which processing stops. One of domain.Purposes(), and a
	// PERMANENT string: it is stored, replayed, and compared against a Go
	// constant on every notification for a subject who has one.
	Purpose string

	// ActorID is who objected. The subject; carried for the reason
	// PersonalDataCorrected carries it.
	ActorID string

	ObjectedAt time.Time
}

func (*ProcessingObjected) EventType() string { return "compliance.ProcessingObjected.v1" }

// ProcessingObjectionWithdrawn records that the subject released one objection.
//
// Only the subject can produce it. That asymmetry with LegalHoldLifted — which
// an operator produces — is the whole distinction between an instruction and a
// setting: a hold is ours to place and lift, and an objection is theirs.
type ProcessingObjectionWithdrawn struct {
	SubjectID string

	Purpose string

	ActorID string

	WithdrawnAt time.Time
}

func (*ProcessingObjectionWithdrawn) EventType() string {
	return "compliance.ProcessingObjectionWithdrawn.v1"
}

package domain

import (
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// LegalHoldCategory is the stream category, and it is PERMANENT: it is half of
// every stream name, so changing it orphans every hold ever placed.
const LegalHoldCategory eventsourcing.Category = "legalhold"

// LegalHoldStreamKey is the subject's pseudonym.
//
// One stream per subject rather than one per matter, for the reason Restriction
// uses: a hold is a STATE — this subject's data is held or it is not — and the
// erasure workflow's question is "is this subject held right now", which a
// stream per matter would turn into a fold across several.
//
// The cost is that two concurrent matters over one subject share a stream, so
// the second hold is a no-op and lifting the first releases both. That is
// wrong, and it is deliberately deferred: multiple concurrent holds need a
// matter-keyed model and a "held while ANY matter stands" rule, and building
// that before a second matter exists would be building the general case for a
// problem nobody has. What makes deferring safe is that the aggregate REFUSES a
// second placement rather than silently absorbing it — see Place.
func LegalHoldStreamKey(subjectID string) string { return subjectID }

// MaxMatterLength bounds the matter reference.
//
// Short on purpose. It is a handle — "litigation 2026-4711" — and the narrative
// lives in operator_audit_log. A field long enough for prose is a field prose
// ends up in, and this one is on the tenant's permanent log where ADR-002 says
// prose must not be.
const MaxMatterLength = 120

// LegalHold is one subject's hold state (compliance.md §4 step 2, §7).
//
// # What a hold does, and what it does not
//
// It suspends erasure and retention purges. It does NOT refuse them: a held
// subject's erasure request is DEFERRED and executes automatically when the
// hold lifts (§7). That distinction is the only reading that survives both
// obligations at once — Article 17 gives a right the controller cannot decline,
// and a litigation hold is a duty it cannot ignore.
//
// It also does not touch the account. A held subject signs in, works, and is
// told nothing: a hold is a fact about what we may DELETE, not about what they
// may do, and surfacing it would tell somebody they are under investigation.
type LegalHold struct {
	eventsourcing.Base

	subjectID string
	held      bool
	matter    string
	placedBy  string
	placedAt  time.Time
}

var _ eventsourcing.Root = (*LegalHold)(nil)

// NewLegalHold returns an empty aggregate for the repository to rebuild into.
func NewLegalHold() *LegalHold { return &LegalHold{} }

// Held reports whether this subject's data is currently held.
//
// FALSE for a subject nothing was ever recorded about, which is the answer the
// erasure workflow gets for almost everybody. That is the right default here
// and it is worth saying why, because it is the opposite of this codebase's
// usual fail-closed instinct: a hold is an EXCEPTION to a statutory right, so
// defaulting to "held" would be defaulting to withholding a right nobody
// claimed.
func (h *LegalHold) Held() bool { return h.held }

// Matter is the reference the hold was placed under. Empty unless held.
func (h *LegalHold) Matter() string { return h.matter }

// PlacedBy is the operator who placed it, and PlacedAt when.
func (h *LegalHold) PlacedBy() string    { return h.placedBy }
func (h *LegalHold) PlacedAt() time.Time { return h.placedAt }

// Exists reports whether anything has ever been recorded for this subject.
func (h *LegalHold) Exists() bool { return h.subjectID != "" }

// Apply rebuilds state from the log.
func (h *LegalHold) Apply(event eventsourcing.Event) {
	switch ev := event.(type) {
	case *contract.LegalHoldPlaced:
		h.subjectID = ev.SubjectID
		h.held = true
		h.matter = ev.Matter
		h.placedBy = ev.PlacedBy
		h.placedAt = ev.PlacedAt

	case *contract.LegalHoldLifted:
		h.subjectID = ev.SubjectID
		h.held = false
		h.matter = ""
		h.placedBy = ""
		h.placedAt = time.Time{}
	}
}

// Place holds a subject's data.
//
// # A second placement is REFUSED, not absorbed
//
// The obvious idempotency — already held, record nothing, succeed — is wrong
// here, and it is wrong in a way that would only surface during a dispute.
//
// One stream per subject means one hold at a time. If a second matter's hold
// were silently absorbed, lifting the FIRST matter would release the subject
// while the second was still live — and the release would look correct to
// everybody, because there is no record that two matters ever overlapped.
//
// Refusing makes the limitation visible at the moment somebody hits it, which
// is when the decision to build matter-keyed holds should be taken. Absorbing
// it would defer the discovery to the erasure that should not have run.
func (h *LegalHold) Place(subjectID, placedBy, matter string, at time.Time) error {
	switch {
	case subjectID == "":
		return fmt.Errorf("compliance: a legal hold needs a subject")
	case placedBy == "":
		return fmt.Errorf("compliance: a legal hold needs an owner; one placed by nobody " +
			"is one nobody can be asked about (compliance.md §7)")
	case matter == "":
		return fmt.Errorf("compliance: a legal hold needs a matter reference")
	case len(matter) > MaxMatterLength:
		return fmt.Errorf("compliance: a matter reference is at most %d characters; it is a "+
			"handle, and the narrative belongs in the operator audit log", MaxMatterLength)
	case h.held:
		return fmt.Errorf("compliance: this subject is already held under %q. One hold at a "+
			"time: a second would be released by lifting the first, and nothing would "+
			"record that two matters overlapped", h.matter)
	}

	eventsourcing.Record(h, &contract.LegalHoldPlaced{
		SubjectID: subjectID,
		PlacedBy:  placedBy,
		Matter:    matter,
		PlacedAt:  at.UTC(),
	})
	return nil
}

// Lift releases a subject.
//
// Idempotent, unlike Place, and the asymmetry is the point. Lifting a hold that
// does not exist is asking for a state that already holds — the subject is not
// held — and refusing would make the safe direction the awkward one.
//
// The two directions have different costs when they are wrong. A hold placed
// twice and absorbed leaves data unprotected later; a lift that does nothing
// leaves data protected that need not be, which the next lift fixes.
func (h *LegalHold) Lift(subjectID, liftedBy string, at time.Time) error {
	switch {
	case subjectID == "":
		return fmt.Errorf("compliance: lifting a hold needs a subject")
	case liftedBy == "":
		return fmt.Errorf("compliance: lifting a hold needs an owner; somebody decides a " +
			"matter is closed, and a hold that lapsed on its own would be a hold with a " +
			"timer, which compliance.md §7 gives it none")
	}
	if !h.held {
		return nil
	}

	eventsourcing.Record(h, &contract.LegalHoldLifted{
		SubjectID: subjectID,
		LiftedBy:  liftedBy,
		LiftedAt:  at.UTC(),
	})
	return nil
}

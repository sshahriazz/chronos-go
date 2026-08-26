// Package app is compliance's use cases.
//
// It orchestrates erasure and owns none of the data being erased. Every module
// that holds personal data erases its own — compliance decides WHEN, destroys
// the key that makes all of it unreadable, and records that it happened.
//
// The import contract makes that separation structural rather than a convention:
// `modules/compliance/**` may import another module's `contract` package and
// nothing else (CONVENTIONS §2), so the work each module does is reached through
// a port satisfied at the composition root.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
)

// Vault destroys the subject key. This is the irreversible step.
type Vault interface {
	// Erase destroys the wrapped data key. Idempotent: a subject already erased
	// matches nothing and succeeds.
	Erase(ctx context.Context, subjectID string) error
}

// AccountErasure is the identity half — sessions, identifier reservations, and
// the account's own terminal event.
//
// Declared here and satisfied by identity's own use case, because only identity
// knows what an account holds.
type AccountErasure interface {
	Erase(ctx context.Context, subjectID string) error
}

// Confirmation tells the person what happened, and what was retained.
//
// It runs BEFORE the key is destroyed and that ordering is the whole reason this
// is a separate port rather than a notification-catalogue entry. NOTIFICATIONS
// §9 requires the confirmation before the address is purged, and after the
// destroy there is no address left to resolve — the vault answers a tombstone,
// and a send to an erased subject is skipped rather than failed.
//
// `retained` is the RESOLVED exemption set for this subject, not a fixed list.
// It used to be `[]string` of hand-written sentences, and the change of type is
// the point: a class, a period and an ARTICLE travel separately, so the
// confirmation can say what was kept and on what legal basis rather than
// carrying a sentence that happens to mention both.
type Confirmation interface {
	SendErasureComplete(
		ctx context.Context, subjectID string, retained []domain.RetentionPolicy,
	) error
}

// RetentionExemptions resolves what an erasure will leave behind, per subject.
//
// A port rather than a direct call to *Exemptions so a test can assert what
// happens when the answer is empty — which is the case the erasure refuses, and
// which no real resolver can produce today because two of the classes are
// unconditional.
type RetentionExemptions interface {
	For(ctx context.Context, subjectID string) []domain.RetentionPolicy
}

// ObjectErasure deletes the subject's stored objects.
//
// A separate port from the vault because the two destroy different things and
// only one of them is a key. Destroying the subject key makes every VAULT field
// unreadable at once; an object in SeaweedFS is outside the vault entirely, so
// no key destruction touches it.
type ObjectErasure interface {
	ErasePrefixes(ctx context.Context, subjectID string) (int, error)
}

// Erasure executes a due erasure request.
type Erasure struct {
	vault      Vault
	accounts   AccountErasure
	objects    ObjectErasure
	confirm    Confirmation
	holds      LegalHolds
	deferrals  Deferrals
	exemptions RetentionExemptions
	log        *slog.Logger
	now        func() time.Time
}

// Deferrals records that a request is waiting, and that the person was told.
//
// # Why the erasure writes it rather than the workflow
//
// The workflow re-runs its execute step for as long as a hold stands. Every
// attempt reaches this code, so this is where "have we already answered them"
// is asked — and asking it here means the answer survives a workflow being
// restarted from scratch, which a variable in workflow state would not.
type Deferrals interface {
	// Defer records the wait ONCE and returns whether it recorded anything.
	//
	// The bool is what stops a caller logging a deferral on every attempt for
	// weeks; the aggregate is what makes the second call free.
	Defer(ctx context.Context, subjectID string, at time.Time) (recorded bool, err error)

	// Resume clears it. Idempotent, and the COMMON path: every erasure of an
	// unheld subject passes through here, so it must be free.
	Resume(ctx context.Context, subjectID string, at time.Time) error
}

// LegalHolds answers compliance.md §4 step 2: "check LegalHold → held ⇒ defer
// and explain".
//
// # It is REQUIRED, not optional, and that is a deliberate reversal
//
// Until holds existed, this check could not be written — nothing could place
// one, so a check against them could only ever pass. That is the shape a
// vacuous test takes, and the worklist named it as blocked rather than pretend
// otherwise.
//
// Now that holds exist, the opposite failure is the live one: an erasure path
// constructed WITHOUT a hold checker would destroy a key that a court order
// says must be preserved, and it would do so silently, because every other step
// would succeed. So the constructor refuses a nil rather than treating the
// check as an enhancement.
type LegalHolds interface {
	// Held reports whether this subject's data is currently held, and under
	// which matter.
	//
	// An ERROR is not "not held". The caller must treat a failure to answer as
	// a reason not to proceed — see Execute, where it defers.
	Held(ctx context.Context, subjectID string) (matter string, held bool, err error)
}

// ErasureDeps is what Erasure needs.
type ErasureDeps struct {
	Vault      Vault
	Accounts   AccountErasure
	Objects    ObjectErasure
	Confirm    Confirmation
	Log        *slog.Logger
	Holds      LegalHolds
	Deferrals  Deferrals
	Exemptions RetentionExemptions
	Now        func() time.Time
}

func NewErasure(d ErasureDeps) (*Erasure, error) {
	switch {
	case d.Vault == nil:
		return nil, fmt.Errorf("compliance: a vault is required; destroying the subject key " +
			"is the erasure, and without it every other step is bookkeeping over data that " +
			"is still readable")
	case d.Accounts == nil:
		return nil, fmt.Errorf("compliance: an account eraser is required; without it the " +
			"key is destroyed while the account's sessions keep authenticating")
	case d.Objects == nil:
		return nil, fmt.Errorf("compliance: an object eraser is required; destroying the " +
			"subject key makes every VAULT field unreadable and does nothing at all to an " +
			"avatar, which is a photograph of the person sitting in an object store")
	case d.Confirm == nil:
		return nil, fmt.Errorf("compliance: a confirmation sender is required; it is the " +
			"one notification that cannot be sent afterwards, because afterwards there is " +
			"no address to send it to")
	case d.Holds == nil:
		return nil, fmt.Errorf("compliance: a legal-hold checker is required; compliance.md " +
			"§4 step 2 gates the erasure on it, and an eraser constructed without one " +
			"destroys a key that a court order says must be preserved — silently, because " +
			"every other step succeeds")
	case d.Deferrals == nil:
		return nil, fmt.Errorf("compliance: a deferral recorder is required; Article 12(4) " +
			"obliges us to tell somebody their request is not being acted on, and without " +
			"this the erasure waits silently for as long as a matter runs")
	case d.Exemptions == nil:
		return nil, fmt.Errorf("compliance: a retention-exemption resolver is required; " +
			"compliance.md §4 step 3 is 'resolve retention exemptions', and §7 requires " +
			"the confirmation to say what survives and on what legal basis. An eraser " +
			"without one would send a confirmation implying total deletion while tax " +
			"records are retained under Article 17(3)(b)")
	case d.Now == nil:
		return nil, fmt.Errorf("compliance: a clock is required")
	}
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	return &Erasure{
		vault: d.Vault, accounts: d.Accounts, objects: d.Objects,
		confirm: d.Confirm, holds: d.Holds, deferrals: d.Deferrals,
		exemptions: d.Exemptions, log: log, now: d.Now,
	}, nil
}

// ErrHeld means a legal hold stands over this subject (compliance.md §7).
//
// # It is DEFERRED, not refused, and the caller is what makes that true
//
// §7: "a held subject's erasure request is deferred, not refused, and executes
// automatically when the hold lifts". This error is how Execute says so; the
// deferral itself belongs to the workflow, which does not consume the request.
//
// It is a distinguishable sentinel precisely so that the workflow can tell it
// apart from a failure. A hold retried on a backoff would hammer the store for
// however long a matter runs; a hold that ENDED the request would refuse a
// statutory right. Neither is what §7 asks for, and both are what an
// indistinguishable error produces.
var ErrHeld = errors.New("compliance: a legal hold stands over this subject")

// Execute erases one subject.
//
// # The order is the design, and step 2 is the point of no return
//
// compliance.md §4:
//
//  1. confirm to the person       ← LAST moment their address is readable
//  2. DESTROY the subject key     ← irreversible
//  3. the account's own cleanup   ← sessions, identifiers, the terminal event
//
// The published sequence puts the confirmation at the END, and it cannot go
// there: the mail is rendered from an address the vault resolves, and step 2
// makes that impossible. So it moves to the front, which is the only position
// that satisfies "before the address is purged".
//
// The cost of moving it is stated rather than hidden: if step 2 fails after the
// mail is sent, somebody has been told their account is erased when it is not.
// That is survivable because the caller is a Temporal workflow and step 2 is
// idempotent — it retries until it succeeds — whereas the reverse ordering has
// no recovery at all. A mail that can never be sent is not retryable by anyone.
//
// # Why the account cleanup comes AFTER the destroy
//
// It appends `UserErased`, which asserts that the key is gone. Running it first
// would record that fact before it was true, and a failure in between leaves a
// log claiming an account is unreadable while every address still resolves.
func (e *Erasure) Execute(ctx context.Context, subjectID string) error {
	if subjectID == "" {
		return fmt.Errorf("compliance: an erasure needs a subject")
	}

	// STEP 2, and it comes before the confirmation as well as before the
	// destroy.
	//
	// compliance.md §4 puts the hold check second, ahead of everything
	// irreversible. It has to be ahead of the CONFIRMATION too, which the
	// published order does not say because the published order has the
	// confirmation last — mailing "your data has been erased" to somebody whose
	// erasure is deferred would be a false statement about a legal obligation,
	// and it is the one message here that cannot be retracted.
	matter, held, err := e.holds.Held(ctx, subjectID)
	switch {
	case err != nil:
		// A failure to ANSWER is not "not held". Proceeding would destroy a key
		// on the assumption that no hold exists, which is the assumption the
		// check was added to stop anybody making.
		return fmt.Errorf("compliance: checking legal holds for %s: %w", subjectID, err)
	case held:
		// # Article 12(4), and it is recorded BEFORE the sentinel is returned
		//
		// "If the controller does not take action on the request of the data
		// subject, the controller shall inform the data subject without delay
		// and at the latest within one month of the reasons for not taking
		// action."
		//
		// Recording the deferral is what triggers that answer — the
		// notification catalogue turns ErasureDeferred into mail — and it is
		// what keeps the evidence that the answer was owed and when.
		//
		// It happens on the FIRST attempt only. The workflow re-runs this step
		// for as long as the hold stands, and a person told weekly that their
		// erasure is still deferred is being harassed by a compliance
		// obligation.
		//
		// The MATTER does not go into it. That is the whole difficulty of this
		// message: the hold's own event names the matter, and this one is what
		// reaches the subject, so naming it would tell somebody they are under
		// investigation. What is disclosable is the GROUND — Article 17(3)(e) —
		// which is a legal basis rather than a fact about their case.
		recorded, deferErr := e.deferrals.Defer(ctx, subjectID, e.now())
		if deferErr != nil {
			// FAILS rather than returning ErrHeld, so the workflow RETRIES
			// instead of settling into its long wait. Settling would leave the
			// person unanswered for the length of a matter, which is the
			// obligation this branch exists to meet.
			return fmt.Errorf("compliance: recording the deferral of %s: %w", subjectID, deferErr)
		}
		if recorded {
			e.log.WarnContext(ctx, "an erasure was DEFERRED by a legal hold",
				"subject_id", subjectID, "matter", matter)
		}
		return fmt.Errorf("%w: matter %q", ErrHeld, matter)
	}

	// NOT held. Clear any deferral that stood, so the window has a close.
	//
	// This is the common path — every erasure of an unheld subject reaches it —
	// so the aggregate makes it free: nothing is recorded unless a deferral was
	// actually open.
	//
	// A failure here does NOT stop the erasure. The obstacle is gone, the
	// person has been told it would complete automatically, and refusing to
	// proceed because a bookkeeping append failed would hold their data longer
	// for no one's benefit. It is reported instead.
	if err := e.deferrals.Resume(ctx, subjectID, e.now()); err != nil {
		e.log.ErrorContext(ctx, "an erasure resumed and the deferral could not be closed",
			"subject_id", subjectID, "error", err)
	}

	// STEP 3 — "resolve retention exemptions" (compliance.md §4).
	//
	// It happens HERE, one line before the confirmation, and not earlier: the
	// resolved set exists only to be stated, so resolving it before the hold
	// check would ask billing a question about somebody whose erasure is not
	// going to run.
	//
	// It cannot fail. Every question this resolver cannot answer resolves
	// towards naming the class, because implying total deletion when tax records
	// survive is the misleading statement §7 names.
	retained := e.exemptions.For(ctx, subjectID)
	if len(retained) == 0 {
		// REFUSED. Two exemptions are unconditional — the event log and the
		// operator audit trail apply to everybody who ever used this system — so
		// an empty set is not a subject with unusually little data. It is a
		// resolver that is not doing its job, and sending the confirmation
		// anyway would tell somebody everything about them is gone.
		//
		// The confirmation sender refuses an empty list too. This is the second
		// of the two, deliberately: that one protects the message, and this one
		// stops the erasure before its irreversible step on the same evidence.
		return fmt.Errorf("compliance: no retention exemptions resolved for %s; the event "+
			"log and the operator audit trail survive every erasure, so an empty set is a "+
			"broken resolver rather than a subject with nothing retained", subjectID)
	}

	if err := e.confirm.SendErasureComplete(ctx, subjectID, retained); err != nil {
		// FAILS THE WHOLE ERASURE rather than proceeding without it. The
		// alternative is an erasure nobody was told about, which is both a
		// process failure under Article 12 and the one part of this that cannot
		// be repaired afterwards.
		return fmt.Errorf("compliance: confirming the erasure to %s: %w", subjectID, err)
	}

	if err := e.vault.Erase(ctx, subjectID); err != nil {
		return fmt.Errorf("compliance: destroying the subject key for %s: %w", subjectID, err)
	}

	// OBJECTS, and they are the reason a key destruction is not the whole story.
	// compliance.md §4 step 4 traverses "streams, rows, objects": the first two
	// are covered by the key that just went, and the third is not — an avatar
	// lives in SeaweedFS, outside the vault, and stays servable by a signed URL
	// until something deletes it.
	//
	// AFTER the destroy rather than before, so the irreversible step is not
	// gated on a bucket being reachable. A failure here leaves objects behind
	// under a key-destroyed subject, which the workflow retries — and retrying
	// is safe because deleting an object already gone is not an error.
	if _, err := e.objects.ErasePrefixes(ctx, subjectID); err != nil {
		return fmt.Errorf("compliance: erasing the objects of %s: %w", subjectID, err)
	}

	if err := e.accounts.Erase(ctx, subjectID); err != nil {
		return fmt.Errorf("compliance: erasing the account of %s: %w", subjectID, err)
	}
	return nil
}

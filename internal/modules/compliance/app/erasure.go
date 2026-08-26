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
	"time"
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
type Confirmation interface {
	SendErasureComplete(ctx context.Context, subjectID string, retained []string) error
}

// Retained is what survives an erasure, and why.
//
// Stated to the person rather than assumed, because a confirmation implying
// total deletion when tax records survive is a misleading statement about
// processing (compliance.md §7, NOTIFICATIONS §9).
//
// It is a fixed list rather than a computed one, and that is honest for now:
// nothing in this build can yet ask billing "does this subject appear on an
// invoice". Naming the categories unconditionally is over-inclusive, which is
// the safe direction — telling somebody their invoices may be retained when
// they have none is a smaller wrong than the reverse.
var Retained = []string{
	"invoices and tax records, where a statutory retention period applies " +
		"(Article 17(3)(b))",
	"operator audit entries, which keep only the pseudonym — the key that could " +
		"resolve it to you is destroyed",
	"the event log, which is pseudonymised by that same key destruction rather " +
		"than rewritten",
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
	vault    Vault
	accounts AccountErasure
	objects  ObjectErasure
	confirm  Confirmation
	holds    LegalHolds
	now      func() time.Time
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
	Vault    Vault
	Accounts AccountErasure
	Objects  ObjectErasure
	Confirm  Confirmation
	Holds    LegalHolds
	Now      func() time.Time
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
	case d.Now == nil:
		return nil, fmt.Errorf("compliance: a clock is required")
	}
	return &Erasure{
		vault: d.Vault, accounts: d.Accounts, objects: d.Objects,
		confirm: d.Confirm, holds: d.Holds, now: d.Now,
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
		// Deferred. The workflow catches this sentinel and waits for
		// LegalHoldLifted rather than retrying or failing the request — see
		// ErrHeld for why the distinction has to be visible in the type.
		return fmt.Errorf("%w: matter %q", ErrHeld, matter)
	}

	if err := e.confirm.SendErasureComplete(ctx, subjectID, Retained); err != nil {
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

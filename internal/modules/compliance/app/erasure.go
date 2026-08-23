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

// Erasure executes a due erasure request.
type Erasure struct {
	vault    Vault
	accounts AccountErasure
	confirm  Confirmation
	now      func() time.Time
}

// ErasureDeps is what Erasure needs.
type ErasureDeps struct {
	Vault    Vault
	Accounts AccountErasure
	Confirm  Confirmation
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
	case d.Confirm == nil:
		return nil, fmt.Errorf("compliance: a confirmation sender is required; it is the " +
			"one notification that cannot be sent afterwards, because afterwards there is " +
			"no address to send it to")
	case d.Now == nil:
		return nil, fmt.Errorf("compliance: a clock is required")
	}
	return &Erasure{vault: d.Vault, accounts: d.Accounts, confirm: d.Confirm, now: d.Now}, nil
}

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

	if err := e.accounts.Erase(ctx, subjectID); err != nil {
		return fmt.Errorf("compliance: erasing the account of %s: %w", subjectID, err)
	}
	return nil
}

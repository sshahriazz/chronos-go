package piivault

import (
	"context"
	"errors"
	"fmt"

	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

// AddressBook moves a subject's addresses between the vault's slots.
//
// # It exists so that identity never sees an address
//
// `identity` works in blind indexes and pseudonyms: its port for the vault is
// write-only on purpose, because a port that could read an address is a port
// through which an address reaches a log line, an error message or an event
// (ADR-002). An email change nevertheless has to MOVE addresses — the pending
// one becomes primary, the primary becomes the previous, a revert puts them
// back — and each of those needs the current value.
//
// Doing the move here is what keeps both properties. The use case names the
// transition; this is the only code that sees what is being moved.
//
// # Every method is idempotent
//
// Each is called from a handler whose append may be retried, and the aggregate
// has already decided whether the transition is legal. Promoting with nothing
// pending, or restoring with no previous address, changes nothing and returns
// no error — failing would turn a retry the aggregate correctly treats as a
// no-op into a permanent error.
type AddressBook struct{ vault pii.Vault }

var _ app.SubjectAddresses = (*AddressBook)(nil)

// NewAddressBook builds one.
func NewAddressBook(v pii.Vault) (*AddressBook, error) {
	if v == nil {
		return nil, errors.New("piivault: an address book needs a vault")
	}
	return &AddressBook{vault: v}, nil
}

// StagePending records the address an email change is claiming.
func (a *AddressBook) StagePending(ctx context.Context, id pii.SubjectID, address string) error {
	if address == "" {
		return errors.New("piivault: staging an empty pending address would leave the " +
			"change with nowhere to mail its verification link")
	}
	return a.put(ctx, id, map[pii.Field]string{pii.FieldPendingEmail: address})
}

// PromotePending makes the pending address primary and the primary previous.
func (a *AddressBook) PromotePending(ctx context.Context, id pii.SubjectID) error {
	profile, err := a.profile(ctx, id)
	if err != nil {
		return err
	}
	pending := profile.Get(pii.FieldPendingEmail)
	if pending == "" {
		// Already promoted, or never staged. Idempotent by the doc above: this is
		// what a retried append looks like from here.
		return nil
	}
	if err := a.put(ctx, id, map[pii.Field]string{
		pii.FieldEmail: pending,
		// The address being left, kept so the revert has something to restore.
		pii.FieldPreviousEmail: profile.Get(pii.FieldEmail),
	}); err != nil {
		return err
	}
	// FORGOTTEN, not written empty: an empty value is refused by pii.Validate,
	// and deliberately — a field reading back as "" would be indistinguishable
	// from one nobody ever set, and the notification path depends on telling
	// those apart.
	//
	// AFTER the write above, so a failure between the two leaves the account's
	// mail already going to the new address with a stale pending value beside
	// it. The reverse order would leave the pending address gone and the primary
	// unmoved, and the retry would then find nothing to promote.
	return a.forget(ctx, id, pii.FieldPendingEmail)
}

// DiscardPending forgets a claimed address that was never proven.
func (a *AddressBook) DiscardPending(ctx context.Context, id pii.SubjectID) error {
	return a.forget(ctx, id, pii.FieldPendingEmail)
}

// RestorePrevious undoes a completed change.
func (a *AddressBook) RestorePrevious(ctx context.Context, id pii.SubjectID) error {
	profile, err := a.profile(ctx, id)
	if err != nil {
		return err
	}
	previous := profile.Get(pii.FieldPreviousEmail)
	if previous == "" {
		return nil
	}
	if err := a.put(ctx, id, map[pii.Field]string{pii.FieldEmail: previous}); err != nil {
		return err
	}
	// The window is SPENT once the revert lands, so the address that was reverted
	// away from is not kept as the new "previous". Keeping it would offer a
	// revert of the revert, and the two addresses could then be swapped back and
	// forth from whichever mailbox answered last.
	for _, field := range []pii.Field{pii.FieldPreviousEmail, pii.FieldPendingEmail} {
		if err := a.forget(ctx, id, field); err != nil {
			return err
		}
	}
	return nil
}

func (a *AddressBook) profile(ctx context.Context, id pii.SubjectID) (pii.Profile, error) {
	profile, err := a.vault.Profile(ctx, id)
	switch {
	case errors.Is(err, pii.ErrErased), errors.Is(err, pii.ErrNoSubject):
		// Nothing to move, and nothing recoverable by retrying. An erased subject
		// has no addresses by construction and an absent one never had any; both
		// are correctly a no-op rather than an error that would park the append.
		return pii.Profile{}, nil
	case err != nil:
		return pii.Profile{}, fmt.Errorf("piivault: reading addresses for %s: %w", id, err)
	}
	return profile, nil
}

func (a *AddressBook) put(ctx context.Context, id pii.SubjectID, values map[pii.Field]string) error {
	if err := a.vault.PutAll(ctx, id, values); err != nil {
		return fmt.Errorf("piivault: moving addresses for %s: %w", id, err)
	}
	return nil
}

func (a *AddressBook) forget(ctx context.Context, id pii.SubjectID, field pii.Field) error {
	if err := a.vault.Forget(ctx, id, field); err != nil {
		return fmt.Errorf("piivault: forgetting %s for %s: %w", field, id, err)
	}
	return nil
}

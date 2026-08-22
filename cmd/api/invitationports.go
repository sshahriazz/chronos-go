package main

import (
	"context"
	"errors"

	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	identityentitlement "github.com/chronos/chronos-go/internal/modules/entitlement/app"
	identityapp "github.com/chronos/chronos-go/internal/modules/identity/app"
	identitycontract "github.com/chronos/chronos-go/internal/modules/identity/contract"
	workspaceapp "github.com/chronos/chronos-go/internal/modules/workspace/app"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/pii"
	"github.com/chronos/chronos-go/internal/server/interceptor"
)

// This file is where workspace's invitation ports meet identity's and the
// vault's implementations.
//
// It lives in cmd/api and nowhere else on purpose. `modules/A` may import
// `modules/B/contract` and nothing more (CONVENTIONS §2), so workspace declares
// what it needs as an interface and this composition root — which may import
// every module — is the only place allowed to satisfy it with identity's
// adapter. A shortcut in either module would be the exact coupling the contract
// exists to prevent.

// accountDirectory answers "is this address already somebody's?".
//
// A READ, and only a read. CONVENTIONS §2 permits cross-module queries and
// forbids cross-module commands, and the shape enforces it: there is nothing
// here that could change an identity.
type accountDirectory struct {
	accounts interface {
		AccountByEmailIndex(ctx context.Context, index identitycontract.EmailIndex) (identityapp.Account, error)
	}
	reads interface {
		Account(ctx context.Context, subjectID string) (identityapp.AccountView, error)
	}
}

var _ workspaceapp.Directory = (*accountDirectory)(nil)

// SubjectFor returns the pseudonym claiming an index.
//
// "Nobody claims it" is a NORMAL answer here, unlike everywhere else this
// lookup is used. On identity's own paths a miss must be indistinguishable from
// a wrong password, because the caller is unauthenticated and the question is an
// enumeration oracle. Here the caller is an authenticated workspace admin who
// typed the address themselves, and the answer they get back — an invitation was
// created — is identical either way: the response carries no token, no address,
// and nothing that says whether the person already had an account.
func (d *accountDirectory) SubjectFor(
	ctx context.Context, index identitycontract.EmailIndex,
) (string, bool, error) {
	account, err := d.accounts.AccountByEmailIndex(ctx, index)
	switch {
	case errors.Is(err, identityapp.ErrNoSuchAccount):
		return "", false, nil
	case err != nil:
		return "", false, err
	}
	return account.SubjectID, true, nil
}

// vaultAddresses records an invitee's address under their pseudonym.
//
// Narrowed to the one field, because the only thing this flow legitimately does
// is write the address it is about to send to. A use case holding the whole
// vault could read any field of any subject.
type vaultAddresses struct {
	vault interface {
		Put(ctx context.Context, id pii.SubjectID, field pii.Field, value string) error
	}
}

var _ workspaceapp.Addresses = (*vaultAddresses)(nil)

func (a *vaultAddresses) PutEmail(ctx context.Context, subjectID, email string) error {
	return a.vault.Put(ctx, pii.SubjectID(subjectID), pii.FieldEmail, email)
}

// ulidSubjects mints a pseudonym for an invitee with no account.
//
// The id is a `subj_` ULID like any other, and it is NOT an account: nothing
// registers, nothing can authenticate as it, and it exists only to hang the
// vault entry holding the invitee's address off. When that person does register,
// identity mints its own — and the two are reconciled by
// InvitationAccepted.AcceptedBy rather than by pretending one was the other.
type ulidSubjects struct{ clock clock.Clock }

var _ workspaceapp.SubjectMinter = (*ulidSubjects)(nil)

func (s *ulidSubjects) NewSubject() string {
	return ids.New[ids.Subject](s.clock.Now(), ids.Entropy()).String()
}

// IsAccount reports whether a pseudonym names a real account.
//
// Deliberately NOT a lookup of the address or its index. identity drops the
// blind index at this exact boundary because it is a re-identification handle,
// and acceptance does not need one — see the port's own comment.
//
// A minted invitation pseudonym lands in the false branch, which is not an
// error: it names a vault entry rather than an account, so there is nothing for
// identity to know about it.
func (d *accountDirectory) IsAccount(ctx context.Context, subjectID string) (bool, error) {
	_, err := d.reads.Account(ctx, subjectID)
	switch {
	case errors.Is(err, identityapp.ErrNoSuchSubject):
		return false, nil
	case err != nil:
		return false, err
	}
	return true, nil
}

// seatReserver translates entitlement's already-held signal into workspace's.
//
// Both modules declare the same value because neither may import the other's app
// package (CONVENTIONS §2), and this is the one place that knows both names. It
// is not ceremony: without the translation workspace's errors.As never matches,
// the already-held case falls through as a plain error, and a person who already
// holds a seat cannot be added to a second workspace at all.
type seatReserver struct {
	inner interface {
		ReserveFor(ctx context.Context, orgID, limitKey, subjectRef string) (string, error)
		Commit(ctx context.Context, reservationID string) error
		Release(ctx context.Context, reservationID string) error
		ReleaseFor(ctx context.Context, orgID, limitKey, subjectRef string) error
	}
}

var _ workspaceapp.Reserver = (*seatReserver)(nil)

func (r *seatReserver) ReserveFor(
	ctx context.Context, orgID, limitKey, subjectRef string,
) (string, error) {
	id, err := r.inner.ReserveFor(ctx, orgID, limitKey, subjectRef)
	var held identityentitlement.SeatAlreadyHeld
	if errors.As(err, &held) {
		return id, workspaceapp.SeatAlreadyHeld{ReservationID: held.ReservationID}
	}
	return id, err
}

func (r *seatReserver) Commit(ctx context.Context, reservationID string) error {
	return r.inner.Commit(ctx, reservationID)
}

func (r *seatReserver) Release(ctx context.Context, reservationID string) error {
	return r.inner.Release(ctx, reservationID)
}

func (r *seatReserver) ReleaseFor(ctx context.Context, orgID, limitKey, subjectRef string) error {
	return r.inner.ReleaseFor(ctx, orgID, limitKey, subjectRef)
}

// joinPermission asks gate 3 about an organization the caller did not name.
//
// The gate reads the tenant scope from the context, because "which organization
// is this request in" is precisely the question a caller must not answer for
// itself. Acceptance is the one flow where that scope cannot exist yet: the
// person clicking the link is not a member, so gate 1 had nothing to resolve.
//
// So the scope is attached HERE, from the organization the TOKEN named. That is
// safe for the reason it is unsafe everywhere else — the id did not come from
// the caller, it came from a 256-bit capability this system issued and stored and
// has just verified.
//
// GROW and not WRITE: joining adds a person to an organization, and
// organization.md §5.2's rule is that growth stops before work does. A past-due
// tenant keeps working and stops adding people.
type joinPermission struct{ gate interceptor.Subscriptions }

var _ workspaceapp.Subscriptions = (*joinPermission)(nil)

func (p *joinPermission) PermitJoin(ctx context.Context, orgID string) error {
	// UserID is left empty: the gate reads only OrgID, and the accepting account
	// is not a member of this tenant yet — naming them here would assert a
	// relationship that is exactly what the acceptance is about to create.
	scoped := db.WithTenant(ctx, db.Tenant{OrgID: orgID})
	return p.gate.Permit(scoped, optionsv1.OperationClass_OPERATION_CLASS_GROW)
}

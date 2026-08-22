package main

import (
	"context"
	"errors"

	identityapp "github.com/chronos/chronos-go/internal/modules/identity/app"
	identitycontract "github.com/chronos/chronos-go/internal/modules/identity/contract"
	workspaceapp "github.com/chronos/chronos-go/internal/modules/workspace/app"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/pii"
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

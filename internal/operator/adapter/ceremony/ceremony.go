// Package ceremony adapts the shared OIDC and WebAuthn adapters to the operator
// plane's ports.
//
// # Why the shared adapters are reused, and what is NOT shared
//
// The protocols are the same and a second implementation of either would be a
// second set of bugs. What is deliberately not shared is the CONFIGURATION: a
// different issuer, a different OAuth client, and — most importantly — a
// different WebAuthn relying party.
//
// The RP ID is the one that would be tempting to share and must not be. It is
// bound into every credential at registration, so a tenant's passkey created
// for the product's RP ID would be presentable to any relying party using that
// same ID. Giving the operator console its own means a tenant credential is not
// merely unauthorized here — it cannot be asserted at all.
package ceremony

import (
	"context"
	"fmt"

	oidcadapter "github.com/chronos/chronos-go/internal/adapter/oidc"
	waadapter "github.com/chronos/chronos-go/internal/adapter/webauthn"
	"github.com/chronos/chronos-go/internal/operator/app"
)

// IdP adapts the OIDC provider.
type IdP struct {
	provider *oidcadapter.Provider

	// hostedDomain pins a Google Workspace domain. Empty means unpinned.
	hostedDomain string
}

// NewIdP builds the adapter.
func NewIdP(p *oidcadapter.Provider, hostedDomain string) (*IdP, error) {
	if p == nil {
		return nil, fmt.Errorf("operator ceremony: the IdP adapter needs a provider")
	}
	return &IdP{provider: p, hostedDomain: hostedDomain}, nil
}

var _ app.IdentityProvider = (*IdP)(nil)

// Begin starts an authorization request.
func (i *IdP) Begin() (app.IdPCeremony, error) {
	c, err := i.provider.Begin()
	if err != nil {
		return app.IdPCeremony{}, err
	}
	return app.IdPCeremony{
		AuthorizationURL: c.AuthorizationURL,
		State:            c.State,
		Nonce:            c.Nonce,
		Verifier:         c.Verifier,
	}, nil
}

// Finish exchanges the code, verifies the ID token, and enforces the hosted
// domain.
//
// The domain check is here rather than in the use case because it is a property
// of THIS provider's claims — `hd` is Google's, and a second IdP would assert
// its tenancy differently. Putting it in the use case would make the use case
// know one provider's vocabulary.
func (i *IdP) Finish(ctx context.Context, c app.IdPCeremony, cb app.IdPCallback) (app.IdPIdentity, error) {
	identity, err := i.provider.Finish(ctx, oidcadapter.Ceremony{
		State: c.State, Nonce: c.Nonce, Verifier: c.Verifier,
	}, oidcadapter.Callback{Code: cb.Code, State: cb.State, Issuer: cb.Issuer})
	if err != nil {
		return app.IdPIdentity{}, err
	}

	if i.hostedDomain != "" {
		hd, _ := identity.Claims["hd"].(string)
		if hd != i.hostedDomain {
			// Refused before the account lookup, so a personal account at the
			// same provider never reaches the operator table at all. The error
			// says nothing about the domain we expect: this endpoint is
			// unauthenticated, and naming it would publish which Workspace runs
			// our back office.
			return app.IdPIdentity{}, fmt.Errorf(
				"operator: this identity is not from a permitted directory")
		}
	}

	return app.IdPIdentity{
		Issuer:  identity.Issuer,
		Subject: identity.Subject,
		Claims:  identity.Claims,
	}, nil
}

// Authenticator adapts the WebAuthn ceremony.
type Authenticator struct{ c *waadapter.Ceremony }

// NewAuthenticator builds the adapter.
func NewAuthenticator(c *waadapter.Ceremony) (*Authenticator, error) {
	if c == nil {
		return nil, fmt.Errorf("operator ceremony: the authenticator adapter needs a ceremony")
	}
	return &Authenticator{c: c}, nil
}

var _ app.Authenticator = (*Authenticator)(nil)

// account builds the WebAuthn user for an operator.
//
// The user HANDLE is the operator id, and the NAME is the operator id too. Both
// travel to the authenticator and are stored by it permanently — synced to a
// cloud backup, shown on a lock screen — which is the one store ADR-002 can
// never reach to erase. An operator id is a pseudonym; their work address is
// not, and putting it here would be the same mistake identity.md §5 refuses for
// a TOTP label.
//
// The cost is a lock screen that shows `opr_01ARZ…` rather than a name. On a
// back office with a handful of operators that is a readability annoyance; the
// alternative is unerasable personal data on hardware we do not control.
func account(operatorID string, existing [][]byte) waadapter.Account {
	return waadapter.Account{
		SubjectID: operatorID,
		Username:  operatorID,
		Existing:  existing,
	}
}

// BeginRegistration starts an enrolment.
func (a *Authenticator) BeginRegistration(operatorID, _ string, existing [][]byte) (app.WAChallenge, error) {
	ch, err := a.c.BeginRegistration(account(operatorID, existing))
	if err != nil {
		return app.WAChallenge{}, err
	}
	return app.WAChallenge{Options: ch.Options, State: ch.State, ExpiresAt: ch.ExpiresAt}, nil
}

// FinishRegistration verifies an enrolment.
func (a *Authenticator) FinishRegistration(
	operatorID, _ string, state, credentialJSON []byte,
) (app.WARegistration, error) {
	reg, err := a.c.FinishRegistration(account(operatorID, nil), state, credentialJSON)
	if err != nil {
		return app.WARegistration{}, err
	}
	return app.WARegistration{
		ID: reg.ID, PublicKey: reg.PublicKey, SignCount: reg.SignCount,
		AAGUID: reg.AAGUID, Transports: reg.Transports,
		UserVerified:   reg.UserVerified,
		BackupEligible: reg.BackupEligible, BackupState: reg.BackupState,
	}, nil
}

// BeginLogin starts an assertion.
//
// It always names the operator's credentials, never the discoverable path. The
// tenant plane wants usernameless login because a person arriving at a sign-in
// page has not said who they are; here the SSO step already proved it, so an
// assertion that let the authenticator offer ANY credential it holds would
// discard a fact we have — and would accept a credential belonging to a
// different operator, which the ownership check would then have to catch.
func (a *Authenticator) BeginLogin(operatorID string, stored []app.StoredCredential) (app.WAChallenge, error) {
	ch, err := a.c.BeginLogin(account(operatorID, credentialIDs(stored)), toStored(stored))
	if err != nil {
		return app.WAChallenge{}, err
	}
	return app.WAChallenge{Options: ch.Options, State: ch.State, ExpiresAt: ch.ExpiresAt}, nil
}

// FinishLogin verifies an assertion.
func (a *Authenticator) FinishLogin(
	operatorID string, stored []app.StoredCredential, state, credentialJSON []byte,
) (app.WAAssertion, error) {
	as, err := a.c.FinishLogin(account(operatorID, credentialIDs(stored)), toStored(stored), state, credentialJSON)
	if err != nil {
		return app.WAAssertion{}, err
	}
	return app.WAAssertion{
		ID: as.ID, SignCount: as.SignCount,
		UserVerified: as.UserVerified,
		// READ, not ignored. See waadapter.Assertion.CloneWarning — a caller
		// that drops this has clone detection that does nothing while every
		// test passes.
		CloneWarning: as.CloneWarning,
	}, nil
}

func toStored(in []app.StoredCredential) []waadapter.StoredCredential {
	out := make([]waadapter.StoredCredential, 0, len(in))
	for _, c := range in {
		out = append(out, waadapter.StoredCredential{
			ID: c.ID, PublicKey: c.PublicKey, SignCount: c.SignCount,
			AAGUID: c.AAGUID, Transports: c.Transports,
			BackupEligible: c.BackupEligible, BackupState: c.BackupState,
		})
	}
	return out
}

func credentialIDs(in []app.StoredCredential) [][]byte {
	out := make([][]byte, 0, len(in))
	for _, c := range in {
		out = append(out, []byte(c.ID))
	}
	return out
}

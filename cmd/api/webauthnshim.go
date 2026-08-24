package main

import (
	"github.com/chronos/chronos-go/internal/adapter/webauthn"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
)

// ceremonyShim presents the WebAuthn adapter as identity's Ceremonies port.
//
// # Why the two type sets exist at all
//
// CONVENTIONS §2: a port is declared by its CONSUMER and satisfied at the
// composition root. `identity/app` declares what it needs a ceremony to do in
// its own vocabulary, and `adapter/webauthn` speaks the library's. Neither
// imports the other, so the translation happens here — in the one place that is
// allowed to know both.
//
// It is mechanical on purpose. Anything that had to make a DECISION about a
// credential would be a decision taken outside the module that owns it; every
// method below moves fields and nothing else.
type ceremonyShim struct{ inner *webauthn.Ceremony }

var _ app.Ceremonies = ceremonyShim{}

func (c ceremonyShim) BeginRegistration(
	a app.CeremonyAccount,
) (app.CeremonyChallenge, error) {
	got, err := c.inner.BeginRegistration(account(a))
	if err != nil {
		return app.CeremonyChallenge{}, err
	}
	return challenge(got), nil
}

func (c ceremonyShim) FinishRegistration(
	a app.CeremonyAccount, state, response []byte,
) (app.CeremonyCredential, error) {
	got, err := c.inner.FinishRegistration(account(a), state, response)
	if err != nil {
		return app.CeremonyCredential{}, err
	}
	return app.CeremonyCredential{
		ID:             got.ID,
		PublicKey:      got.PublicKey,
		SignCount:      got.SignCount,
		AAGUID:         got.AAGUID,
		Transports:     got.Transports,
		UserVerified:   got.UserVerified,
		BackupEligible: got.BackupEligible,
		BackupState:    got.BackupState,
	}, nil
}

func (c ceremonyShim) BeginLogin(
	a app.CeremonyAccount, stored []app.CeremonyStored,
) (app.CeremonyChallenge, error) {
	got, err := c.inner.BeginLogin(account(a), storedCredentials(stored))
	if err != nil {
		return app.CeremonyChallenge{}, err
	}
	return challenge(got), nil
}

func (c ceremonyShim) FinishLogin(
	a app.CeremonyAccount, stored []app.CeremonyStored, state, response []byte,
) (app.CeremonyAssertion, error) {
	got, err := c.inner.FinishLogin(account(a), storedCredentials(stored), state, response)
	if err != nil {
		return app.CeremonyAssertion{}, err
	}
	return app.CeremonyAssertion{
		ID:           got.ID,
		SignCount:    got.SignCount,
		UserVerified: got.UserVerified,
		// CARRIED, and this one line is the whole reason the adapter returns a
		// struct rather than an id: the library sets this and returns NO error, so
		// a shim that dropped it would leave clone detection silently doing
		// nothing while every test still passed.
		CloneWarning: got.CloneWarning,
	}, nil
}

func account(a app.CeremonyAccount) webauthn.Account {
	return webauthn.Account{
		SubjectID: a.SubjectID,
		Username:  a.Username,
		Existing:  a.Existing,
	}
}

func challenge(c webauthn.Challenge) app.CeremonyChallenge {
	return app.CeremonyChallenge{
		Options:   c.Options,
		State:     c.State,
		ExpiresAt: c.ExpiresAt,
	}
}

func storedCredentials(in []app.CeremonyStored) []webauthn.StoredCredential {
	out := make([]webauthn.StoredCredential, 0, len(in))
	for _, s := range in {
		out = append(out, webauthn.StoredCredential{
			ID:             s.ID,
			PublicKey:      s.PublicKey,
			SignCount:      s.SignCount,
			AAGUID:         s.AAGUID,
			Transports:     s.Transports,
			UserVerified:   s.UserVerified,
			BackupEligible: s.BackupEligible,
			BackupState:    s.BackupState,
		})
	}
	return out
}

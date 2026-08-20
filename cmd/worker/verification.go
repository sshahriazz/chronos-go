package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	identitypg "github.com/chronos/chronos-go/internal/modules/identity/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/token"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	identityreactor "github.com/chronos/chronos-go/internal/modules/identity/reactor"
	"github.com/chronos/chronos-go/internal/platform/clock"
)

// newVerificationIssuer builds the thing that mints verification links, or
// reports why it could not be.
//
// Constructed in the composition root and held on dependencies, like the
// reservation sweep and retention above it, so that its absence is a logged,
// testable fact rather than a reactor quietly missing from a list. A worker
// without it consumes no EmailVerificationRequested at all: every registration
// then completes, claims its address, and mails nobody.
func newVerificationIssuer(d *dependencies) (*app.VerificationIssuer, error) {
	if d.pool == nil {
		return nil, errors.New("no read model: token digests live in identity_token, " +
			"so nothing can record the digest an emailed link is checked against")
	}
	guards, err := identitypg.NewGuards(pgadapter.New(d.pool))
	if err != nil {
		return nil, err
	}

	// One minter, held rather than built per call: token.New carries the entropy
	// source, and a per-call constructor makes "what mints our secrets" a question
	// with more than one answer.
	minter := token.New()
	return app.NewVerificationIssuer(app.VerificationIssuerDeps{
		Clock:  clock.System{},
		Tokens: guards,
		// A function rather than the *Minter, because adapter/token imports app,
		// so app cannot name the adapter's return type. The same shape cmd/api
		// passes into the registration use case.
		Minter: func(p app.TokenPurpose, now time.Time) (app.MintedToken, error) {
			t, err := minter.Mint(p, now)
			if err != nil {
				return app.MintedToken{}, err
			}
			return app.MintedToken{
				Plaintext: t.Plaintext, Digest: t.Digest, ExpiresAt: t.ExpiresAt,
			}, nil
		},
	})
}

// issuerAdapter presents identity's use case as the reactor's port.
//
// Two structurally identical types rather than one shared one, for the reason
// sweepAdapter gives: the alternative is identity/reactor importing identity/app,
// and a reactor that can reach into a use case is a reactor that will eventually
// make a decision for it. The conversion is mechanical and total.
type issuerAdapter struct{ issuer *app.VerificationIssuer }

var _ identityreactor.Issuer = issuerAdapter{}

func (a issuerAdapter) IssueVerification(
	ctx context.Context, subjectID string,
) (identityreactor.Verification, error) {
	v, err := a.issuer.IssueVerification(ctx, subjectID)
	if err != nil {
		return identityreactor.Verification{}, err
	}
	return identityreactor.Verification{
		Plaintext:   v.Plaintext,
		ExpiresAt:   v.ExpiresAt,
		TTL:         v.TTL,
		Fingerprint: v.Fingerprint,
	}, nil
}

// newVerificationMail builds the verification-mail reactor.
//
// It decodes with identity's OWN codec rather than this binary's notification
// codec. The two answer different questions: newCodec is the catalogue-driven
// reactor's, and every type in it must have a notification decision recorded
// against it or events_test.go fails the build. This reactor is not
// catalogue-driven — it mints a credential, which no catalogue Data function
// could do — so registering identity's whole event set there would demand a
// notification decision for thirty events that have nothing to do with this one.
func newVerificationMail(d *dependencies) (*identityreactor.VerificationMail, error) {
	if d.verification == nil {
		return nil, errors.New("no verification issuer was constructed")
	}
	codec, _ := newIdentityCodec()

	var opts []identityreactor.Option
	if d.temporal != nil {
		// Durable delivery, for the reason ADR-017 gives: an SMTP outage becomes
		// an hour of workflow retries that survive this process restarting, rather
		// than a parked backlog of people who registered and were never told how
		// to finish. Conditional because the client is nil with TEMPORAL_ENABLED
		// false, and that deployment must still deliver — inline, through the same
		// dispatcher.
		opts = append(opts, identityreactor.WithWorkflows(d.temporal))
	}
	r, err := identityreactor.NewVerificationMail(
		issuerAdapter{issuer: d.verification}, codec, d.Notify(), opts...)
	if err != nil {
		return nil, fmt.Errorf("verification mail: %w", err)
	}
	return r, nil
}

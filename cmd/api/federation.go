package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/chronos/chronos-go/internal/adapter/oidc"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	identitypg "github.com/chronos/chronos-go/internal/modules/identity/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/config"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// buildFederation constructs identity.md §7's flow, or nothing.
//
// # Nothing is a supported outcome
//
// Federation needs client credentials that cannot be defaulted, so a deployment
// configuring none is normal — not degraded. It returns a nil INTERFACE rather
// than a typed nil pointer, which is the distinction that broke the passkey
// wiring on its first run: a nil pointer stored in an interface makes that
// interface non-nil, so the handler's guard never fires and every RPC panics on
// a nil receiver instead of refusing.
func (d *dependencies) buildFederation(
	ctx context.Context, cfg *config.Config, log *slog.Logger,
	users app.AggregateLoader[*domain.User],
	readModel app.UserDirectory,
	accounts app.AccountDirectory,
	index app.EmailIndexer,
	revocations app.SessionRevoker,
) (app.FederationFlowShim, error) {
	configs := map[string]oidc.Config{}
	for _, name := range cfg.Identity.FederationProviders {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "":
			continue
		case "google":
			if !cfg.Identity.GoogleConfigured() {
				// Named but unconfigured is a MISTAKE, not an omission: somebody
				// asked for the button and left the credentials out, and starting
				// quietly would leave a deployment that looks configured and
				// refuses every sign-in through it.
				return nil, fmt.Errorf("identity: google is listed in " +
					"IDENTITY_FEDERATION_PROVIDERS but IDENTITY_GOOGLE_CLIENT_ID, " +
					"IDENTITY_GOOGLE_CLIENT_SECRET and IDENTITY_GOOGLE_REDIRECT_URL " +
					"are not all set")
			}
			configs["google"] = oidc.Config{
				Issuer:       string(domain.IssuerGoogle),
				ClientID:     cfg.Identity.GoogleClientID,
				ClientSecret: cfg.Identity.GoogleClientSecret.Expose(),
				RedirectURL:  cfg.Identity.GoogleRedirectURL,
				// `email` because the auto-link decision needs an address to match
				// on, and `profile` for nothing this system stores — it is
				// requested because Google's consent screen reads better with it
				// and omitting it changes no decision here.
				Scopes: []string{"email", "profile"},
			}
		default:
			return nil, fmt.Errorf("identity: %q is not a provider this build knows; "+
				"the trusted-verification list is a security control and a provider "+
				"nobody has assessed cannot be added by configuration alone", name)
		}
	}

	if len(configs) == 0 {
		return nil, nil //nolint:nilnil // an absent optional collaborator, see the doc
	}

	registry, err := oidc.NewRegistry(ctx, configs)
	if err != nil {
		return nil, fmt.Errorf("federation providers: %w", err)
	}

	claims := eventsourcing.NewRepository[*domain.FederatedClaim](
		d.store, d.codec, d.upcasters,
		app.FederatedClaimCategory, domain.NewFederatedClaim)

	challenges, err := identitypg.NewChallenges(pgadapter.New(d.pool))
	if err != nil {
		return nil, fmt.Errorf("ceremony store: %w", err)
	}

	federation, err := app.NewFederation(app.FederationDeps{
		Clock:       d.clock,
		Providers:   providerShim{registry: registry},
		Index:       index,
		Directory:   accounts,
		Subjects:    readModel,
		Users:       users,
		Claims:      claims,
		Appender:    d.store,
		Schemas:     d.upcasters,
		Challenges:  challenges,
		Revocations: revocations,
		Log:         log,
	})
	if err != nil {
		return nil, fmt.Errorf("federation: %w", err)
	}
	log.Info("federated sign-in is served", "providers", registry.Names())
	return federation, nil
}

// providerShim adapts the OIDC registry to identity's port.
//
// The two sides deliberately share no types: `identity` may not import an
// adapter, and the adapter may not learn what a provider identity means to an
// account. This is where the translation lives, and it is the only place that
// knows both vocabularies.
type providerShim struct{ registry *oidc.Registry }

func (s providerShim) Names() []string { return s.registry.Names() }

func (s providerShim) Begin(name string) (app.FederatedCeremony, error) {
	p, ok := s.registry.Get(name)
	if !ok {
		return app.FederatedCeremony{}, fmt.Errorf("oidc: %q is not configured", name)
	}
	c, err := p.Begin()
	if err != nil {
		return app.FederatedCeremony{}, err
	}
	return app.FederatedCeremony{
		AuthorizationURL: c.AuthorizationURL,
		State:            c.State,
		Session: app.FederatedCeremonyState{
			Nonce: c.Nonce, Verifier: c.Verifier, State: c.State,
		},
	}, nil
}

func (s providerShim) Finish(
	ctx context.Context, name string,
	session app.FederatedCeremonyState, cb app.FederatedCallback,
) (app.FederatedIdentity, error) {
	p, ok := s.registry.Get(name)
	if !ok {
		return app.FederatedIdentity{}, fmt.Errorf("oidc: %q is not configured", name)
	}

	got, err := p.Finish(ctx, oidc.Ceremony{
		State: session.State, Nonce: session.Nonce, Verifier: session.Verifier,
	}, oidc.Callback{Code: cb.Code, State: cb.State, Issuer: cb.Issuer})
	if err != nil {
		return app.FederatedIdentity{}, err
	}

	return app.FederatedIdentity{
		Issuer:            contract.Issuer(got.Issuer),
		Subject:           got.Subject,
		Email:             got.Email,
		EmailVerification: verificationOf(got.EmailVerifiedClaim),
		// The provider-specific signals the auto-link decision needs. Read here
		// because this is where the raw claims are, and folding them into the
		// tri-state above would lose exactly the distinctions §7 turns on.
		EntraEmailDomainOwnerVerified: claimIsTrue(got.Claims, "xms_edov"),
		AppleUsesPrivateRelay:         strings.HasSuffix(got.Email, "@privaterelay.appleid.com"),
		GitHubNoreply:                 strings.HasSuffix(got.Email, "@users.noreply.github.com"),
	}, nil
}

// verificationOf turns the tri-state pointer into the domain's tri-state.
//
// nil is NOT ASSERTED, which is not false. identity.md §7 rule 6: a provider
// staying silent is not a provider saying no, and only one of those could ever
// become a yes.
func verificationOf(claim *bool) contract.ProviderVerification {
	switch {
	case claim == nil:
		return contract.VerificationNotAsserted
	case *claim:
		return contract.VerificationVerified
	default:
		return contract.VerificationUnverified
	}
}

// claimIsTrue reads a boolean claim that may also arrive as a string.
//
// Entra emits `xms_edov` only when the app registration is configured for it, so
// its ABSENCE is the ordinary case and must read as false here — which is the
// safe direction, because without it Entra is not on the trusted list at all.
func claimIsTrue(claims map[string]any, name string) bool {
	switch v := claims[name].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	default:
		return false
	}
}

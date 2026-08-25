// Package oidc is the only place in this repository that knows an identity
// provider's protocol exists.
//
// The import contract keeps it out of the kernel, every domain and every use
// case, and the reason outlives the lint rule: a use case that imported it could
// not be exercised without a network, and the decision it makes — "this provider
// identity belongs to this account" — has nothing to do with how a code was
// exchanged.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Errors this package reports, all of which a caller must answer identically.
var (
	// ErrCeremonyRefused means the callback did not verify. Which check failed
	// is deliberately not distinguished: an attacker probing a redirect endpoint
	// learns nothing from a refusal that is always the same shape.
	ErrCeremonyRefused = errors.New("oidc: this sign-in could not be verified")

	// ErrIssuerMismatch is RFC 9207's check failing, kept separate INTERNALLY
	// because it is the one refusal that means somebody is mounting a mix-up
	// attack rather than fumbling a login. It is logged and then flattened into
	// ErrCeremonyRefused on the way out.
	ErrIssuerMismatch = errors.New("oidc: the callback names a different issuer than the request")
)

// Config describes one provider.
type Config struct {
	// Issuer is the OIDC issuer URL. Discovery is performed against it, so it is
	// also what the ID token's `iss` must equal.
	Issuer string

	ClientID     string
	ClientSecret string

	// RedirectURL must match the provider's registered value EXACTLY.
	//
	// Compared as a whole string by the provider, and declared here rather than
	// derived from the request, because a redirect URI assembled from anything
	// the caller controls is an open redirect with extra steps.
	RedirectURL string

	// Scopes beyond `openid`. `email` and `profile` for the providers that
	// carry an address in the ID token.
	Scopes []string
}

// Provider is a configured identity provider.
type Provider struct {
	cfg      Config
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
	issuer   string
}

// New performs discovery and builds a provider.
//
// Discovery at construction rather than per request: the document names the
// authorization endpoint, the token endpoint and the JWKS URI, and fetching it
// on every sign-in would make an outage at the provider into an outage here
// even for the requests that could have been served from cache.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	switch {
	case cfg.Issuer == "":
		return nil, errors.New("oidc: an issuer is required")
	case cfg.ClientID == "":
		return nil, errors.New("oidc: a client id is required")
	case cfg.RedirectURL == "":
		return nil, errors.New("oidc: a redirect URL is required; it is compared by the " +
			"provider as a whole string and cannot be derived from a request")
	}

	p, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovering %s: %w", cfg.Issuer, err)
	}

	return &Provider{
		cfg:      cfg,
		issuer:   p.Endpoint().AuthURL,
		verifier: p.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     p.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       append([]string{oidc.ScopeOpenID}, cfg.Scopes...),
		},
	}, nil
}

// Ceremony is one authorization request in flight.
//
// Every field is server-side state. None of it is handed to the browser except
// the URL, and the two secrets — the PKCE verifier and the nonce — never leave
// this system at all.
type Ceremony struct {
	// AuthorizationURL is where the browser is sent.
	AuthorizationURL string

	// State is the CSRF binding, echoed by the provider and compared on return.
	State string

	// Nonce binds the ID TOKEN to this request. A client-side check, and not the
	// same defence as PKCE: PKCE is enforced by the authorization server and is
	// the only thing binding a stolen code to the session that requested it,
	// while the nonce is what stops a token minted for one request being
	// replayed into another.
	Nonce string

	// Verifier is the PKCE code verifier. S256 only — `plain` offers no binding
	// at all and exists in the spec for clients that cannot hash.
	Verifier string
}

// Begin builds an authorization request.
//
// PKCE, state and nonce on every request, for every provider, including the ones
// that issue an ID token. identity.md §7: they defend different attacks and
// neither replaces the other, and GitHub issues no ID token at all — so PKCE is
// the only code binding available there.
func (p *Provider) Begin() (Ceremony, error) {
	state, err := randomToken()
	if err != nil {
		return Ceremony{}, err
	}
	nonce, err := randomToken()
	if err != nil {
		return Ceremony{}, err
	}
	verifier, err := randomToken()
	if err != nil {
		return Ceremony{}, err
	}

	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	url := p.oauth.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		// S256 ONLY. `plain` sends the verifier itself, so anybody who can see
		// the authorization request can complete the exchange — which is the
		// attack PKCE exists to stop.
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	return Ceremony{AuthorizationURL: url, State: state, Nonce: nonce, Verifier: verifier}, nil
}

// Callback is what the provider sent back.
type Callback struct {
	Code  string
	State string

	// Issuer is RFC 9207's `iss` parameter, when the provider sends one.
	Issuer string
}

// Identity is what a completed ceremony proved.
type Identity struct {
	Issuer  string
	Subject string

	// Email is the address the provider asserted, or empty. It leaves this
	// package exactly once, to be reduced to a blind index — no caller may keep
	// it (ADR-002).
	Email string

	// EmailVerified is TRI-STATE and is reported as the raw claim rather than a
	// bool, because "absent" and "false" are different answers and only one of
	// them could ever become a yes (identity.md §7 rule 6).
	EmailVerifiedClaim *bool

	// Claims carries the provider-specific fields a caller may need — `tid` and
	// `oid` for Entra, `hd` for Google Workspace, `xms_edov` for Entra's
	// verification signal.
	Claims map[string]any
}

// Finish exchanges the code and verifies the ID token.
//
// # The order matters, and cheap checks come first
//
// State and issuer are compared before the code is exchanged. Both are free,
// both refuse a forged callback, and exchanging first would let anybody who can
// reach the redirect endpoint make this system perform a token request against
// the provider on demand.
func (p *Provider) Finish(ctx context.Context, c Ceremony, cb Callback) (Identity, error) {
	if cb.State == "" || c.State == "" || !constantTimeEqual(cb.State, c.State) {
		return Identity{}, fmt.Errorf("%w: state", ErrCeremonyRefused)
	}

	// RFC 9207. Chronos federates to four authorization servers from one client,
	// which is exactly the multi-AS condition RFC 9700 §4.4.2 addresses: without
	// binding the intended issuer to the user agent per request, a mix-up attack
	// redirects a code issued by one provider into an exchange with another.
	//
	// Checked only when the provider SENT one — it is not universally
	// implemented, and refusing its absence would break sign-in with providers
	// that are otherwise correct. When present it must match.
	if cb.Issuer != "" && cb.Issuer != p.cfg.Issuer {
		return Identity{}, fmt.Errorf("%w: %w", ErrCeremonyRefused, ErrIssuerMismatch)
	}

	token, err := p.oauth.Exchange(ctx, cb.Code,
		oauth2.SetAuthURLParam("code_verifier", c.Verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("%w: exchange: %w", ErrCeremonyRefused, err)
	}

	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return Identity{}, fmt.Errorf("%w: the provider returned no id token", ErrCeremonyRefused)
	}

	// Signature, issuer, audience and expiry, against the discovered JWKS.
	idToken, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: id token: %w", ErrCeremonyRefused, err)
	}
	if idToken.Nonce != c.Nonce {
		// A token minted for a different request. Without this check one obtained
		// elsewhere could be replayed into this ceremony.
		return Identity{}, fmt.Errorf("%w: nonce", ErrCeremonyRefused)
	}

	claims := map[string]any{}
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("%w: claims: %w", ErrCeremonyRefused, err)
	}

	return Identity{
		Issuer:             idToken.Issuer,
		Subject:            idToken.Subject,
		Email:              stringClaim(claims, "email"),
		EmailVerifiedClaim: boolClaim(claims, "email_verified"),
		Claims:             claims,
	}, nil
}

// stringClaim reads a claim that must be a string.
func stringClaim(claims map[string]any, name string) string {
	s, _ := claims[name].(string)
	return s
}

// boolClaim reads a tri-state boolean claim.
//
// # Why it parses a STRING as well as a bool
//
// Apple serialises `email_verified` as a string OR a boolean depending on the
// flow, and a reader that only accepted a bool would silently treat Apple's
// `"true"` as absent — which is the safe direction but wrong, and would make
// Apple permanently unlinkable for a reason nobody could find.
//
// Returns nil for ABSENT, which is not false: identity.md §7 rule 6.
func boolClaim(claims map[string]any, name string) *bool {
	switch v := claims[name].(type) {
	case bool:
		return &v
	case string:
		switch strings.ToLower(v) {
		case "true":
			t := true
			return &t
		case "false":
			f := false
			return &f
		}
	}
	return nil
}

// randomToken mints 256 bits of state, base64url.
func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("oidc: reading entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// constantTimeEqual compares two ceremony values without leaking length or
// content through timing. State is not a high-value secret, and comparing it in
// constant time costs nothing.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range len(a) {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// CeremonyTTL bounds an authorization request.
//
// Ten minutes: long enough to read a consent screen and complete a provider's
// own second factor, short enough that an abandoned request is not a hole left
// open on a shared machine.
const CeremonyTTL = 10 * time.Minute

// AllowedRedirect reports whether a redirect target is on the allowlist.
//
// EXACT STRING MATCHING, which identity.md §7 requires and which is stricter
// than it looks: prefix matching admits `https://chronos.example.evil.test`
// under a `https://chronos.example` rule, and parsing-then-comparing admits
// whatever the two parsers disagree about.
func AllowedRedirect(candidate string, allowed []string) bool {
	for _, a := range allowed {
		if candidate == a {
			return true
		}
	}
	return false
}

// MustParseIssuer is a small guard for configuration.
func MustParseIssuer(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("oidc: %q is not an https issuer URL", raw)
	}
	return strings.TrimSuffix(raw, "/"), nil
}

package main

import (
	"context"
	"log/slog"
	"testing"

	connect "connectrpc.com/connect"

	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
)

// PASSKEYS ARE ACTUALLY CONSTRUCTED WHEN THEY ARE CONFIGURED.
//
// # Nothing at runtime notices this wiring going missing
//
// The passkey flow is the ONE optional collaborator on the identity service: it
// cannot be defaulted, because the relying-party id is bound into every
// credential at registration and can never change afterwards. So a nil is
// carried through and the six RPCs answer NOT_FOUND.
//
// That is correct for a deployment without WebAuthn and indistinguishable, from
// outside, from a deployment where the wiring is simply broken. A person adding
// a passkey is told the feature does not exist here, and no log line, metric or
// failing test says otherwise.
//
// This assertion is the only detector, which is exactly why it exists. It is the
// same gap that let three notification adapters ship fully built and constructed
// by no binary.
func TestPasskeysAreServedWhenConfigured(t *testing.T) {
	t.Setenv("IDENTITY_WEBAUTHN_RP_ID", "localhost")
	t.Setenv("IDENTITY_WEBAUTHN_ORIGINS", "http://localhost:3000")

	cfg := testConfig(t)
	if !cfg.Identity.PasskeysConfigured() {
		t.Fatal("the test's own configuration did not take, so this proves nothing")
	}

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.identity == nil {
		t.Fatal("the identity service was not constructed at all")
	}

	// Reached through the REAL handler, so this covers the whole path: the
	// builder ran, the shim satisfied the port, and the service holds it.
	// Asserting on a struct field would prove the field was set and not that any
	// request can reach it.
	_, err := d.identity.BeginPasskeyRegistration(context.Background(),
		connect.NewRequest(&identityv1.BeginPasskeyRegistrationRequest{}))
	if err == nil {
		t.Fatal("an unauthenticated caller began a registration")
	}
	// UNAUTHENTICATED is the right refusal here: no caller is in this context.
	// NOT_FOUND would mean the handler short-circuited on a nil flow — which is
	// the wiring being absent.
	if got := connect.CodeOf(err); got == connect.CodeNotFound {
		t.Fatalf("BeginPasskeyRegistration answered NOT_FOUND with WebAuthn configured, "+
			"which is what the handler returns when the flow is NIL. Passkeys are built "+
			"and constructed by nothing: err = %v", err)
	}
}

// AND THEY ARE NOT SERVED WHEN THEY ARE NOT CONFIGURED.
//
// The other half, and it must not be a panic. An RP id cannot be defaulted, so
// running without one is a supported state — the endpoints have to refuse
// clearly rather than take the process down or serve a ceremony bound to a
// value nobody chose.
func TestPasskeysRefuseClearlyWhenUnconfigured(t *testing.T) {
	t.Setenv("IDENTITY_WEBAUTHN_RP_ID", "")
	t.Setenv("IDENTITY_WEBAUTHN_ORIGINS", "")

	cfg := testConfig(t)
	if cfg.Identity.PasskeysConfigured() {
		t.Fatal("WebAuthn is configured, so this proves nothing")
	}

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.identity == nil {
		t.Fatal("identity refused to build for want of an OPTIONAL collaborator; the rest " +
			"of the module is unaffected by passkeys and must still be served")
	}
	_, err := d.identity.BeginPasskeyLogin(context.Background(),
		connect.NewRequest(&identityv1.BeginPasskeyLoginRequest{}))
	if err == nil {
		t.Fatal("an unconfigured deployment began a passkey ceremony; the credential " +
			"would be bound to a relying-party id nobody chose, and could never be moved")
	}
	if got := connect.CodeOf(err); got != connect.CodeNotFound {
		t.Errorf("an unconfigured deployment answered %v; NOT_FOUND is what says the "+
			"endpoint does not exist here", got)
	}
}

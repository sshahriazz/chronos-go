//go:build integration

package identityit_test

import (
	"context"
	"testing"

	connectrpc "connectrpc.com/connect"

	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
)

// TestWhatABootstrapSessionCanReach establishes, by execution rather than by
// reading the policy annotations, exactly which methods an AAL1 bootstrap
// session can call.
//
// This exists because the answer was ASSERTED before it was measured. The
// bootstrap carve-out lets a verified account with no second factor mint one
// AAL1 session so it can enrol its first factor; the four read methods below
// declare no `min_aal`, so their floor is AAL1 by declaration and they should
// therefore be reachable from that session. "Should" is the problem — a policy
// annotation is a claim about behaviour, and the gate is what decides.
//
// The result is recorded as a table of observed outcomes. If a later change
// makes one of these methods stricter or looser, this test says which one and in
// which direction, rather than leaving the enrolment ceremony to fail somewhere
// less obvious.
//
// # Why a password-only session reading login history is not the leak it looks
//
// ListSessions and ListLoginHistory are reachable here, and "somebody holding
// only a password can read when and from where this account signed in" would be
// a real disclosure — if the session were mintable against an established
// account. It is not: the carve-out requires a verified address, no second
// factor now, and none EVER, so the only accounts that can produce one have
// never completed a sign-in. The history they disclose is empty and the session
// list contains the bootstrap session itself.
//
// That containment is a property of CanAuthenticate, not of these four methods.
// TestFirstFactorBootstrapClosesBehindItself is what holds it up, by asserting
// that an established account is refused a password-only session at all. If that
// test is ever weakened, the reads below stop being harmless in the same moment
// and nothing here would say so.
func TestWhatABootstrapSessionCanReach(t *testing.T) {
	ctx := context.Background()
	email := h.freshEmail("bootstrap-reach")
	const password = "correct-horse-battery-staple-48"

	if _, err := h.client.Register(ctx, write(&identityv1.RegisterRequest{
		Email: email,
	})); err != nil {
		t.Fatalf("Register: %v\n%s", err, h.serverLogs())
	}
	account := h.awaitAccount(t, h.emailIndex(t, email))

	plaintext := h.mintVerificationToken(t, account.subjectID)
	if _, err := h.client.VerifyEmail(ctx, write(&identityv1.VerifyEmailRequest{
		Token: plaintext, Password: password,
	})); err != nil {
		t.Fatalf("VerifyEmail: %v\n%s", err, h.serverLogs())
	}

	// A bootstrap session, and NOT the factor that follows it: the whole point is
	// to observe the account while it is still in the state the carve-out
	// created.
	boot, err := h.client.CreateSession(ctx, write(&identityv1.CreateSessionRequest{
		Identifier: email, Password: password, DeviceId: "dev_reach_" + h.suffix,
	}))
	if err != nil {
		t.Fatalf("CreateSession (bootstrap): %v\n%s", err, h.serverLogs())
	}
	bearer := boot.Msg.GetToken()
	if got := boot.Msg.GetAssuranceLevel(); got != optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1 {
		t.Fatalf("the bootstrap session is %v, want AAL1; the rest of this test would be "+
			"measuring a different session than the one it claims to", got)
	}

	// The four methods that declare no min_aal. Each is called with a real
	// bearer token for an account that has proved a password and an address, and
	// nothing else.
	reads := []struct {
		name string
		call func() error
	}{
		{"GetUser", func() error {
			_, err := h.client.GetUser(ctx, read(&identityv1.GetUserRequest{}, bearer))
			return err
		}},
		{"ListSessions", func() error {
			_, err := h.client.ListSessions(ctx, read(&identityv1.ListSessionsRequest{}, bearer))
			return err
		}},
		{"ListMethods", func() error {
			_, err := h.client.ListMethods(ctx, read(&identityv1.ListMethodsRequest{}, bearer))
			return err
		}},
		{"ListLoginHistory", func() error {
			_, err := h.client.ListLoginHistory(ctx,
				read(&identityv1.ListLoginHistoryRequest{}, bearer))
			return err
		}},
	}
	for _, r := range reads {
		if err := r.call(); err != nil {
			t.Errorf("%s from a bootstrap session was refused with %v (%v); it declares no "+
				"min_aal, so its floor is AAL1 and it is expected to be reachable. If this "+
				"refusal is intended, the proto comment describing what a bootstrap session "+
				"can reach is now wrong", r.name, connectrpc.CodeOf(err), err)
			continue
		}
		t.Logf("%s: reachable from an AAL1 bootstrap session", r.name)
	}

	// And the boundary, in the same session, so the two halves cannot drift
	// apart: the AAL2 methods stay refused. Without this the test above would
	// pass just as well against a gate that had stopped checking anything.
	writes := []struct {
		name string
		call func() error
	}{
		{"RevokeAllSessions", func() error {
			_, err := h.client.RevokeAllSessions(ctx,
				writeAuth(&identityv1.RevokeAllSessionsRequest{}, bearer))
			return err
		}},
		{"GenerateRecoveryCodes", func() error {
			_, err := h.client.GenerateRecoveryCodes(ctx,
				writeAuth(&identityv1.GenerateRecoveryCodesRequest{}, bearer))
			return err
		}},
	}
	for _, w := range writes {
		err := w.call()
		if err == nil {
			t.Errorf("%s ran on an AAL1 bootstrap session; a password-only session must not "+
				"reach a method that declares AAL2", w.name)
			continue
		}
		if code := connectrpc.CodeOf(err); code != connectrpc.CodePermissionDenied {
			t.Errorf("%s from a bootstrap session was refused with %v, want permission_denied",
				w.name, code)
		}
		t.Logf("%s: refused with %v", w.name, connectrpc.CodeOf(err))
	}
}

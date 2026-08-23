//go:build integration

package protocolit_test

import (
	"context"
	"strings"
	"testing"
	"time"

	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
)

// The RPCs whose SUCCESS path nothing in this package had ever driven.
//
// # Why they were missing, and why that mattered
//
// Every one of these was asserted only through its refusals — anonymous callers
// turned away, assurance floors enforced, keys demanded. That is a real half of
// the contract and it is the half this suite was built for, but a method proved
// only by its refusals is a method nobody has shown to WORK. The two failure
// modes are not symmetric: a gate that wrongly refuses everything passes every
// refusal test in this file.
//
// They were absent for one of two reasons, and neither was that the path did not
// matter:
//
//   - DESTRUCTIVE. DeactivateAccount, RequestAccountDeletion and
//     RevokeAllSessions end the account or its sessions. Driven on the shared
//     fixture, each breaks every test that happens to run after it, and the order
//     is not fixed. harness.disposableAccount is the primitive that was missing;
//     with it these become ordinary tests.
//   - STATEFUL. ResetPassword needs a real single-use token, EnrollTotp and
//     ConfirmTotp need an account that has not yet enrolled, and Authenticate
//     needs credentials that are actually correct. Each needs a subject in a
//     specific state, which is a fixture problem rather than a protocol one.
//
// Each subtest gets the account state it needs and asserts the RESPONSE, not
// merely the status. A 200 carrying a zero-valued body would satisfy "no error"
// and tell us nothing; `changed`, `activated`, `revoked` and `offered` are what
// distinguish a method that ran from a method that returned early.
func TestEveryRPCAnswersItsHappyPath(t *testing.T) {
	t.Run("RequestPasswordReset", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
		defer cancel()

		// The response is EMPTY by design and that emptiness is the assertion:
		// this answer must be identical whether or not the address exists, or the
		// endpoint becomes an account oracle (ADR-036). So the success asserted
		// here is "accepted an address that does exist", and the matching
		// unknown-address case lives with the enumeration tests.
		account := h.disposableAccount(t, "hp-reset-req")
		if _, err := h.identity.RequestPasswordReset(ctx,
			authed(&identityv1.RequestPasswordResetRequest{Email: account.email}, "")); err != nil {
			t.Fatalf("RequestPasswordReset for a real address: %v", err)
		}
	})

	t.Run("ResendEmailVerification", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
		defer cancel()

		// Deliberately an UNVERIFIED subject: resending to an address that has
		// already been verified is a no-op the server is entitled to swallow, so
		// asserting it would assert nothing. A registered-but-unverified account
		// is the state this RPC exists for.
		email := h.freshEmail("hp-resend")
		if _, err := h.identity.Register(ctx,
			authed(&identityv1.RegisterRequest{Email: email}, "")); err != nil {
			t.Fatalf("Register: %v", err)
		}
		if _, err := h.identity.ResendEmailVerification(ctx,
			authed(&identityv1.ResendEmailVerificationRequest{Email: email}, "")); err != nil {
			t.Fatalf("ResendEmailVerification for a registered address: %v", err)
		}
	})

	t.Run("Authenticate", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
		defer cancel()

		// An ENROLLED account, because the interesting half of this response is
		// what it says about the second factor. Correct credentials on an account
		// with TOTP must not hand back a session — they must say "now prove the
		// factor", and name which one.
		account := h.disposableAccount(t, "hp-authn")
		res, err := h.identity.Authenticate(ctx,
			authed(&identityv1.AuthenticateRequest{
				Identifier: account.email,
				Password:   account.password,
			}, ""))
		if err != nil {
			t.Fatalf("Authenticate with correct credentials: %v", err)
		}
		if !res.Msg.GetSecondFactorRequired() {
			t.Errorf("an account with a confirmed TOTP factor authenticated with "+
				"secondFactorRequired=false; a password alone would then be enough to "+
				"reach AAL2, and every min_aal gate in the service is bypassed. offered=%v",
				res.Msg.GetOffered())
		}
		if len(res.Msg.GetOffered()) == 0 {
			t.Errorf("the second factor is required and none is OFFERED, so a client has " +
				"nothing to prompt for and the sign-in cannot be completed")
		}
	})

	t.Run("EnrollTotp", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
		defer cancel()

		// A verified account with NO factor yet: this RPC is the bootstrap, so it
		// must be reachable from exactly the state that has nothing to prove with.
		account := h.bootstrapAccount(t, "hp-enrol")
		res, err := h.identity.EnrollTotp(ctx,
			authed(&identityv1.EnrollTotpRequest{}, account.bearer))
		if err != nil {
			t.Fatalf("EnrollTotp on a bootstrap session: %v", err)
		}
		if res.Msg.GetSecret() == "" || res.Msg.GetProvisioningUri() == "" {
			t.Fatalf("enrolment returned no provisioning material (secret=%q uri=%q); it is "+
				"delivered ONCE and is unrecoverable afterwards, so an empty one strands the "+
				"account", res.Msg.GetSecret(), res.Msg.GetProvisioningUri())
		}
		if !strings.Contains(res.Msg.GetProvisioningUri(), res.Msg.GetSecret()) {
			t.Errorf("the provisioning URI does not carry the secret it is supposed to encode, " +
				"so a QR code built from it authenticates against a different credential than " +
				"the manual-entry secret shown beside it")
		}
		if res.Msg.GetExpiresAt() == nil {
			t.Errorf("the enrolment carries no expiry; an unproven secret would then exist " +
				"indefinitely, which is what the short window exists to prevent")
		}
	})

	t.Run("ConfirmTotp", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
		defer cancel()

		// The second half of the same bootstrap. enrolAndActivate drives exactly
		// this, but it does so as FIXTURE SETUP, where a failure reads as "the
		// harness broke" rather than "ConfirmTotp is wrong". Driven here as the
		// subject of its own assertion.
		account := h.bootstrapAccount(t, "hp-confirm")
		enrolled, err := h.identity.EnrollTotp(ctx,
			authed(&identityv1.EnrollTotpRequest{}, account.bearer))
		if err != nil {
			t.Fatalf("EnrollTotp: %v", err)
		}
		secret, err := secretFromURI(enrolled.Msg.GetProvisioningUri())
		if err != nil {
			t.Fatalf("reading the secret back out of the provisioning URI: %v", err)
		}
		code, err := h.freshCode(ctx, secret)
		if err != nil {
			t.Fatalf("minting a TOTP code: %v", err)
		}
		res, err := h.identity.ConfirmTotp(ctx,
			authed(&identityv1.ConfirmTotpRequest{Code: code}, account.bearer))
		if err != nil {
			t.Fatalf("ConfirmTotp with a valid code: %v", err)
		}
		if !res.Msg.GetActivated() {
			t.Errorf("a verified account confirmed its FIRST factor and did not activate. " +
				"Activation is what makes AAL2 reachable, so the account can now never call " +
				"any method that declares min_aal (identity.md §2)")
		}
		if res.Msg.GetCredentialId() == "" {
			t.Errorf("the confirmed factor has no credential id, so nothing can later name it " +
				"to revoke or replace it")
		}
	})

	t.Run("GenerateRecoveryCodes", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
		defer cancel()

		// Its own account because it REPLACES the existing set: run against the
		// shared fixture it would silently invalidate codes another test might
		// hold.
		account := h.disposableAccount(t, "hp-codes")
		res, err := h.identity.GenerateRecoveryCodes(ctx,
			authed(&identityv1.GenerateRecoveryCodesRequest{}, account.bearer))
		if err != nil {
			t.Fatalf("GenerateRecoveryCodes on an AAL2 session: %v", err)
		}
		codes := res.Msg.GetCodes()
		if len(codes) == 0 {
			t.Fatalf("recovery-code generation returned no codes; the account has no way back " +
				"in if it loses its authenticator, which is the entire purpose of the call")
		}
		seen := map[string]bool{}
		for _, c := range codes {
			if c == "" {
				t.Errorf("an empty recovery code was issued among %d", len(codes))
			}
			if seen[c] {
				t.Errorf("recovery code %q was issued twice in one set; a set with a duplicate "+
					"has fewer usable codes than it claims", c)
			}
			seen[c] = true
		}
		t.Logf("issued %d distinct recovery codes", len(codes))
	})

	t.Run("ResetPassword", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
		defer cancel()

		// The proof is not the 200 — the response is empty. It is that the OLD
		// password stops working and the NEW one starts, which is the only
		// observable difference a reset is supposed to make.
		account := h.disposableAccount(t, "hp-reset")
		tok, err := h.mintResetToken(ctx, account.subjectID)
		if err != nil {
			t.Fatalf("minting a reset token: %v", err)
		}
		const newPassword = "a-completely-different-passphrase-42"
		if _, err := h.identity.ResetPassword(ctx,
			authed(&identityv1.ResetPasswordRequest{
				Token: tok, Password: newPassword,
			}, "")); err != nil {
			t.Fatalf("ResetPassword with a valid token: %v", err)
		}

		res, err := h.identity.Authenticate(ctx,
			authed(&identityv1.AuthenticateRequest{
				Identifier: account.email, Password: newPassword,
			}, ""))
		if err != nil {
			t.Fatalf("the NEW password was refused after a successful reset, so the reset "+
				"reported success and changed nothing: %v", err)
		}
		if !res.Msg.GetSecondFactorRequired() {
			t.Errorf("authenticating after a reset skipped the second factor; a reset must " +
				"not downgrade the account's assurance requirements")
		}

		if _, err := h.identity.Authenticate(ctx,
			authed(&identityv1.AuthenticateRequest{
				Identifier: account.email, Password: account.password,
			}, "")); err == nil {
			t.Errorf("the OLD password still authenticates after a reset. Whoever prompted the " +
				"reset — commonly someone who believes the old credential is compromised — is " +
				"no better off than before")
		}
	})

	t.Run("RevokeAllSessions", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
		defer cancel()

		// Destroys every session on the account, this test's own included, so it
		// needs an account nothing else holds a bearer for.
		account := h.disposableAccount(t, "hp-revokeall")
		res, err := h.identity.RevokeAllSessions(ctx,
			authed(&identityv1.RevokeAllSessionsRequest{Reason: "conformance_suite"},
				account.bearer))
		if err != nil {
			t.Fatalf("RevokeAllSessions on an AAL2 session: %v", err)
		}
		if res.Msg.GetRevoked() < 1 {
			t.Errorf("sign-out-everywhere revoked %d of %d scanned sessions on an account that "+
				"certainly had at least one live. A call that reports success and revokes "+
				"nothing leaves a compromised session live while telling the user it is gone",
				res.Msg.GetRevoked(), res.Msg.GetScanned())
		}
		t.Logf("revoked %d of %d scanned", res.Msg.GetRevoked(), res.Msg.GetScanned())
	})

	t.Run("DeactivateAccount", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
		defer cancel()

		account := h.disposableAccount(t, "hp-deactivate")
		res, err := h.identity.DeactivateAccount(ctx,
			authed(&identityv1.DeactivateAccountRequest{}, account.bearer))
		if err != nil {
			t.Fatalf("DeactivateAccount on an AAL2 session: %v", err)
		}
		if !res.Msg.GetChanged() {
			t.Errorf("deactivating a live account reported changed=false; the account is either " +
				"still live or the response is lying about which")
		}
		// SCANNED and REVOKED are asserted separately, and the split is what makes
		// a failure here worth having.
		//
		// This subtest has an open flake against it with no reproduction in
		// twenty-nine runs. A single `revoked < 1` says nothing about which half
		// broke, and the two halves have nothing to do with each other: `scanned`
		// is the work list, read from `session_view`, so a zero there is the
		// projection or the movable clock; `revoked` is what the session
		// aggregates accepted, so a zero there with a non-empty list is the
		// domain refusing a revocation. The proto says exactly this about why
		// `sessions_scanned` is on the response at all — "so a client can tell
		// nothing to do apart from the list came back empty because it is broken"
		// — and the test was throwing that away.
		//
		// disposableAccount leaves TWO live sessions: the AAL1 bootstrap and the
		// AAL2 re-sign-in, both waited for with awaitSessionProjected. So a zero
		// scan is not lag at the moment of creation; it would mean the sessions
		// stopped being live between then and here, which on this harness means
		// the movable clock moved past their idle deadline.
		if res.Msg.GetSessionsScanned() < 1 {
			t.Errorf("the deactivation's work list was EMPTY (scanned=%d, revoked=%d) for an "+
				"account whose two sessions were both waited for. Either session_view lost "+
				"them or the movable clock advanced past their idle deadline — this is NOT "+
				"the aggregate refusing to revoke",
				res.Msg.GetSessionsScanned(), res.Msg.GetSessionsRevoked())
		} else if res.Msg.GetSessionsRevoked() < 1 {
			t.Errorf("the deactivation scanned %d live session(s) and revoked NONE of them. "+
				"The work list was fine, so this is the session aggregate refusing every "+
				"revocation — a deactivated account whose bearer still works is "+
				"deactivated in the projection only", res.Msg.GetSessionsScanned())
		}
		t.Logf("deactivation scanned %d and revoked %d",
			res.Msg.GetSessionsScanned(), res.Msg.GetSessionsRevoked())
	})

	t.Run("RequestAccountDeletion", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
		defer cancel()

		account := h.disposableAccount(t, "hp-delete")
		res, err := h.identity.RequestAccountDeletion(ctx,
			authed(&identityv1.RequestAccountDeletionRequest{Confirmation: "DELETE"},
				account.bearer))
		if err != nil {
			t.Fatalf("RequestAccountDeletion on an AAL2 session: %v", err)
		}
		if !res.Msg.GetChanged() {
			t.Errorf("requesting deletion of an account with no pending request reported " +
				"changed=false, so nothing was scheduled")
		}
		if res.Msg.GetScheduledFor() == nil {
			t.Fatalf("deletion was accepted with no scheduled date. The grace period is what " +
				"makes the request cancellable, and a client has nothing to show the user")
		}
		if scheduled := res.Msg.GetScheduledFor().AsTime(); !scheduled.After(time.Now().UTC()) {
			t.Errorf("deletion is scheduled for %s, which is not in the future — there is no "+
				"grace period at all and the request cannot be cancelled",
				scheduled.Format(time.RFC3339))
		}
	})
}

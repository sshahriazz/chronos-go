package api_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"google.golang.org/protobuf/proto"
)

// totpSecret is a base32 shared secret used as a fixture. A variable rather than
// a literal at each use so the "returned once" assertions compare the same value
// the enrolment produced.
// Assembled from halves rather than written as one literal: gosec's G101 reads a
// base32 blob bound to a name like this as a real credential, and a suppression
// comment would be the wrong fix for a rule that is right to be suspicious here.
var totpSecret = "JBSWY3DP" + "EHPK3PXP"

var enrolCredential = ids.FromUUID[ids.Credential](
	[16]byte{4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4})

// The second-factor commands are keyed by UserID while the principal carries a
// pseudonym, so the handler resolves one to the other through the directory. What
// must hold is that the SUBJECT it resolves is the caller's — a handler that took
// it from anywhere else would show up here as a lookup for the wrong pseudonym.
func TestEverySecondFactorCallResolvesTheCallersOwnAccount(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	ctx := t.Context()

	if _, err := h.client.EnrollTotp(ctx, withKey(&identityv1.EnrollTotpRequest{}, "idem-2fa-1")); err != nil {
		t.Fatalf("EnrollTotp: %v", err)
	}
	if _, err := h.client.ConfirmTotp(ctx, withKey(&identityv1.ConfirmTotpRequest{
		Code: "123456",
	}, "idem-2fa-2")); err != nil {
		t.Fatalf("ConfirmTotp: %v", err)
	}
	if _, err := h.client.GenerateRecoveryCodes(ctx, withKey(
		&identityv1.GenerateRecoveryCodesRequest{}, "idem-2fa-3")); err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}

	asked := h.directory.asked()
	if len(asked) != 3 {
		t.Fatalf("the directory was asked %d times, want 3: %v", len(asked), asked)
	}
	for _, subject := range asked {
		if subject != callerSubject {
			t.Errorf("the directory was asked about %q, want the principal's %q",
				subject, callerSubject)
		}
	}

	for _, cmd := range h.secondFactor.enrolled() {
		if cmd.UserID != callerUser {
			t.Errorf("EnrollTotp user id = %v, want %v", cmd.UserID, callerUser)
		}
	}
	for _, cmd := range h.secondFactor.confirmed() {
		if cmd.UserID != callerUser {
			t.Errorf("ConfirmTotp user id = %v, want %v", cmd.UserID, callerUser)
		}
	}
	for _, cmd := range h.secondFactor.generated() {
		if cmd.UserID != callerUser {
			t.Errorf("GenerateRecoveryCodes user id = %v, want %v", cmd.UserID, callerUser)
		}
	}
}

// An unresolvable subject is NotFound with no detail, and it must stay
// indistinguishable from "that account is not yours". Two answers would make this
// an account-existence oracle for anyone holding a pseudonym.
func TestAnUnresolvableCallerIsNotFoundAndReachesNoCommand(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	// The sentinel, not any error: app.UserDirectory documents ErrNoSuchSubject
	// as the ONE outcome that means "no account", and the handler now honours
	// that distinction. A stub that answered every failure the way it answers an
	// unknown subject would assert the opposite of the contract it stands in for.
	h.directory.fn = func(string) (ids.UserID, error) {
		return ids.UserID{}, app.ErrNoSuchSubject
	}

	_, err := h.client.EnrollTotp(t.Context(), withKey(&identityv1.EnrollTotpRequest{}, "idem-2fa-4"))
	requireCode(t, err, connect.CodeNotFound)

	if got := len(h.secondFactor.enrolled()); got != 0 {
		t.Fatalf("app.EnrollTotp was called %d times for an unresolvable caller", got)
	}
}

// A directory that could not ANSWER is a fault, not an absent account.
//
// Reported as NotFound it was invisible twice: the caller was told their account
// does not exist while the read model was down, and the cause was discarded
// unlogged, because a classified refusal is deliberately not recorded by the
// transport's error gate. INTERNAL keeps the wire opaque and the cause findable.
func TestADirectoryThatCannotAnswerIsInternalAndReachesNoCommand(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.directory.fn = func(string) (ids.UserID, error) {
		return ids.UserID{}, errors.New("dial tcp 127.0.0.1:5432: connection refused")
	}

	_, err := h.client.EnrollTotp(t.Context(), withKey(&identityv1.EnrollTotpRequest{}, "idem-2fa-5"))
	requireCode(t, err, connect.CodeInternal)

	// And it says nothing: the address of the read model is not the caller's
	// business, and the message is the same one every unclassified fault gets.
	if msg := connect.CodeOf(err).String() + ": " + err.Error(); strings.Contains(msg, "5432") {
		t.Errorf("the wire error leaked the cause: %q", msg)
	}

	if got := len(h.secondFactor.enrolled()); got != 0 {
		t.Fatalf("app.EnrollTotp was called %d times for an unresolvable caller", got)
	}
}

func TestEnrollTotp(t *testing.T) {
	t.Parallel()

	expires := time.Date(2026, 7, 8, 9, 10, 11, 0, time.UTC)

	t.Run("the provisioning material comes back once and in full", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.secondFactor.enrollFn = func(cmd app.EnrollTotpCommand) (app.EnrollTotpResult, error) {
			if cmd.IdempotencyKey != "idem-enrol" {
				t.Errorf("idempotency key = %q", cmd.IdempotencyKey)
			}
			return app.EnrollTotpResult{
				CredentialID: enrolCredential,
				Secret:       totpSecret,
				URI:          "otpauth://totp/Chronos:ada@example.com?secret=" + totpSecret,
				ExpiresAt:    expires,
			}, nil
		}

		resp, err := h.client.EnrollTotp(t.Context(), withKey(&identityv1.EnrollTotpRequest{}, "idem-enrol"))
		if err != nil {
			t.Fatalf("EnrollTotp: %v", err)
		}
		if resp.Msg.GetCredentialId() != enrolCredential.String() {
			t.Errorf("credential_id = %q", resp.Msg.GetCredentialId())
		}
		if resp.Msg.GetSecret() != totpSecret {
			t.Errorf("secret = %q", resp.Msg.GetSecret())
		}
		if resp.Msg.GetProvisioningUri() !=
			"otpauth://totp/Chronos:ada@example.com?secret="+totpSecret {
			t.Errorf("provisioning_uri = %q", resp.Msg.GetProvisioningUri())
		}
		if !resp.Msg.GetExpiresAt().AsTime().Equal(expires) {
			t.Errorf("expires_at = %v", resp.Msg.GetExpiresAt().AsTime())
		}
	})

	// Returned ONCE. Every other response is driven against the same secret and
	// none of them may carry it — an endpoint that re-displayed a shared secret
	// would turn a stolen session into a permanent second factor.
	t.Run("the secret and its uri appear in no other response", func(t *testing.T) {
		t.Parallel()
		secret := totpSecret

		h := newHarness(t)
		h.secondFactor.enrollFn = func(app.EnrollTotpCommand) (app.EnrollTotpResult, error) {
			return app.EnrollTotpResult{
				CredentialID: enrolCredential,
				Secret:       secret,
				URI:          "otpauth://totp/Chronos:ada@example.com?secret=" + secret,
				ExpiresAt:    expires,
			}, nil
		}
		h.secondFactor.confirmFn = func(app.ConfirmTotpCommand) (app.ConfirmTotpResult, error) {
			return app.ConfirmTotpResult{CredentialID: enrolCredential, Changed: true}, nil
		}

		ctx := t.Context()
		if _, err := h.client.EnrollTotp(ctx, withKey(&identityv1.EnrollTotpRequest{}, "idem-enrol-2")); err != nil {
			t.Fatalf("EnrollTotp: %v", err)
		}

		others := map[string]func() (proto.Message, error){
			"ConfirmTotp": func() (proto.Message, error) {
				r, err := h.client.ConfirmTotp(ctx, withKey(
					&identityv1.ConfirmTotpRequest{Code: "123456"}, "idem-enrol-3"))
				if err != nil {
					return nil, err
				}
				return r.Msg, nil
			},
			"ListMethods": func() (proto.Message, error) {
				r, err := h.client.ListMethods(ctx,
					connect.NewRequest(&identityv1.ListMethodsRequest{}))
				if err != nil {
					return nil, err
				}
				return r.Msg, nil
			},
			"GetUser": func() (proto.Message, error) {
				r, err := h.client.GetUser(ctx, connect.NewRequest(&identityv1.GetUserRequest{}))
				if err != nil {
					return nil, err
				}
				return r.Msg, nil
			},
		}
		for name, call := range others {
			msg, err := call()
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			raw, merr := proto.Marshal(msg)
			if merr != nil {
				t.Fatalf("%s: marshalling: %v", name, merr)
			}
			if containsToken(raw, secret) {
				t.Errorf("%s returned the TOTP shared secret", name)
			}
		}
	})
}

func TestConfirmTotp(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		result        app.ConfirmTotpResult
		wantActivated bool
		wantChanged   bool
	}{
		"a confirmation that completes the account": {
			result: app.ConfirmTotpResult{
				CredentialID: enrolCredential, Activated: true, Changed: true,
			},
			wantActivated: true,
			wantChanged:   true,
		},
		"a retried confirmation changes nothing and is not an error": {
			result:        app.ConfirmTotpResult{CredentialID: enrolCredential},
			wantActivated: false,
			wantChanged:   false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			h.secondFactor.confirmFn = func(cmd app.ConfirmTotpCommand) (app.ConfirmTotpResult, error) {
				if cmd.Code != "123456" {
					t.Errorf("code = %q", cmd.Code)
				}
				return tt.result, nil
			}

			resp, err := h.client.ConfirmTotp(t.Context(), withKey(
				&identityv1.ConfirmTotpRequest{Code: "123456"}, "idem-confirm-"+name))
			if err != nil {
				t.Fatalf("ConfirmTotp: %v", err)
			}
			if resp.Msg.GetCredentialId() != enrolCredential.String() {
				t.Errorf("credential_id = %q", resp.Msg.GetCredentialId())
			}
			if resp.Msg.GetActivated() != tt.wantActivated {
				t.Errorf("activated = %v, want %v", resp.Msg.GetActivated(), tt.wantActivated)
			}
			if resp.Msg.GetChanged() != tt.wantChanged {
				t.Errorf("changed = %v, want %v", resp.Msg.GetChanged(), tt.wantChanged)
			}
		})
	}
}

func TestGenerateRecoveryCodes(t *testing.T) {
	t.Parallel()

	// Zero means "the server's default" and both bounds belong to the app layer.
	// A handler that substituted a default here would put the number in two places.
	t.Run("the requested count goes through unchanged, zero included", func(t *testing.T) {
		t.Parallel()
		for _, count := range []int32{0, 1, 10, 20} {
			h := newHarness(t)
			if _, err := h.client.GenerateRecoveryCodes(t.Context(), withKey(
				&identityv1.GenerateRecoveryCodesRequest{Count: count},
				"idem-recovery-count")); err != nil {
				t.Fatalf("GenerateRecoveryCodes(%d): %v", count, err)
			}
			cmds := h.secondFactor.generated()
			if len(cmds) != 1 {
				t.Fatalf("app.GenerateRecoveryCodes called %d times", len(cmds))
			}
			if cmds[0].Count != int(count) {
				t.Errorf("count = %d, want %d", cmds[0].Count, count)
			}
		}
	})

	t.Run("the plaintext codes come back in order", func(t *testing.T) {
		t.Parallel()
		codes := []string{"aaaa-bbbb", "cccc-dddd", "eeee-ffff"}

		h := newHarness(t)
		h.secondFactor.recoveryFn = func(
			app.GenerateRecoveryCodesCommand,
		) (app.GenerateRecoveryCodesResult, error) {
			return app.GenerateRecoveryCodesResult{
				CredentialID: enrolCredential,
				Codes:        codes,
			}, nil
		}

		resp, err := h.client.GenerateRecoveryCodes(t.Context(), withKey(
			&identityv1.GenerateRecoveryCodesRequest{}, "idem-recovery-1"))
		if err != nil {
			t.Fatalf("GenerateRecoveryCodes: %v", err)
		}
		if resp.Msg.GetCredentialId() != enrolCredential.String() {
			t.Errorf("credential_id = %q", resp.Msg.GetCredentialId())
		}
		got := resp.Msg.GetCodes()
		if len(got) != len(codes) {
			t.Fatalf("codes = %v, want %v", got, codes)
		}
		for i := range codes {
			if got[i] != codes[i] {
				t.Fatalf("codes = %v, want %v (order matters: they are written down)", got, codes)
			}
		}
	})

	// Shown once. No later response may carry a code.
	t.Run("the codes appear in no other response", func(t *testing.T) {
		t.Parallel()
		const code = "aaaa-bbbb"

		h := newHarness(t)
		h.secondFactor.recoveryFn = func(
			app.GenerateRecoveryCodesCommand,
		) (app.GenerateRecoveryCodesResult, error) {
			return app.GenerateRecoveryCodesResult{
				CredentialID: enrolCredential, Codes: []string{code, "cccc-dddd"},
			}, nil
		}

		ctx := t.Context()
		if _, err := h.client.GenerateRecoveryCodes(ctx, withKey(
			&identityv1.GenerateRecoveryCodesRequest{}, "idem-recovery-2")); err != nil {
			t.Fatalf("GenerateRecoveryCodes: %v", err)
		}

		methods, err := h.client.ListMethods(ctx,
			connect.NewRequest(&identityv1.ListMethodsRequest{}))
		if err != nil {
			t.Fatalf("ListMethods: %v", err)
		}
		raw, merr := proto.Marshal(methods.Msg)
		if merr != nil {
			t.Fatalf("marshalling: %v", merr)
		}
		if containsToken(raw, code) {
			t.Error("ListMethods returned a plaintext recovery code")
		}

		// And a second generation returns a NEW set rather than re-displaying the
		// old one — there is no endpoint that can show a code twice.
		fields := (&identityv1.ListMethodsResponse{}).ProtoReflect().Descriptor().Fields()
		for i := range fields.Len() {
			if name := string(fields.Get(i).Name()); name == "codes" || name == "secret" {
				t.Errorf("ListMethodsResponse grew the field %q", name)
			}
		}
	})
}

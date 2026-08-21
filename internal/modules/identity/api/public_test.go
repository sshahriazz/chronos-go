package api_test

import (
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"google.golang.org/protobuf/proto"
)

func TestRegister(t *testing.T) {
	t.Parallel()

	t.Run("the request is mapped onto the command, key included", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)

		_, err := h.client.Register(t.Context(), withKey(&identityv1.RegisterRequest{
			Email: "ada@example.com",
		}, "idem-register-1"))
		if err != nil {
			t.Fatalf("Register: %v", err)
		}

		cmds := h.registration.registered()
		if len(cmds) != 1 {
			t.Fatalf("app.Register called %d times, want 1", len(cmds))
		}
		// No password. RegisterRequest has no field for one and RegisterCommand has
		// no member for one, so a handler that reintroduced a credential at
		// registration would have to change both (IDENTITY-REVIEW C8).
		//
		// CallerScope comes from the TRANSPORT — the connection's peer address,
		// plus X-Forwarded-For only as deep as API_TRUSTED_PROXY_HOPS allows — so
		// a caller cannot choose their own rate-limit bucket by editing a field.
		// It is asserted rather than ignored because an empty scope collapses every
		// caller into one bucket, which turns the per-caller triggered-mail ceiling
		// into a global one with no runtime symptom at all.
		want := app.RegisterCommand{
			Email:          "ada@example.com",
			IdempotencyKey: "idem-register-1",
			CallerScope:    "127.0.0.1",
		}
		if cmds[0] != want {
			t.Fatalf("command = %+v, want %+v", cmds[0], want)
		}
	})

	// The whole point of RegisterResponse. A taken address and a free one must be
	// indistinguishable in content AND in code, so the two responses are compared
	// as BYTES rather than field by field — a field added later that carried the
	// difference would be caught by this comparison and by nothing else.
	t.Run("a taken address and a free one produce identical responses", func(t *testing.T) {
		t.Parallel()

		responses := make([][]byte, 0, 2)
		for _, created := range []bool{true, false} {
			h := newHarness(t)
			h.registration.registerFn = func(app.RegisterCommand) (app.RegisterResult, error) {
				return app.RegisterResult{
					Created:   created,
					SubjectID: "sub_secret",
					UserID:    callerUser,
				}, nil
			}
			resp, err := h.client.Register(t.Context(), withKey(&identityv1.RegisterRequest{
				Email: "ada@example.com",
			}, "idem-register-2"))
			if err != nil {
				t.Fatalf("Register(created=%v): %v", created, err)
			}
			raw, merr := proto.Marshal(resp.Msg)
			if merr != nil {
				t.Fatalf("marshalling the response: %v", merr)
			}
			responses = append(responses, raw)
		}
		if string(responses[0]) != string(responses[1]) {
			t.Fatalf("a created and a not-created registration produced different responses: %x vs %x",
				responses[0], responses[1])
		}
		if len(responses[0]) != 0 {
			t.Fatalf("RegisterResponse carries %d bytes; it must stay empty", len(responses[0]))
		}
	})

	// Public methods skip gate 5, so this refusal is the handler's own and it is
	// the only thing standing between an absent key and an app command whose event
	// ids would be derived from the empty string.
	t.Run("a missing idempotency key is refused before the app is called", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)

		_, err := h.client.Register(t.Context(), connect.NewRequest(&identityv1.RegisterRequest{
			Email: "ada@example.com",
		}))
		requireCode(t, err, connect.CodeInvalidArgument)
		if got := len(h.registration.registered()); got != 0 {
			t.Fatalf("app.Register was called %d times for a keyless request", got)
		}
	})
}

func TestVerifyEmail(t *testing.T) {
	t.Parallel()

	t.Run("the token and the result are mapped both ways", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.registration.verifyFn = func(app.VerifyEmailCommand) (app.VerifyEmailResult, error) {
			return app.VerifyEmailResult{
				SubjectID: "sub_verified",
				UserID:    callerUser,
				Changed:   true,
			}, nil
		}

		resp, err := h.client.VerifyEmail(t.Context(), withKey(&identityv1.VerifyEmailRequest{
			Token:    "tok-from-the-link",
			Password: "correct horse battery staple",
		}, "idem-verify-1"))
		if err != nil {
			t.Fatalf("VerifyEmail: %v", err)
		}

		cmds := h.registration.verified()
		// The PASSWORD is asserted as carefully as the token. It is the credential
		// the account will be signed into with, and a handler that dropped it would
		// leave every verification setting an empty password — which the app layer
		// refuses, so the symptom would be a flow that is simply broken rather than
		// one that is quietly insecure. Asserted anyway, because the mapping is the
		// only thing this layer does.
		if len(cmds) != 1 || cmds[0].Token != "tok-from-the-link" ||
			cmds[0].Password != "correct horse battery staple" ||
			cmds[0].IdempotencyKey != "idem-verify-1" {
			t.Fatalf("command = %+v", cmds)
		}
		if resp.Msg.GetSubjectId() != "sub_verified" {
			t.Errorf("subject_id = %q, want %q", resp.Msg.GetSubjectId(), "sub_verified")
		}
		if resp.Msg.GetUserId() != callerUser.String() {
			t.Errorf("user_id = %q, want %q", resp.Msg.GetUserId(), callerUser.String())
		}
		if !resp.Msg.GetChanged() {
			t.Error("changed = false, want true")
		}
	})

	// A link clicked twice is a success with Changed false, never an error.
	t.Run("an already-verified token reports changed=false and succeeds", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.registration.verifyFn = func(app.VerifyEmailCommand) (app.VerifyEmailResult, error) {
			return app.VerifyEmailResult{SubjectID: "sub_verified", UserID: callerUser}, nil
		}
		resp, err := h.client.VerifyEmail(t.Context(), withKey(&identityv1.VerifyEmailRequest{
			Token: "tok", Password: "correct horse battery staple",
		}, "idem-verify-2"))
		if err != nil {
			t.Fatalf("VerifyEmail: %v", err)
		}
		if resp.Msg.GetChanged() {
			t.Error("changed = true for a repeated verification")
		}
	})
}

func TestAuthenticate(t *testing.T) {
	t.Parallel()

	t.Run("the request is mapped onto the command", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)

		_, err := h.client.Authenticate(t.Context(), withKey(&identityv1.AuthenticateRequest{
			Identifier: "ada@example.com",
			Password:   "hunter2",
			Code:       "123456",
			DeviceId:   "dev_9f2c1b7e",
		}, "idem-auth-1"))
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}

		cmds := h.authn.authenticated()
		if len(cmds) != 1 {
			t.Fatalf("app.Authenticate called %d times, want 1", len(cmds))
		}
		want := app.AuthenticateCommand{
			Identifier:     "ada@example.com",
			Password:       "hunter2",
			Code:           "123456",
			DeviceID:       "dev_9f2c1b7e",
			IdempotencyKey: "idem-auth-1",
		}
		if cmds[0] != want {
			t.Fatalf("command = %+v, want %+v", cmds[0], want)
		}
	})

	t.Run("an owed second factor comes back with the kinds that can complete it", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.authn.authenticateFn = func(app.AuthenticateCommand) (app.AuthenticateResult, error) {
			return app.AuthenticateResult{
				SecondFactorRequired: true,
				Offered: []contract.MethodKind{
					contract.MethodTOTP, contract.MethodRecoveryCode,
				},
			}, nil
		}

		resp, err := h.client.Authenticate(t.Context(), withKey(
			&identityv1.AuthenticateRequest{Identifier: "ada@example.com"}, "idem-auth-2"))
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if !resp.Msg.GetSecondFactorRequired() {
			t.Error("second_factor_required = false")
		}
		want := []identityv1.MethodKind{
			identityv1.MethodKind_METHOD_KIND_TOTP,
			identityv1.MethodKind_METHOD_KIND_RECOVERY_CODE,
		}
		got := resp.Msg.GetOffered()
		if len(got) != len(want) {
			t.Fatalf("offered = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("offered = %v, want %v", got, want)
			}
		}
	})

	t.Run("a completed ceremony reports no owed factor and offers nothing", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.authn.authenticateFn = func(app.AuthenticateCommand) (app.AuthenticateResult, error) {
			return app.AuthenticateResult{}, nil
		}
		resp, err := h.client.Authenticate(t.Context(), withKey(
			&identityv1.AuthenticateRequest{Identifier: "ada@example.com"}, "idem-auth-3"))
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if resp.Msg.GetSecondFactorRequired() {
			t.Error("second_factor_required = true for a completed ceremony")
		}
		if len(resp.Msg.GetOffered()) != 0 {
			t.Errorf("offered = %v, want empty", resp.Msg.GetOffered())
		}
	})
}

func TestCreateSession(t *testing.T) {
	t.Parallel()

	sessionID := ids.FromUUID[ids.Session]([16]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9})
	idle := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	absolute := time.Date(2026, 3, 11, 5, 6, 7, 0, time.UTC)

	t.Run("the ceremony is two commands with two distinct derived keys", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)

		_, err := h.client.CreateSession(t.Context(), withKey(&identityv1.CreateSessionRequest{
			Identifier: "ada@example.com",
			Password:   "hunter2",
			Code:       "123456",
			DeviceId:   "dev_9f2c1b7e",
		}, "idem-session-1"))
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}

		auth := h.authn.authenticated()
		created := h.authn.created()
		if len(auth) != 1 || len(created) != 1 {
			t.Fatalf("calls: authenticate=%d createSession=%d, want 1 and 1", len(auth), len(created))
		}
		if auth[0].IdempotencyKey == created[0].IdempotencyKey {
			t.Fatalf("both commands derived event ids from the same key %q; the first event of "+
				"each would claim the same id and one append would silently collapse",
				auth[0].IdempotencyKey)
		}
		for _, key := range []string{auth[0].IdempotencyKey, created[0].IdempotencyKey} {
			if len(key) <= len("idem-session-1") || key[:len("idem-session-1")] != "idem-session-1" {
				t.Fatalf("derived key %q does not carry the client's key at its head", key)
			}
		}
		if auth[0].Identifier != "ada@example.com" || auth[0].Password != "hunter2" ||
			auth[0].Code != "123456" || auth[0].DeviceID != "dev_9f2c1b7e" {
			t.Fatalf("credentials were not re-presented to Authenticate: %+v", auth[0])
		}
		if created[0].DeviceID != "dev_9f2c1b7e" {
			t.Fatalf("device id = %q, want dev_9f2c1b7e", created[0].DeviceID)
		}
	})

	t.Run("the minted session is returned once and in full", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.authn.createFn = func(app.CreateSessionCommand) (app.CreateSessionResult, error) {
			return app.CreateSessionResult{
				SessionID:                  sessionID,
				SubjectID:                  callerSubject,
				Token:                      "the-plaintext-bearer-token",
				AAL:                        contract.AAL2,
				IdleExpiresAt:              idle,
				AbsoluteExpiresAt:          absolute,
				RequiresCredentialRotation: true,
			}, nil
		}

		resp, err := h.client.CreateSession(t.Context(), withKey(&identityv1.CreateSessionRequest{
			Identifier: "ada@example.com", Password: "hunter2", Code: "123456",
		}, "idem-session-2"))
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		if resp.Msg.GetToken() != "the-plaintext-bearer-token" {
			t.Errorf("token = %q", resp.Msg.GetToken())
		}
		if resp.Msg.GetSessionId() != sessionID.String() {
			t.Errorf("session_id = %q, want %q", resp.Msg.GetSessionId(), sessionID.String())
		}
		if resp.Msg.GetSubjectId() != callerSubject {
			t.Errorf("subject_id = %q, want %q", resp.Msg.GetSubjectId(), callerSubject)
		}
		if resp.Msg.GetAssuranceLevel() != optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2 {
			t.Errorf("assurance_level = %v", resp.Msg.GetAssuranceLevel())
		}
		if !resp.Msg.GetIdleExpiresAt().AsTime().Equal(idle) {
			t.Errorf("idle_expires_at = %v, want %v", resp.Msg.GetIdleExpiresAt().AsTime(), idle)
		}
		if !resp.Msg.GetAbsoluteExpiresAt().AsTime().Equal(absolute) {
			t.Errorf("absolute_expires_at = %v, want %v",
				resp.Msg.GetAbsoluteExpiresAt().AsTime(), absolute)
		}
		if !resp.Msg.GetRequiresCredentialRotation() {
			t.Error("requires_credential_rotation = false")
		}
	})

	// The token belongs to this response and to no other. Every other RPC is
	// driven against the same fake result, and none of them may carry it.
	t.Run("the bearer token appears in no other response", func(t *testing.T) {
		t.Parallel()
		const token = "the-plaintext-bearer-token"

		h := newHarness(t)
		h.authn.createFn = func(app.CreateSessionCommand) (app.CreateSessionResult, error) {
			return app.CreateSessionResult{
				SessionID: sessionID, SubjectID: callerSubject, Token: token,
				AAL: contract.AAL2, IdleExpiresAt: idle, AbsoluteExpiresAt: absolute,
			}, nil
		}
		h.queries.accountFn = func(string) (app.AccountView, error) {
			return app.AccountView{SubjectID: callerSubject, UserID: callerUser}, nil
		}

		ctx := t.Context()
		if _, err := h.client.CreateSession(ctx, withKey(&identityv1.CreateSessionRequest{
			Identifier: "ada@example.com", Password: "hunter2", Code: "123456",
		}, "idem-session-3")); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}

		others := map[string]func() (proto.Message, error){
			"GetUser": func() (proto.Message, error) {
				r, err := h.client.GetUser(ctx, connect.NewRequest(&identityv1.GetUserRequest{}))
				if err != nil {
					return nil, err
				}
				return r.Msg, nil
			},
			"ListSessions": func() (proto.Message, error) {
				r, err := h.client.ListSessions(ctx,
					connect.NewRequest(&identityv1.ListSessionsRequest{}))
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
			"ListLoginHistory": func() (proto.Message, error) {
				r, err := h.client.ListLoginHistory(ctx,
					connect.NewRequest(&identityv1.ListLoginHistoryRequest{}))
				if err != nil {
					return nil, err
				}
				return r.Msg, nil
			},
			"Authenticate": func() (proto.Message, error) {
				r, err := h.client.Authenticate(ctx, withKey(
					&identityv1.AuthenticateRequest{Identifier: "ada@example.com"}, "idem-session-4"))
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
			if containsToken(raw, token) {
				t.Errorf("%s returned the session bearer token", name)
			}
		}
	})

	// The evidence CreateSession needs is unserializable and unconstructible
	// outside app, so the only Proof a test can observe is the zero one. What is
	// asserted is that the handler PASSES IT THROUGH rather than branching on
	// SecondFactorRequired and inventing a different outcome: a zero Proof mints
	// nothing, and the refusal is the app layer's single undifferentiated one.
	t.Run("an incomplete ceremony still exchanges its proof, and does not branch", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.authn.authenticateFn = func(app.AuthenticateCommand) (app.AuthenticateResult, error) {
			return app.AuthenticateResult{
				SecondFactorRequired: true,
				Offered:              []contract.MethodKind{contract.MethodTOTP},
			}, nil
		}
		h.authn.createFn = func(cmd app.CreateSessionCommand) (app.CreateSessionResult, error) {
			if cmd.Proof.SubjectID() != "" || cmd.Proof.AAL() != contract.AAL0 {
				t.Errorf("a non-zero proof reached CreateSession from an incomplete ceremony")
			}
			return app.CreateSessionResult{}, errs.Unauthenticatedf(
				"this request has not authenticated")
		}

		_, err := h.client.CreateSession(t.Context(), withKey(&identityv1.CreateSessionRequest{
			Identifier: "ada@example.com", Password: "hunter2",
		}, "idem-session-5"))
		requireCode(t, err, connect.CodeUnauthenticated)

		if got := len(h.authn.created()); got != 1 {
			t.Fatalf("app.CreateSession called %d times, want 1 — the handler short-circuited "+
				"on SecondFactorRequired instead of letting app refuse", got)
		}
	})

	t.Run("a failed authentication never reaches CreateSession", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.authn.authenticateFn = func(app.AuthenticateCommand) (app.AuthenticateResult, error) {
			return app.AuthenticateResult{}, errs.Unauthenticatedf("authentication failed")
		}

		_, err := h.client.CreateSession(t.Context(), withKey(&identityv1.CreateSessionRequest{
			Identifier: "ada@example.com", Password: "wrong",
		}, "idem-session-6"))
		requireCode(t, err, connect.CodeUnauthenticated)

		if got := len(h.authn.created()); got != 0 {
			t.Fatalf("app.CreateSession was called %d times after a refused authentication", got)
		}
	})
}

// containsToken reports whether raw wire bytes contain the token's bytes.
func containsToken(raw []byte, token string) bool {
	return len(token) > 0 && indexOf(raw, []byte(token)) >= 0
}

func indexOf(haystack, needle []byte) int {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return -1
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// TestResendEmailVerification is where the enumeration property is asserted at
// the WIRE, which is the only place it can be asserted honestly: the app layer
// can return four different outcomes and this layer must render all four the
// same, so a test that inspected an app result would be testing the wrong side of
// the boundary.
func TestResendEmailVerification(t *testing.T) {
	t.Parallel()

	t.Run("the request is mapped onto the command, key included", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)

		_, err := h.client.ResendEmailVerification(t.Context(),
			withKey(&identityv1.ResendEmailVerificationRequest{Email: "ada@example.com"},
				"idem-resend-1"))
		if err != nil {
			t.Fatalf("ResendEmailVerification: %v", err)
		}

		cmds := h.resender.resends()
		if len(cmds) != 1 {
			t.Fatalf("app.Resend called %d times, want 1", len(cmds))
		}
		if cmds[0].Email != "ada@example.com" {
			t.Errorf("Email = %q, want %q", cmds[0].Email, "ada@example.com")
		}
		if cmds[0].IdempotencyKey != "idem-resend-1" {
			t.Errorf("IdempotencyKey = %q, want %q", cmds[0].IdempotencyKey, "idem-resend-1")
		}
		// The per-caller ceiling has nothing to count against without this, and the
		// app layer refuses an empty one — so an unset scope is a 500 on every
		// resend rather than a silently disabled axis. Asserted here because the
		// value comes from the TRANSPORT, which only a real server produces.
		if cmds[0].CallerScope == "" {
			t.Error("the handler passed no caller scope; the per-caller ceiling would " +
				"have nothing to count against")
		}
		// The peer address, with the port stripped. A scope that still carried the
		// ephemeral port would give every new TCP connection a fresh budget, which
		// makes the ceiling free to defeat.
		if strings.Contains(cmds[0].CallerScope, ":") &&
			!strings.HasPrefix(cmds[0].CallerScope, "::") {
			t.Errorf("caller scope %q still carries a port", cmds[0].CallerScope)
		}
	})

	// The trust boundary, asserted at the WIRE for the same reason the scope
	// itself is: only a real server produces a peer address, and the whole point
	// of the property is that the header loses to it.
	t.Run("the default trusts no proxy, so X-Forwarded-For cannot choose a bucket",
		func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)

			req := withKey(&identityv1.ResendEmailVerificationRequest{Email: "ada@example.com"},
				"idem-resend-xff")
			// A caller writing several plausible client addresses, exactly as an
			// attacker evading a per-caller ceiling would.
			req.Header().Set("X-Forwarded-For", "192.0.2.111, 198.51.100.222")

			if _, err := h.client.ResendEmailVerification(t.Context(), req); err != nil {
				t.Fatalf("ResendEmailVerification: %v", err)
			}

			cmds := h.resender.resends()
			if len(cmds) != 1 {
				t.Fatalf("app.Resend called %d times, want 1", len(cmds))
			}
			for _, spoofed := range []string{"192.0.2.111", "198.51.100.222"} {
				if strings.Contains(cmds[0].CallerScope, spoofed) {
					t.Errorf("caller scope %q was taken from X-Forwarded-For with the "+
						"default trust boundary of zero hops; the ceiling would then be "+
						"keyed on a value the attacker writes",
						cmds[0].CallerScope)
				}
			}
		})

	// The other half: once an operator declares a hop, the header IS the scope —
	// otherwise the setting exists and does nothing, which is the failure this
	// whole change is fixing.
	t.Run("one trusted hop takes the last entry of X-Forwarded-For", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, options{trustedProxyHops: 1})

		req := withKey(&identityv1.ResendEmailVerificationRequest{Email: "ada@example.com"},
			"idem-resend-xff-trusted")
		req.Header().Set("X-Forwarded-For", "192.0.2.111, 198.51.100.222")

		if _, err := h.client.ResendEmailVerification(t.Context(), req); err != nil {
			t.Fatalf("ResendEmailVerification: %v", err)
		}

		cmds := h.resender.resends()
		if len(cmds) != 1 {
			t.Fatalf("app.Resend called %d times, want 1", len(cmds))
		}
		if cmds[0].CallerScope != "198.51.100.222" {
			t.Errorf("caller scope = %q, want %q — the rightmost entry is the one the "+
				"single trusted proxy appended; anything else is caller-written",
				cmds[0].CallerScope, "198.51.100.222")
		}
	})

	// The four outcomes an unauthenticated caller must not be able to tell apart:
	// no account, a link sent, an account that is already verified, and one that
	// cannot be verified at all. Compared as BYTES, so a field added later that
	// carried the difference is caught here and nowhere else.
	t.Run("every outcome produces an identical response", func(t *testing.T) {
		t.Parallel()

		outcomes := []app.ResendOutcome{
			app.ResendNoAccount,
			app.ResendRequested,
			app.ResendAlreadyVerified,
			app.ResendNotPending,
			app.ResendRaced,
		}
		responses := make([][]byte, 0, len(outcomes))
		for _, outcome := range outcomes {
			h := newHarness(t)
			h.resender.resendFn = func(app.ResendVerificationCommand) (
				app.ResendVerificationResult, error,
			) {
				return app.ResendVerificationResult{Outcome: outcome}, nil
			}
			resp, err := h.client.ResendEmailVerification(t.Context(),
				withKey(&identityv1.ResendEmailVerificationRequest{Email: "ada@example.com"},
					"idem-resend-2"))
			if err != nil {
				t.Fatalf("ResendEmailVerification(outcome=%v): %v", outcome, err)
			}
			raw, merr := proto.Marshal(resp.Msg)
			if merr != nil {
				t.Fatalf("marshalling the response: %v", merr)
			}
			responses = append(responses, raw)
		}
		for i, raw := range responses {
			if string(raw) != string(responses[0]) {
				t.Fatalf("outcome %v produced %x while %v produced %x; the difference IS "+
					"the account-existence oracle this endpoint exists to avoid being",
					outcomes[i], raw, outcomes[0], responses[0])
			}
		}
		if len(responses[0]) != 0 {
			t.Fatalf("ResendEmailVerificationResponse carries %d bytes; it must stay empty",
				len(responses[0]))
		}
	})

	t.Run("a rate-limited resend is refused with RESOURCE_EXHAUSTED", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.resender.resendFn = func(app.ResendVerificationCommand) (
			app.ResendVerificationResult, error,
		) {
			return app.ResendVerificationResult{}, errs.RateLimitedf("too many")
		}

		_, err := h.client.ResendEmailVerification(t.Context(),
			withKey(&identityv1.ResendEmailVerificationRequest{Email: "ada@example.com"},
				"idem-resend-3"))
		requireCode(t, err, connect.CodeResourceExhausted)
	})

	// Public methods skip gate 5, so this refusal is the handler's own.
	t.Run("a missing idempotency key is refused before the app is called", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)

		_, err := h.client.ResendEmailVerification(t.Context(),
			connect.NewRequest(&identityv1.ResendEmailVerificationRequest{
				Email: "ada@example.com",
			}))
		requireCode(t, err, connect.CodeInvalidArgument)
		if got := len(h.resender.resends()); got != 0 {
			t.Errorf("the app was called %d times without an idempotency key", got)
		}
	})

	// Public: reachable with no session at all. This is the population the RPC
	// exists for — a Pending account can hold no session, so an authenticated
	// resend would serve nobody who needs it.
	t.Run("it is reachable without a session", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, options{authnErr: errs.Unauthenticatedf("no session")})

		if _, err := h.client.ResendEmailVerification(t.Context(),
			withKey(&identityv1.ResendEmailVerificationRequest{Email: "ada@example.com"},
				"idem-resend-4")); err != nil {
			t.Fatalf("an unauthenticated resend was refused with %v; the accounts that "+
				"need this call are exactly the ones that cannot obtain a session", err)
		}
	})
}

func TestRequestPasswordReset(t *testing.T) {
	t.Parallel()

	t.Run("the request is mapped onto the command, key and caller scope included",
		func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)

			_, err := h.client.RequestPasswordReset(t.Context(),
				withKey(&identityv1.RequestPasswordResetRequest{Email: "ada@example.com"},
					"idem-reset-1"))
			if err != nil {
				t.Fatalf("RequestPasswordReset: %v", err)
			}

			cmds := h.resets.requests()
			if len(cmds) != 1 {
				t.Fatalf("app.Request called %d times, want 1", len(cmds))
			}
			if cmds[0].Email != "ada@example.com" {
				t.Errorf("Email = %q, want %q", cmds[0].Email, "ada@example.com")
			}
			if cmds[0].IdempotencyKey != "idem-reset-1" {
				t.Errorf("IdempotencyKey = %q, want %q", cmds[0].IdempotencyKey, "idem-reset-1")
			}
			// Without a scope the per-caller ceiling has nothing to count against,
			// and the app layer refuses an empty one — so an unset scope is a 500 on
			// every reset request rather than a silently disabled axis. Asserted here
			// because the value comes from the TRANSPORT, which only a real server
			// produces.
			if cmds[0].CallerScope == "" {
				t.Error("the handler passed no caller scope; the per-caller ceiling would " +
					"have nothing to count against")
			}
		})

	// The trust boundary, asserted at the WIRE. A reset request is a mail trigger
	// aimed at somebody else's mailbox, so a caller able to choose their own
	// rate-limit bucket by writing a header defeats the only control on it.
	t.Run("the default trusts no proxy, so X-Forwarded-For cannot choose a bucket",
		func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)

			req := withKey(&identityv1.RequestPasswordResetRequest{Email: "ada@example.com"},
				"idem-reset-xff")
			req.Header().Set("X-Forwarded-For", "192.0.2.111, 198.51.100.222")

			if _, err := h.client.RequestPasswordReset(t.Context(), req); err != nil {
				t.Fatalf("RequestPasswordReset: %v", err)
			}
			cmds := h.resets.requests()
			if len(cmds) != 1 {
				t.Fatalf("app.Request called %d times, want 1", len(cmds))
			}
			for _, spoofed := range []string{"192.0.2.111", "198.51.100.222"} {
				if strings.Contains(cmds[0].CallerScope, spoofed) {
					t.Errorf("caller scope %q was taken from X-Forwarded-For with the "+
						"default trust boundary of zero hops", cmds[0].CallerScope)
				}
			}
		})

	// The five outcomes an unauthenticated caller must not be able to tell apart.
	// Compared as BYTES, so a field added later that carried the difference — a
	// `sent` flag, a retry hint — is caught here and nowhere else.
	t.Run("every outcome produces an identical response", func(t *testing.T) {
		t.Parallel()

		outcomes := []app.ResetOutcome{
			app.ResetNoAccount,
			app.ResetRequested,
			app.ResetNoPassword,
			app.ResetNotEligible,
			app.ResetRaced,
		}
		responses := make([][]byte, 0, len(outcomes))
		for _, outcome := range outcomes {
			h := newHarness(t)
			h.resets.requestFn = func(app.RequestPasswordResetCommand) (
				app.RequestPasswordResetResult, error,
			) {
				return app.RequestPasswordResetResult{Outcome: outcome}, nil
			}
			resp, err := h.client.RequestPasswordReset(t.Context(),
				withKey(&identityv1.RequestPasswordResetRequest{Email: "ada@example.com"},
					"idem-reset-2"))
			if err != nil {
				t.Fatalf("RequestPasswordReset(outcome=%v): %v", outcome, err)
			}
			raw, merr := proto.Marshal(resp.Msg)
			if merr != nil {
				t.Fatalf("marshalling the response: %v", merr)
			}
			responses = append(responses, raw)
		}
		for i, raw := range responses {
			if string(raw) != string(responses[0]) {
				t.Fatalf("outcome %v produced %x while %v produced %x; the difference IS "+
					"the account-existence oracle this endpoint exists to avoid being",
					outcomes[i], raw, outcomes[0], responses[0])
			}
		}
		if len(responses[0]) != 0 {
			t.Fatalf("RequestPasswordResetResponse carries %d bytes; it must stay empty",
				len(responses[0]))
		}
	})

	t.Run("a rate-limited request is refused with RESOURCE_EXHAUSTED", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.resets.requestFn = func(app.RequestPasswordResetCommand) (
			app.RequestPasswordResetResult, error,
		) {
			return app.RequestPasswordResetResult{}, errs.RateLimitedf("too many")
		}

		_, err := h.client.RequestPasswordReset(t.Context(),
			withKey(&identityv1.RequestPasswordResetRequest{Email: "ada@example.com"},
				"idem-reset-3"))
		requireCode(t, err, connect.CodeResourceExhausted)
	})

	// Public methods skip gate 5, so this refusal is the handler's own.
	t.Run("a missing idempotency key is refused before the app is called", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)

		_, err := h.client.RequestPasswordReset(t.Context(),
			connect.NewRequest(&identityv1.RequestPasswordResetRequest{
				Email: "ada@example.com",
			}))
		requireCode(t, err, connect.CodeInvalidArgument)
		if got := len(h.resets.requests()); got != 0 {
			t.Errorf("the app was called %d times without an idempotency key", got)
		}
	})

	// Public: reachable with no session at all. The population that needs this
	// call is exactly the population that cannot obtain one.
	t.Run("it is reachable without a session", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, options{authnErr: errs.Unauthenticatedf("no session")})

		if _, err := h.client.RequestPasswordReset(t.Context(),
			withKey(&identityv1.RequestPasswordResetRequest{Email: "ada@example.com"},
				"idem-reset-4")); err != nil {
			t.Fatalf("an unauthenticated reset request was refused with %v", err)
		}
	})
}

func TestResetPassword(t *testing.T) {
	t.Parallel()

	t.Run("the token and the password reach the app unchanged", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)

		_, err := h.client.ResetPassword(t.Context(),
			withKey(&identityv1.ResetPasswordRequest{
				Token:    "a-reset-token",
				Password: "a-brand-new-passphrase",
			}, "idem-complete-1"))
		if err != nil {
			t.Fatalf("ResetPassword: %v", err)
		}

		cmds := h.resets.completions()
		if len(cmds) != 1 {
			t.Fatalf("app.Complete called %d times, want 1", len(cmds))
		}
		if cmds[0].Token != "a-reset-token" {
			t.Errorf("Token = %q, want %q", cmds[0].Token, "a-reset-token")
		}
		if cmds[0].Password != "a-brand-new-passphrase" {
			t.Errorf("Password = %q, want the password as typed", cmds[0].Password)
		}
		if cmds[0].IdempotencyKey != "idem-complete-1" {
			t.Errorf("IdempotencyKey = %q, want %q", cmds[0].IdempotencyKey, "idem-complete-1")
		}
	})

	// The response must stay empty however much the app layer knows.
	//
	// This is the ASVS 5.0 V6.4.3 assertion at the transport: a reset must not
	// advance the caller towards a session, and the cheapest way to be sure is
	// that a fully populated result still marshals to zero bytes. A field added
	// later — a subject id, "you may now sign in", a token — fails here.
	t.Run("a fully populated result still marshals to nothing", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.resets.completeFn = func(app.ResetPasswordCommand) (app.ResetPasswordResult, error) {
			return app.ResetPasswordResult{
				SubjectID:       "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV",
				UserID:          ids.MustParse[ids.User]("usr_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
				SessionsRevoked: 3,
				TokensRevoked:   2,
			}, nil
		}

		resp, err := h.client.ResetPassword(t.Context(),
			withKey(&identityv1.ResetPasswordRequest{
				Token:    "a-reset-token",
				Password: "a-brand-new-passphrase",
			}, "idem-complete-2"))
		if err != nil {
			t.Fatalf("ResetPassword: %v", err)
		}
		raw, merr := proto.Marshal(resp.Msg)
		if merr != nil {
			t.Fatalf("marshalling the response: %v", merr)
		}
		if len(raw) != 0 {
			t.Fatalf("ResetPasswordResponse carries %d bytes (%x); a reset must return "+
				"nothing a client could mistake for a session", len(raw), raw)
		}
	})

	// A spent, expired or unknown link is one refusal, rendered by the shared
	// mapping and nothing else.
	t.Run("an unusable link is INVALID_ARGUMENT", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.resets.completeFn = func(app.ResetPasswordCommand) (app.ResetPasswordResult, error) {
			return app.ResetPasswordResult{}, errs.ValidationFailedf(
				"this password-reset link is no longer valid; request a new one")
		}

		_, err := h.client.ResetPassword(t.Context(),
			withKey(&identityv1.ResetPasswordRequest{
				Token:    "spent",
				Password: "a-brand-new-passphrase",
			}, "idem-complete-3"))
		requireCode(t, err, connect.CodeInvalidArgument)
	})

	// The schema-level refusals — an empty token, a password below the floor —
	// are protovalidate's, and protovalidate is an interceptor this harness does
	// not run. They are asserted against the REAL server instead, in
	// internal/adapter/identityit, where the production interceptor chain is the
	// one under test. Restating them here with a hand-rolled check would assert
	// that this test file can validate a message, which nothing depends on.

	t.Run("it is reachable without a session", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, options{authnErr: errs.Unauthenticatedf("no session")})

		if _, err := h.client.ResetPassword(t.Context(),
			withKey(&identityv1.ResetPasswordRequest{
				Token:    "a-reset-token",
				Password: "a-brand-new-passphrase",
			}, "idem-complete-6")); err != nil {
			t.Fatalf("an unauthenticated reset was refused with %v; it is reached from a "+
				"mailbox by a browser that has never authenticated", err)
		}
	})
}

// ---------------------------------------------------------------------------
// CheckUsernameAvailability
// ---------------------------------------------------------------------------

// TestCheckUsernameAvailability is the one public endpoint in this service whose
// two outcomes are DELIBERATELY distinguishable.
//
// Every other public handler here drops what it learned, because an address is
// secret and a distinguishable answer is an account-existence oracle. A handle is
// not secret — publication is its entire purpose (ADR-051) — so this handler
// returns the answer, and this test is where that difference is written down so
// nobody "harmonises" it later.
func TestCheckUsernameAvailability(t *testing.T) {
	t.Parallel()

	t.Run("the answer reaches the wire, both ways", func(t *testing.T) {
		t.Parallel()
		for _, available := range []bool{true, false} {
			t.Run(map[bool]string{true: "available", false: "taken"}[available],
				func(t *testing.T) {
					t.Parallel()
					h := newHarness(t)
					h.usernames.checkFn = func(app.CheckUsernameCommand) (app.CheckUsernameResult, error) {
						return app.CheckUsernameResult{
							Available: available, Username: "ada_lovelace",
						}, nil
					}

					resp, err := h.client.CheckUsernameAvailability(t.Context(),
						connect.NewRequest(&identityv1.CheckUsernameAvailabilityRequest{
							Username: "Ada_Lovelace",
						}))
					if err != nil {
						t.Fatalf("CheckUsernameAvailability: %v", err)
					}
					if resp.Msg.GetAvailable() != available {
						t.Errorf("available=%v, want %v — the two outcomes must stay "+
							"distinguishable here, or the signup form cannot tell a person "+
							"their handle is taken until after they have spent a link",
							resp.Msg.GetAvailable(), available)
					}
					// The CANONICAL form, not what was typed. A client that echoed the
					// input would show somebody @Ada_Lovelace for a handle that will be
					// claimed as @ada_lovelace.
					if got := resp.Msg.GetUsername(); got != "ada_lovelace" {
						t.Errorf("username %q, want the normalized ada_lovelace", got)
					}
				})
		}
	})

	// Normalization belongs to the app layer, and the transport must not do any of
	// it. A handler that trimmed or folded here would be a SECOND definition of
	// the canonical form, and the two would disagree the first time either changed
	// — which for a value that names a permanent stream is unrecoverable.
	t.Run("the raw handle reaches the app layer unchanged", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)

		if _, err := h.client.CheckUsernameAvailability(t.Context(),
			connect.NewRequest(&identityv1.CheckUsernameAvailabilityRequest{
				Username: "Ada_Lovelace",
			})); err != nil {
			t.Fatalf("CheckUsernameAvailability: %v", err)
		}
		cmds := h.usernames.checks()
		if len(cmds) != 1 {
			t.Fatalf("app.Check called %d times, want 1", len(cmds))
		}
		if cmds[0].Username != "Ada_Lovelace" {
			t.Errorf("the app layer received %q, want the raw input", cmds[0].Username)
		}
	})

	// The response carries exactly two fields, and this is the type-level half of
	// the "no reason field" rule. Taken, reserved and tombstoned are one answer,
	// and the third is the one that matters: it would announce that the account
	// behind a handle was erased.
	t.Run("the response has no field that could name a reason", func(t *testing.T) {
		t.Parallel()
		fields := (&identityv1.CheckUsernameAvailabilityResponse{}).
			ProtoReflect().Descriptor().Fields()
		allowed := map[string]bool{"available": true, "username": true}
		for i := range fields.Len() {
			name := string(fields.Get(i).Name())
			if !allowed[name] {
				t.Errorf("CheckUsernameAvailabilityResponse grew the field %q. Taken, "+
					"reserved and tombstoned must stay ONE answer: 'this handle belonged "+
					"to an erased account' is a fact about a person, and the tombstone "+
					"exists to protect that person (ADR-051)", name)
			}
		}
	})

	// The caller scope comes from the connection, exactly as the resend's does.
	// A ceiling keyed on a field the caller can choose is not a ceiling.
	t.Run("the caller scope comes from the transport, not from a field", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)

		req := connect.NewRequest(&identityv1.CheckUsernameAvailabilityRequest{
			Username: "ada_lovelace",
		})
		req.Header().Set("X-Forwarded-For", "192.0.2.111, 198.51.100.222")
		if _, err := h.client.CheckUsernameAvailability(t.Context(), req); err != nil {
			t.Fatalf("CheckUsernameAvailability: %v", err)
		}

		cmds := h.usernames.checks()
		if len(cmds) != 1 {
			t.Fatalf("app.Check called %d times, want 1", len(cmds))
		}
		if cmds[0].CallerScope == "" {
			t.Fatal("no caller scope was derived; every request would then share one bucket")
		}
		for _, spoofed := range []string{"192.0.2.111", "198.51.100.222"} {
			if strings.Contains(cmds[0].CallerScope, spoofed) {
				t.Errorf("caller scope %q was taken from X-Forwarded-For with the default "+
					"trust boundary of zero hops", cmds[0].CallerScope)
			}
		}
	})

	// It is a READ, and it needs no idempotency key: it appends nothing, mints
	// nothing and spends nothing, so there is no second application for a key to
	// collapse. Every mutating RPC in this service refuses a request without one,
	// and this test says why this one does not.
	t.Run("no idempotency key is required", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)

		if _, err := h.client.CheckUsernameAvailability(t.Context(),
			connect.NewRequest(&identityv1.CheckUsernameAvailabilityRequest{
				Username: "ada_lovelace",
			})); err != nil {
			t.Fatalf("a read was refused for want of an idempotency key: %v", err)
		}
	})

	// An app-layer refusal is rendered by the shared mapping and by nothing else,
	// which is what keeps this handler from acquiring a switch.
	t.Run("a rate-limited check is rendered by the shared mapping", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.usernames.checkFn = func(app.CheckUsernameCommand) (app.CheckUsernameResult, error) {
			return app.CheckUsernameResult{}, errs.RateLimitedf("too many username checks")
		}

		_, err := h.client.CheckUsernameAvailability(t.Context(),
			connect.NewRequest(&identityv1.CheckUsernameAvailabilityRequest{
				Username: "ada_lovelace",
			}))
		requireCode(t, err, connect.CodeResourceExhausted)
	})
}

// TestCheckUsernameAvailabilityIsPublicAndAREAD pins the policy annotations.
//
// Public because the population that needs it — somebody choosing a handle at
// the signup form — has no account by definition. READ because it appends
// nothing: classing it as a WRITE would block it once an org is suspended, which
// makes no sense for a call that creates nothing and belongs to no org.
func TestCheckUsernameAvailabilityIsPublicAndARead(t *testing.T) {
	t.Parallel()

	method := identityv1.File_chronos_identity_v1_identity_proto.
		Services().ByName("IdentityService").Methods().ByName("CheckUsernameAvailability")
	if method == nil {
		t.Fatal("CheckUsernameAvailability is not declared on IdentityService")
	}
	opts := method.Options()
	if !proto.GetExtension(opts, optionsv1.E_Public).(bool) {
		t.Error("CheckUsernameAvailability is not public; the people who need it have " +
			"no account, so requiring one would make the endpoint serve nobody")
	}
	if got := proto.GetExtension(opts, optionsv1.E_Operation).(optionsv1.OperationClass); got !=
		optionsv1.OperationClass_OPERATION_CLASS_READ {
		t.Errorf("operation class %s, want READ — it appends nothing and mints nothing", got)
	}
}

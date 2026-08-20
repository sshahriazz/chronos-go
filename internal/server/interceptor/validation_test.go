package interceptor_test

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"connectrpc.com/validate"
	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/identity/v1/identityv1connect"
)

// The declarative constraints in identity.proto are only worth the bytes they
// occupy if something ENFORCES them, and this file is the thing that proves it
// does. It is an end-to-end test through the real `connectrpc.com/validate`
// interceptor, over the real generated messages, against a real HTTP server —
// not a call to protovalidate.Validate, which would pass just as happily with
// the interceptor deleted from the composition root.
//
// Every case comes in a pair. A rule that only ever rejects is indistinguishable
// from a rule that rejects everything, and one that only ever accepts is
// indistinguishable from no rule at all; asserting both directions is what makes
// the assertion mean something. The `accepts` half also proves the request
// reached the handler, so a rule can never quietly refuse valid input.

// reachedHandler is what a passing request sets. Its address is compared rather
// than its value, so a case that never dispatches cannot look like a pass.
type recorder struct {
	identityv1connect.UnimplementedIdentityServiceHandler
	reached bool
}

func (r *recorder) Register(
	context.Context, *connect.Request[identityv1.RegisterRequest],
) (*connect.Response[identityv1.RegisterResponse], error) {
	r.reached = true
	return connect.NewResponse(&identityv1.RegisterResponse{}), nil
}

func (r *recorder) VerifyEmail(
	context.Context, *connect.Request[identityv1.VerifyEmailRequest],
) (*connect.Response[identityv1.VerifyEmailResponse], error) {
	r.reached = true
	return connect.NewResponse(&identityv1.VerifyEmailResponse{}), nil
}

func (r *recorder) Authenticate(
	context.Context, *connect.Request[identityv1.AuthenticateRequest],
) (*connect.Response[identityv1.AuthenticateResponse], error) {
	r.reached = true
	return connect.NewResponse(&identityv1.AuthenticateResponse{}), nil
}

func (r *recorder) CreateSession(
	context.Context, *connect.Request[identityv1.CreateSessionRequest],
) (*connect.Response[identityv1.CreateSessionResponse], error) {
	r.reached = true
	return connect.NewResponse(&identityv1.CreateSessionResponse{}), nil
}

func (r *recorder) ListSessions(
	context.Context, *connect.Request[identityv1.ListSessionsRequest],
) (*connect.Response[identityv1.ListSessionsResponse], error) {
	r.reached = true
	return connect.NewResponse(&identityv1.ListSessionsResponse{}), nil
}

func (r *recorder) ListLoginHistory(
	context.Context, *connect.Request[identityv1.ListLoginHistoryRequest],
) (*connect.Response[identityv1.ListLoginHistoryResponse], error) {
	r.reached = true
	return connect.NewResponse(&identityv1.ListLoginHistoryResponse{}), nil
}

func (r *recorder) EnrollTotp(
	context.Context, *connect.Request[identityv1.EnrollTotpRequest],
) (*connect.Response[identityv1.EnrollTotpResponse], error) {
	r.reached = true
	return connect.NewResponse(&identityv1.EnrollTotpResponse{}), nil
}

func (r *recorder) ConfirmTotp(
	context.Context, *connect.Request[identityv1.ConfirmTotpRequest],
) (*connect.Response[identityv1.ConfirmTotpResponse], error) {
	r.reached = true
	return connect.NewResponse(&identityv1.ConfirmTotpResponse{}), nil
}

func (r *recorder) GenerateRecoveryCodes(
	context.Context, *connect.Request[identityv1.GenerateRecoveryCodesRequest],
) (*connect.Response[identityv1.GenerateRecoveryCodesResponse], error) {
	r.reached = true
	return connect.NewResponse(&identityv1.GenerateRecoveryCodesResponse{}), nil
}

func (r *recorder) RevokeSession(
	context.Context, *connect.Request[identityv1.RevokeSessionRequest],
) (*connect.Response[identityv1.RevokeSessionResponse], error) {
	r.reached = true
	return connect.NewResponse(&identityv1.RevokeSessionResponse{}), nil
}

func (r *recorder) RevokeAllSessions(
	context.Context, *connect.Request[identityv1.RevokeAllSessionsRequest],
) (*connect.Response[identityv1.RevokeAllSessionsResponse], error) {
	r.reached = true
	return connect.NewResponse(&identityv1.RevokeAllSessionsResponse{}), nil
}

// newValidatingClient starts a server carrying ONLY the validation interceptor,
// so a refusal can have come from nowhere else.
func newValidatingClient(t *testing.T) (identityv1connect.IdentityServiceClient, *recorder) {
	t.Helper()

	svc := &recorder{}
	_, handler := identityv1connect.NewIdentityServiceHandler(svc,
		connect.WithInterceptors(validate.NewInterceptor()))

	mux := httptest.NewServer(handler)
	t.Cleanup(mux.Close)

	return identityv1connect.NewIdentityServiceClient(mux.Client(), mux.URL), svc
}

// A ULID body is 26 Crockford base32 characters. Obviously fabricated, and it
// has to be well-formed for the accept half of the session cases to mean
// anything.
const (
	goodSessionID = "sess_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	badSessionID  = "ws_01ARZ3NDEKTSV4RRFFQ69G5FAV"
)

type validationCase struct {
	name string
	call func(context.Context, identityv1connect.IdentityServiceClient) error
	// why records what the rejection is protecting, so a future reader deleting
	// a case has to argue with the reason rather than with the assertion.
	why string
}

// TestValidationRejectsMalformedRequests is the refusal half.
//
// Every case must come back InvalidArgument AND must not reach the handler. The
// second assertion is the one that catches a rule which "fails" for an unrelated
// reason — a handler that itself errored would also produce a non-nil error.
func TestValidationRejectsMalformedRequests(t *testing.T) {
	t.Parallel()

	cases := []validationCase{
		{
			name: "Register/no email",
			why:  "the address is what the account is; an empty one creates an account nobody can reach",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.Register(ctx, connect.NewRequest(&identityv1.RegisterRequest{}))
				return err
			},
		},
		{
			name: "Register/email with no domain",
			why:  "domain.NormalizeEmail requires a local part and a domain",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.Register(ctx, connect.NewRequest(&identityv1.RegisterRequest{
					Email: "not-an-address",
				}))
				return err
			},
		},
		{
			name: "Register/dotless domain",
			why:  "a dotless domain is never routable, so the address can never be verified",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.Register(ctx, connect.NewRequest(&identityv1.RegisterRequest{
					Email: "someone@localhost",
				}))
				return err
			},
		},
		{
			name: "Register/local part over 64 bytes",
			why:  "RFC 5321 §4.5.3.1.1, and domain.MaxLocalPartBytes",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.Register(ctx, connect.NewRequest(&identityv1.RegisterRequest{
					Email: strings.Repeat("a", 65) + "@example.com",
				}))
				return err
			},
		},
		{
			name: "Register/address over 254 bytes",
			why:  "RFC 5321 §4.5.3.1.3, and domain.MaxEmailBytes",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.Register(ctx, connect.NewRequest(&identityv1.RegisterRequest{
					Email: strings.Repeat("a", 60) + "@" + strings.Repeat("b", 200) + ".com",
				}))
				return err
			},
		},
		{
			name: "VerifyEmail/password under 8 characters",
			why: "domain.MinPasswordRunes. The floor lives on THIS message because this is " +
				"where a password is chosen — registration no longer takes one (IDENTITY-REVIEW C8). " +
				"It is not an oracle: the rule runs before the handler, so a short password is " +
				"refused without the token being looked at, let alone spent.",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.VerifyEmail(ctx, connect.NewRequest(&identityv1.VerifyEmailRequest{
					Token:    "a-token-shaped-string",
					Password: "7chars.",
				}))
				return err
			},
		},
		{
			name: "VerifyEmail/password over 4096 bytes",
			why:  "domain.MaxPasswordBytes; an unbounded field is a free way to make one request expensive",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.VerifyEmail(ctx, connect.NewRequest(&identityv1.VerifyEmailRequest{
					Token:    "a-token-shaped-string",
					Password: strings.Repeat("a", 4097),
				}))
				return err
			},
		},
		{
			name: "VerifyEmail/no token",
			why:  "the token IS the authentication for this call",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.VerifyEmail(ctx, connect.NewRequest(&identityv1.VerifyEmailRequest{}))
				return err
			},
		},
		{
			name: "Authenticate/identifier over 254 bytes",
			why:  "no account can hold an address this long, so refusing it discloses nothing",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.Authenticate(ctx, connect.NewRequest(&identityv1.AuthenticateRequest{
					Identifier: strings.Repeat("a", 250) + "@example.com",
					Password:   "correct horse battery staple",
				}))
				return err
			},
		},
		{
			name: "Authenticate/device id over 128 characters",
			why:  "the value enters an append-only event log, where unbounded means unbounded forever",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.Authenticate(ctx, connect.NewRequest(&identityv1.AuthenticateRequest{
					Identifier: "someone@example.com",
					Password:   "correct horse battery staple",
					DeviceId:   strings.Repeat("d", 129),
				}))
				return err
			},
		},
		{
			name: "ListSessions/negative page size",
			why:  "page.Clamp treats a negative size as a caller bug rather than as zero",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.ListSessions(ctx, connect.NewRequest(&identityv1.ListSessionsRequest{
					PageSize: -1,
				}))
				return err
			},
		},
		{
			name: "ListLoginHistory/negative page size",
			why:  "same rule as ListSessions; a per-message rule can be forgotten on one message",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.ListLoginHistory(ctx, connect.NewRequest(&identityv1.ListLoginHistoryRequest{
					PageSize: -50,
				}))
				return err
			},
		},
		{
			name: "EnrollTotp/no account name",
			why:  "the authenticator app would show an unlabelled entry, which is how people delete the wrong credential",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.EnrollTotp(ctx, connect.NewRequest(&identityv1.EnrollTotpRequest{}))
				return err
			},
		},
		{
			name: "ConfirmTotp/no code",
			why:  "authenticated, on the caller's own account: a malformed-input refusal here is not an oracle",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.ConfirmTotp(ctx, connect.NewRequest(&identityv1.ConfirmTotpRequest{}))
				return err
			},
		},
		{
			name: "GenerateRecoveryCodes/count over the maximum",
			why:  "app.MaxRecoveryCodeCount is 20; every code is a row plus a hash in one transaction",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.GenerateRecoveryCodes(ctx, connect.NewRequest(
					&identityv1.GenerateRecoveryCodesRequest{Count: 21}))
				return err
			},
		},
		{
			name: "GenerateRecoveryCodes/negative count",
			why:  "app.mintRecoveryCodes refuses anything below one",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.GenerateRecoveryCodes(ctx, connect.NewRequest(
					&identityv1.GenerateRecoveryCodesRequest{Count: -1}))
				return err
			},
		},
		{
			name: "RevokeSession/no session id",
			why:  "there is no default session to revoke; an empty id would have to mean something",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.RevokeSession(ctx, connect.NewRequest(&identityv1.RevokeSessionRequest{}))
				return err
			},
		},
		{
			name: "RevokeSession/workspace id where a session id belongs",
			why:  "CONVENTIONS §4: a wrong-type identifier is invalid_argument at the boundary, not not-found three layers down",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.RevokeSession(ctx, connect.NewRequest(&identityv1.RevokeSessionRequest{
					SessionId: badSessionID,
				}))
				return err
			},
		},
		{
			name: "RevokeSession/free text in reason",
			why:  "reason enters an event; free text a user typed is where personal data arrives (ADR-002)",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.RevokeSession(ctx, connect.NewRequest(&identityv1.RevokeSessionRequest{
					SessionId: goodSessionID,
					Reason:    "Alice asked me to sign out her iPhone",
				}))
				return err
			},
		},
		{
			name: "RevokeAllSessions/malformed spared session",
			why:  "an unparseable exception would silently spare nothing and sign the caller out",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.RevokeAllSessions(ctx, connect.NewRequest(&identityv1.RevokeAllSessionsRequest{
					ExceptSessionId: "sess_not-a-ulid",
				}))
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client, svc := newValidatingClient(t)

			err := tc.call(t.Context(), client)
			if err == nil {
				t.Fatalf("the request was accepted, so nothing enforces this rule: %s", tc.why)
			}
			if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
				t.Fatalf("code = %s, want invalid_argument (%s); error: %v", got, tc.why, err)
			}
			if svc.reached {
				t.Fatalf("the handler ran anyway: validation is decorative here (%s)", tc.why)
			}
		})
	}
}

// TestValidationAcceptsWellFormedRequests is the acceptance half.
//
// Without it, every rule above would still pass if the interceptor refused
// unconditionally — which is the failure mode a validation test is most likely
// to hide, because a refusal looks like the rule working.
func TestValidationAcceptsWellFormedRequests(t *testing.T) {
	t.Parallel()

	cases := []validationCase{
		{
			name: "Register/ordinary address and password",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.Register(ctx, connect.NewRequest(&identityv1.RegisterRequest{
					Email: "someone@example.com",
				}))
				return err
			},
		},
		{
			name: "Register/internationalized domain",
			why:  "the built-in email rule is ASCII-only; domain.NormalizeEmail converts to punycode instead",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.Register(ctx, connect.NewRequest(&identityv1.RegisterRequest{
					Email: "someone@münchen.example",
				}))
				return err
			},
		},
		{
			name: "Register/plus tag and dots, which are NOT stripped",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.Register(ctx, connect.NewRequest(&identityv1.RegisterRequest{
					Email: "a.b+tag@sub.example.co.uk",
				}))
				return err
			},
		},
		{
			name: "VerifyEmail/password at exactly the 8-character floor",
			why:  "an off-by-one in the floor locks out the shortest permitted password",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.VerifyEmail(ctx, connect.NewRequest(&identityv1.VerifyEmailRequest{
					Token:    "a-token-shaped-string",
					Password: "8charsxx",
				}))
				return err
			},
		},
		{
			name: "Register/no password field exists to violate",
			why: "IDENTITY-REVIEW C8: RegisterRequest carries no password and field 2 is " +
				"reserved. This case is here so that a future field at that number, or a " +
				"revived one under another name, has to be added past a test that says why " +
				"it must not be.",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				msg := &identityv1.RegisterRequest{Email: "someone@example.com"}
				if fd := msg.ProtoReflect().Descriptor().Fields(); fd.Len() != 1 {
					return fmt.Errorf("RegisterRequest has %d fields, want exactly 1 (email); "+
						"a credential set at registration is the pre-hijacking premise", fd.Len())
				}
				_, err := c.Register(ctx, connect.NewRequest(msg))
				return err
			},
		},
		{
			name: "Authenticate/a wrong password is NOT a validation failure",
			why:  "the oracle: a refusal for shape tells an attacker their guess was structurally wrong",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.Authenticate(ctx, connect.NewRequest(&identityv1.AuthenticateRequest{
					Identifier: "someone@example.com",
					Password:   "x", // one character: refused at Register, accepted here
				}))
				return err
			},
		},
		{
			name: "Authenticate/an empty password reaches the handler",
			why:  "even `required` would separate 'you sent nothing' from 'you sent the wrong thing'",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.Authenticate(ctx, connect.NewRequest(&identityv1.AuthenticateRequest{
					Identifier: "someone@example.com",
				}))
				return err
			},
		},
		{
			name: "Authenticate/a malformed identifier reaches the handler",
			why:  "a shape rule would split ADR-036's one refusal into 'not an address' and 'no such account'",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.Authenticate(ctx, connect.NewRequest(&identityv1.AuthenticateRequest{
					Identifier: "not-an-address",
					Password:   "correct horse battery staple",
				}))
				return err
			},
		},
		{
			name: "CreateSession/no code reaches the handler",
			why:  "the message's contract is that a missing second factor is the SAME undifferentiated refusal",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.CreateSession(ctx, connect.NewRequest(&identityv1.CreateSessionRequest{
					Identifier: "someone@example.com",
					Password:   "correct horse battery staple",
				}))
				return err
			},
		},
		{
			name: "CreateSession/a recovery code and a TOTP code are both accepted",
			why:  "a shape rule admitting one would report which factors the account holds",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.CreateSession(ctx, connect.NewRequest(&identityv1.CreateSessionRequest{
					Identifier: "someone@example.com",
					Password:   "correct horse battery staple",
					Code:       "abcd-efgh-jkmn",
				}))
				return err
			},
		},
		{
			name: "ListSessions/zero page size means the server default",
			why:  "zero is 'the caller did not say', not 'the caller asked for none'",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.ListSessions(ctx, connect.NewRequest(&identityv1.ListSessionsRequest{}))
				return err
			},
		},
		{
			name: "ListSessions/an oversized page size is CLAMPED, not refused",
			why:  "page.Clamp caps at 200; a `lte` rule here would refuse what the server chose to satisfy with less",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.ListSessions(ctx, connect.NewRequest(&identityv1.ListSessionsRequest{
					PageSize: 10_000,
				}))
				return err
			},
		},
		{
			name: "GenerateRecoveryCodes/zero means the server default",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.GenerateRecoveryCodes(ctx, connect.NewRequest(
					&identityv1.GenerateRecoveryCodesRequest{}))
				return err
			},
		},
		{
			name: "GenerateRecoveryCodes/count at exactly the maximum",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.GenerateRecoveryCodes(ctx, connect.NewRequest(
					&identityv1.GenerateRecoveryCodesRequest{Count: 20}))
				return err
			},
		},
		{
			name: "RevokeSession/a well-formed session id and snake_case reason",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.RevokeSession(ctx, connect.NewRequest(&identityv1.RevokeSessionRequest{
					SessionId: goodSessionID,
					Reason:    "user_signed_out",
				}))
				return err
			},
		},
		{
			name: "RevokeAllSessions/an empty exception spares nothing",
			why:  "identity.md §7 requires a compromise response to void the asking session too",
			call: func(ctx context.Context, c identityv1connect.IdentityServiceClient) error {
				_, err := c.RevokeAllSessions(ctx, connect.NewRequest(
					&identityv1.RevokeAllSessionsRequest{Reason: "password_reset"}))
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client, svc := newValidatingClient(t)

			err := tc.call(t.Context(), client)
			if err != nil {
				t.Fatalf("a well-formed request was refused: %v (%s)", err, tc.why)
			}
			if !svc.reached {
				t.Fatal("the call returned no error but never reached the handler")
			}
		})
	}
}

// TestValidationReportsTheOffendingField checks that a refusal is actionable.
//
// protovalidate returns a buf.validate.Violations detail naming the field and
// the rule id. A client that cannot see WHICH field failed has to guess, and a
// generic "invalid argument" is what makes people disable client-side validation
// and retry blindly.
func TestValidationReportsTheOffendingField(t *testing.T) {
	t.Parallel()
	client, _ := newValidatingClient(t)

	_, err := client.Register(t.Context(), connect.NewRequest(&identityv1.RegisterRequest{
		Email: "not-an-address",
	}))
	if err == nil {
		t.Fatal("a malformed address was accepted")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("error is a %T, not a *connect.Error", err)
	}
	if len(connectErr.Details()) == 0 {
		t.Fatal("the refusal carries no violation detail, so a client cannot tell which field failed")
	}
	if !strings.Contains(err.Error(), "email") {
		t.Errorf("the refusal does not name the offending field: %v", err)
	}
}

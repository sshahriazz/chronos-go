//go:build integration

package protocolit_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"
	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/identity/v1/identityv1connect"
	profilev1 "github.com/chronos/chronos-go/gen/proto/chronos/profile/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/profile/v1/profilev1connect"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"google.golang.org/protobuf/types/known/emptypb"
)

// TestEveryReadAnswersTheSameOverEveryProtocol is ADR-007's claim, checked.
//
// "All RPC — gRPC, gRPC-Web and HTTP/JSON — is served by ConnectRPC on one port"
// is a promise to a BROWSER as much as to a Go client, and connect-web speaks a
// different wire format from connect-go. Nothing had ever confirmed the deployed
// binary answers it: internal/server/connect/server_test.go drives the same six
// transports, but against a stub service on an httptest server with no
// interceptor stack at all, so it proves the transport is negotiable rather than
// that a GATED RPC survives the trip.
//
// The assertion is equality against the Connect/HTTP1.1 baseline, not merely
// "no error". A protocol that answered with an empty message would pass a
// nil-error check and be completely broken.
func TestEveryReadAnswersTheSameOverEveryProtocol(t *testing.T) {
	bearer := h.activeBearer(t)

	for _, rc := range reads() {
		t.Run(rc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()

			token := bearer
			if rc.public {
				token = ""
			}

			var baseline string
			for i, tr := range transports() {
				got, err := rc.call(ctx, clientFor(tr.h2), token, tr.opts...)
				if err != nil {
					t.Errorf("%s over %s: %s", rc.name, tr.name, describe(err))
					continue
				}
				if i == 0 {
					baseline = got
					t.Logf("%s baseline (%s): %s", rc.name, tr.name, got)
					continue
				}
				if got != baseline {
					t.Errorf("%s over %s answered\n  %s\nbut over %s answered\n  %s\n"+
						"the wire format may not change the answer (ADR-007)",
						rc.name, tr.name, got, transports()[0].name, baseline)
				}
			}
		})
	}
}

// TestEveryMutationAnswersOverEveryProtocol is the same claim for the write
// side, where it is harder: a mutation carries an Idempotency-Key, and gate 5
// wraps the handler rather than preceding it (CONVENTIONS §6). So this exercises
// the claim-execute-store path once per wire format, with a distinct key each
// time so every run is a real execution rather than a replay.
func TestEveryMutationAnswersOverEveryProtocol(t *testing.T) {
	bearer := h.activeBearer(t)

	for _, mc := range mutations() {
		t.Run(mc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()

			for _, tr := range transports() {
				if err := mc.call(ctx, clientFor(tr.h2), bearer, newIdempotencyKey(), tr.opts...); err != nil {
					t.Errorf("%s over %s: %s", mc.name, tr.name, describe(err))
				}
			}
		})
	}
}

// TestTheErrorReasonSurvivesEveryProtocol is the contract CONVENTIONS §5 states
// and nothing had checked.
//
// > Clients branch on `PLAN_UPGRADE_REQUIRED` versus `ACCESS_DENIED` to show
// > completely different UI. NEVER on the HTTP status.
//
// That is only true if `reason` REACHES the client, and where it travels differs
// per protocol: Connect puts the detail in the JSON body, gRPC puts it in a
// `grpc-status-details-bin` trailer, and gRPC-Web puts that trailer inside the
// response body. Three encodings, one contract, and a client that cannot read
// the reason is a client that must branch on the status — which is precisely
// what the convention forbids.
//
// Three refusals, chosen because they come from three different places in the
// stack: the authn gate, the AAL comparison inside `enforce`, and the handler's
// own idempotency check. A reason that survives one of those and not the others
// would be a mapping gap rather than a transport gap.
func TestTheErrorReasonSurvivesEveryProtocol(t *testing.T) {
	bootBearer := h.bootstrapBearer(t)
	bearer := h.activeBearer(t)

	cases := []struct {
		name   string
		code   connectrpc.Code
		reason errs.Reason
		why    string
		call   func(ctx context.Context, tr transport) error
	}{
		{
			name:   "no bearer at all/GetUser",
			code:   connectrpc.CodeUnauthenticated,
			reason: errs.Unauthenticated,
			why:    "the authn gate refuses before anything else runs (ADR-036: discloses nothing)",
			call: func(ctx context.Context, tr transport) error {
				_, err := identityv1connect.NewIdentityServiceClient(
					clientFor(tr.h2), h.baseURL, tr.opts...).
					GetUser(ctx, connectrpc.NewRequest(&identityv1.GetUserRequest{}))
				return err
			},
		},
		{
			name:   "AAL1 session/GenerateRecoveryCodes",
			code:   connectrpc.CodePermissionDenied,
			reason: errs.StepUpRequired,
			why: "min_aal is ASSURANCE_LEVEL_2 with no bootstrap exemption, so a " +
				"password-only session is refused by the AAL comparison in enforce",
			call: func(ctx context.Context, tr transport) error {
				_, err := identityv1connect.NewIdentityServiceClient(
					clientFor(tr.h2), h.baseURL, tr.opts...).
					GenerateRecoveryCodes(ctx, authed(
						&identityv1.GenerateRecoveryCodesRequest{}, bootBearer))
				return err
			},
		},
		{
			name:   "no Idempotency-Key/UpdateProfile",
			code:   connectrpc.CodeInvalidArgument,
			reason: errs.ValidationFailed,
			why:    "gate 5 refuses a mutation with no key rather than generating one (CONVENTIONS §6)",
			call: func(ctx context.Context, tr transport) error {
				tz := "Europe/Paris"
				req := connectrpc.NewRequest(&profilev1.UpdateProfileRequest{Timezone: &tz})
				stamp(req.Header(), bearer, "")
				_, err := profilev1connect.NewProfileServiceClient(
					clientFor(tr.h2), h.baseURL, tr.opts...).UpdateProfile(ctx, req)
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()

			for _, tr := range transports() {
				err := tc.call(ctx, tr)
				if err == nil {
					t.Errorf("%s over %s succeeded; it must be refused because %s",
						tc.name, tr.name, tc.why)
					continue
				}
				if got := connectrpc.CodeOf(err); got != tc.code {
					t.Errorf("%s over %s: code is %s, want %s (%s)",
						tc.name, tr.name, got, tc.code, describe(err))
				}
				reason, present := reasonOf(err)
				if !present {
					t.Errorf("%s over %s carried NO chronos.errors.v1.ErrorDetail, so a client "+
						"on this protocol has nothing to branch on but the status — which "+
						"CONVENTIONS §5.1 forbids: %s", tc.name, tr.name, describe(err))
					continue
				}
				if reason != string(tc.reason) {
					t.Errorf("%s over %s: reason is %q, want %q (%s)",
						tc.name, tr.name, reason, tc.reason, describe(err))
				}
			}
		})
	}
}

// Every mutation refuses IDENTICALLY over every wire format.
//
// # Why this shape, rather than twenty more successful mutations
//
// TestEveryMutationAnswersOverEveryProtocol drives the success path, and it
// covers two of the twenty. Extending it to all twenty would mean 120 real
// executions, several of them destructive — DeactivateAccount and
// RequestAccountDeletion cannot be run six times against anything one wants to
// keep — so success-equivalence is inherently a representative test.
//
// Refusal-equivalence is not. A refusal is an ANSWER, so the same ADR-007 claim
// applies to it; it is deterministic, it costs no state, and it travels the
// HARDER path of the two. A successful response is a message in the body on
// every protocol. An error is not: Connect puts it in a JSON body, gRPC puts the
// status and its details in a `grpc-status-details-bin` TRAILER, and gRPC-Web
// puts that trailer inside the response body as a length-prefixed frame. Three
// encodings, and only one of them is the one most tests exercise.
//
// So this covers the remaining eighteen mutations on the dimension that is
// actually protocol-specific, and does it for all twenty rather than a sample.
//
// # Why an empty message
//
// The request is sent as emptypb.Empty against each procedure's own URL. Zero
// bytes — and `{}` under the JSON codec — decode as a default-valued instance of
// whatever the method really accepts, because protobuf has no required fields
// and unknown ones are skipped. That is what makes ONE client shape able to
// address twenty different methods without twenty typed stubs, and it exercises
// the real decode path on every protocol rather than short-circuiting it.
//
// The refusal each method produces then differs BY METHOD — a missing
// Idempotency-Key, or a protovalidate rule on a field the empty message left
// unset — and that is fine and deliberate. The comparison is across protocols
// for one method, never across methods.
func TestEveryMutationRefusesIdenticallyOverEveryProtocol(t *testing.T) {
	bearer := h.activeBearer(t)

	for _, mp := range mutatingProcedures() {
		t.Run(mp.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()

			token := bearer
			if mp.public {
				token = ""
			}

			var baseline string
			for i, tr := range transports() {
				// keyless, NOT authed: authed() sets an Idempotency-Key on every
				// request it builds, so using it here would send a complete, valid
				// mutation. Two of these twenty accept an empty body — RevokeAllSessions
				// and GenerateRecoveryCodes have no required field — and they duly
				// EXECUTED, six times each, against the shared account, while the other
				// eighteen refused on protovalidate and looked like passes. The missing
				// key is the one refusal available on all twenty regardless of which
				// rules a message declares, and it is only missing if nothing adds it.
				client := connectrpc.NewClient[emptypb.Empty, emptypb.Empty](
					clientFor(tr.h2), h.baseURL+mp.path, tr.opts...)
				_, err := client.CallUnary(ctx, keyless(&emptypb.Empty{}, token))
				if err == nil {
					t.Fatalf("%s over %s SUCCEEDED with no Idempotency-Key and an empty body. "+
						"Either the gate does not run on this transport, or an empty message is "+
						"being accepted as a complete request", mp.name, tr.name)
				}

				reason, ok := reasonOf(err)
				if !ok {
					t.Errorf("%s over %s refused without a chronos.errors.v1.ErrorDetail, so a "+
						"client on this transport cannot classify the failure (CONVENTIONS §5): %s",
						mp.name, tr.name, describe(err))
					continue
				}
				got := fmt.Sprintf("code=%s reason=%s", connectrpc.CodeOf(err), reason)

				if i == 0 {
					baseline = got
					t.Logf("%s baseline (%s): %s", mp.name, tr.name, got)
					continue
				}
				if got != baseline {
					t.Errorf("%s refused with\n  %s\nover %s, but with\n  %s\nover %s.\n"+
						"The wire format may not change the answer, and an error is an answer "+
						"— it is the one that travels a different way on each protocol (ADR-007)",
						mp.name, got, tr.name, baseline, transports()[0].name)
				}
			}
		})
	}
}

// The one READ that is not GET-able still behaves like a read on every protocol.
//
// # Why it needs its own test
//
// `reads()` is the nine NO_SIDE_EFFECTS methods, because that option is what
// makes connect-go publish a GET route and the whole set is driven through it.
// CheckUsernameAvailability is `OPERATION_CLASS_READ` and does NOT declare
// NO_SIDE_EFFECTS, so it is POST-only and falls outside that set — which left it
// the single method in the service with no cross-protocol assertion and no
// key-is-ignored assertion. It was not excluded on purpose; it fell between two
// enumerators.
//
// Two properties, and they are the read contract:
//
//   - The answer does not depend on the wire format (ADR-007).
//   - An Idempotency-Key is IGNORED, not required and not refused. The gate
//     returns on `!p.Mutating()` before it looks for a header, and a read that
//     started demanding one would break every client that sends a key on
//     everything.
//
// The handle is deliberately one that does not exist, so `available` is true and
// the answer is stable across the six calls. Asking about a taken handle would
// be equally valid and less stable — another test could claim it mid-run.
func TestThePostOnlyReadBehavesLikeAReadOnEveryProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	handle := h.freshUsername()

	var baseline string
	for i, tr := range transports() {
		client := identityv1connect.NewIdentityServiceClient(clientFor(tr.h2), h.baseURL, tr.opts...)

		// authed() sets an Idempotency-Key, which is the point here: a read must
		// ignore it. The public method takes no bearer.
		res, err := client.CheckUsernameAvailability(ctx,
			authed(&identityv1.CheckUsernameAvailabilityRequest{Username: handle}, ""))
		if err != nil {
			t.Fatalf("CheckUsernameAvailability over %s: %s", tr.name, describe(err))
		}
		got := fmt.Sprintf("available=%t username=%q",
			res.Msg.GetAvailable(), res.Msg.GetUsername())

		if i == 0 {
			baseline = got
			if !res.Msg.GetAvailable() {
				t.Fatalf("a freshly generated handle reports unavailable (%s); the fixture is "+
					"colliding and the comparison below would be meaningless", got)
			}
			t.Logf("baseline (%s): %s", tr.name, got)
			continue
		}
		if got != baseline {
			t.Errorf("CheckUsernameAvailability answered\n  %s\nover %s but\n  %s\nover %s.\n"+
				"The wire format may not change the answer (ADR-007)",
				got, tr.name, baseline, transports()[0].name)
		}
	}
}

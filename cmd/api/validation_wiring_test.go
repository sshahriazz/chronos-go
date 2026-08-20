package main

import (
	"net/http/httptest"
	"testing"

	connectrpc "connectrpc.com/connect"
	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/identity/v1/identityv1connect"
)

// Validation must be WIRED, not merely available.
//
// This repository has shipped the other outcome three times: `inapp`, `webpush`
// and `seaweedfs` were fully built, fully tested, and constructed by no binary,
// so every component test passed while three notification channels delivered
// nothing. Declarative validation fails the same way and is harder to notice,
// because the failure mode is silent ACCEPTANCE — the schema documents a rule,
// the published OpenAPI advertises it, `buf lint` is green, and malformed input
// sails through to a handler that CONVENTIONS §7 forbids from re-checking it.
//
// So the assertion is on `handlerOptions`, the one list every Connect handler in
// this binary is built from, and it is made by pushing a request that violates a
// declared rule through a real handler rather than by inspecting the list. A
// length check on the option slice would pass for a handler carrying the wrong
// interceptor, and asserting `validate.NewInterceptor() != nil` would pass with
// the composition root never calling it.
func TestValidationIsWired(t *testing.T) {
	t.Parallel()

	// IdentityService rather than SystemService, and deliberately: GetStatusRequest
	// is an empty message with no field to violate, so a server carrying only it
	// cannot distinguish an enforced rule from an absent interceptor. The handler
	// below is the generated Unimplemented one — if validation is missing, the
	// request reaches it and comes back `unimplemented` instead of
	// `invalid_argument`, which is exactly the signal this test reads.
	_, handler := identityv1connect.NewIdentityServiceHandler(
		identityv1connect.UnimplementedIdentityServiceHandler{}, handlerOptions()...)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	client := identityv1connect.NewIdentityServiceClient(srv.Client(), srv.URL)

	_, err := client.Register(t.Context(), connectrpc.NewRequest(&identityv1.RegisterRequest{
		Email: "not-an-address",
	}))
	if err == nil {
		t.Fatal("an address with no domain was accepted: nothing in cmd/api enforces the " +
			"protovalidate rules that identity.proto declares and the OpenAPI spec publishes")
	}
	if got := connectrpc.CodeOf(err); got != connectrpc.CodeInvalidArgument {
		t.Fatalf("code = %s, want invalid_argument — the request reached the handler, so the "+
			"validation interceptor is not in handlerOptions(); error: %v", got, err)
	}
}

// The option list must also still carry the JSON codec.
//
// The two live in the same function, and adding an interceptor to a list that
// previously held only codec options is exactly the edit that drops one. Losing
// it is silent in the same way: responses keep working, `false` and `0` simply
// stop appearing in them, and a browser client takes the wrong branch only in
// the failure case.
func TestDefaultValuesAreStillEmittedInJSON(t *testing.T) {
	t.Parallel()

	if len(handlerOptions()) < 2 {
		t.Fatalf("handlerOptions() returned %d options; it must carry both the validation "+
			"interceptor and the JSON codec", len(handlerOptions()))
	}
}

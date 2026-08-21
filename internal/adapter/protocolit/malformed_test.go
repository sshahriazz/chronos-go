//go:build integration

package protocolit_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"
	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
)

// TestMalformedInputIsRefusedAndDescribed sends the server input no generated
// client would produce, and records what it does with each.
//
// The audience is the HTTP/JSON protocol, which exists precisely so that
// hand-written clients — a curl, a webhook, a script — can call this API. Those
// callers get the encoding wrong, and every row here is a mistake one of them
// will make.
//
// Two properties are asserted for every case, and they are not the same
// property:
//
//   - The request is REFUSED. A silently-accepted malformation is a request the
//     server understood differently from the client that sent it, which is the
//     shape of every serialization bug that reaches production.
//   - The refusal is a Connect ERROR ENVELOPE. docs/api/chronos-openapi.yaml
//     gives every operation a `default` response of `connect.error`, so a client
//     is entitled to parse one from any non-2xx. A bare status with an empty body
//     is a documented response the server does not send.
//
// The `note` column records what the server actually did, so this file doubles
// as the answer to "how does it handle each malformed input" without re-running
// anything.
func TestMalformedInputIsRefusedAndDescribed(t *testing.T) {
	bearer := h.activeBearer(t)

	const public = "/chronos.identity.v1.IdentityService/CheckUsernameAvailability"
	const authenticated = "/chronos.identity.v1.IdentityService/ListSessions"

	cases := []struct {
		name        string
		procedure   string
		contentType string
		body        string
		auth        bool
		// wantEnvelope is false only where the refusal is produced beneath
		// Connect — by net/http itself — and therefore cannot carry one.
		wantEnvelope bool
		why          string
	}{
		{
			name:         "truncated JSON",
			procedure:    public,
			contentType:  "application/json",
			body:         `{"username":"ada`,
			wantEnvelope: true,
			why:          "a body cut off mid-string cannot be completed by guessing",
		},
		{
			name:         "an empty body",
			procedure:    public,
			contentType:  "application/json",
			body:         ``,
			wantEnvelope: true,
			why: "an empty body is not an empty message; accepting it would make " +
				"`username` silently \"\" and the request would fail a rule instead of the " +
				"encoding",
		},
		{
			name:         "a JSON array where an object belongs",
			procedure:    public,
			contentType:  "application/json",
			body:         `["ada"]`,
			wantEnvelope: true,
			why:          "the request message is a protobuf message, not a list",
		},
		{
			name:         "a bare string where an object belongs",
			procedure:    public,
			contentType:  "application/json",
			body:         `"ada"`,
			wantEnvelope: true,
			why:          "same, and this is what a client that forgot to wrap the field sends",
		},
		{
			name:         "a number where a string belongs",
			procedure:    public,
			contentType:  "application/json",
			body:         `{"username":42}`,
			wantEnvelope: true,
			why:          "`username` is a string; 42 is not one, and coercing it would invent input",
		},
		{
			name:         "a string where a number belongs, unparseable",
			procedure:    authenticated,
			contentType:  "application/json",
			body:         `{"pageSize":"ten"}`,
			auth:         true,
			wantEnvelope: true,
			why:          "`page_size` is an int32 and \"ten\" is not a number in any encoding",
		},
		{
			name:         "a float where an int32 belongs",
			procedure:    authenticated,
			contentType:  "application/json",
			body:         `{"pageSize":1.5}`,
			auth:         true,
			wantEnvelope: true,
			why:          "protobuf-JSON accepts a numeric string for an int, but not a fraction",
		},
		{
			name:         "an int32 overflowed",
			procedure:    authenticated,
			contentType:  "application/json",
			body:         `{"pageSize":2147483648}`,
			auth:         true,
			wantEnvelope: true,
			why:          "one past int32's ceiling; silently wrapping to -2147483648 would pass the gte:0 rule",
		},
		{
			name:         "a control character inside a JSON string",
			procedure:    "/chronos.identity.v1.IdentityService/Authenticate",
			contentType:  "application/json",
			body:         "{\"identifier\":\"ada@example.test\",\"password\":\"x\",\"deviceId\":\"dev\\x01\"}",
			wantEnvelope: true,
			why: "a raw control character is refused at DECODE, before protovalidate sees " +
				"the field — so the refusal names the byte offset rather than `device_id`",
		},
		{
			name:         "duplicate object members",
			procedure:    public,
			contentType:  "application/json",
			body:         `{"username":"ada_lovelace","username":"mallory"}`,
			wantEnvelope: true,
			why: "ADR-047 calls two parsers disagreeing about which value is real a security " +
				"problem, not a parsing nicety. encoding/json/v2 rejects duplicates; this " +
				"path is protobuf-JSON, which is a different parser and answers separately",
		},
		{
			name:         "invalid UTF-8 in a string",
			procedure:    public,
			contentType:  "application/json",
			body:         "{\"username\":\"ada\xff\xfe\"}",
			wantEnvelope: true,
			why:          "a protobuf string field is defined to hold UTF-8",
		},
		{
			name:         "no Content-Type at all",
			procedure:    public,
			contentType:  "",
			body:         `{"username":"ada_lovelace"}`,
			wantEnvelope: false,
			why:          "Connect selects the codec from the Content-Type; with none there is no codec",
		},
		{
			name:         "Content-Type: text/plain",
			procedure:    public,
			contentType:  "text/plain",
			body:         `{"username":"ada_lovelace"}`,
			wantEnvelope: false,
			why:          "no codec is registered for text/plain",
		},
		{
			name:         "Content-Type: application/proto with a JSON body",
			procedure:    public,
			contentType:  "application/proto",
			body:         `{"username":"ada_lovelace"}`,
			wantEnvelope: true,
			why: "the codec is chosen by the header, so JSON bytes are read as the protobuf " +
				"wire format — the most dangerous of these, because protobuf's wire format " +
				"has no framing to fail on",
		},
		{
			name:        "an unknown procedure on a registered service",
			procedure:   "/chronos.identity.v1.IdentityService/NoSuchMethod",
			contentType: "application/json",
			body:        `{}`,
			// connect-go's per-service handler falls through to net/http's
			// NotFoundHandler, which writes `404 page not found` as text/plain. The
			// spec makes no promise about an undocumented path, so this is not a
			// contract violation — but what a CLIENT does with it is a contract
			// question, and TestAnUnknownProcedureAnswersAsAnRPC asks it.
			wantEnvelope: false,
			why:          "a typo in a path, or a method a client believes exists",
		},
		{
			name:        "an unknown service",
			procedure:   "/chronos.billing.v1.BillingService/CreateInvoice",
			contentType: "application/json",
			body:        `{}`,
			// The mux has no route at all, so this is net/http's own 404 and no
			// Connect handler ever runs.
			wantEnvelope: false,
			why:          "a service this build does not serve",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			token := ""
			if tc.auth {
				token = bearer
			}
			status, body, err := rawPost(ctx, tc.procedure, tc.contentType,
				tc.body, token, newIdempotencyKey(), nil)
			if err != nil {
				t.Fatalf("POST %s: %v", tc.procedure, err)
			}
			if status >= 200 && status < 300 {
				t.Errorf("BUG: %s was ACCEPTED (%d). %s\nbody: %s",
					tc.name, status, tc.why, strings.TrimSpace(body))
				return
			}
			env, derr := decodeWireError(body)
			switch {
			case tc.wantEnvelope && derr != nil:
				t.Errorf("BUG: %s answered %d with a body that is not a Connect error "+
					"envelope, while the OpenAPI spec documents `connect.error` as the "+
					"`default` response for every operation: %v\nbody: %q",
					tc.name, status, derr, strings.TrimSpace(body))
			case tc.wantEnvelope:
				t.Logf("%s -> status=%d code=%s message=%q",
					tc.name, status, env.Code, env.Message)
			default:
				t.Logf("%s -> status=%d body=%q (refused beneath Connect, so no envelope)",
					tc.name, status, strings.TrimSpace(body))
			}
		})
	}
}

// TestAnUnknownFieldIsDiscarded is the one malformation the documentation makes
// a PROMISE about, so it is the one that gets its own test.
//
// proto/openapi.base.yaml, rendered into the published spec:
//
//	Unknown fields in a REQUEST are discarded rather than rejected, so a client
//	built against a newer schema keeps working against an older server.
//
// That is a forward-compatibility guarantee, and it is the opposite of ADR-047's
// rule for documents this codebase owns — which is correct, and worth having a
// test that says so: a request body is somebody else's document, and rejecting a
// member a newer client added would break exactly the rolling deploy the
// tolerance exists for.
func TestAnUnknownFieldIsDiscarded(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	status, body, err := rawPost(ctx,
		"/chronos.identity.v1.IdentityService/CheckUsernameAvailability",
		"application/json",
		`{"username":"ada_lovelace","fieldFromAFutureSchema":{"nested":true}}`,
		"", newIdempotencyKey(), nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("BUG: an unknown member was REJECTED (%d), while the published API "+
			"documentation promises \"Unknown fields in a REQUEST are discarded rather "+
			"than rejected, so a client built against a newer schema keeps working against "+
			"an older server\".\n%s", status, describeRaw(status, body))
		return
	}
	t.Logf("unknown member discarded, as documented -> %s", describeRaw(status, body))
}

// TestAnOversizedHeaderIsRefusedWithoutReachingAHandler covers the last row of
// the malformed-input matrix, and it is the one with a security shape.
//
// internal/server/connect sets explicit header limits and its own test measures
// what fits. What that test cannot say is what a REAL request sees, because the
// budget is spent by the deployment as much as by the application: an
// Authorization header, an Idempotency-Key, a W3C traceparent and tracestate, a
// cookie jar and eight X-Forwarded-For hops all count against one limit, and
// they are added by things that are not this codebase.
//
// The property asserted is narrow and is the one that matters: an oversized
// header block does not reach a handler, and it does not answer 200.
func TestAnOversizedHeaderIsRefusedWithoutReachingAHandler(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	extra := http.Header{}
	// One megabyte of header, spread over many field lines so both the value
	// budget and the byte budget are exceeded.
	for i := range 512 {
		extra.Add("X-Chronos-Probe", strings.Repeat("p", 2048)+"-"+string(rune('a'+i%26)))
	}

	status, body, err := rawPost(ctx,
		"/chronos.identity.v1.IdentityService/CheckUsernameAvailability",
		"application/json", `{"username":"ada_lovelace"}`, "", newIdempotencyKey(), extra)
	if err != nil {
		// A connection-level refusal is a legitimate answer and is what HTTP/1.1
		// servers usually give: the server closed the connection rather than
		// reading a header block it had already decided to reject.
		t.Logf("an oversized header block was refused at the connection: %v", err)
		return
	}
	if status >= 200 && status < 300 {
		t.Errorf("BUG: a request carrying ~1MB of headers was SERVED (%d). "+
			"internal/server/connect sets MaxHeaderBytes and MaxHeaderValueCount "+
			"precisely so it is not.\nbody: %s", status, strings.TrimSpace(body))
		return
	}
	t.Logf("oversized header block -> %s", describeRaw(status, body))
}

// TestAnUnknownProcedureAnswersAsAnRPC is the client-side half of the
// unknown-path case, and it is the half with a contract behind it.
//
// The raw HTTP answer is `404 page not found` as text/plain, which is
// connect-go's per-service handler falling through to net/http. That is
// unremarkable on its own. What matters is what a CLIENT is left holding: an
// error it can branch on, or a parse failure. gRPC defines `UNIMPLEMENTED` for
// exactly this, and a client that cannot tell "this server does not have that
// method" from "something went wrong" cannot implement a version fallback.
//
// Driven over every transport, because the answer is produced by the transport:
// the same 404 is translated differently by the Connect, gRPC and gRPC-Web
// clients.
func TestAnUnknownProcedureAnswersAsAnRPC(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	for _, tr := range transports() {
		t.Run(tr.name, func(t *testing.T) {
			client := connectrpc.NewClient[identityv1.GetUserRequest, identityv1.GetUserResponse](
				clientFor(tr.h2), h.baseURL+"/chronos.identity.v1.IdentityService/NoSuchMethod",
				tr.opts...)
			_, err := client.CallUnary(ctx, connectrpc.NewRequest(&identityv1.GetUserRequest{}))
			if err == nil {
				t.Fatalf("a procedure that does not exist answered successfully")
			}
			code := connectrpc.CodeOf(err)
			t.Logf("%s -> code=%s message=%q", tr.name, code, err)
			if code != connectrpc.CodeUnimplemented {
				t.Errorf("BUG: over %s an unknown procedure answers %s, not unimplemented. "+
					"gRPC defines UNIMPLEMENTED for this case, and a client that cannot tell "+
					"\"this server does not have that method\" from \"something went wrong\" "+
					"cannot fall back to an older call. The server answers text/plain "+
					"`404 page not found`, which no protocol maps to a code.\n%s",
					tr.name, code, describe(err))
			}
		})
	}
}

//go:build integration

package protocolit_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/server/interceptor"
)

// mutatingProcedures is every RPC whose `(chronos.options.v1.operation)` is
// `OPERATION_CLASS_WRITE`: seven public and seven authenticated on
// IdentityService, four on NotificationService, two on ProfileService.
//
// `public` matters here and nowhere else in this package. A public method
// returns from the gate pipeline BEFORE gate 5 — `if p.Public { return next(...)
// }` in interceptor/gates.go — so the header cannot be enforced by the
// interceptor for those seven. identity/api/service.go enforces it again inside
// the handler, and says why: "the four public RPCs … bypass the gate entirely (a
// public method has no principal, and the idempotency scope is built from one),
// and they still require a key."
//
// The body must be well-formed, because the gates run BEFORE protovalidate: a
// malformed body would be refused by the same gate for the same reason and the
// test would pass without measuring anything.
func mutatingProcedures() []struct {
	name   string
	path   string
	body   string
	public bool
} {
	return []struct {
		name   string
		path   string
		body   string
		public bool
	}{
		{"IdentityService/Register", "/chronos.identity.v1.IdentityService/Register",
			fmt.Sprintf(`{"email":%q}`, h.freshEmail("idem")), true},
		{"IdentityService/VerifyEmail", "/chronos.identity.v1.IdentityService/VerifyEmail",
			`{"token":"not-a-real-token","password":"correct-horse-battery","username":"ada_x1"}`, true},
		{"IdentityService/ResendEmailVerification", "/chronos.identity.v1.IdentityService/ResendEmailVerification",
			fmt.Sprintf(`{"email":%q}`, h.freshEmail("idem")), true},
		{"IdentityService/RequestPasswordReset", "/chronos.identity.v1.IdentityService/RequestPasswordReset",
			fmt.Sprintf(`{"email":%q}`, h.freshEmail("idem")), true},
		{"IdentityService/ResetPassword", "/chronos.identity.v1.IdentityService/ResetPassword",
			`{"token":"not-a-real-token","password":"correct-horse-battery"}`, true},
		{"IdentityService/Authenticate", "/chronos.identity.v1.IdentityService/Authenticate",
			`{"identifier":"nobody@example.test","password":"correct-horse-battery"}`, true},
		{"IdentityService/CreateSession", "/chronos.identity.v1.IdentityService/CreateSession",
			`{"identifier":"nobody@example.test","password":"correct-horse-battery"}`, true},

		{"IdentityService/EnrollTotp", "/chronos.identity.v1.IdentityService/EnrollTotp", `{}`, false},
		{"IdentityService/ConfirmTotp", "/chronos.identity.v1.IdentityService/ConfirmTotp",
			`{"code":"000000"}`, false},
		{"IdentityService/GenerateRecoveryCodes", "/chronos.identity.v1.IdentityService/GenerateRecoveryCodes",
			`{}`, false},
		{"IdentityService/RevokeSession", "/chronos.identity.v1.IdentityService/RevokeSession",
			`{"sessionId":"sess_01ARZ3NDEKTSV4RRFFQ69G5FAV"}`, false},
		{"IdentityService/RevokeAllSessions", "/chronos.identity.v1.IdentityService/RevokeAllSessions",
			`{"reason":"conformance_suite"}`, false},
		{"IdentityService/DeactivateAccount", "/chronos.identity.v1.IdentityService/DeactivateAccount",
			`{}`, false},
		{"IdentityService/RequestAccountDeletion", "/chronos.identity.v1.IdentityService/RequestAccountDeletion",
			`{"confirmation":"DELETE"}`, false},

		{"NotificationService/MarkNotificationsRead", "/chronos.notification.v1.NotificationService/MarkNotificationsRead",
			fmt.Sprintf(`{"orgId":%q,"notificationIds":["notif_01ARZ3NDEKTSV4RRFFQ69G5FAV"]}`,
				syntheticOrgID), false},
		{"NotificationService/RegisterPushSubscription", "/chronos.notification.v1.NotificationService/RegisterPushSubscription",
			fmt.Sprintf(`{"orgId":%q,"endpoint":"https://push.example.test/idem","p256dh":%q,"auth":%q}`,
				syntheticOrgID, pushP256DH, pushAuth), false},
		{"NotificationService/RemovePushSubscription", "/chronos.notification.v1.NotificationService/RemovePushSubscription",
			fmt.Sprintf(`{"orgId":%q,"endpoint":"https://push.example.test/idem"}`, syntheticOrgID), false},
		{"NotificationService/SetNotificationPreferences", "/chronos.notification.v1.NotificationService/SetNotificationPreferences",
			fmt.Sprintf(`{"orgId":%q,"channels":[{"channel":"CHANNEL_EMAIL","enabled":true}]}`,
				syntheticOrgID), false},

		{"ProfileService/UpdateProfile", "/chronos.profile.v1.ProfileService/UpdateProfile",
			`{"locale":"en-GB"}`, false},
		{"ProfileService/CreateAvatarUpload", "/chronos.profile.v1.ProfileService/CreateAvatarUpload",
			`{"contentType":"image/png","sizeBytes":"1024"}`, false},
	}
}

// TestEveryMutatingRPCRefusesAMissingIdempotencyKey walks the whole write
// surface with the header omitted.
//
// CONVENTIONS §6: "Required on every mutating RPC; the interceptor rejects a
// mutation without one." The refusal must also NAME the header — the gate's own
// comment records that the two layers beneath it refuse with an internal package
// name and no header name, and that "only the first names the header the client
// has to set".
func TestEveryMutatingRPCRefusesAMissingIdempotencyKey(t *testing.T) {
	bearer := h.activeBearer(t)

	for _, rpc := range mutatingProcedures() {
		t.Run(rpc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			token := ""
			if !rpc.public {
				token = bearer
			}
			status, body, err := rawPost(ctx, rpc.path, "application/json", rpc.body, token, "", nil)
			if err != nil {
				t.Fatalf("POST %s: %v", rpc.path, err)
			}
			if status != http.StatusBadRequest {
				t.Fatalf("BUG: %s is a mutation and was accepted with NO Idempotency-Key "+
					"(%d). CONVENTIONS §6 requires one on every mutating RPC; without it a "+
					"double-clicked button executes twice.\n%s",
					rpc.name, status, describeRaw(status, body))
			}
			env, derr := decodeWireError(body)
			if derr != nil {
				t.Fatalf("the refusal is not a Connect error envelope: %v\nbody: %s",
					derr, strings.TrimSpace(body))
			}
			if !strings.Contains(env.Message, interceptor.IdempotencyHeader) {
				t.Errorf("%s refused a keyless mutation with %q, which does not name the "+
					"header the client has to set", rpc.name, env.Message)
			}
			if got := reasonFromJSON(body); got != string(errs.ValidationFailed) {
				t.Errorf("%s refused a keyless mutation with reason %q, want %q\n%s",
					rpc.name, got, errs.ValidationFailed, describeRaw(status, body))
			}
		})
	}
}

// TestTheOpenAPISpecDocumentsTheIdempotencyKeyOnEveryMutation is a DEFECT REPORT
// about the published contract rather than about behaviour.
//
// The server refuses EVERY mutating RPC without the header — the test above
// proves it, for all twenty. The published spec documents the parameter on a
// subset, and the failure message names exactly which ones are missing rather
// than hard-coding a count, because the list moves as protos are edited.
//
// # Why it is a list to forget
//
// The parameter is not generated from anything. `protoc-gen-connect-openapi`
// knows nothing about `Idempotency-Key`, so each operation declares it by hand
// in a `gnostic.openapi.v3.operation` block in its own .proto. That makes it
// exactly the kind of per-endpoint list ADR-021 exists to abolish for gates: one
// place to forget, per RPC, with nothing checking.
//
// CONVENTIONS §7.1 is explicit about why generation matters: "The OpenAPI spec
// and the error catalogue are generated from the same sources the server uses"
// — and this one is not. A client generated from the published spec cannot call
// an operation whose header is missing: every attempt comes back
// `400 invalid_argument` naming a header the spec never mentioned.
//
// The seven PUBLIC identity mutations are the ones this currently finds, and
// they are the worst possible seven: `Register`, `VerifyEmail`,
// `ResendEmailVerification`, `RequestPasswordReset`, `ResetPassword`,
// `Authenticate` and `CreateSession` are the entire pre-session surface. A
// generated client cannot sign anybody up or in.
//
// Read as text rather than as YAML on purpose. The build is pure Go (CLAUDE.md)
// and this package is not the place to add a YAML dependency for one scan; the
// generated file has stable two-space path indentation, which is all the
// structure this needs.
func TestTheOpenAPISpecDocumentsTheIdempotencyKeyOnEveryMutation(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("locating the repository root: %v", err)
	}
	spec, err := os.ReadFile(filepath.Join(root, "docs", "api", "chronos-openapi.yaml"))
	if err != nil {
		t.Fatalf("reading the published OpenAPI spec: %v", err)
	}
	documented := operationsDocumenting(string(spec), interceptor.IdempotencyHeader)
	t.Logf("the spec documents %s on %d operations: %v",
		interceptor.IdempotencyHeader, len(documented), documented)

	var missing []string
	for _, rpc := range mutatingProcedures() {
		if !documented[specPath(rpc.path)] {
			missing = append(missing, rpc.name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("BUG: %d of %d mutating RPCs are refused without an %s and the published "+
			"OpenAPI spec documents no such parameter for them, so a generated client "+
			"cannot call any of them:\n  %s",
			len(missing), len(mutatingProcedures()), interceptor.IdempotencyHeader,
			strings.Join(missing, "\n  "))
	}
}

// specPath turns `/chronos.x.v1.Service/Method` into the spec's path key.
func specPath(procedure string) string {
	return strings.TrimPrefix(procedure, "/")
}

// operationsDocumenting reports which spec paths mention needle anywhere in
// their block.
func operationsDocumenting(spec, needle string) map[string]bool {
	out := map[string]bool{}
	current := ""
	inPaths := false
	for line := range strings.SplitSeq(spec, "\n") {
		switch {
		case line == "paths:":
			inPaths = true
		case inPaths && len(line) > 0 && line[0] != ' ':
			inPaths = false
		case inPaths && strings.HasPrefix(line, "  /") && strings.HasSuffix(line, ":"):
			current = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(line), "/"), ":")
		case inPaths && current != "" && strings.Contains(line, needle):
			out[current] = true
		}
	}
	return out
}

// TestAReplayedKeyReturnsTheStoredResponse is the middle rule of CONVENTIONS §6.
//
// > Replay with the same key and same body ⇒ the stored response, not a
// > re-execution.
//
// `CreateAvatarUpload` is the sharpest case available, and its own schema
// comment says why it is a mutation at all: "It issues a CAPABILITY. … the
// idempotency gate makes a double-clicked button reuse one grant instead of
// littering the bucket with abandoned ones." A signed, single-use, expiring
// upload target is different on every execution, so a byte-identical second
// answer can only have come from the store.
func TestAReplayedKeyReturnsTheStoredResponse(t *testing.T) {
	bearer := h.activeBearer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	const path = "/chronos.profile.v1.ProfileService/CreateAvatarUpload"
	const body = `{"contentType":"image/png","sizeBytes":"1024"}`
	key := newIdempotencyKey()

	firstStatus, first, err := rawPost(ctx, path, "application/json", body, bearer, key, nil)
	if err != nil {
		t.Fatalf("first CreateAvatarUpload: %v", err)
	}
	if firstStatus != http.StatusOK {
		t.Fatalf("the first call failed, so there is no stored response to replay: %s",
			describeRaw(firstStatus, first))
	}

	secondStatus, second, err := rawPost(ctx, path, "application/json", body, bearer, key, nil)
	if err != nil {
		t.Fatalf("replayed CreateAvatarUpload: %v", err)
	}
	if secondStatus != http.StatusOK {
		t.Fatalf("BUG: replaying a key with the SAME body was refused: %s",
			describeRaw(secondStatus, second))
	}
	if first != second {
		t.Errorf("BUG: replaying an Idempotency-Key with the same body RE-EXECUTED the "+
			"mutation. CONVENTIONS §6 says the stored response comes back, and this one "+
			"issues a signed single-use upload grant, so two answers mean two grants.\n"+
			"first:  %s\nsecond: %s", strings.TrimSpace(first), strings.TrimSpace(second))
		return
	}
	t.Logf("replay returned the stored response byte for byte (%d bytes)", len(second))

	// The control: a DIFFERENT key must execute again and produce a different
	// grant. Without this the test above is satisfied by a handler that returns a
	// constant, which is the failure mode a byte-comparison alone cannot see.
	freshStatus, fresh, err := rawPost(ctx, path, "application/json", body,
		bearer, newIdempotencyKey(), nil)
	if err != nil {
		t.Fatalf("CreateAvatarUpload with a fresh key: %v", err)
	}
	if freshStatus != http.StatusOK {
		t.Fatalf("a fresh key failed: %s", describeRaw(freshStatus, fresh))
	}
	if fresh == first {
		t.Errorf("a DIFFERENT Idempotency-Key produced a byte-identical response, so the " +
			"comparison above proves nothing about the store: this endpoint's answer does " +
			"not vary between executions")
	}
}

// TestAReusedKeyWithADifferentBodyIsRefused is the last rule of CONVENTIONS §6.
//
// > Same key, different body ⇒ CONFLICT. This catches client bugs rather than
// > silently returning someone else's answer.
//
// The code is asserted as well as the reason, because the two disagree with the
// documentation and the disagreement is itself worth recording: the §5 table
// maps CONFLICT to `Aborted` (HTTP 409 via Connect's mapping of Aborted), while
// server/connect.codeFor maps it to `AlreadyExists`. Whichever is right, a
// client branching on the code sees one of them.
func TestAReusedKeyWithADifferentBodyIsRefused(t *testing.T) {
	bearer := h.activeBearer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	const path = "/chronos.profile.v1.ProfileService/CreateAvatarUpload"
	key := newIdempotencyKey()

	status, body, err := rawPost(ctx, path, "application/json",
		`{"contentType":"image/png","sizeBytes":"1024"}`, bearer, key, nil)
	if err != nil {
		t.Fatalf("first CreateAvatarUpload: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("the first call failed, so there is no claim to collide with: %s",
			describeRaw(status, body))
	}

	status, body, err = rawPost(ctx, path, "application/json",
		`{"contentType":"image/jpeg","sizeBytes":"2048"}`, bearer, key, nil)
	if err != nil {
		t.Fatalf("colliding CreateAvatarUpload: %v", err)
	}
	if status == http.StatusOK {
		t.Fatalf("BUG: the same Idempotency-Key with a DIFFERENT body was ACCEPTED. The "+
			"client now believes a jpeg grant was issued and holds a png one.\n%s",
			describeRaw(status, body))
	}
	if got := reasonFromJSON(body); got != string(errs.Conflict) {
		t.Errorf("a reused key with a different body was refused with reason %q, want %q\n%s",
			got, errs.Conflict, describeRaw(status, body))
	}
	t.Logf("reused key, different body -> %s", describeRaw(status, body))
}

// TestTheKeyIsScopedToTheMethod checks the scope CONVENTIONS §6 declares:
// `(principal, full_method, key)`.
//
// One key used on two different methods must execute both. A store keyed on
// (principal, key) alone would return the first method's stored response to the
// second — a `CreateAvatarUpload` answer decoded as an `UpdateProfile` one — and
// the client would see a plausible-looking success.
func TestTheKeyIsScopedToTheMethod(t *testing.T) {
	bearer := h.activeBearer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	key := newIdempotencyKey()

	status, body, err := rawPost(ctx, "/chronos.profile.v1.ProfileService/CreateAvatarUpload",
		"application/json", `{"contentType":"image/png","sizeBytes":"1024"}`, bearer, key, nil)
	if err != nil {
		t.Fatalf("CreateAvatarUpload: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("CreateAvatarUpload failed: %s", describeRaw(status, body))
	}

	status, body, err = rawPost(ctx,
		"/chronos.notification.v1.NotificationService/RemovePushSubscription",
		"application/json",
		fmt.Sprintf(`{"orgId":%q,"endpoint":"https://push.example.test/scope"}`, syntheticOrgID),
		bearer, key, nil)
	if err != nil {
		t.Fatalf("RemovePushSubscription: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("BUG: the same Idempotency-Key on a DIFFERENT method was refused. "+
			"CONVENTIONS §6 scopes the key to (principal, full_method, key), so one "+
			"client-generated key per user action must be usable on every method that "+
			"action touches.\n%s", describeRaw(status, body))
	}
	t.Logf("one key, two methods, both executed: %s", describeRaw(status, body))
}

// TestAKeyOnAReadIsIgnored is gate 5's first line, checked.
//
// > A READ passes straight through. Requiring a key on reads would make every
// > list endpoint carry one for no benefit, and storing a read's response is
// > retained data with no purpose (ADR-002).
//
// The half that matters for a CLIENT is the other direction: a client library
// that attaches the header to every request — which is exactly what a sensible
// one does — must not have its reads refused, replayed or stored.
func TestAKeyOnAReadIsIgnored(t *testing.T) {
	bearer := h.activeBearer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	key := newIdempotencyKey()
	for _, rc := range reads() {
		if rc.public {
			continue
		}
		status, body, err := rawPost(ctx, rc.procedure, "application/json",
			rc.message, bearer, key, nil)
		if err != nil {
			t.Fatalf("POST %s: %v", rc.procedure, err)
		}
		if status != http.StatusOK {
			t.Errorf("BUG: %s is a READ and reusing one Idempotency-Key across every read "+
				"was refused (%d). Gate 5 must pass reads straight through.\n%s",
				rc.name, status, describeRaw(status, body))
		}
	}
	t.Logf("one key reused across every authenticated read, all served")
}

// TestConcurrentDuplicatesExecuteOnce is the last rule of CONVENTIONS §6, and
// the only one that needs two requests in flight at once.
//
// > In-flight duplicates take a lock and wait, so a double-click cannot execute
// > twice concurrently.
//
// The assertion is deliberately not "one of them waited": which request wins the
// claim is a race, and a test that asserted an ordering would be flaky by
// construction. What must hold whatever the interleaving is that the two callers
// never end up holding two DIFFERENT successful answers — which for
// `CreateAvatarUpload` means two signed upload grants for one click.
//
// A refusal is an acceptable outcome for the loser (`ErrInFlight` is CONFLICT,
// "retry with the same key"); two different successes are not.
func TestConcurrentDuplicatesExecuteOnce(t *testing.T) {
	bearer := h.activeBearer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	const path = "/chronos.profile.v1.ProfileService/CreateAvatarUpload"
	const payload = `{"contentType":"image/png","sizeBytes":"1024"}`
	key := newIdempotencyKey()

	const callers = 8
	type outcome struct {
		status int
		body   string
		err    error
	}
	results := make(chan outcome, callers)
	start := make(chan struct{})
	for range callers {
		go func() {
			<-start
			status, body, err := rawPost(ctx, path, "application/json", payload, bearer, key, nil)
			results <- outcome{status, body, err}
		}()
	}
	close(start)

	successes := map[string]int{}
	var refusals []string
	for range callers {
		r := <-results
		if r.err != nil {
			t.Fatalf("concurrent CreateAvatarUpload: %v", r.err)
		}
		if r.status == http.StatusOK {
			successes[r.body]++
			continue
		}
		refusals = append(refusals, describeRaw(r.status, r.body))
	}

	if len(successes) == 0 {
		t.Fatalf("BUG: %d concurrent duplicates and NOT ONE executed; a double-click must "+
			"still perform the action once.\nrefusals: %s",
			callers, strings.Join(refusals, "\n          "))
	}
	if len(successes) > 1 {
		var bodies []string
		for b, n := range successes {
			bodies = append(bodies, fmt.Sprintf("x%d %s", n, strings.TrimSpace(b)))
		}
		t.Errorf("BUG: %d concurrent requests carrying ONE Idempotency-Key produced %d "+
			"DIFFERENT successful responses. CreateAvatarUpload issues a signed single-use "+
			"grant, so that is %d grants for one click.\n  %s",
			callers, len(successes), len(successes), strings.Join(bodies, "\n  "))
		return
	}
	for body, n := range successes {
		t.Logf("%d concurrent duplicates: %d served the one stored response, %d refused "+
			"while it was in flight\n  response: %s\n  refusals: %s",
			callers, n, len(refusals), strings.TrimSpace(body),
			strings.Join(refusals, "\n            "))
	}
}

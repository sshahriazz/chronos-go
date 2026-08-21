//go:build integration

package protocolit_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/server/interceptor"
)

// authenticatedProcedures is every RPC that is NOT `(chronos.options.v1.public)
// = true`: the twelve on IdentityService, the seven on NotificationService and
// the three on ProfileService.
//
// Listed as paths plus a minimal well-formed body, because the assertion is that
// the authn gate refuses BEFORE anything else — including protovalidate, which
// runs after the gates (cmd/api.handlerOptions puts the gate pipeline outermost
// so that "your email field is malformed" is never told to a caller who has not
// authenticated, ADR-036).
func authenticatedProcedures() []struct {
	name string
	path string
	body string
} {
	return []struct {
		name string
		path string
		body string
	}{
		{"IdentityService/GetUser", "/chronos.identity.v1.IdentityService/GetUser", `{}`},
		{"IdentityService/ListSessions", "/chronos.identity.v1.IdentityService/ListSessions", `{}`},
		{"IdentityService/ListMethods", "/chronos.identity.v1.IdentityService/ListMethods", `{}`},
		{"IdentityService/ListLoginHistory", "/chronos.identity.v1.IdentityService/ListLoginHistory", `{}`},
		{"IdentityService/EnrollTotp", "/chronos.identity.v1.IdentityService/EnrollTotp", `{}`},
		{"IdentityService/ConfirmTotp", "/chronos.identity.v1.IdentityService/ConfirmTotp", `{"code":"000000"}`},
		{"IdentityService/GenerateRecoveryCodes", "/chronos.identity.v1.IdentityService/GenerateRecoveryCodes", `{}`},
		{"IdentityService/RevokeSession", "/chronos.identity.v1.IdentityService/RevokeSession",
			`{"sessionId":"sess_01ARZ3NDEKTSV4RRFFQ69G5FAV"}`},
		{"IdentityService/RevokeAllSessions", "/chronos.identity.v1.IdentityService/RevokeAllSessions", `{}`},
		{"IdentityService/DeactivateAccount", "/chronos.identity.v1.IdentityService/DeactivateAccount", `{}`},
		{"IdentityService/RequestAccountDeletion", "/chronos.identity.v1.IdentityService/RequestAccountDeletion",
			`{"confirmation":"DELETE"}`},
		{"NotificationService/ListNotifications", "/chronos.notification.v1.NotificationService/ListNotifications",
			fmt.Sprintf(`{"orgId":%q}`, syntheticOrgID)},
		{"NotificationService/GetUnreadCount", "/chronos.notification.v1.NotificationService/GetUnreadCount",
			fmt.Sprintf(`{"orgId":%q}`, syntheticOrgID)},
		{"NotificationService/MarkNotificationsRead", "/chronos.notification.v1.NotificationService/MarkNotificationsRead",
			fmt.Sprintf(`{"orgId":%q,"notificationIds":["notif_01ARZ3NDEKTSV4RRFFQ69G5FAV"]}`, syntheticOrgID)},
		{"NotificationService/RegisterPushSubscription", "/chronos.notification.v1.NotificationService/RegisterPushSubscription",
			fmt.Sprintf(`{"orgId":%q,"endpoint":"https://push.example.test/auth","p256dh":%q,"auth":%q}`,
				syntheticOrgID, pushP256DH, pushAuth)},
		{"NotificationService/RemovePushSubscription", "/chronos.notification.v1.NotificationService/RemovePushSubscription",
			fmt.Sprintf(`{"orgId":%q,"endpoint":"https://push.example.test/auth"}`, syntheticOrgID)},
		{"NotificationService/GetNotificationPreferences", "/chronos.notification.v1.NotificationService/GetNotificationPreferences",
			fmt.Sprintf(`{"orgId":%q}`, syntheticOrgID)},
		{"NotificationService/SetNotificationPreferences", "/chronos.notification.v1.NotificationService/SetNotificationPreferences",
			fmt.Sprintf(`{"orgId":%q,"channels":[{"channel":"CHANNEL_EMAIL","enabled":true}]}`, syntheticOrgID)},
		{"ProfileService/GetProfile", "/chronos.profile.v1.ProfileService/GetProfile", `{}`},
		{"ProfileService/UpdateProfile", "/chronos.profile.v1.ProfileService/UpdateProfile", `{"locale":"en-GB"}`},
		{"ProfileService/CreateAvatarUpload", "/chronos.profile.v1.ProfileService/CreateAvatarUpload",
			`{"contentType":"image/png","sizeBytes":"1024"}`},
	}
}

// TestEveryAuthenticatedRPCRefusesAnAnonymousCaller walks the whole
// non-public surface with no Authorization header.
//
// The pipeline is declarative (ADR-021) and the same interceptor guards every
// method, so a single case would "prove" it. It is done per RPC anyway, because
// the failure this catches is not a broken interceptor: it is an RPC whose
// policy was written without `public: true` and without an `authz` block, or one
// whose handler was mounted with a different option list. Both are per-method
// mistakes, and both are invisible to a per-interceptor test.
func TestEveryAuthenticatedRPCRefusesAnAnonymousCaller(t *testing.T) {
	for _, rpc := range authenticatedProcedures() {
		t.Run(rpc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			status, body, err := rawPost(ctx, rpc.path, "application/json",
				rpc.body, "", newIdempotencyKey(), nil)
			if err != nil {
				t.Fatalf("POST %s: %v", rpc.path, err)
			}
			if status != http.StatusUnauthorized {
				t.Fatalf("BUG: %s answered %d to a caller with no Authorization header, "+
					"want 401.\n%s", rpc.name, status, describeRaw(status, body))
			}
			if got := reasonFromJSON(body); got != string(errs.Unauthenticated) {
				t.Errorf("%s refused an anonymous caller with reason %q, want %q\n%s",
					rpc.name, got, errs.Unauthenticated, describeRaw(status, body))
			}
		})
	}
}

// TestAnUnusableBearerTokenIsIndistinguishable is ADR-036 at the bottom rung of
// the ladder.
//
// > | Failed at | Response | Discloses |
// > | authn     | UNAUTHENTICATED | nothing |
//
// "Nothing" is a claim about what a caller can DISTINGUISH, not merely about the
// code. Four different bad tokens — absent, syntactically wrong, well-formed but
// unknown, and one belonging to a session that was deliberately revoked — must
// produce the same code, the same reason and the same message. A message that
// said "session revoked" for one of them would turn the header into an oracle
// for "is this token one that ever existed".
func TestAnUnusableBearerTokenIsIndistinguishable(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	revoked := h.revokedBearer(t)

	cases := []struct {
		name   string
		header string
	}{
		{"no Authorization header", ""},
		{"the word Bearer with nothing after it", "Bearer"},
		{"Bearer with an empty token", "Bearer "},
		{"a token of punctuation", "Bearer !!!!!!!!"},
		{"the wrong scheme", "Basic YWRhOnBhc3N3b3Jk"},
		{"a lowercase scheme with a plausible token", "bearer " + strings.Repeat("a", 43)},
		{"a well-formed token that names no session", "Bearer " + strings.Repeat("a", 43)},
		{"a token for a session that was revoked", "Bearer " + revoked},
	}

	type answer struct {
		status int
		code   string
		reason string
		msg    string
	}
	seen := map[string][]string{}

	for _, tc := range cases {
		extra := http.Header{}
		if tc.header != "" {
			extra.Set(interceptor.AuthorizationHeader, tc.header)
		}
		status, body, err := rawPost(ctx, "/chronos.identity.v1.IdentityService/GetUser",
			"application/json", `{}`, "", "", extra)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		env, _ := decodeWireError(body)
		a := answer{status, env.Code, reasonFromJSON(body), env.Message}
		key := fmt.Sprintf("status=%d code=%s reason=%s message=%q", a.status, a.code, a.reason, a.msg)
		seen[key] = append(seen[key], tc.name)
		t.Logf("%-45s -> %s", tc.name, key)
	}

	if len(seen) != 1 {
		t.Errorf("BUG: %d DISTINGUISHABLE answers to an unusable bearer token, want exactly "+
			"1. ADR-036 puts the authn rung at \"discloses nothing\", and a caller who can "+
			"tell these apart has an oracle for which tokens ever existed:\n%s",
			len(seen), renderGroups(seen))
	}
}

// revokedBearer establishes a second session for the active account and revokes
// it through the public API, returning its now-dead token.
//
// Revoked through RevokeSession rather than by deleting a row, because the
// property under test is what the AUTHN GATE does with a token whose session the
// system has retired — and a row this test deleted would be a test of its own
// SQL.
func (hh *harness) revokedBearer(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	code, err := hh.freshCode(ctx, hh.active.secret)
	if err != nil {
		t.Fatalf("minting a TOTP code: %v", err)
	}
	res, err := hh.identity.CreateSession(ctx,
		authed(&identityv1.CreateSessionRequest{
			Identifier: hh.active.email, Password: hh.active.password, Code: code,
			DeviceId: "dev_doomed_" + hh.suffix,
		}, ""))
	if err != nil {
		t.Fatalf("CreateSession for the session to be revoked: %v\n%s", err, hh.serverLogs())
	}
	doomed := res.Msg.GetToken()
	if err := hh.awaitSessionProjected(ctx, res.Msg.GetSessionId()); err != nil {
		t.Fatalf("%v", err)
	}

	if _, err := hh.identity.RevokeSession(ctx, authed(&identityv1.RevokeSessionRequest{
		SessionId: res.Msg.GetSessionId(),
		Reason:    "conformance_suite",
	}, hh.activeBearer(t))); err != nil {
		t.Fatalf("RevokeSession: %v\n%s", err, hh.serverLogs())
	}
	return doomed
}

// TestASessionPastItsOwnDeadlineIsRefused is a DEFECT REPORT, and every fact in
// it is one the server states about itself.
//
// The reproduction is three of the server's own answers, in order:
//
//  1. `ListSessions` reports the session's `idleExpiresAt`.
//  2. The ADR-054 clock control is pushed past that instant and reports the new
//     `now`, which is later.
//  3. `GetUser` with the same bearer token still answers 200.
//
// # The cause: cmd/api runs two clocks
//
// cmd/api/gates.go builds the authenticator with two fields:
//
//	interceptor.NewSessionAuthenticator(interceptor.SessionAuthenticatorDeps{
//		TX:  pgadapter.New(d.pool),
//		Log: log,
//	})
//
// `SessionAuthenticatorDeps.Now` is left unset, and interceptor/authn.go
// defaults it: `if a.now == nil { a.now = time.Now }`. Meanwhile `d.clock` — the
// clock every deadline in identity is WRITTEN from, and the one ADR-054's
// control moves — is never passed. So `GetSessionByToken`'s
// `t.idle_expires_at > $2` compares a deadline written by one clock against a
// `now` read from another.
//
// cmd/api/deps.go names this hazard in its own words, three lines above where
// the clock is built: "a collaborator built before the clock it should have been
// given is how a process ends up with two of them."
//
// # What it costs
//
// In a deployment the two clocks agree, so session expiry works. The costs are
// still real:
//
//   - Session expiry is UNTESTABLE through the mechanism built for testing it.
//     ADR-054 exists so a suite can make time pass; it cannot make a session
//     expire, so no test in this repository has ever watched one do so.
//   - The idle refresh writes `idle_expires_at` from `time.Now()` while
//     CreateSession wrote it from `d.clock`, so the two halves of one session's
//     lifetime are kept on different clocks. TestASessionsOwnTimestampsAgree
//     below shows the consequence directly.
//   - The day anything injects a clock that is not wall time — a leap-smear
//     wrapper, a test double, a fixed instant — the gate silently disagrees with
//     the rest of the process, and the symptom is sessions that expire early or
//     never.
//
// The fix is one field in cmd/api/gates.go. It is deliberately not made here.
func TestASessionPastItsOwnDeadlineIsRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	bearer := h.activeBearer(t)
	sessions, err := h.identity.ListSessions(ctx,
		authed(&identityv1.ListSessionsRequest{}, bearer))
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	var deadline time.Time
	for _, s := range sessions.Msg.GetSessions() {
		if s.GetSessionId() == h.active.sessionID {
			deadline = s.GetIdleExpiresAt().AsTime()
		}
	}
	if deadline.IsZero() {
		t.Fatalf("the server did not report an idle deadline for session %s, so there is "+
			"nothing to travel past", h.active.sessionID)
	}

	now, err := h.clockState(ctx, http.MethodGet, h.clockURL+"/debug/clock")
	if err != nil {
		t.Fatalf("reading the server's clock: %v", err)
	}
	// One hour past the deadline the server itself reported.
	h.advanceServerClock(t, deadline.Sub(now.now)+time.Hour)
	after, err := h.clockState(ctx, http.MethodGet, h.clockURL+"/debug/clock")
	if err != nil {
		t.Fatalf("reading the server's clock: %v", err)
	}
	t.Logf("session %s idleExpiresAt=%s; the server's clock now reads %s",
		h.active.sessionID, deadline.Format(time.RFC3339), after.now.Format(time.RFC3339))

	status, body, err := rawPost(ctx, "/chronos.identity.v1.IdentityService/GetUser",
		"application/json", `{}`, bearer, "", nil)
	if err != nil {
		t.Fatalf("POST GetUser: %v", err)
	}
	if status == http.StatusOK {
		t.Fatalf("BUG: the server says this session's idle deadline was %s, the server says "+
			"it is now %s, and the server still served the request (200).\n"+
			"cmd/api/gates.go builds the authenticator without a Now, so authn.go defaults "+
			"it to time.Now while every deadline identity writes comes from d.clock. "+
			"The process runs two clocks, and session expiry is unreachable from the "+
			"mechanism ADR-054 built to reach it.\n%s",
			deadline.Format(time.RFC3339), after.now.Format(time.RFC3339),
			describeRaw(status, body))
	}
	if got := reasonFromJSON(body); got != string(errs.Unauthenticated) {
		t.Errorf("an expired session was refused with reason %q, want %q\n%s",
			got, errs.Unauthenticated, describeRaw(status, body))
	}
	t.Logf("expired session -> %s", describeRaw(status, body))
}

// TestASessionsOwnTimestampsAgree is the same defect, stated without any clock
// travel at all — which makes it the cheaper reproduction and the one that would
// still fail on a build with the control disabled.
//
// A session cannot have been LAST SEEN before it was CREATED. It happens here
// because the two timestamps are written by different clocks in one process:
// `createdAt` by identity's injected clock, `lastSeenAt` by the authn gate's
// `time.Now`. With ADR-054's control idle the two are microseconds apart and the
// ordering is luck; with the control moved even one second, `lastSeenAt` lands
// firmly in the past.
func TestASessionsOwnTimestampsAgree(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	bearer := h.activeBearer(t)
	// Two calls: the first is what makes the gate write lastSeenAt at all, the
	// second is what reads it back.
	if _, err := h.identity.GetUser(ctx,
		authed(&identityv1.GetUserRequest{}, bearer)); err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	sessions, err := h.identity.ListSessions(ctx,
		authed(&identityv1.ListSessionsRequest{}, bearer))
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}

	// ONLY the session this test is calling with. ListSessions returns every live
	// session on the account, and the package's clock is global and movable
	// (ADR-054) — activeBearer's own comment notes that "one test pushes it past
	// the idle window". A session created under one offset and touched under
	// another has timestamps that straddle a clock move, so comparing them
	// measures the harness rather than the server. The current session was
	// created and touched without a move in between, which is what makes the
	// ordering meaningful.
	current := h.active.sessionID
	checked := 0
	for _, s := range sessions.Msg.GetSessions() {
		if s.GetSessionId() != current {
			continue
		}
		checked++
		created := s.GetCreatedAt().AsTime()
		lastSeen := s.GetLastSeenAt().AsTime()
		if lastSeen.IsZero() || !lastSeen.Before(created) {
			t.Logf("session %s created=%s lastSeen=%s", s.GetSessionId(),
				created.Format(time.RFC3339Nano), lastSeen.Format(time.RFC3339Nano))
			continue
		}
		t.Errorf("BUG: session %s reports lastSeenAt=%s, which is BEFORE its "+
			"createdAt=%s. One row, two clocks. createdAt comes from identity's "+
			"injected clock; lastSeenAt came from the DATABASE's now(), written by "+
			"the TouchSession statement in db/query/identity/session.sql. The two "+
			"agree in production and diverge as soon as ADR-054's movable clock is "+
			"moved, which is why this is visible here and nowhere else. It was "+
			"originally misdiagnosed as cmd/api/gates.go leaving "+
			"SessionAuthenticatorDeps.Now unset — that was a real defect and is "+
			"fixed, but it was never what wrote this column.",
			s.GetSessionId(), lastSeen.Format(time.RFC3339Nano),
			created.Format(time.RFC3339Nano))
	}
	// Without this the test passes by matching nothing, which is exactly how a
	// renamed or unprojected session id would hide the defect it exists to catch.
	if checked != 1 {
		t.Fatalf("expected to examine exactly the current session %s, examined %d of the "+
			"%d returned; the assertion above measured nothing",
			current, checked, len(sessions.Msg.GetSessions()))
	}
}

// TestTheAssuranceFloorIsEnforcedPerMethod is ADR-021's `min_aal` and
// `bootstrap_min_aal`, on the wire.
//
// The two options are not the same rule and the difference is the whole reason
// an account can ever get its FIRST second factor: `min_aal = ASSURANCE_LEVEL_2`
// on EnrollTotp would be unsatisfiable for an account that has none, so
// `bootstrap_min_aal = ASSURANCE_LEVEL_1` relaxes it for exactly that account.
// The relaxation is read from the PRINCIPAL — the authenticator reports whether
// the account has ever held a proven factor — so a caller cannot claim it.
//
// The bootstrap account is the one this needs: verified, password only, no
// second factor, holding an AAL1 session. Every method that declares
// `min_aal = ASSURANCE_LEVEL_2` with NO bootstrap exemption must refuse it with
// STEP_UP_REQUIRED, and the two that carry the exemption must admit it.
func TestTheAssuranceFloorIsEnforcedPerMethod(t *testing.T) {
	bearer := h.bootstrapBearer(t)

	refused := []struct{ name, path, body string }{
		{"GenerateRecoveryCodes", "/chronos.identity.v1.IdentityService/GenerateRecoveryCodes", `{}`},
		{"RevokeSession", "/chronos.identity.v1.IdentityService/RevokeSession",
			`{"sessionId":"sess_01ARZ3NDEKTSV4RRFFQ69G5FAV"}`},
		{"RevokeAllSessions", "/chronos.identity.v1.IdentityService/RevokeAllSessions", `{}`},
		{"DeactivateAccount", "/chronos.identity.v1.IdentityService/DeactivateAccount", `{}`},
		{"RequestAccountDeletion", "/chronos.identity.v1.IdentityService/RequestAccountDeletion",
			`{"confirmation":"DELETE"}`},
	}

	for _, rpc := range refused {
		t.Run("min_aal=AAL2 refuses an AAL1 session/"+rpc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			status, body, err := rawPost(ctx, rpc.path, "application/json",
				rpc.body, bearer, newIdempotencyKey(), nil)
			if err != nil {
				t.Fatalf("POST %s: %v", rpc.path, err)
			}
			if status != http.StatusForbidden {
				t.Fatalf("BUG: %s declares min_aal = ASSURANCE_LEVEL_2 and no bootstrap "+
					"exemption, and a password-only AAL1 session got %d.\n%s",
					rpc.name, status, describeRaw(status, body))
			}
			if got := reasonFromJSON(body); got != string(errs.StepUpRequired) {
				t.Errorf("%s refused an AAL1 session with reason %q, want %q — a client shows "+
					"a re-authentication prompt for STEP_UP_REQUIRED and an \"ask an admin\" "+
					"message for ACCESS_DENIED (CONVENTIONS §5)\n%s",
					rpc.name, got, errs.StepUpRequired, describeRaw(status, body))
			}
		})
	}

	t.Run("bootstrap_min_aal=AAL1 admits the same session/EnrollTotp", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()

		status, body, err := rawPost(ctx, "/chronos.identity.v1.IdentityService/EnrollTotp",
			"application/json", `{}`, bearer, newIdempotencyKey(), nil)
		if err != nil {
			t.Fatalf("POST EnrollTotp: %v", err)
		}
		if status != http.StatusOK {
			t.Fatalf("BUG: EnrollTotp declares bootstrap_min_aal = ASSURANCE_LEVEL_1, and an "+
				"account with no second factor holding an AAL1 session was refused (%d). "+
				"That account can now never enrol one, and never activate (identity.md §2)."+
				"\n%s", status, describeRaw(status, body))
		}
		t.Logf("EnrollTotp admitted the bootstrap session, as declared")
	})

	// ConfirmTotp declares the SAME pair as EnrollTotp — min_aal = AAL2 with
	// bootstrap_min_aal = AAL1 — and was the one method carrying a declared floor
	// that nothing on the wire asserted. It is the second half of the same
	// bootstrap: enrolling without confirming leaves the account exactly where it
	// started, so if this gate refused an AAL1 session the account could enrol a
	// factor it could never activate.
	//
	// The code is deliberately wrong, because this asserts the GATE and not the
	// verification. Passing the gate is visible as any answer that is NOT
	// 403/STEP_UP_REQUIRED; a rejected code is the expected outcome and proves the
	// request reached the handler.
	t.Run("bootstrap_min_aal=AAL1 admits the same session/ConfirmTotp", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()

		status, body, err := rawPost(ctx, "/chronos.identity.v1.IdentityService/ConfirmTotp",
			"application/json", `{"code":"000000"}`, bearer, newIdempotencyKey(), nil)
		if err != nil {
			t.Fatalf("POST ConfirmTotp: %v", err)
		}
		if status == http.StatusForbidden && reasonFromJSON(body) == string(errs.StepUpRequired) {
			t.Fatalf("BUG: ConfirmTotp declares bootstrap_min_aal = ASSURANCE_LEVEL_1 and "+
				"refused an AAL1 session with STEP_UP_REQUIRED. An account with no second "+
				"factor can then enrol one and never confirm it, so it can never reach AAL2 "+
				"— and every AAL2 method stays unreachable forever.\n%s",
				describeRaw(status, body))
		}
		t.Logf("ConfirmTotp admitted the bootstrap session (answered %d), as declared", status)
	})
}

// renderGroups formats the distinguishable-answer map for a failure message.
func renderGroups(seen map[string][]string) string {
	var b strings.Builder
	for answer, names := range seen {
		fmt.Fprintf(&b, "  %s\n    from: %s\n", answer, strings.Join(names, ", "))
	}
	return b.String()
}

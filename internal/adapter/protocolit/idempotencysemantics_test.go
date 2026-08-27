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
)

// idemCase is one AUTHENTICATED mutation, driven through the full idempotency
// contract rather than only through "a key is required".
//
// `other` is a second body that is VALID and different. Valid matters: the
// collision rule is about the STORE noticing two different requests under one
// key, and a body that protovalidate refuses never reaches the store, so an
// invalid `other` would produce a refusal that looks like a pass and measures
// nothing. Where no second valid body exists, `other` is nil and the reason is
// stated on the case.
type idemCase struct {
	name  string
	path  string
	setup func(t *testing.T) (bearer string, body string, other string)

	// gatedReplay is the status a REPLAY answers when the first call's own
	// success revokes the caller's authorization to make the call again.
	//
	// Two methods are in this position and it is not a defect: the gate pipeline
	// runs BEFORE Idempotency.Do, by design — reading a stored response is
	// reading a previous answer, and a caller who may no longer make the request
	// may no longer read it either. ConfirmTotp activates the account, which ends
	// the bootstrap exemption its own AAL1 session depended on; DeactivateAccount
	// revokes every session including the one that called it.
	//
	// So for these the observable contract is not "the stored response comes
	// back" but "the gate answers first", and asserting the gate is what pins the
	// ordering. Zero means the ordinary stored-response rule applies.
	gatedReplay int
}

// TestTheIdempotencyContractHoldsForEveryAuthenticatedMutation closes the
// dimension that was previously asserted on two RPCs out of thirty.
//
// # What the contract is, and who it applies to
//
// CONVENTIONS §6 states three rules, and this drives the two that "a key is
// required" does not cover:
//
//	Replay, same key, SAME body      the stored response, not a re-execution
//	Replay, same key, DIFFERENT body CONFLICT
//
// It applies to the THIRTEEN authenticated mutations and to no others, and that
// is a property of the code rather than a convenience:
//
//   - The seven PUBLIC mutations never reach the store at all. gates.go returns
//     at `if p.Public { return next(ctx, req) }` before Idempotency.Do, so
//     there is no scope to key on — the scope is `(principal, method, key)` and a
//     public caller has no principal. Their key is enforced by the handler and
//     gives the resulting command a stable identity; it does not buy a replay.
//     TestAPublicMutationHasNoStoredReplay below proves that absence rather than
//     asserting it in prose.
//   - The nine reads pass straight through on `!p.Mutating()`, which
//     TestAKeyOnAReadIsIgnored already covers.
//
// # Why a byte comparison
//
// A replay is indistinguishable from a re-execution for any method whose answer
// is deterministic, so the assertion is only meaningful where the two would
// differ — and it is strongest on the destructive methods. A SECOND execution of
// DeactivateAccount reports `changed:false`, because by then the account is
// already deactivated. A replay reports `changed:true`, because that is what the
// first execution said. So the byte comparison is not pedantry here: it is the
// only thing that separates "the store answered" from "the handler ran again and
// happened not to fail".
func TestTheIdempotencyContractHoldsForEveryAuthenticatedMutation(t *testing.T) {
	for _, ic := range authenticatedMutationCases() {
		t.Run(ic.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
			defer cancel()

			bearer, body, other := ic.setup(t)
			key := newIdempotencyKey()

			status, first, err := rawPost(ctx, ic.path, "application/json", body, bearer, key, nil)
			if err != nil {
				t.Fatalf("POST %s: %v", ic.path, err)
			}
			if status != http.StatusOK {
				t.Fatalf("the FIRST call must succeed or there is no stored response to replay, "+
					"and this test would then assert nothing.\n%s", describeRaw(status, first))
			}

			// Replay: same key, same body.
			replayStatus, replay, err := rawPost(ctx, ic.path, "application/json", body, bearer, key, nil)
			if err != nil {
				t.Fatalf("replaying %s: %v", ic.path, err)
			}
			if ic.gatedReplay != 0 {
				// Asserted on the FIRST reply, with no polling.
				//
				// This test carried a 20-second poll for exactly as long as session
				// revocation was not immediate: `GetSessionByToken` checks
				// `session_view.revoked_at`, the projector writes that column, and a
				// deactivated account's own bearer kept authenticating until it did.
				// The tolerance was honest about the code and hid what ADR-018
				// promises — "immediate, server-side" — behind a window whose width
				// was another component's health.
				//
				// Revocation now destroys the session's digest in the same request
				// that appends the event, so the join has nothing to resolve on the
				// very next call. The poll is gone, and its absence is the assertion:
				// if the destroy is ever dropped, this fails here rather than passing
				// slowly.
				if replayStatus != ic.gatedReplay {
					t.Fatalf("this call's success revokes the caller's own authorization, so a "+
						"replay must be refused by the GATE with %d, on the NEXT REQUEST — the "+
						"pipeline reaches Idempotency.Do only after the gates pass, and the "+
						"revocation destroys the session's secret rather than waiting for a "+
						"projection. It answered %d.\n%s",
						ic.gatedReplay, replayStatus, describeRaw(replayStatus, replay))
				}
				t.Logf("%s: replay refused by the gate with %d, as it must be — the success "+
					"itself ended the caller's authorization, and a stored response is still "+
					"a response", ic.name, replayStatus)
				return
			}
			if replayStatus != http.StatusOK {
				t.Fatalf("a replay of the same key with the same body answered %d rather than "+
					"returning the stored response.\n%s",
					replayStatus, describeRaw(replayStatus, replay))
			}
			if replay != first {
				t.Errorf("replaying %s with the same key and the same body answered\n  %s\n"+
					"but the first call answered\n  %s\n"+
					"A replay must return the STORED response. A body that differs means the "+
					"handler ran a second time, which is the double execution the key exists "+
					"to prevent (CONVENTIONS §6).",
					ic.name, strings.TrimSpace(replay), strings.TrimSpace(first))
			}

			if other == "" {
				t.Logf("%s: replay verified; no second valid body exists, so the collision rule "+
					"does not apply", ic.name)
				return
			}

			// Collision: same key, different body.
			collideStatus, collide, err := rawPost(ctx, ic.path, "application/json", other, bearer, key, nil)
			if err != nil {
				t.Fatalf("colliding %s: %v", ic.path, err)
			}
			if collideStatus == http.StatusOK {
				t.Fatalf("reusing one key for a DIFFERENT body was accepted (%d). The caller now "+
					"receives an answer computed for someone else's request — which is the "+
					"failure the fingerprint exists to catch, and it fails silently.\n%s",
					collideStatus, describeRaw(collideStatus, collide))
			}
			if got := reasonFromJSON(collide); got != string(errs.Conflict) {
				t.Errorf("a key reused with a different body refused with reason %q, want %q. "+
					"A client distinguishes its own bug (it reused a key) from a server "+
					"condition by that reason alone.\n%s",
					got, errs.Conflict, describeRaw(collideStatus, collide))
			}
			t.Logf("%s: replay returned the stored response; a different body under the same "+
				"key returned %s", ic.name, reasonFromJSON(collide))
		})
	}
}

// authenticatedMutationCases is all thirteen, each with the account state its
// success path needs.
//
// The account choice per case is not incidental. A method that ends the account
// gets its OWN account, because a replay assertion needs the first call to have
// really happened and the fixture to survive long enough to ask again.
func authenticatedMutationCases() []idemCase {
	shared := func(t *testing.T) string { return h.activeBearer(t) }

	return []idemCase{
		{
			name: "IdentityService/EnrollTotp",
			path: "/chronos.identity.v1.IdentityService/EnrollTotp",
			setup: func(t *testing.T) (string, string, string) {
				// A bootstrap account, because enrolment is only reachable from an
				// account that has not enrolled.
				//
				// No `other`: the message's only field is `account_name`, which is
				// `deprecated = true` and slated for deletion at the first release
				// boundary. Building a collision case on a field scheduled for
				// removal would make this test fail for a reason unrelated to
				// idempotency the day it goes.
				a := h.bootstrapAccount(t, "idem-enrol")
				return a.bearer, `{}`, ""
			},
		},
		{
			name: "IdentityService/ConfirmTotp",
			path: "/chronos.identity.v1.IdentityService/ConfirmTotp",
			setup: func(t *testing.T) (string, string, string) {
				ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
				defer cancel()

				a := h.bootstrapAccount(t, "idem-confirm")
				enrolled, err := h.identity.EnrollTotp(ctx,
					authed(&identityv1.EnrollTotpRequest{}, a.bearer))
				if err != nil {
					t.Fatalf("EnrollTotp: %v", err)
				}
				secret, err := secretFromURI(enrolled.Msg.GetProvisioningUri())
				if err != nil {
					t.Fatalf("reading the enrolled secret: %v", err)
				}
				code, err := h.freshCode(ctx, secret)
				if err != nil {
					t.Fatalf("minting a code: %v", err)
				}
				// The colliding body is a DIFFERENT well-formed code. It is wrong,
				// and that is the point: it must be refused for reusing the key, not
				// for being wrong, which is what distinguishes the store from the
				// verifier.
				return a.bearer, fmt.Sprintf(`{"code":%q}`, code), `{"code":"000000"}`
			},
			// Confirming the FIRST factor activates the account, and activation is
			// exactly what ends `bootstrap_min_aal = AAL1`. The session that was
			// admitted a moment ago is now an AAL1 session facing a plain
			// `min_aal = AAL2`, so the replay meets STEP_UP_REQUIRED.
			gatedReplay: http.StatusForbidden,
		},
		{
			name: "IdentityService/GenerateRecoveryCodes",
			path: "/chronos.identity.v1.IdentityService/GenerateRecoveryCodes",
			setup: func(t *testing.T) (string, string, string) {
				// Its own account: the call REPLACES the existing set, so a replay
				// that silently re-executed would invalidate codes the first answer
				// already handed out. That is exactly what the byte comparison
				// detects here.
				a := h.disposableAccount(t, "idem-codes")
				return a.bearer, `{"count":8}`, `{"count":12}`
			},
		},
		{
			name: "IdentityService/RevokeSession",
			path: "/chronos.identity.v1.IdentityService/RevokeSession",
			setup: func(t *testing.T) (string, string, string) {
				ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
				defer cancel()

				// Two sessions on one disposable account: one to revoke, one to keep
				// making the call with. Revoking the caller's own session would make
				// the replay unauthenticated and turn a store failure into a 401.
				a := h.disposableAccount(t, "idem-revoke")
				victim := a.sessionID
				if err := h.reSignIn(ctx, a); err != nil {
					t.Fatalf("establishing a second session: %v", err)
				}
				return a.bearer,
					fmt.Sprintf(`{"sessionId":%q,"reason":"conformance_suite"}`, victim),
					fmt.Sprintf(`{"sessionId":%q,"reason":"a_different_reason"}`, victim)
			},
		},
		{
			name: "IdentityService/RevokeAllSessions",
			path: "/chronos.identity.v1.IdentityService/RevokeAllSessions",
			setup: func(t *testing.T) (string, string, string) {
				// except_session_id spares the CALLER's session. Without it the call
				// revokes the bearer that made it, the replay is 401, and what the
				// test measures becomes "sign-out-everywhere works" rather than
				// anything about idempotency. disposableAccount leaves two sessions
				// behind, so there is still a session to revoke.
				a := h.disposableAccount(t, "idem-revokeall")
				return a.bearer,
					fmt.Sprintf(`{"exceptSessionId":%q,"reason":"conformance_suite"}`, a.sessionID),
					fmt.Sprintf(`{"exceptSessionId":%q,"reason":"a_different_reason"}`, a.sessionID)
			},
		},
		{
			name: "IdentityService/DeactivateAccount",
			path: "/chronos.identity.v1.IdentityService/DeactivateAccount",
			setup: func(t *testing.T) (string, string, string) {
				// The sharpest replay case in the suite. A re-execution answers
				// `changed:false` — the account is already deactivated by then — so a
				// byte-identical `changed:true` can only have come from the store.
				//
				// No `other`: DeactivateAccountRequest declares no fields, so every
				// body is the same body and a collision cannot be constructed.
				a := h.disposableAccount(t, "idem-deactivate")
				return a.bearer, `{}`, ""
			},
			// Deactivation revokes every session on the account, the caller's
			// included, so the bearer that made the call cannot make it again.
			gatedReplay: http.StatusUnauthorized,
		},
		{
			name: "IdentityService/RequestAccountDeletion",
			path: "/chronos.identity.v1.IdentityService/RequestAccountDeletion",
			setup: func(t *testing.T) (string, string, string) {
				// No `other`: `confirmation` must be the literal "DELETE", so the one
				// valid body is the only valid body. Anything else is refused by
				// protovalidate before the store is consulted.
				a := h.disposableAccount(t, "idem-deletion")
				return a.bearer, `{"confirmation":"DELETE"}`, ""
			},
		},
		{
			name: "NotificationService/MarkNotificationsRead",
			path: "/chronos.notification.v1.NotificationService/MarkNotificationsRead",
			setup: func(t *testing.T) (string, string, string) {
				// Real feed rows. A synthetic id answers NOT_FOUND — correctly, and
				// the API refuses an id the caller does not own before it appends —
				// so nothing would ever be stored and the replay would assert
				// nothing.
				bearer := shared(t)
				one := h.seedNotification(t, h.active.subjectID, syntheticOrgID)
				two := h.seedNotification(t, h.active.subjectID, syntheticOrgID)
				return bearer,
					fmt.Sprintf(`{"orgId":%q,"notificationIds":[%q]}`, syntheticOrgID, one),
					fmt.Sprintf(`{"orgId":%q,"notificationIds":[%q]}`, syntheticOrgID, two)
			},
		},
		{
			name: "NotificationService/RegisterPushSubscription",
			path: "/chronos.notification.v1.NotificationService/RegisterPushSubscription",
			setup: func(t *testing.T) (string, string, string) {
				one := "https://push.example.test/idem-" + randomTag()
				two := "https://push.example.test/idem-" + randomTag()
				return shared(t),
					fmt.Sprintf(`{"orgId":%q,"endpoint":%q,"p256dh":%q,"auth":%q}`,
						syntheticOrgID, one, pushP256DH, pushAuth),
					fmt.Sprintf(`{"orgId":%q,"endpoint":%q,"p256dh":%q,"auth":%q}`,
						syntheticOrgID, two, pushP256DH, pushAuth)
			},
		},
		{
			name: "NotificationService/RemovePushSubscription",
			path: "/chronos.notification.v1.NotificationService/RemovePushSubscription",
			setup: func(t *testing.T) (string, string, string) {
				return shared(t),
					fmt.Sprintf(`{"orgId":%q,"endpoint":"https://push.example.test/rm-%s"}`,
						syntheticOrgID, randomTag()),
					fmt.Sprintf(`{"orgId":%q,"endpoint":"https://push.example.test/rm-%s"}`,
						syntheticOrgID, randomTag())
			},
		},
		{
			name: "NotificationService/SetNotificationPreferences",
			path: "/chronos.notification.v1.NotificationService/SetNotificationPreferences",
			setup: func(t *testing.T) (string, string, string) {
				return shared(t),
					fmt.Sprintf(`{"orgId":%q,"channels":[{"channel":"CHANNEL_EMAIL","enabled":true}]}`,
						syntheticOrgID),
					fmt.Sprintf(`{"orgId":%q,"channels":[{"channel":"CHANNEL_EMAIL","enabled":false}]}`,
						syntheticOrgID)
			},
		},
		{
			name: "ProfileService/UpdateProfile",
			path: "/chronos.profile.v1.ProfileService/UpdateProfile",
			setup: func(t *testing.T) (string, string, string) {
				return shared(t),
					`{"displayName":"Idempotency One"}`,
					`{"displayName":"Idempotency Two"}`
			},
		},
		{
			name: "ProfileService/CreateAvatarUpload",
			path: "/chronos.profile.v1.ProfileService/CreateAvatarUpload",
			setup: func(t *testing.T) (string, string, string) {
				return shared(t),
					`{"contentType":"image/png","sizeBytes":"1024"}`,
					`{"contentType":"image/png","sizeBytes":"2048"}`
			},
		},
	}
}

// A PUBLIC mutation gets no stored replay, and this proves the absence.
//
// # Why assert a negative at all
//
// The published contract now says every mutation requires an Idempotency-Key,
// which is true and is what a client must do. It would be easy to read that as
// "therefore every mutation replays", and it does not: the store is keyed on
// `(principal, method, key)` and a public caller has no principal, so
// Idempotency.Do is never reached for these seven — gates.go returns first.
//
// That leaves a claim in the documentation that nothing checks. If a future
// change moved the public branch below the idempotency gate, public mutations
// would silently acquire a store scoped to no principal, and one caller's key
// could collide with another's. Nothing in the suite would notice.
//
// The observable difference is the collision rule: WITH a store, a second call
// under the same key with a different body is CONFLICT. Without one, it is just
// another request. So sending two different bodies under one key and requiring
// that the second is NOT a conflict is exactly the absence, expressed as
// something a test can see.
func TestAPublicMutationHasNoStoredReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	const path = "/chronos.identity.v1.IdentityService/ResendEmailVerification"
	key := newIdempotencyKey()

	// Two DIFFERENT bodies under ONE key. Both are well-formed, so neither can be
	// refused by protovalidate, and this RPC answers identically for known and
	// unknown addresses (ADR-036) so neither can be refused for existing or not.
	first := fmt.Sprintf(`{"email":%q}`, h.freshEmail("nostore-a"))
	second := fmt.Sprintf(`{"email":%q}`, h.freshEmail("nostore-b"))

	status, body, err := rawPost(ctx, path, "application/json", first, "", key, nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("the first public mutation was refused, so the second proves nothing.\n%s",
			describeRaw(status, body))
	}

	status2, body2, err := rawPost(ctx, path, "application/json", second, "", key, nil)
	if err != nil {
		t.Fatalf("POST (second): %v", err)
	}
	if reasonFromJSON(body2) == string(errs.Conflict) {
		t.Fatalf("a public mutation answered CONFLICT for a reused key with a different body, "+
			"which means it IS being fingerprinted against a store. The scope is "+
			"(principal, method, key) and a public caller has no principal, so whatever it "+
			"is scoped to now is shared across callers — one client's key can refuse "+
			"another's request.\n%s", describeRaw(status2, body2))
	}
	if status2 != http.StatusOK {
		t.Errorf("a public mutation with a fresh valid body was refused (%d) for reusing a "+
			"key. Public mutations are not stored, so the key cannot be a reason to "+
			"refuse.\n%s", status2, describeRaw(status2, body2))
	}
	t.Logf("public mutation: a reused key with a different body answered %d, not CONFLICT — "+
		"no store, as gates.go implies", status2)
}

//go:build integration

package protocolit_test

import (
	"context"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"

	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/internal/platform/db"
)

// Session revocation, against the RUNNING SERVER, and specifically the property
// that does NOT depend on the projector.
//
// # The gap these close
//
// `GetSessionByToken` inner-joins `session_token` (the secret) with
// `session_view` (the facts) and refuses a row whose `revoked_at` is set. That
// column is written by the PROJECTOR from `SessionRevoked`, so for as long as
// the projector was behind, a revoked session kept authenticating — milliseconds
// when it is healthy, unbounded while it is stopped, being rebuilt, or wedged on
// an unrelated event, and silent in every case, because a request served by a
// revoked session looks exactly like one served by a live one.
//
// ADR-018 says this token's revocation is "Immediate, server-side". A window
// whose width is another component's health is not that, and it fails OPEN,
// which ADR-010 permits nowhere but OpenFGA's inverse.
//
// Revocation now destroys the digest in the same request that appends the event.
// The tests below assert both halves of that: the row is gone, and the bearer is
// refused on the very next call.
//
// # Why the digest and not just the 401
//
// Because a 401 alone cannot tell the fix from a fast projector. The suite's
// projectors run, and another integration package's may hold the lease and be
// projecting too, so "the bearer stopped working" is satisfied by the old
// behaviour on a quiet machine. The absence of the `session_token` row is the
// projector-independent fact: with no digest, the join has nothing to resolve
// whatever `session_view` says.

// digestRows counts the secret halves a subject still holds.
//
// A system transaction: `session_token` carries no tenant column, because a
// session belongs to a person rather than to an organization.
func digestRows(t *testing.T, ctx context.Context, sessionID string) int {
	t.Helper()

	var rows int
	err := h.pg.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx,
			`SELECT count(*) FROM session_token WHERE session_id = $1`, sessionID).Scan(&rows)
	})
	if err != nil {
		t.Fatalf("counting session secrets: %v", err)
	}
	return rows
}

// REVOKING A SESSION DESTROYS ITS SECRET AND REFUSES IT ON THE NEXT REQUEST.
//
// No wait anywhere in this test, deliberately. The point is that there is
// nothing to wait for.
func TestRevokingASessionTakesEffectWithoutTheProjector(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	account := h.disposableAccount(t, "revoke-now")
	sessionID := account.sessionID

	if got := digestRows(t, ctx, sessionID); got != 1 {
		t.Fatalf("the live session has %d secret rows, want 1; this test would then "+
			"assert the absence of something that was never there", got)
	}

	if _, err := h.identity.RevokeSession(ctx,
		authedIdem(&identityv1.RevokeSessionRequest{
			SessionId: sessionID, Reason: "user_signed_out",
		}, account.bearer)); err != nil {
		t.Fatalf("RevokeSession: %v\n%s", err, h.serverLogs())
	}

	// THE PROJECTOR-INDEPENDENT ASSERTION.
	if got := digestRows(t, ctx, sessionID); got != 0 {
		t.Errorf("the revoked session kept %d secret row(s). It therefore resolves for as "+
			"long as the session projection takes to set revoked_at — which is unbounded "+
			"while the projector is stopped, and ADR-018 promises this revocation is "+
			"immediate and server-side", got)
	}

	// And the wire agrees, on the very next call.
	_, err := h.identity.ListSessions(ctx, authed(&identityv1.ListSessionsRequest{}, account.bearer))
	if err == nil {
		t.Fatal("a revoked session authenticated on the next request")
	}
	if got := connectrpc.CodeOf(err); got != connectrpc.CodeUnauthenticated {
		t.Errorf("want unauthenticated for a revoked session, got %v: %v", got, err)
	}
}

// SIGNING OUT EVERYWHERE ELSE DESTROYS THE OTHER SECRETS AND KEEPS ITS OWN.
//
// The spared session is the one making the request, so a revocation that
// destroyed its digest would sign the caller out of the call they used to sign
// everybody else out — and would do it in a way no unit test on the plan can
// see, because the append and the epoch bump look identical either way.
func TestSigningOutEverywhereElseSparesTheCallersOwnSecret(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()

	account := h.disposableAccount(t, "revoke-others")
	caller := account.sessionID

	// A second session for the same person, opened the way a second device would.
	if err := h.reSignIn(ctx, account); err != nil {
		t.Fatalf("opening a second session: %v\n%s", err, h.serverLogs())
	}
	other := account.sessionID
	if other == caller {
		t.Fatalf("the second sign-in reused session %s, so there is no other session to "+
			"revoke and this test asserts nothing", caller)
	}

	// `account.bearer` is now the SECOND session's, so that is the spared one.
	if _, err := h.identity.RevokeAllSessions(ctx,
		authedIdem(&identityv1.RevokeAllSessionsRequest{
			ExceptSessionId: other, Reason: "user_signed_out_everywhere",
		}, account.bearer)); err != nil {
		t.Fatalf("RevokeAllSessions: %v\n%s", err, h.serverLogs())
	}

	if got := digestRows(t, ctx, caller); got != 0 {
		t.Errorf("the first session kept %d secret row(s) after a sign-out-everywhere-else; "+
			"it keeps authenticating until the projector catches up", got)
	}
	if got := digestRows(t, ctx, other); got != 1 {
		t.Fatalf("the SPARED session lost its secret (%d rows, want 1). The caller asked to "+
			"sign out everywhere ELSE and was signed out too", got)
	}

	// And the spared session still works, which is what makes it spared.
	if _, err := h.identity.ListSessions(ctx,
		authed(&identityv1.ListSessionsRequest{}, account.bearer)); err != nil {
		t.Errorf("the spared session no longer authenticates: %v", err)
	}
}

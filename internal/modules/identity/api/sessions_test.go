package api_test

import (
	"testing"

	"connectrpc.com/connect"
	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// A well-formed session id belonging to somebody else. It is only ever used to
// name WHICH session; whose it must be is the principal's business.
const someSessionID = "sess_01ARZ3NDEKTSV4RRFFQ69G5FAV"

func TestRevokeSession(t *testing.T) {
	t.Parallel()

	t.Run("the session comes from the request and the owner from the principal", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)

		_, err := h.client.RevokeSession(t.Context(), withKey(&identityv1.RevokeSessionRequest{
			SessionId: someSessionID,
			Reason:    "user_signed_out",
		}, "idem-revoke-1"))
		if err != nil {
			t.Fatalf("RevokeSession: %v", err)
		}

		cmds := h.authn.revoked()
		if len(cmds) != 1 {
			t.Fatalf("app.RevokeSession called %d times, want 1", len(cmds))
		}
		if cmds[0].SessionID.String() != someSessionID {
			t.Errorf("session id = %q, want %q", cmds[0].SessionID.String(), someSessionID)
		}
		if cmds[0].SubjectID != callerSubject {
			t.Errorf("subject = %q, want the principal's %q", cmds[0].SubjectID, callerSubject)
		}
		if cmds[0].Reason != "user_signed_out" {
			t.Errorf("reason = %q", cmds[0].Reason)
		}
		if cmds[0].IdempotencyKey != "idem-revoke-1" {
			t.Errorf("idempotency key = %q", cmds[0].IdempotencyKey)
		}
		// Left to the app layer, which defaults it to the subject. A request that
		// could set it would let a caller claim somebody else's action in the log.
		if cmds[0].ActorID != "" {
			t.Errorf("actor id = %q, want empty so app defaults it", cmds[0].ActorID)
		}
	})

	t.Run("an already-revoked session reports changed=false and succeeds", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.authn.revokeFn = func(app.RevokeSessionCommand) (app.RevokeSessionResult, error) {
			return app.RevokeSessionResult{Changed: false}, nil
		}

		resp, err := h.client.RevokeSession(t.Context(), withKey(&identityv1.RevokeSessionRequest{
			SessionId: someSessionID,
		}, "idem-revoke-2"))
		if err != nil {
			t.Fatalf("RevokeSession: %v", err)
		}
		if resp.Msg.GetChanged() {
			t.Error("changed = true for an already-revoked session")
		}
	})

	t.Run("a changed revocation reports it", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.authn.revokeFn = func(app.RevokeSessionCommand) (app.RevokeSessionResult, error) {
			return app.RevokeSessionResult{Changed: true}, nil
		}
		resp, err := h.client.RevokeSession(t.Context(), withKey(&identityv1.RevokeSessionRequest{
			SessionId: someSessionID,
		}, "idem-revoke-3"))
		if err != nil {
			t.Fatalf("RevokeSession: %v", err)
		}
		if !resp.Msg.GetChanged() {
			t.Error("changed = false")
		}
	})
}

func TestRevokeAllSessions(t *testing.T) {
	t.Parallel()

	t.Run("the subject comes from the principal and the counts come back", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.authn.revokeAllFn = func(
			app.RevokeAllSessionsCommand,
		) (app.RevokeAllSessionsResult, error) {
			return app.RevokeAllSessionsResult{Revoked: 3, Scanned: 4}, nil
		}

		resp, err := h.client.RevokeAllSessions(t.Context(), withKey(
			&identityv1.RevokeAllSessionsRequest{
				ExceptSessionId: someSessionID,
				Reason:          "password_reset",
			}, "idem-revoke-all-1"))
		if err != nil {
			t.Fatalf("RevokeAllSessions: %v", err)
		}

		cmds := h.authn.revokedAll()
		if len(cmds) != 1 {
			t.Fatalf("app.RevokeAllSessions called %d times, want 1", len(cmds))
		}
		if cmds[0].SubjectID != callerSubject {
			t.Errorf("subject = %q, want the principal's %q", cmds[0].SubjectID, callerSubject)
		}
		if cmds[0].Except.String() != someSessionID {
			t.Errorf("except = %q, want %q", cmds[0].Except.String(), someSessionID)
		}
		if cmds[0].Reason != "password_reset" {
			t.Errorf("reason = %q", cmds[0].Reason)
		}
		if resp.Msg.GetRevoked() != 3 || resp.Msg.GetScanned() != 4 {
			t.Errorf("revoked/scanned = %d/%d, want 3/4",
				resp.Msg.GetRevoked(), resp.Msg.GetScanned())
		}
	})

	// Empty spares NOTHING, and that is what a compromise response needs: a reset
	// must void every session including the one that asked, because the party
	// asking may be the attacker. An empty value must not become an error, and it
	// must not become a spared session either.
	t.Run("an empty except id spares nothing", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)

		_, err := h.client.RevokeAllSessions(t.Context(), withKey(
			&identityv1.RevokeAllSessionsRequest{}, "idem-revoke-all-2"))
		if err != nil {
			t.Fatalf("RevokeAllSessions: %v", err)
		}

		cmds := h.authn.revokedAll()
		if len(cmds) != 1 {
			t.Fatalf("app.RevokeAllSessions called %d times, want 1", len(cmds))
		}
		if !cmds[0].Except.IsZero() {
			t.Fatalf("except = %v, want the zero session id", cmds[0].Except)
		}
		var zero ids.SessionID
		if cmds[0].Except != zero {
			t.Fatalf("except = %v, want %v", cmds[0].Except, zero)
		}
	})
}

// The counts are int in the app layer and int32 on the wire. A plain conversion
// turns a value past the limit into a NEGATIVE count, and "sign out everywhere
// ended -2 sessions" is an answer no client can act on. Neither bound is
// reachable in practice, which is exactly why it has to be asserted rather than
// reasoned about.
func TestRevokeAllSessionsNarrowsItsCountsWithoutWrapping(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		revoked, scanned int
		wantRevoked      int32
		wantScanned      int32
	}{
		"ordinary counts pass through": {3, 4, 3, 4},
		"a count past the wire's limit saturates": {
			1 << 40, 1 << 41, 1<<31 - 1, 1<<31 - 1,
		},
		"a negative count becomes zero": {-1, -2, 0, 0},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			h.authn.revokeAllFn = func(
				app.RevokeAllSessionsCommand,
			) (app.RevokeAllSessionsResult, error) {
				return app.RevokeAllSessionsResult{Revoked: tt.revoked, Scanned: tt.scanned}, nil
			}

			resp, err := h.client.RevokeAllSessions(t.Context(), withKey(
				&identityv1.RevokeAllSessionsRequest{}, "idem-counts-"+name))
			if err != nil {
				t.Fatalf("RevokeAllSessions: %v", err)
			}
			if resp.Msg.GetRevoked() != tt.wantRevoked {
				t.Errorf("revoked = %d, want %d", resp.Msg.GetRevoked(), tt.wantRevoked)
			}
			if resp.Msg.GetScanned() != tt.wantScanned {
				t.Errorf("scanned = %d, want %d", resp.Msg.GetScanned(), tt.wantScanned)
			}
		})
	}
}

// Both revocations act on the caller's own account. Driving them with a session
// id the caller does not own must change nothing about WHOSE account is touched:
// the subject is the principal's in every case.
func TestRevocationsNeverTakeTheirSubjectFromTheRequest(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	ctx := t.Context()

	if _, err := h.client.RevokeSession(ctx, withKey(&identityv1.RevokeSessionRequest{
		SessionId: someSessionID,
	}, "idem-revoke-sub-1")); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if _, err := h.client.RevokeAllSessions(ctx, withKey(
		&identityv1.RevokeAllSessionsRequest{ExceptSessionId: someSessionID},
		"idem-revoke-sub-2")); err != nil {
		t.Fatalf("RevokeAllSessions: %v", err)
	}

	for _, cmd := range h.authn.revoked() {
		if cmd.SubjectID != callerSubject || cmd.SubjectID == otherSubject {
			t.Errorf("RevokeSession subject = %q, want %q", cmd.SubjectID, callerSubject)
		}
	}
	for _, cmd := range h.authn.revokedAll() {
		if cmd.SubjectID != callerSubject || cmd.SubjectID == otherSubject {
			t.Errorf("RevokeAllSessions subject = %q, want %q", cmd.SubjectID, callerSubject)
		}
	}
}

// A principal that is not a person carries a KEY's identifier rather than a
// pseudonym, so reading it as a subject would answer for whatever account that
// string happened to name. It is refused, and no command runs.
func TestANonHumanPrincipalIsRefused(t *testing.T) {
	t.Parallel()

	principal := defaultPrincipal()
	principal.Subject.Kind = "api_key"
	h := newHarness(t, options{principal: &principal})

	_, err := h.client.GetUser(t.Context(), connect.NewRequest(&identityv1.GetUserRequest{}))
	requireCode(t, err, connect.CodeUnauthenticated)

	if calls := h.queries.recorded(); len(calls) != 0 {
		t.Fatalf("the read side answered for a non-human principal: %+v", calls)
	}
}

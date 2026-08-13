package projection

import (
	"context"
	"fmt"

	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// SessionName keys the checkpoint row and the single-writer lease.
const SessionName = "identity_session"

// Session builds session_view and login_history_view.
//
// It writes the PROJECTED half of a session only. The bearer-token digest and
// the idle deadline live in session_token, written by the login handler, because
// neither is in the log: a digest in an event would outlive the session forever,
// and recording each idle refresh would make every authenticated read a write
// (migration 00010).
//
// The practical consequence is worth stating plainly: this projection can be
// rebuilt from position zero, and doing so signs everybody out for the duration
// — the token rows survive, but nothing resolves until the facts are replayed.
// That is the price of being able to fix a session-projection bug by replaying
// the log, and it is the right one.
type Session struct{ dispatch *projection.Dispatch }

var _ projection.Projection = (*Session)(nil)

// NewSession wires the session and authentication handlers.
func NewSession(codec eventsourcing.Codec) *Session {
	d := projection.NewDispatch(codec)

	projection.On[contract.SessionCreated](d, func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.SessionCreated,
	) error {
		// DO NOTHING on conflict, not DO UPDATE. A replay must not resurrect a
		// session that was revoked after it was created: the revocation is a
		// later event and would be replayed after this one, but only if this one
		// did not overwrite the row with its original state in between.
		aal, err := aalColumn(e.AAL)
		if err != nil {
			return fmt.Errorf("session %s: %w", e.SessionID, err)
		}
		w.Exec(identitydb.UpsertSession,
			e.SessionID, e.SubjectID, nullable(e.DeviceID), aal,
			e.AbsoluteExpiresAt, e.RequiresCredentialRotation, e.CreatedAt)
		return nil
	})

	projection.On[contract.SessionElevated](d, func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.SessionElevated,
	) error {
		aal, err := aalColumn(e.AAL)
		if err != nil {
			return fmt.Errorf("session %s: %w", e.SessionID, err)
		}
		w.Exec(identitydb.ElevateSession,
			e.SessionID, aal, nullable(e.Scope), e.ElevatedUntil)
		return nil
	})

	projection.On[contract.SessionRevoked](d, func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.SessionRevoked,
	) error {
		w.Exec(identitydb.RevokeSession, e.SessionID)
		return nil
	})

	projection.On[contract.SessionExpired](d, func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.SessionExpired,
	) error {
		// Expiry marks the row revoked too. The two are different FACTS — one is
		// a security signal, one is routine — and the events stay distinct, but
		// the read model only needs to know the session is over. Which of them
		// ended it is answerable from the log.
		w.Exec(identitydb.RevokeSession, e.SessionID)
		return nil
	})

	projection.On[contract.AuthenticationSucceeded](d, func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.AuthenticationSucceeded,
	) error {
		methods := make([]string, len(e.Methods))
		for i, m := range e.Methods {
			methods[i] = string(m)
		}
		aal, err := aalColumn(e.AAL)
		if err != nil {
			return fmt.Errorf("authentication for %s: %w", e.SubjectID, err)
		}
		w.Exec(identitydb.RecordLoginAttempt,
			nullable(e.SubjectID), nil, true, nil, methods, &aal,
			nullable(e.DeviceID), e.SucceededAt)
		return nil
	})

	projection.On[contract.AuthenticationFailed](d, func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.AuthenticationFailed,
	) error {
		// SubjectID is empty when the identifier matched no account, and is
		// written as NULL rather than "". A foreign key no longer enforces that
		// (migration 00009), so the empty string would insert happily and become
		// a subject nobody can look up.
		reason := string(e.Reason)
		w.Exec(identitydb.RecordLoginAttempt,
			nullable(e.SubjectID), nullable(string(e.Index)), false, &reason,
			nil, nil, nullable(e.DeviceID), e.FailedAt)
		return nil
	})

	return &Session{dispatch: d}
}

func (s *Session) Name() string { return SessionName }

func (s *Session) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{EventTypePrefixes: []string{"identity."}}
}

func (s *Session) Apply(ctx context.Context, w db.Writer, env projection.Envelope) error {
	return s.dispatch.Apply(ctx, w, env)
}

func (s *Session) Handles(eventType string) bool { return s.dispatch.Handles(eventType) }

// Reset is a no-op that returns an error explaining why.
//
// Both of this projection's tables are truncated by the User projection's Reset,
// in ONE statement, because session_view carries a foreign key to user_view and
// Postgres refuses to truncate either alone. Splitting the reset across two
// projections would mean two transactions and a window in which one table has
// been emptied and the other has not.
//
// Rebuilding this projection therefore requires rebuilding both together, and
// saying so loudly is better than silently truncating half the graph.
func (s *Session) Reset(_ context.Context, _ db.Querier) error {
	return fmt.Errorf("identity session projection: cannot be reset alone; session_view and "+
		"user_view are truncated together by the %q projection because a foreign key ties "+
		"them and Postgres refuses to truncate either on its own — rebuild %q instead",
		UserName, UserName)
}

// aalColumn narrows an assurance level to the column's type, refusing anything
// the system cannot actually establish.
//
// A conversion rather than a cast, and it returns an error rather than carrying
// a //nolint for the overflow. AssuranceLevel is an int and the column is an
// integer with CHECK (aal IN (1, 2)), so a plain int32() would truncate silently
// and hand the database a value its constraint then rejects — surfacing as a
// constraint violation naming a number that appears nowhere in the event.
//
// Refusing here STOPS the projection, which is correct: an event carrying an AAL
// this build cannot represent was written by a newer deployment or is corrupt,
// and both mean "do not guess". A projection that skipped the event would build
// a read model quietly missing sessions.
func aalColumn(a contract.AssuranceLevel) (int32, error) {
	// An explicit switch returning LITERALS, not a conversion guarded by a
	// range check. Both are correct; only this one is analyzable — a static
	// checker cannot see that Valid() narrows an int to {1, 2}, so the guarded
	// version needs a //nolint, and a suppression is a promise a reader has to
	// take on trust.
	//
	// Here there is no conversion to suppress. The mapping is duplicated from
	// AssuranceLevel.Valid, which is deliberate: making AAL3 establishable must
	// be a decision taken in both places, and the compiler shows the second one.
	switch a {
	case contract.AAL1:
		return 1, nil
	case contract.AAL2:
		return 2, nil
	default:
		return 0, fmt.Errorf("assurance level %d is not one this build can record; "+
			"only AAL1 and AAL2 are establishable (contract.AssuranceLevel.Valid)", int(a))
	}
}

// nullable converts an empty string to a NULL parameter.
//
// Empty-string-as-absent is a real hazard in this schema: subject_id and
// device_id are both nullable pseudonyms, and "" would insert as a subject that
// exists and matches nothing.
func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

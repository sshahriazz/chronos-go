package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Sessions implements the three ports a login needs from PostgreSQL: resolving an
// identifier to an account, storing a bearer token's digest, and listing the
// sessions a subject can still use.
//
// One type for three ports because they are the two halves of one table pair plus
// the lookup that precedes them, and because splitting them would give the login
// path three constructors to forget one of at the composition root.
//
// The halves are NOT symmetrical, and the asymmetry is the design (migration
// 00010). session_view is a PROJECTION: the projector writes it from
// SessionCreated and SessionRevoked, and a rebuild truncates and replays it.
// session_token is AUTHORITATIVE: it holds the digest and the idle deadline,
// neither of which is in the log, so no replay can restore them. This adapter
// therefore WRITES only the authoritative half and only READS the projected one —
// a command handler that wrote revoked_at would end sessions with nothing in the
// log saying so, and the next rebuild would bring them all back.
type Sessions struct{ tx db.SystemTX }

var (
	_ app.AccountDirectory = (*Sessions)(nil)
	_ app.SessionTokens    = (*Sessions)(nil)
	_ app.LiveSessions     = (*Sessions)(nil)
)

// NewSessions builds the adapter.
func NewSessions(tx db.SystemTX) (*Sessions, error) {
	if tx == nil {
		return nil, errors.New("identity/postgres: a system transaction is required; identity's " +
			"tables carry no RLS, so the transaction helper is the whole boundary")
	}
	return &Sessions{tx: tx}, nil
}

// AccountByEmailIndex resolves a blind index to the account claiming it.
//
// By INDEX, never by address: the address is not in this database at all. The
// caller derives the index with the blind-index key and asks for it, which is what
// lets the login lookup work while no projection holds personal data.
func (s *Sessions) AccountByEmailIndex(
	ctx context.Context, index contract.EmailIndex,
) (app.Account, error) {
	if index == "" {
		// Reported as "no account" rather than as a validation error: the caller can
		// do nothing different with the distinction, and the uniform answer is what
		// keeps the endpoint from becoming an oracle.
		return app.Account{}, app.ErrNoSuchAccount
	}

	var out app.Account
	err := s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		var (
			subjectID, userID, emailIndex, state string
			emailVerified                        bool
			registeredAt                         pgtype.Timestamptz
			activatedAt                          pgtype.Timestamptz
			deactivatedAt                        pgtype.Timestamptz
			suspendedAt                          pgtype.Timestamptz
		)
		// The state columns are scanned and DISCARDED. They are read only because
		// the statement selects them, and they are dropped here deliberately: the
		// account's own events decide whether it may authenticate, and a projection
		// is behind the log by construction, so a decision taken from these columns
		// could be taken twice with two different answers.
		scanErr := q.QueryRow(ctx, identitydb.GetUserByEmailIndex, string(index)).Scan(
			&subjectID, &userID, &emailIndex, &state, &emailVerified,
			&registeredAt, &activatedAt, &deactivatedAt, &suspendedAt)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return app.ErrNoSuchAccount
		}
		if scanErr != nil {
			return fmt.Errorf("identity/postgres: resolving an email index: %w", scanErr)
		}

		id, err := ids.Parse[ids.User](userID)
		if err != nil {
			// NOT reported as "no account". A row whose id does not parse was written
			// by something that is not this application, and answering "wrong
			// password" to it hides exactly the tampering identity.md §4.2 exists to
			// surface.
			return fmt.Errorf("identity/postgres: user id %q is unreadable: %w", userID, err)
		}
		if subjectID == "" {
			return fmt.Errorf("identity/postgres: the account for an email index carries no subject")
		}
		out = app.Account{UserID: id, SubjectID: subjectID}
		return nil
	})
	if err != nil {
		return app.Account{}, err
	}
	return out, nil
}

// Issue records the digest of a freshly minted bearer token.
//
// A plain INSERT, not an upsert. A digest is 256 bits of fresh randomness, so a
// conflict is not a retry — it is either the same token being issued twice, which
// no correct caller does, or a collision that is not going to happen. Absorbing it
// with ON CONFLICT DO NOTHING would silently point one digest at whichever session
// wrote it first, and the second user would hold a token for somebody else's
// session.
func (s *Sessions) Issue(ctx context.Context, token app.NewSessionToken) error {
	switch {
	case len(token.Digest) != 32:
		// The column has a CHECK on the width. Refused here to say why rather than
		// surfacing a constraint name — a short digest means the caller hashed
		// something other than a token.
		//
		// This guard SURVIVES its mutation, because the constraint refuses the same
		// values one layer down and the caller sees an error either way. Recorded so
		// the survival is not read as proof the check is unnecessary: it names the
		// mistake, and it keeps a malformed digest from reaching the database at all.
		return fmt.Errorf("identity/postgres: a session token digest is %d bytes, want 32",
			len(token.Digest))
	case token.SessionID.IsZero():
		return errors.New("identity/postgres: a session token needs the session it opens; " +
			"a row with no session joins nothing and is never swept")
	case token.IdleExpiresAt.IsZero():
		// The column is NOT NULL, and a zero value would be year 1 — an idle
		// deadline already in the past, so the session resolves on no request at all
		// and the user is signed out the instant they sign in.
		return errors.New("identity/postgres: a session token needs an idle deadline")
	}

	return s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		if _, err := q.Exec(ctx, identitydb.IssueSessionToken,
			token.Digest, token.SessionID.String(), token.IdleExpiresAt.UTC()); err != nil {
			return fmt.Errorf("identity/postgres: issuing a session token: %w", err)
		}
		return nil
	})
}

// List returns the sessions a subject can still use, newest first.
//
// It reads the PROJECTED half alone and does not join session_token, which is the
// difference between this and the device list. A session whose token row has
// already been swept — revoked or expired, then cleaned up — is invisible to a
// join and must still be revocable: the session_view row is what a rebuild
// replays, so a session missing from this list is one that never gets its
// SessionRevoked event.
func (s *Sessions) List(
	ctx context.Context, subjectID string, now time.Time,
) ([]ids.SessionID, error) {
	if subjectID == "" {
		// Refused rather than answered with an empty list. An empty list means
		// "nothing to sign out", and a caller acting on that would report a
		// successful sign-out-everywhere that touched nothing.
		return nil, errors.New("identity/postgres: listing live sessions needs a subject")
	}
	if now.IsZero() {
		// The statement compares against it, so year 1 matches every unexpired
		// session — but it also silently changes what "live" means, and the one
		// caller is the flow that must not be partial.
		return nil, errors.New("identity/postgres: listing live sessions needs the instant to " +
			"judge expiry at")
	}

	var out []ids.SessionID
	err := s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Query(ctx, identitydb.ListLiveSessionIDs, subjectID, now.UTC())
		if err != nil {
			return fmt.Errorf("identity/postgres: listing live sessions: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var raw string
			if err := rows.Scan(&raw); err != nil {
				return fmt.Errorf("identity/postgres: reading a live session: %w", err)
			}
			id, err := ids.Parse[ids.Session](raw)
			if err != nil {
				// Refused, not skipped. Skipping would drop a session from a
				// sign-out-everywhere while reporting success, which is the one
				// outcome that flow may not have.
				return fmt.Errorf("identity/postgres: session id %q is unreadable: %w", raw, err)
			}
			out = append(out, id)
		}
		if err := rows.Err(); err != nil {
			// A partial read is a partial sign-out. Reported, so the caller retries
			// rather than acting on a truncated list.
			//
			// UNTESTED, and stated rather than hidden: provoking a mid-iteration
			// failure needs the connection to die between rows, which nothing here can
			// arrange. Deleting this check passes the whole suite — the branch is kept
			// because a truncated list is the one answer this query may not give.
			return fmt.Errorf("identity/postgres: reading live sessions: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Destroy removes the digests of named sessions.
//
// A SYSTEM transaction, like Issue: `session_token` carries no tenant column —
// a session belongs to a person, not to an organization — and a revocation is
// performed from paths that have no organization in scope at all, an erasure and
// a password reset among them.
//
// An empty list is a no-op rather than an error. `RevokeAllSessions` on an
// account with nothing live plans no appends and destroys no digests, and that
// is an ordinary outcome rather than a caller mistake.
func (s *Sessions) Destroy(ctx context.Context, sessions []ids.SessionID) (int64, error) {
	if len(sessions) == 0 {
		return 0, nil
	}

	values := make([]string, 0, len(sessions))
	for _, id := range sessions {
		if id.IsZero() {
			// Refused rather than skipped. A zero id means the caller lost track of
			// which sessions it revoked, and destroying the rest of the list would
			// leave one session live while reporting a complete revocation.
			return 0, errors.New("identity/postgres: destroying a session secret needs the " +
				"session it belongs to; a zero id in the list means the caller does not " +
				"know which sessions it ended")
		}
		values = append(values, id.String())
	}

	var destroyed int64
	err := s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		tag, err := q.Exec(ctx, identitydb.DeleteSessionTokens, values)
		if err != nil {
			return fmt.Errorf("identity/postgres: destroying session secrets: %w", err)
		}
		destroyed = tag
		return nil
	})
	return destroyed, err
}

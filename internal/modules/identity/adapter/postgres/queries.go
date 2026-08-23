package postgres

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/page"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// ReadModel is identity's read side against PostgreSQL: the account screen, the
// device list, the method list and recent activity.
//
// One type for four ports because they are four reads of the same three tables
// plus `credential`, and because splitting them would give the composition root
// four constructors to forget one of.
//
// It NEVER writes. Not "does not currently write" — there is no statement here
// that is not a SELECT, and that is what makes every table it touches either
// replayable from the log or, in `credential`'s case, untouched by a read
// (ADR-019).
//
// Every statement runs inside db.SystemTX. Identity's tables carry no row-level
// security — a user exists before any organization, so there is no workspace_id
// to SET LOCAL — which means the transaction helper is the whole boundary and the
// subject filter in each statement is the whole tenant scope.
type ReadModel struct{ tx db.SystemTX }

var (
	_ app.AccountReader      = (*ReadModel)(nil)
	_ app.SessionReader      = (*ReadModel)(nil)
	_ app.MethodReader       = (*ReadModel)(nil)
	_ app.LoginHistoryReader = (*ReadModel)(nil)
	_ app.UserDirectory      = (*ReadModel)(nil)
)

// NewReadModel builds the adapter.
func NewReadModel(tx db.SystemTX) (*ReadModel, error) {
	if tx == nil {
		return nil, errors.New("identity/postgres: a system transaction is required; identity's " +
			"tables carry no RLS, so the transaction helper is the whole boundary")
	}
	return &ReadModel{tx: tx}, nil
}

// Account returns the projected account for a pseudonym.
//
// It reads user_view, which is a PROJECTION and therefore behind the log. That is
// safe here and would not be everywhere: this answer is RENDERED, never decided
// from. A registration that has not yet been projected reads as "no such
// account", which costs the user a refresh; the same row read as authority would
// cost a decision taken twice with two different answers.
func (r *ReadModel) Account(ctx context.Context, subjectID string) (app.AccountView, error) {
	if subjectID == "" {
		// Reported as "no account" rather than as a validation error: the app layer
		// already refuses an empty subject, so reaching here means a second caller
		// appeared, and the uniform answer is the one that cannot become an oracle.
		return app.AccountView{}, app.ErrNoSuchSubject
	}

	var out app.AccountView
	err := r.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		var (
			subject, userID, emailIndex, state string
			emailVerified                      bool
			username                           pgtype.Text
			registeredAt                       pgtype.Timestamptz
			activatedAt                        pgtype.Timestamptz
			deactivatedAt                      pgtype.Timestamptz
			suspendedAt                        pgtype.Timestamptz
			deletionRequestedAt                pgtype.Timestamptz
			deletionScheduledFor               pgtype.Timestamptz
		)
		scanErr := q.QueryRow(ctx, identitydb.GetUserBySubject, subjectID).Scan(
			&subject, &userID, &emailIndex, &state, &emailVerified, &username,
			&registeredAt, &activatedAt, &deactivatedAt, &suspendedAt,
			&deletionRequestedAt, &deletionScheduledFor)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return app.ErrNoSuchSubject
		}
		if scanErr != nil {
			return fmt.Errorf("identity/postgres: reading an account: %w", scanErr)
		}

		// emailIndex is scanned because the statement selects it, and DROPPED here.
		// It is a keyed lookup value over an address: anyone holding the blind-index
		// key can confirm a candidate address against it, and no screen has a use
		// for it. Letting it out of this function would put a re-identification
		// handle in a result whose whole design is that it carries a pseudonym.
		_ = emailIndex

		id, err := ids.Parse[ids.User](userID)
		if err != nil {
			// Refused, not reported as "no account". A user_view row can hold an
			// empty user id transiently — SetUserState inserts a placeholder if a
			// state change is projected before the registration that created it —
			// and answering "no such account" would hide both that ordering bug and
			// a row written by something that is not this application.
			return fmt.Errorf("identity/postgres: user id %q is unreadable: %w", userID, err)
		}
		lifecycle, err := accountState(state)
		if err != nil {
			return err
		}

		out = app.AccountView{
			SubjectID:     subject,
			UserID:        id,
			State:         lifecycle,
			EmailVerified: emailVerified,

			// The one user-supplied string this read side returns, and the one
			// deliberate exception to "no personal data leaves the adapter"
			// (ADR-051). A handle is published by design, so a screen that could not
			// show a person their own handle would be hiding the only part of their
			// identity that is not secret.
			//
			// NULL becomes "", which is the true statement about the two rows that
			// can hold it: an account that has not verified yet, and an account whose
			// handle was erased. Neither has a handle to show.
			Username: username.String,

			RegisteredAt:  utc(registeredAt),
			ActivatedAt:   utc(activatedAt),
			DeactivatedAt: utc(deactivatedAt),
			SuspendedAt:   utc(suspendedAt),

			// Two columns rather than one boolean. "When did they ask" is the audit
			// question and "when does it fall due" is the operational one, and the
			// second is the date the person was mailed — deriving it here from the
			// first plus the CURRENT grace period would move a deadline that has
			// already been communicated.
			DeletionRequestedAt:  utc(deletionRequestedAt),
			DeletionScheduledFor: utc(deletionScheduledFor),
		}
		return nil
	})
	if err != nil {
		return app.AccountView{}, err
	}
	return out, nil
}

// accountState maps the projected lifecycle string to the domain type.
//
// An unrecognised value is an ERROR rather than domain.StateNone. StateNone means
// "this account does not exist", so a state this build cannot parse — a row from
// a newer deployment, or one written outside the application — would render as a
// missing account while the row sits there. The states are the ones the user
// projector writes, and it writes them through domain.State.String().
func accountState(s string) (domain.State, error) {
	switch s {
	case domain.StatePending.String():
		return domain.StatePending, nil
	case domain.StateActive.String():
		return domain.StateActive, nil
	case domain.StateDeactivated.String():
		return domain.StateDeactivated, nil
	case domain.StateSuspended.String():
		return domain.StateSuspended, nil
	default:
		return domain.StateNone, fmt.Errorf(
			"identity/postgres: account state %q is not one this application writes", s)
	}
}

// Sessions returns one page of the device list.
//
// It JOINS session_token, unlike the sign-out-everywhere work list, and the
// difference is deliberate in both directions: a device list needs the idle
// deadline and the last-seen time, which live only in the authoritative half, and
// a session whose secret has been swept is no longer a device anybody is signed in
// on. Revocation must not depend on the secret still existing, which is why that
// path uses ListLiveSessionIDs instead.
func (r *ReadModel) Sessions(
	ctx context.Context, subjectID string, after page.Keyset, limit int32,
) ([]app.SessionSummary, error) {
	if subjectID == "" {
		return nil, errors.New("identity/postgres: listing sessions needs a subject")
	}
	if limit <= 0 {
		// Refused rather than passed through. `LIMIT 0` returns nothing, and an
		// empty page reads as "you have no other devices" — a caller that miscounted
		// its page size would be told the list had ended.
		return nil, fmt.Errorf("identity/postgres: a session page limit of %d returns nothing", limit)
	}

	createdBefore, sessionBefore, err := sessionCursorArgs(after)
	if err != nil {
		return nil, err
	}

	var out []app.SessionSummary
	err = r.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Query(ctx, identitydb.ListSessions,
			subjectID, createdBefore, sessionBefore, limit)
		if err != nil {
			return fmt.Errorf("identity/postgres: listing sessions: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var (
				sessionID  string
				deviceID   pgtype.Text
				aal        int32
				idle       pgtype.Timestamptz
				absolute   pgtype.Timestamptz
				createdAt  pgtype.Timestamptz
				lastSeenAt pgtype.Timestamptz
			)
			if err := rows.Scan(&sessionID, &deviceID, &aal, &idle, &absolute,
				&createdAt, &lastSeenAt); err != nil {
				return fmt.Errorf("identity/postgres: reading a session: %w", err)
			}
			id, err := ids.Parse[ids.Session](sessionID)
			if err != nil {
				// Refused, not skipped. Skipping would drop a device from the list a
				// user revokes from, and the device they cannot see is the device they
				// cannot sign out.
				return fmt.Errorf("identity/postgres: session id %q is unreadable: %w", sessionID, err)
			}
			out = append(out, app.SessionSummary{
				SessionID:         id,
				DeviceID:          deviceID.String,
				AAL:               contract.AssuranceLevel(aal),
				IdleExpiresAt:     utc(idle),
				AbsoluteExpiresAt: utc(absolute),
				CreatedAt:         utc(createdAt),
				LastSeenAt:        utc(lastSeenAt),
			})
		}
		if err := rows.Err(); err != nil {
			// A truncated page would end the list early and, worse, would end it with
			// a next token pointing past rows the caller never saw.
			return fmt.Errorf("identity/postgres: reading sessions: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Methods returns every authentication method on an account.
//
// It reads `credential`, and it selects METADATA only — the statement in
// db/query/identity/credential.sql names six columns and `verifier` is not among
// them. That is the boundary: the sealed TOTP secret and the password verifier
// live in the same row as what this returns, so the guarantee has to come from
// the projection list rather than from anything downstream.
func (r *ReadModel) Methods(ctx context.Context, subjectID string) ([]app.AuthMethod, error) {
	if subjectID == "" {
		return nil, errors.New("identity/postgres: listing methods needs a subject")
	}

	var out []app.AuthMethod
	err := r.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Query(ctx, identitydb.ListCredentials, subjectID)
		if err != nil {
			return fmt.Errorf("identity/postgres: listing methods: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var (
				credentialID string
				kind         string
				enabledAt    pgtype.Timestamptz
				disabledAt   pgtype.Timestamptz
				createdAt    pgtype.Timestamptz
				lastUsedAt   pgtype.Timestamptz
			)
			if err := rows.Scan(&credentialID, &kind, &enabledAt, &disabledAt,
				&createdAt, &lastUsedAt); err != nil {
				return fmt.Errorf("identity/postgres: reading a method: %w", err)
			}
			id, err := ids.Parse[ids.Credential](credentialID)
			if err != nil {
				return fmt.Errorf("identity/postgres: credential id %q is unreadable: %w",
					credentialID, err)
			}
			// The kind is passed through unvalidated on purpose. domain treats an
			// unrecognised kind as the WEAKEST method and as a second factor only
			// (StrengthOf, RoleOf), so a kind this build does not know is safe to
			// carry and dangerous to drop — a method hidden from this screen is a
			// method the account holder cannot notice or remove.
			out = append(out, app.AuthMethod{
				Method: domain.Method{
					ID:         id,
					Kind:       contract.MethodKind(kind),
					EnabledAt:  utc(enabledAt),
					DisabledAt: utc(disabledAt),
				},
				AddedAt:    utc(createdAt),
				LastUsedAt: utc(lastUsedAt),
			})
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("identity/postgres: reading methods: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// LoginHistory returns one page of recent authentication attempts.
func (r *ReadModel) LoginHistory(
	ctx context.Context, subjectID string, after page.Keyset, limit int32,
) ([]app.LoginRecord, error) {
	if subjectID == "" {
		return nil, errors.New("identity/postgres: listing login history needs a subject")
	}
	if limit <= 0 {
		return nil, fmt.Errorf("identity/postgres: a login-history page limit of %d returns nothing", limit)
	}

	occurredBefore, idBefore, err := loginCursorArgs(after)
	if err != nil {
		return nil, err
	}

	var out []app.LoginRecord
	err = r.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Query(ctx, identitydb.ListLoginHistory,
			subjectID, occurredBefore, idBefore, limit)
		if err != nil {
			return fmt.Errorf("identity/postgres: listing login history: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var (
				id         int64
				succeeded  bool
				reason     pgtype.Text
				methods    []string
				aal        pgtype.Int4
				deviceID   pgtype.Text
				occurredAt pgtype.Timestamptz
			)
			if err := rows.Scan(&id, &succeeded, &reason, &methods, &aal,
				&deviceID, &occurredAt); err != nil {
				return fmt.Errorf("identity/postgres: reading a login attempt: %w", err)
			}
			kinds := make([]contract.MethodKind, 0, len(methods))
			for _, m := range methods {
				kinds = append(kinds, contract.MethodKind(m))
			}
			out = append(out, app.LoginRecord{
				ID:        id,
				Succeeded: succeeded,
				Reason:    contract.FailureReason(reason.String),
				Methods:   kinds,
				// A NULL aal reads as AAL0 — "nothing was established" — which is
				// what a refused attempt actually means. contract.AAL0 exists
				// precisely so the zero value is not silently AAL1.
				AAL:        contract.AssuranceLevel(aal.Int32),
				DeviceID:   deviceID.String,
				OccurredAt: utc(occurredAt),
			})
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("identity/postgres: reading login history: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Cursors
// ---------------------------------------------------------------------------

// beforeEverything is the cursor value for the FIRST page.
//
// Both list statements compare `(sort_col, unique_col) < ($n, $n+1)`, so the
// first page needs a position strictly above every row rather than a separate
// statement without the comparison. Postgres's `timestamptz 'infinity'` is
// exactly that value: every stored timestamp is finite, so the row comparison
// short-circuits on the first component and the tiebreaker is never consulted —
// which is why the second argument below can be a zero value.
//
// The alternative — `($n IS NULL OR (…) < (…))` in the SQL — was rejected because
// the OR makes the predicate non-sargable, and the index that exists to serve
// this exact ORDER BY would stop being used on the one page every client asks for.
//
// Verified against the running server: `(now(),'x') < ('infinity'::timestamptz,”)`
// and `(now(),1::bigint) < ('infinity'::timestamptz,0::bigint)` are both true.
var beforeEverything = pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true}

// sessionCursorArgs turns a keyset into the two bind values ListSessions expects.
//
// The arity and the TYPES are checked rather than assumed. A cursor carrying a
// string where a timestamp belongs would bind as text, and Postgres would compare
// it lexically against a timestamptz column — or refuse — but the interesting
// failure is the one that does not refuse: a mis-typed cursor that still produces
// rows produces the WRONG rows, silently.
func sessionCursorArgs(after page.Keyset) (pgtype.Timestamptz, string, error) {
	if after.IsStart() {
		return beforeEverything, "", nil
	}
	args := after.Args()
	if len(args) != 2 {
		return pgtype.Timestamptz{}, "", fmt.Errorf(
			"identity/postgres: a session cursor has %d columns, want 2", len(args))
	}
	createdAt, ok := args[0].(time.Time)
	if !ok {
		return pgtype.Timestamptz{}, "", fmt.Errorf(
			"identity/postgres: a session cursor's created_at is %T, want a timestamp", args[0])
	}
	sessionID, ok := args[1].(string)
	if !ok {
		return pgtype.Timestamptz{}, "", fmt.Errorf(
			"identity/postgres: a session cursor's session_id is %T, want a string", args[1])
	}
	return pgtype.Timestamptz{Time: createdAt.UTC(), Valid: true}, sessionID, nil
}

// loginCursorArgs turns a keyset into the two bind values ListLoginHistory
// expects. See sessionCursorArgs.
func loginCursorArgs(after page.Keyset) (pgtype.Timestamptz, int64, error) {
	if after.IsStart() {
		return beforeEverything, 0, nil
	}
	args := after.Args()
	if len(args) != 2 {
		return pgtype.Timestamptz{}, 0, fmt.Errorf(
			"identity/postgres: a login-history cursor has %d columns, want 2", len(args))
	}
	occurredAt, ok := args[0].(time.Time)
	if !ok {
		return pgtype.Timestamptz{}, 0, fmt.Errorf(
			"identity/postgres: a login-history cursor's occurred_at is %T, want a timestamp", args[0])
	}
	id, ok := args[1].(int64)
	if !ok {
		return pgtype.Timestamptz{}, 0, fmt.Errorf(
			"identity/postgres: a login-history cursor's id is %T, want an integer", args[1])
	}
	return pgtype.Timestamptz{Time: occurredAt.UTC(), Valid: true}, id, nil
}

// utc renders a nullable timestamp as a UTC time, with NULL becoming the zero
// time.
//
// A zero time is the honest representation of "never happened" for every column
// this file reads — activated_at, disabled_at, last_seen_at — and the callers
// document it that way. UTC because storage is UTC and pgx hands back a time in
// the connection's zone (CLAUDE.md: all times UTC).
func utc(ts pgtype.Timestamptz) time.Time {
	if !ts.Valid {
		return time.Time{}
	}
	return ts.Time.UTC()
}

// UserBySubject returns the account id a pseudonym names.
//
// It lives here rather than at the composition root, where it was first written.
// The composition root ASSEMBLES dependencies; a type that knows how to answer a
// port from a query is an adapter, and leaving it in main means the next binary
// that needs the same answer either imports from a command package or writes it
// a second time.
//
// One question answered from the row Account already reads, rather than a second
// statement: the account id is a column on `user_view`, and a dedicated query
// would be a second place for the two to disagree about what a pseudonym names.
//
// It reads a PROJECTION and is therefore eventually consistent. Safe here for the
// reason the port documents: the answer only NAMES a stream, and every decision
// taken afterwards is taken against that stream's events under an
// expected-revision precondition. A stale or missing row costs a retry, never a
// wrong decision.
//
// app.ErrNoSuchSubject passes through unchanged, and that is the contract: the
// caller answers an unknown subject identically to an unknown token, so an error
// that distinguished them would be an account-existence oracle for anyone holding
// a pseudonym.
func (r *ReadModel) UserBySubject(ctx context.Context, subjectID string) (ids.UserID, error) {
	account, err := r.Account(ctx, subjectID)
	if err != nil {
		return ids.UserID{}, err
	}
	return account.UserID, nil
}

// OverdueDeletion is one deletion request whose deadline has passed.
type OverdueDeletion struct {
	SubjectID    string
	ScheduledFor time.Time
}

// ListOverdueDeletions is the erasure backstop's work list.
//
// # Why identity answers a compliance question
//
// The deadline is projected onto `user_view`, and that table belongs to
// identity's projection (CONVENTIONS §8). compliance may not read another
// module's tables directly, so the query lives here and the composition root
// narrows it to compliance's port.
//
// A SYSTEM transaction: the caller is a scheduled workflow with no request and
// no tenant scope, and `user_view` carries no row security — a profile is global
// to a person and isolation there is by pseudonym, not by organization.
func (r *ReadModel) ListOverdueDeletions(
	ctx context.Context, before time.Time, limit int,
) ([]OverdueDeletion, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("identity: a positive limit is required, got %d", limit)
	}

	var out []OverdueDeletion
	err := r.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		if limit > math.MaxInt32 {
			return fmt.Errorf("identity: a limit of %d does not fit a query bound", limit)
		}
		rows, err := q.Query(ctx, identitydb.ListOverdueDeletions,
			before.UTC(), int32(limit)) //nolint:gosec // bounded on the line above
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var row OverdueDeletion
			var scheduled pgtype.Timestamptz
			if err := rows.Scan(&row.SubjectID, &scheduled); err != nil {
				return err
			}
			if scheduled.Valid {
				row.ScheduledFor = scheduled.Time.UTC()
			}
			out = append(out, row)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("identity: listing overdue deletion requests: %w", err)
	}
	return out, nil
}

// Package postgres implements the operator plane's ports against its own six
// tables.
//
// # Every statement here runs as chronos_operator
//
// That role is granted these six tables and nothing else, so a bug in this
// package cannot reach a tenant table — the query does not fail, it cannot be
// written. TestTheOperatorRoleCannotReadTenantTables asserts that against a
// real database rather than assuming it.
//
// # Every statement here uses InSystemTx, and that is correct rather than lax
//
// The tenant plane's rule is that every query runs under `SET LOCAL
// app.workspace_id`, because every row belongs to a tenant and a query that
// forgets its scope is a cross-tenant breach. Operator tables have no tenant
// column and no RLS policy, so there is no scope for a `SET LOCAL` to feed:
// setting one would be a statement with no effect, which is worse than none
// because a reader would take it for protection.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	operatordb "github.com/chronos/chronos-go/gen/sqlc/operator"
	"github.com/chronos/chronos-go/internal/operator/app"
	"github.com/chronos/chronos-go/internal/operator/contract"
	"github.com/chronos/chronos-go/internal/platform/db"
)

// Store implements Accounts, Credentials, Sessions, Ceremonies and Directory.
//
// One type rather than five, because they share a transaction source and
// nothing else — and five types over one pool would be five constructors to
// wire with no boundary between them that means anything.
type Store struct{ tx db.SystemTX }

// New builds the store.
func New(tx db.SystemTX) (*Store, error) {
	if tx == nil {
		return nil, fmt.Errorf("operator postgres: the store needs a transaction source")
	}
	return &Store{tx: tx}, nil
}

var (
	_ app.Accounts    = (*Store)(nil)
	_ app.Credentials = (*Store)(nil)
	_ app.Sessions    = (*Store)(nil)
	_ app.Ceremonies  = (*Store)(nil)
)

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

// ByBinding resolves an operator from what the IdP asserted.
func (s *Store) ByBinding(ctx context.Context, issuer, providerSubject string) (app.OperatorRecord, error) {
	var rec app.OperatorRecord
	err := s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		return scanOperator(q.QueryRow(ctx, operatordb.GetOperatorByBinding, issuer, providerSubject), &rec)
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return app.OperatorRecord{}, app.ErrNotAnOperator
	case err != nil:
		return app.OperatorRecord{}, fmt.Errorf("operator postgres: resolving by binding: %w", err)
	}
	return rec, nil
}

// ByID resolves an operator by their own id.
func (s *Store) ByID(ctx context.Context, operatorID string) (app.OperatorRecord, error) {
	var rec app.OperatorRecord
	err := s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		return scanOperator(q.QueryRow(ctx, operatordb.GetOperator, operatorID), &rec)
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return app.OperatorRecord{}, app.ErrNotAnOperator
	case err != nil:
		return app.OperatorRecord{}, fmt.Errorf("operator postgres: resolving by id: %w", err)
	}
	return rec, nil
}

func scanOperator(row db.Row, rec *app.OperatorRecord) error {
	var role string
	if err := row.Scan(&rec.OperatorID, &rec.SubjectID, &rec.Issuer, &rec.ProviderSubject,
		&role, &rec.DisabledAt, &rec.ProvisionedAt); err != nil {
		return err
	}
	rec.Role = contract.Role(role)
	return nil
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

// List returns every authenticator an operator holds.
func (s *Store) List(ctx context.Context, operatorID string) ([]app.StoredCredential, error) {
	var out []app.StoredCredential
	err := s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Query(ctx, operatordb.ListOperatorCredentials, operatorID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, _, err := scanCredential(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("operator postgres: listing authenticators: %w", err)
	}
	return out, nil
}

// Count reports how many authenticators an operator holds — the bootstrap
// window's own condition, read server-side and never asserted by a caller.
func (s *Store) Count(ctx context.Context, operatorID string) (int64, error) {
	var n int64
	err := s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx, operatordb.CountOperatorCredentials, operatorID).Scan(&n)
	})
	if err != nil {
		return 0, fmt.Errorf("operator postgres: counting authenticators: %w", err)
	}
	return n, nil
}

// Get resolves one credential across every operator.
func (s *Store) Get(ctx context.Context, credentialID string) (app.StoredCredential, string, error) {
	var (
		cred  app.StoredCredential
		owner string
	)
	err := s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		var err error
		cred, owner, err = scanCredential(q.QueryRow(ctx, operatordb.GetOperatorCredential, credentialID))
		return err
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return app.StoredCredential{}, "", app.ErrCeremonyRefused
	case err != nil:
		return app.StoredCredential{}, "", fmt.Errorf("operator postgres: reading a credential: %w", err)
	}
	return cred, owner, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanCredential(row scanner) (app.StoredCredential, string, error) {
	var (
		c                           app.StoredCredential
		owner                       string
		signCount                   int64
		label                       *string
		createdAt                   time.Time
		lastUsedAt, cloneWarnedAt   *time.Time
		backupEligible, backupState bool
	)
	if err := row.Scan(&c.ID, &owner, &c.PublicKey, &signCount, &c.AAGUID, &c.Transports,
		&backupEligible, &backupState, &label, &createdAt, &lastUsedAt, &cloneWarnedAt); err != nil {
		return app.StoredCredential{}, "", err
	}
	if signCount < 0 {
		// The column has a CHECK forbidding this, so reaching it means the
		// constraint was dropped. Refused rather than clamped: a negative
		// counter would make the clone comparison meaningless in the direction
		// that lets a clone through.
		return app.StoredCredential{}, "", fmt.Errorf(
			"operator postgres: credential %q has a negative signature counter", c.ID)
	}
	c.SignCount = uint32(signCount)
	c.BackupEligible = backupEligible
	c.BackupState = backupState
	return c, owner, nil
}

// Insert stores a new enrolment, and fails rather than replaces on a duplicate
// credential id.
func (s *Store) Insert(ctx context.Context, c app.NewCredential) error {
	var label *string
	if c.Label != "" {
		label = &c.Label
	}
	err := s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx, operatordb.InsertOperatorCredential,
			c.ID, c.OperatorID, c.PublicKey, int64(c.SignCount), c.AAGUID, c.Transports,
			c.BackupEligible, c.BackupState, label)
		return err
	})
	if err != nil {
		return fmt.Errorf("operator postgres: storing an authenticator: %w", err)
	}
	return nil
}

// Advance moves the signature counter forward atomically.
func (s *Store) Advance(ctx context.Context, credentialID string, to uint32) (bool, error) {
	var moved bool
	err := s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		n, err := q.Exec(ctx, operatordb.AdvanceOperatorSignCount, credentialID, int64(to))
		if err != nil {
			return err
		}
		moved = n > 0
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("operator postgres: advancing a signature counter: %w", err)
	}
	return moved, nil
}

// Touch records use without moving the counter.
func (s *Store) Touch(ctx context.Context, credentialID string) error {
	return s.exec(ctx, "recording a credential's use", operatordb.TouchOperatorCredential, credentialID)
}

// FlagClone records a counter regression.
func (s *Store) FlagClone(ctx context.Context, credentialID string) error {
	return s.exec(ctx, "flagging a clone warning", operatordb.FlagOperatorCredentialClone, credentialID)
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

// Issue stores a session.
func (s *Store) Issue(ctx context.Context, n app.NewSession) error {
	ip := parseIP(n.FromIP)
	var credentialID *string
	if n.CredentialID != "" {
		credentialID = &n.CredentialID
	}
	err := s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx, operatordb.InsertOperatorSession,
			n.Digest, n.SessionID, n.OperatorID, string(n.Stage), n.ExpiresAt.UTC(), ip, credentialID)
		return err
	})
	if err != nil {
		return fmt.Errorf("operator postgres: issuing a session: %w", err)
	}
	return nil
}

// Resolve returns the session behind a token digest.
//
// The query JOINS operator_account, so a disabled operator's live session stops
// working the moment the disable projects — which is what operator.md §3 means
// by "offboarding is immediate and verified". Doing the disabled check in Go
// after two round trips would leave a window whose width is a network hop.
func (s *Store) Resolve(ctx context.Context, digest []byte, now time.Time) (app.SessionRecord, error) {
	var (
		rec          app.SessionRecord
		stage, role  string
		credentialID *string
		disabledAt   *time.Time
	)
	err := s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx, operatordb.ResolveOperatorSession, digest, now.UTC()).Scan(
			&rec.SessionID, &rec.OperatorID, &stage, &rec.ExpiresAt, &credentialID,
			&rec.SubjectID, &role, &disabledAt)
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return app.SessionRecord{}, app.ErrSessionRefused
	case err != nil:
		return app.SessionRecord{}, fmt.Errorf("operator postgres: resolving a session: %w", err)
	case disabledAt != nil:
		return app.SessionRecord{}, app.ErrSessionRefused
	}
	rec.Stage = app.Stage(stage)
	rec.Role = contract.Role(role)
	if credentialID != nil {
		rec.CredentialID = *credentialID
	}
	return rec, nil
}

// End marks a session over and reports whether this call changed anything.
func (s *Store) End(ctx context.Context, digest []byte, now time.Time) (bool, error) {
	var changed bool
	err := s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		affected, err := q.Exec(ctx, operatordb.EndOperatorSession, digest, now.UTC())
		if err != nil {
			return err
		}
		changed = affected > 0
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("operator postgres: ending a session: %w", err)
	}
	return changed, nil
}

// EndAllFor ends every live session an operator holds.
func (s *Store) EndAllFor(ctx context.Context, operatorID string, now time.Time) error {
	return s.exec(ctx, "ending an operator's sessions", operatordb.EndOperatorSessionsFor,
		operatorID, now.UTC())
}

// SweepSessions removes sessions past their deadline.
func (s *Store) SweepSessions(ctx context.Context, before time.Time) (int64, error) {
	var n int64
	err := s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		affected, err := q.Exec(ctx, operatordb.SweepOperatorSessions, before.UTC())
		if err != nil {
			return err
		}
		n = affected
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("operator postgres: sweeping sessions: %w", err)
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// Ceremonies
// ---------------------------------------------------------------------------

// Store persists a ceremony in flight.
func (s *Store) Store(
	ctx context.Context, id string, kind app.CeremonyKind, operatorID string,
	payload []byte, expiresAt time.Time,
) error {
	var owner *string
	if operatorID != "" {
		owner = &operatorID
	}
	return s.exec(ctx, "storing a ceremony", operatordb.InsertOperatorCeremony,
		id, string(kind), owner, payload, expiresAt.UTC())
}

// Consume redeems a ceremony exactly once.
//
// The atomicity is the database's: `UPDATE … WHERE consumed_at IS NULL
// RETURNING` leaves no window between a read and a write for a replay to slip
// through, which a read-then-write in Go would.
func (s *Store) Consume(
	ctx context.Context, id string, kind app.CeremonyKind, now time.Time,
) (string, []byte, error) {
	var (
		gotID, gotKind string
		owner          *string
		payload        []byte
		expiresAt      time.Time
	)
	err := s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx, operatordb.ConsumeOperatorCeremony, id, now.UTC(), string(kind)).
			Scan(&gotID, &gotKind, &owner, &payload, &expiresAt)
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// Absent, already consumed, expired, or the wrong kind. ONE answer for
		// all four: telling the caller which would tell an attacker whether a
		// ceremony id exists.
		return "", nil, app.ErrCeremonyRefused
	case err != nil:
		return "", nil, fmt.Errorf("operator postgres: consuming a ceremony: %w", err)
	}
	if owner == nil {
		return "", payload, nil
	}
	return *owner, payload, nil
}

// SweepCeremonies removes ceremonies past their deadline.
func (s *Store) SweepCeremonies(ctx context.Context, before time.Time) (int64, error) {
	var n int64
	err := s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		affected, err := q.Exec(ctx, operatordb.SweepOperatorCeremonies, before.UTC())
		if err != nil {
			return err
		}
		n = affected
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("operator postgres: sweeping ceremonies: %w", err)
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

func (s *Store) exec(ctx context.Context, what, sql string, args ...any) error {
	err := s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx, sql, args...)
		return err
	})
	if err != nil {
		return fmt.Errorf("operator postgres: %s: %w", what, err)
	}
	return nil
}

// parseIP converts a client address to what the `inet` column takes, and yields
// NULL rather than an error for anything unparseable.
//
// A malformed X-Forwarded-For must not fail a sign-in. The address is evidence
// for anomaly detection, not an authorization input — refusing the request
// would turn a header somebody else controls into a denial-of-service.
func parseIP(s string) *netip.Addr {
	if s == "" {
		return nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return nil
	}
	return &addr
}

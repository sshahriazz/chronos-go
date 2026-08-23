package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/db"
)

// passkeyPrimaryKey is the constraint whose violation IS the security control.
//
// `passkey_credential`'s primary key is the credential id, so it is unique
// across every account rather than per subject — WebAuthn L3 §7.1 step 27. A
// violation here is not a bug: it is an attempt to register a credential id that
// already exists somewhere in the installation, which is either a retry or the
// takeover the constraint exists to refuse.
//
// The literal is a CONSTRAINT NAME. gosec reads "credential" in it and flags a
// hardcoded secret; it is the name Postgres generated for the primary key of a
// table that happens to be about credentials, and it must match that name
// exactly or the violation below stops being recognised and a duplicate
// registration becomes a 500.
//
//nolint:gosec // G101: a constraint name, not a secret
const passkeyPrimaryKey = "passkey_credential_pkey"

// Passkeys is the system of record for WebAuthn material (ADR-057).
//
// NOT a projection. Nothing here is rebuildable from the event log — a public
// key never enters an event — so this type sits beside Credentials in the one
// category of identity state that is written by the code that verifies rather
// than by a projector.
//
// A SYSTEM transaction throughout, for Credentials' reason: this is consulted
// during authentication, where there is no request, no gate 1 and no
// `app.org_id`. A tenant transaction would match nothing, which would look
// exactly like "this account has no passkeys".
type Passkeys struct{ tx db.SystemTX }

func NewPasskeys(tx db.SystemTX) (*Passkeys, error) {
	if tx == nil {
		return nil, fmt.Errorf("identity/postgres: a system transaction source is required")
	}
	return &Passkeys{tx: tx}, nil
}

var _ app.PasskeyStore = (*Passkeys)(nil)

// Register stores a new credential.
//
// # The check and the constraint, not one or the other
//
// ADR-057 is explicit that both are needed and why: the CONSTRAINT is what makes
// uniqueness true under concurrency, and the CHECK is what turns the violation
// into a message rather than a 500. This performs the insert and translates the
// violation; the caller has already looked, and looking alone cannot win a race.
func (p *Passkeys) Register(ctx context.Context, c app.NewPasskey) error {
	switch {
	case c.CredentialID == "":
		return fmt.Errorf("identity/postgres: a credential id is required")
	case c.SubjectID == "":
		return fmt.Errorf("identity/postgres: a subject id is required")
	case len(c.PublicKey) == 0:
		// A row with no key can never verify anything, and the failure would
		// appear at the person's next login rather than here.
		return fmt.Errorf("identity/postgres: a passkey needs a public key")
	}

	return p.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx, identitydb.InsertPasskey,
			c.CredentialID, c.SubjectID, c.PublicKey, int64(c.SignCount),
			c.AAGUID, c.Transports, c.BackupEligible, c.BackupState,
			c.UserVerified, nullable(c.Label), c.RegisteredAt.UTC())
		if err != nil {
			var pg *pgconn.PgError
			if errors.As(err, &pg) && pg.ConstraintName == passkeyPrimaryKey {
				return app.ErrPasskeyAlreadyRegistered
			}
			return fmt.Errorf("identity/postgres: registering a passkey: %w", err)
		}
		return nil
	})
}

// Find returns one credential by id, whoever owns it.
//
// NOT scoped by subject, and that is what a ceremony needs: an assertion names
// the credential and the RP looks it up to learn WHOSE it is. Scoping by a
// subject the caller supplied would mean trusting the caller's claim about their
// own identity, which is the thing the ceremony exists to establish.
func (p *Passkeys) Find(ctx context.Context, credentialID string) (app.StoredPasskey, error) {
	if credentialID == "" {
		return app.StoredPasskey{}, fmt.Errorf("identity/postgres: a credential id is required")
	}
	var out app.StoredPasskey
	err := p.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		row := q.QueryRow(ctx, identitydb.GetPasskey, credentialID)
		return scanPasskey(row, &out)
	})
	switch {
	case errors.Is(err, errNoPasskeyRow):
		return app.StoredPasskey{}, app.ErrNoSuchPasskey
	case err != nil:
		return app.StoredPasskey{}, fmt.Errorf("identity/postgres: reading a passkey: %w", err)
	}
	return out, nil
}

// List returns every passkey an account holds, newest first.
func (p *Passkeys) List(ctx context.Context, subjectID string) ([]app.StoredPasskey, error) {
	if subjectID == "" {
		// Refused rather than answered with an empty list: an empty list means
		// "this account has no passkey", and a caller acting on that would tell
		// somebody to use another method when they have one.
		return nil, fmt.Errorf("identity/postgres: listing passkeys needs a subject")
	}
	var out []app.StoredPasskey
	err := p.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Query(ctx, identitydb.ListPasskeysForSubject, subjectID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var one app.StoredPasskey
			if err := scanPasskey(rows, &one); err != nil {
				return err
			}
			out = append(out, one)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("identity/postgres: listing passkeys: %w", err)
	}
	return out, nil
}

// Advance moves the signature counter forward and reports what happened.
//
// # The whole clone check, and it is one statement
//
// `UPDATE … WHERE sign_count < $new` is atomic, so two concurrent logins cannot
// both advance past each other. Doing the comparison in Go would be a
// read-modify-write that both win (ADR-057).
//
// ZERO ROWS IS NOT AN ERROR, and treating it as one would lock people out. It
// means the presented count did not exceed the stored one, which has two
// completely different causes that this method separates for the caller:
//
//   - 0 → 0, the ordinary case for a SYNCED passkey. Apple and Google report 0
//     permanently, because there is no coherent place to keep a monotonic
//     counter across N devices. Refusing on it would refuse most of the passkeys
//     in existence.
//   - a genuine REGRESSION, which is a warning and a step-up rather than a
//     denial: the spec lists an out-of-order race as a benign cause, and this
//     system treats concurrent sessions as ordinary.
func (p *Passkeys) Advance(
	ctx context.Context, credentialID string, presented uint32, at time.Time,
) (app.SignCountOutcome, error) {
	if credentialID == "" {
		return app.SignCountOutcome{}, fmt.Errorf("identity/postgres: a credential id is required")
	}

	var outcome app.SignCountOutcome
	err := p.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		moved, err := q.Exec(ctx, identitydb.AdvancePasskeySignCount,
			credentialID, int64(presented), at.UTC())
		if err != nil {
			return err
		}
		if moved > 0 {
			outcome.Advanced = true
			return nil
		}

		// It did not move. Read the stored value to tell the two causes apart —
		// and only now, because the common path is one statement and this is the
		// exception.
		var stored app.StoredPasskey
		if err := scanPasskey(q.QueryRow(ctx, identitydb.GetPasskey, credentialID), &stored); err != nil {
			return err
		}
		outcome.Stored = stored.SignCount

		if presented == 0 && stored.SignCount == 0 {
			// A synced passkey. Nothing to advance and nothing wrong; the use
			// still happened, so the timestamp is recorded.
			if _, err := q.Exec(ctx, identitydb.TouchPasskey, credentialID, at.UTC()); err != nil {
				return err
			}
			return nil
		}

		// A REGRESSION. Stamped so an operator can ask "has this credential ever
		// gone backwards, and when" — a question a counter could not answer,
		// because the benign cause is a race and somebody would set a threshold
		// on it.
		outcome.Regressed = true
		if _, err := q.Exec(ctx, identitydb.WarnPasskeyClone, credentialID, at.UTC()); err != nil {
			return err
		}
		_, err = q.Exec(ctx, identitydb.TouchPasskey, credentialID, at.UTC())
		return err
	})
	if err != nil {
		return app.SignCountOutcome{}, fmt.Errorf(
			"identity/postgres: advancing a passkey's sign count: %w", err)
	}
	return outcome, nil
}

// Remove deletes one credential, scoped to its owner.
//
// Scoped by subject unlike Find, and the difference is the direction of trust: a
// ceremony asks "whose is this", while a removal is a caller acting on their own
// account and must not be able to delete somebody else's passkey by naming its
// id.
func (p *Passkeys) Remove(ctx context.Context, credentialID, subjectID string) error {
	if credentialID == "" || subjectID == "" {
		return fmt.Errorf("identity/postgres: removing a passkey needs an id and a subject")
	}
	var removed int64
	err := p.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		n, err := q.Exec(ctx, identitydb.DeletePasskey, credentialID, subjectID)
		removed = n
		return err
	})
	if err != nil {
		return fmt.Errorf("identity/postgres: removing a passkey: %w", err)
	}
	if removed == 0 {
		return app.ErrNoSuchPasskey
	}
	return nil
}

// Erase deletes every passkey an account holds.
//
// DELETED rather than crypto-shredded, because there is no subject key to
// destroy: this material is not encrypted under one. It is the one erasure path
// that removes rows rather than making them unreadable, and ADR-057 states it
// explicitly so it is not discovered later.
func (p *Passkeys) Erase(ctx context.Context, subjectID string) (int, error) {
	if subjectID == "" {
		return 0, fmt.Errorf("identity/postgres: erasing passkeys needs a subject")
	}
	var removed int64
	err := p.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		n, err := q.Exec(ctx, identitydb.DeletePasskeysForSubject, subjectID)
		removed = n
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("identity/postgres: erasing passkeys: %w", err)
	}
	return int(removed), nil
}

// errNoPasskeyRow is the internal sentinel scanPasskey raises for an empty
// result, translated by each caller into the port's own error.
var errNoPasskeyRow = errors.New("identity/postgres: no passkey row")

// scanner is what both QueryRow and Rows satisfy.
type scanner interface{ Scan(dest ...any) error }

func scanPasskey(s scanner, out *app.StoredPasskey) error {
	var (
		aaguid     []byte
		transports []string
		label      pgtype.Text
		created    pgtype.Timestamptz
		lastUsed   pgtype.Timestamptz
		cloneWarn  pgtype.Timestamptz
		signCount  int64
	)
	err := s.Scan(&out.CredentialID, &out.SubjectID, &out.PublicKey, &signCount,
		&aaguid, &transports, &out.BackupEligible, &out.BackupState, &out.UserVerified,
		&label, &created, &lastUsed, &cloneWarn)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errNoPasskeyRow
		}
		return err
	}
	if signCount < 0 {
		// The column is CHECKed non-negative, so this is unreachable — and it is
		// clamped rather than trusted because a negative here would become a
		// gigantic uint32 and make every future counter look like a regression.
		signCount = 0
	}
	out.SignCount = uint32(signCount)
	out.AAGUID = aaguid
	out.Transports = transports
	out.Label = label.String
	out.RegisteredAt = utcOrZero(created)
	out.LastUsedAt = utcOrZero(lastUsed)
	out.CloneWarnedAt = utcOrZero(cloneWarn)
	return nil
}

func utcOrZero(t pgtype.Timestamptz) time.Time {
	if !t.Valid {
		return time.Time{}
	}
	return t.Time.UTC()
}

// nullable turns an empty label into SQL NULL.
//
// So "no label" is one value rather than two — an empty string and a NULL would
// both render as blank and would sort differently.
func nullable(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

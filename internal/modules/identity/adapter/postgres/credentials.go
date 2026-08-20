package postgres

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// Credentials implements app.PasswordCredentials.
//
// It is the one adapter in this module that writes a table which is NOT a
// projection. Everything else identity stores in PostgreSQL is derived from the
// event log and can be truncated and replayed; a password verifier can never be
// in the log at all (identity.md §4), so these rows are authoritative and a
// rebuild must not touch them. Migration 00009 removed the foreign key that
// would have let one cascade into them.
//
// Practically that means every statement here is issued by a COMMAND HANDLER
// rather than a projector, and there is no Reset, no checkpoint and no replay
// path in this file — their absence is the design, not an omission.
type Credentials struct {
	tx db.SystemTX

	// log carries the one event in this file that is not returned to a caller:
	// an orphaned verifier being replaced (StoreFirst). It defaults to
	// slog.Default() rather than being a constructor parameter, because every
	// call site already exists and a signature change would be a wiring edit in
	// three binaries for one warning line. Nothing here logs personal data — the
	// only identifier it can reach is a pseudonym.
	log *slog.Logger
}

var _ app.PasswordCredentials = (*Credentials)(nil)

// kindPassword is the credential table's discriminator for a password.
//
// The table holds five kinds behind a CHECK constraint; this adapter deals in
// exactly one, because the others are not verifiers at all — a TOTP secret lives
// in the vault and a passkey is a public key — and a store that took the kind as
// a parameter would invite a caller to fetch a passkey row and hand it to the
// password hasher.
const kindPassword = "password"

// oneUsablePerKind is the partial unique index that limits a subject to one
// usable credential per kind. Named here because the constraint's identity is
// what distinguishes "this subject already has a password" from every other way
// a write can fail — see Store.
const oneUsablePerKind = "credential_one_usable_per_kind_idx"

// NewCredentials builds the adapter.
func NewCredentials(tx db.SystemTX) (*Credentials, error) {
	if tx == nil {
		return nil, errors.New("identity/postgres: a system transaction is required; " +
			"identity's tables carry no RLS, so the transaction helper is the whole boundary")
	}
	return &Credentials{tx: tx, log: slog.Default()}, nil
}

// Store records the verifier for a newly set password.
func (c *Credentials) Store(ctx context.Context, cred app.NewPasswordCredential) error {
	if err := validateNewPassword(cred); err != nil {
		return err
	}

	return c.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx, identitydb.UpsertCredential,
			cred.ID.String(), cred.SubjectID, kindPassword,
			cred.Verifier, cred.PepperVersion, cred.EnabledAt.UTC())
		if err != nil {
			// The upsert absorbs a repeat of the SAME credential id, which is what
			// makes a crashed-and-retried registration land in the same state. It
			// cannot absorb a SECOND usable password under a NEW id: that
			// contends on the partial unique index instead, and the index is what
			// keeps one subject from holding two live verifiers.
			var pg *pgconn.PgError
			if errors.As(err, &pg) && pg.ConstraintName == oneUsablePerKind {
				return app.ErrPasswordAlreadySet
			}
			return fmt.Errorf("identity/postgres: storing a password verifier: %w", err)
		}
		return nil
	})
}

// StoreFirst records an account's first verifier, clearing any orphan first.
//
// The DELETE and the INSERT are ONE transaction. Split, a crash between them
// leaves the account with no verifier at all and no row to collide with — which
// is recoverable — but a concurrent reader would observe a passwordless instant
// on an account the log says has a password. One statement pair, one commit.
//
// The precondition that makes the DELETE safe belongs to the CALLER and is
// stated on app.PasswordCredentials.StoreFirst: the aggregate must already have
// accepted a first SetPassword, which it does only when its own stream records
// no usable password. This adapter cannot read a stream and does not try.
func (c *Credentials) StoreFirst(ctx context.Context, cred app.NewPasswordCredential) error {
	if err := validateNewPassword(cred); err != nil {
		return err
	}
	return c.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		removed, err := q.Exec(ctx, identitydb.DeleteOrphanedPasswordCredential, cred.SubjectID)
		if err != nil {
			return fmt.Errorf("identity/postgres: clearing an orphaned password verifier: %w", err)
		}
		if removed > 0 {
			// Worth a line, because it is evidence of a crash between the verifier
			// write and the append — the window this method exists for. Silent
			// recovery would make that window unobservable, and an unobservable
			// window is one nobody notices widening. The subject is a pseudonym.
			c.log.WarnContext(ctx, "replaced an orphaned password verifier while setting a first password",
				"module", "identity", "reason", "orphaned_password_verifier",
				"subject_id", cred.SubjectID, "rows", removed)
		}
		if _, err := q.Exec(ctx, identitydb.UpsertCredential,
			cred.ID.String(), cred.SubjectID, kindPassword,
			cred.Verifier, cred.PepperVersion, cred.EnabledAt.UTC()); err != nil {
			// A collision here means a row survived the DELETE, which the DELETE's
			// predicate makes impossible for anything but a concurrent writer. Two
			// first-password attempts for one subject is exactly that, and stopping
			// is right: the other one won.
			var pg *pgconn.PgError
			if errors.As(err, &pg) && pg.ConstraintName == oneUsablePerKind {
				return app.ErrPasswordAlreadySet
			}
			return fmt.Errorf("identity/postgres: storing a first password verifier: %w", err)
		}
		return nil
	})
}

// validateNewPassword is the shared argument check for Store and StoreFirst.
//
// Shared rather than duplicated because each of these refusals exists to turn a
// silent, late-surfacing failure into an immediate one, and a copy that drifted
// would leave one of the two writers without that protection.
func validateNewPassword(cred app.NewPasswordCredential) error {
	switch {
	case cred.ID.IsZero():
		// The id is authenticated into the verifier by the hasher. Storing under
		// a different one — or an empty one — yields a row that can never be
		// opened, and the failure appears at the user's next login rather than
		// here.
		return errors.New("identity/postgres: a credential id is required; the verifier is " +
			"sealed against it and cannot be opened from another row")
	case cred.SubjectID == "":
		return errors.New("identity/postgres: a credential needs a subject")
	case cred.Verifier == "":
		// The table's CHECK constraint would refuse this too. Refused here to say
		// why, rather than surfacing a constraint name: a password row with no
		// verifier satisfies "the account has a password" while verifying
		// nothing, which locks the account out with no error anywhere.
		return errors.New("identity/postgres: a password credential needs a verifier")
	case cred.PepperVersion < 1:
		// A NULL or zero pepper version is invisible to `pepper_version < n`, so
		// the rotation job never visits the row — and destroying the old transit
		// key then locks that user out permanently (identity.md §4).
		return fmt.Errorf("identity/postgres: pepper version %d is not a real version; "+
			"the rotation job would never find this row", cred.PepperVersion)
	case cred.EnabledAt.IsZero():
		// enabled_at NULL means the usable-credential lookup skips the row, so the
		// account is passwordless with a password sitting in the table.
		return errors.New("identity/postgres: a credential needs an enabled-at instant, " +
			"or it is stored and never usable")
	}
	return nil
}

// Find returns the usable password credential for a subject.
func (c *Credentials) Find(ctx context.Context, subjectID string) (app.PasswordCredential, error) {
	if subjectID == "" {
		// Reported as "no credential" rather than as a validation error: the
		// caller can do nothing different with the distinction, and the uniform
		// answer is what stops the endpoint becoming an oracle.
		return app.PasswordCredential{}, app.ErrNoPasswordCredential
	}

	var out app.PasswordCredential
	err := c.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		var (
			credID, subject, kind string
			verifier              pgtype.Text
			pepper                pgtype.Int4
			enabledAt             pgtype.Timestamptz
			failures              int32
		)
		scanErr := q.QueryRow(ctx, identitydb.GetUsableCredential, subjectID, kindPassword).
			Scan(&credID, &subject, &kind, &verifier, &pepper, &enabledAt, &failures)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			// Unknown subject, passwordless account and disabled credential all
			// arrive here. Telling them apart would confirm which addresses have
			// accounts and which of those are locked out.
			return app.ErrNoPasswordCredential
		}
		if scanErr != nil {
			return fmt.Errorf("identity/postgres: reading a password credential: %w", scanErr)
		}

		id, err := ids.Parse[ids.Credential](credID)
		if err != nil {
			// NOT reported as "no credential". A row whose id does not parse was
			// written by something that is not this application, and answering
			// "wrong password" to it hides exactly the tampering that
			// identity.md §4.2 exists to surface.
			return fmt.Errorf("identity/postgres: credential id %q is unreadable: %w", credID, err)
		}
		if !verifier.Valid || verifier.String == "" {
			return fmt.Errorf("identity/postgres: credential %s is a password with no verifier", credID)
		}

		out = app.PasswordCredential{
			ID:            id,
			SubjectID:     subject,
			Verifier:      verifier.String,
			PepperVersion: pepper.Int32,
			Failures:      failures,
			EnabledAt:     enabledAt.Time.UTC(),
		}
		return nil
	})
	if err != nil {
		return app.PasswordCredential{}, err
	}
	return out, nil
}

// Rehash replaces a verifier, but only if the row still holds the old one.
func (c *Credentials) Rehash(
	ctx context.Context, cred ids.CredentialID, expected, replacement string, pepperVersion int32,
) error {
	switch {
	case cred.IsZero():
		return errors.New("identity/postgres: rehashing needs a credential id")
	case expected == "":
		// Without the expected value the statement degenerates into an
		// unconditional write, which is the exact behaviour the compare-and-set
		// exists to prevent: a rehash landing on top of a password the user
		// changed while the login was in flight.
		return errors.New("identity/postgres: rehashing needs the verifier that was verified, " +
			"or the write is unconditional and can undo a password change")
	case replacement == "":
		return errors.New("identity/postgres: rehashing needs a replacement verifier")
	case replacement == expected:
		// Nothing to write, and writing it anyway would report success for a
		// rehash that changed no policy at all — hiding a NeedsRehash that keeps
		// firing because the hasher never actually re-derives anything.
		return errors.New("identity/postgres: the replacement verifier is the stored one")
	case pepperVersion < 1:
		return fmt.Errorf("identity/postgres: pepper version %d is not a real version; "+
			"the rotation job would never find this row", pepperVersion)
	}

	return c.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Exec(ctx, identitydb.RehashCredential,
			replacement, pepperVersion, cred.String(), expected)
		if err != nil {
			return fmt.Errorf("identity/postgres: rehashing a credential: %w", err)
		}
		if rows == 0 {
			// Changed, disabled or gone. Not an error about the database and not
			// a login failure — the login already succeeded. The rehash is stale
			// and must be dropped rather than retried.
			return app.ErrCredentialMoved
		}
		return nil
	})
}

// Replace swaps a password verifier from a reset, but only if the row still
// holds the one the reset was decided against.
//
// The guard is the reset flow's only serialization point; see
// app.PasswordCredentials.Replace and the ResetCredentialPassword statement for
// the concurrency it exists to make impossible.
func (c *Credentials) Replace(
	ctx context.Context, cred ids.CredentialID, expected, replacement string, pepperVersion int32,
) error {
	switch {
	case cred.IsZero():
		return errors.New("identity/postgres: replacing a password needs a credential id")
	case expected == "":
		// Without it the statement degenerates into an unconditional write, and
		// the losing half of two simultaneous resets would silently overwrite the
		// winning one.
		return errors.New("identity/postgres: replacing a password needs the verifier the " +
			"reset was decided against, or two simultaneous resets both write and the " +
			"account keeps whichever committed last")
	case replacement == "":
		return errors.New("identity/postgres: replacing a password needs a replacement verifier")
	case replacement == expected:
		// Two different passwords cannot produce one verifier — the salt alone
		// makes that impossible — so this means the caller passed the stored value
		// back as the replacement, and writing it would report a reset that
		// changed nothing.
		return errors.New("identity/postgres: the replacement verifier is the stored one")
	case pepperVersion < 1:
		return fmt.Errorf("identity/postgres: pepper version %d is not a real version; "+
			"the rotation job would never find this row", pepperVersion)
	}

	return c.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Exec(ctx, identitydb.ResetCredentialPassword,
			replacement, pepperVersion, cred.String(), expected)
		if err != nil {
			return fmt.Errorf("identity/postgres: replacing a password verifier: %w", err)
		}
		if rows == 0 {
			// Changed, disabled, gone, or not a password. Under contention this is
			// the NORMAL outcome for the losing reset, and it must abort: whoever
			// won wrote a password a person deliberately chose.
			return app.ErrCredentialMoved
		}
		return nil
	})
}

// RecordSuccess stamps the credential as used and clears its failure count.
func (c *Credentials) RecordSuccess(ctx context.Context, cred ids.CredentialID) error {
	if cred.IsZero() {
		return errors.New("identity/postgres: recording a success needs a credential id")
	}
	return c.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Exec(ctx, identitydb.TouchCredential, cred.String())
		if err != nil {
			return fmt.Errorf("identity/postgres: recording credential use: %w", err)
		}
		if rows == 0 {
			// Something deleted the row underneath a live login. Reported rather
			// than swallowed, because the alternative — a silent no-op — is
			// indistinguishable from a failure counter that never resets, and
			// that ends in a lockout nobody can explain.
			return app.ErrCredentialNotFound
		}
		return nil
	})
}

// RecordFailure counts one failed attempt and returns the new total.
func (c *Credentials) RecordFailure(ctx context.Context, cred ids.CredentialID) (int32, error) {
	if cred.IsZero() {
		return 0, errors.New("identity/postgres: recording a failure needs a credential id")
	}

	var failures int32
	err := c.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		// The count comes back from the statement that wrote it. A follow-up
		// SELECT would be another transaction's view, so two concurrent failures
		// could both read the pre-increment value and neither would see the
		// ceiling crossed — which is the concurrency an online guessing attack
		// produces by construction.
		scanErr := q.QueryRow(ctx, identitydb.RecordCredentialFailure, cred.String()).Scan(&failures)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return app.ErrCredentialNotFound
		}
		if scanErr != nil {
			return fmt.Errorf("identity/postgres: counting a credential failure: %w", scanErr)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return failures, nil
}

// Disable locks out one authenticator.
func (c *Credentials) Disable(ctx context.Context, cred ids.CredentialID) error {
	if cred.IsZero() {
		// Without an id the statement matches nothing, and reporting success for
		// it would mean a lockout that was requested and never applied.
		return errors.New("identity/postgres: disabling needs a credential id")
	}
	return c.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		// The statement's own `disabled_at IS NULL` guard means a repeat affects
		// zero rows, which is NOT reported as an error: the caller wants the
		// credential unusable and it is. An error there would put a retry loop
		// around a lockout that has already succeeded.
		if _, err := q.Exec(ctx, identitydb.DisableCredential, cred.String()); err != nil {
			return fmt.Errorf("identity/postgres: disabling a credential: %w", err)
		}
		return nil
	})
}

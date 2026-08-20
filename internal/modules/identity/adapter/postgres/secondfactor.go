package postgres

import (
	"context"
	"errors"
	"fmt"

	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// SecondFactors implements app.TotpSecrets and app.RecoveryCodes.
//
// One type for both because they are one thing from storage's point of view: the
// authoritative half of a user's second factors, written by command handlers and
// reconstructable from nothing. Like the password verifier beside them, neither a
// sealed TOTP secret nor a recovery-code digest may enter an event (identity.md
// §4, ADR-002), so a projection rebuild must not reach these rows — and there is
// no Reset, no checkpoint and no replay path in this file, which is the design
// rather than an omission.
//
// Both values are OPAQUE here. This adapter does not seal, open, or hash
// anything: it stores what it is handed. The sealing key lives in the totpseal
// package and the digest is computed in the use case, so a compromise of the
// database yields ciphertext and digests, and a compromise of this file yields
// no key at all.
type SecondFactors struct{ tx db.SystemTX }

var (
	_ app.TotpSecrets   = (*SecondFactors)(nil)
	_ app.RecoveryCodes = (*SecondFactors)(nil)
)

const (
	// kindTotp is the credential table's discriminator for an authenticator app.
	kindTotp = "totp"

	// kindRecoveryCode is the discriminator for the code set.
	//
	// The set is ONE credential holding many digests, not one credential per code.
	// That is what makes "this account has recovery codes" a single fact the
	// aggregate can enable and disable, and it is why recovery_code rows carry a
	// foreign key to this row rather than standing alone.
	kindRecoveryCode = "recovery_code"
)

// digestBytes is the width of a recovery-code digest. The table has a CHECK to
// the same effect; this refuses a wrong-sized value here so the failure names the
// problem instead of a constraint.
const digestBytes = 32

// NewSecondFactors builds the adapter.
func NewSecondFactors(tx db.SystemTX) (*SecondFactors, error) {
	if tx == nil {
		return nil, errors.New("identity/postgres: a system transaction is required; " +
			"identity's tables carry no RLS, so the transaction helper is the whole boundary")
	}
	return &SecondFactors{tx: tx}, nil
}

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------

// Provision records a shared secret that is not yet proven.
//
// The row is written with enabled_at NULL, deliberately. A secret the user has
// scanned but never produced a code from may exist only on this side of the
// exchange, and the usable-credential lookup filters on `enabled_at IS NOT NULL`
// — so an unproven enrolment cannot take part in an authentication however the
// aggregate is read. Confirmation is a separate write (Enable).
func (s *SecondFactors) Provision(ctx context.Context, secret app.NewTotpSecret) error {
	switch {
	case secret.ID.IsZero():
		// The id is authenticated into the sealed secret. Storing it under a
		// different one yields a row that can never be opened, and the failure
		// appears when the user next presents a code rather than here.
		return errors.New("identity/postgres: a credential id is required; the secret is " +
			"sealed against it and cannot be opened from another row")
	case secret.SubjectID == "":
		return errors.New("identity/postgres: a TOTP credential needs a subject")
	case secret.Sealed == "":
		// A TOTP row with no secret satisfies "this account has an authenticator"
		// while verifying nothing, which is a second factor the user cannot use and
		// no error anywhere explains. The password CHECK constraint does not cover
		// this kind, so the refusal has to be here.
		return errors.New("identity/postgres: a TOTP credential needs a sealed secret")
	case secret.KeyVersion < 1:
		// A NULL or zero version is invisible to `pepper_version < n`, so the
		// re-sealing job never visits the row — and destroying the old key then
		// costs that account its second factor permanently (identity.md §4).
		return fmt.Errorf("identity/postgres: key version %d is not a real version; "+
			"the re-sealing job would never find this row", secret.KeyVersion)
	}

	return s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx, identitydb.UpsertCredential,
			secret.ID.String(), secret.SubjectID, kindTotp,
			secret.Sealed, secret.KeyVersion, pgtype.Timestamptz{})
		if err != nil {
			// The upsert absorbs a repeat of the SAME credential id — which is what
			// makes a restarted enrolment converge, replacing the abandoned secret
			// AND clearing enabled_at in one statement. It cannot absorb a SECOND
			// live authenticator under a NEW id: that contends on the partial unique
			// index, which is what keeps one subject from holding two.
			var pg *pgconn.PgError
			if errors.As(err, &pg) && pg.ConstraintName == oneUsablePerKind {
				return fmt.Errorf("identity/postgres: this subject already has an "+
					"authenticator under a different credential id: %w", err)
			}
			return fmt.Errorf("identity/postgres: storing a shared secret: %w", err)
		}
		return nil
	})
}

// Find returns the subject's TOTP credential, proven or not.
func (s *SecondFactors) Find(ctx context.Context, subjectID string) (app.TotpSecret, error) {
	if subjectID == "" {
		// Reported as "no credential" rather than as a validation error: the caller
		// answers a wrong code and a missing enrolment identically, and a different
		// error here would be the oracle that uniformity exists to remove.
		return app.TotpSecret{}, app.ErrNoTotpCredential
	}

	var out app.TotpSecret
	err := s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		var (
			credID, subject, kind string
			sealed                pgtype.Text
			keyVersion            pgtype.Int4
			enabledAt             pgtype.Timestamptz
		)
		scanErr := q.QueryRow(ctx, identitydb.GetCredentialOfKind, subjectID, kindTotp).
			Scan(&credID, &subject, &kind, &sealed, &keyVersion, &enabledAt)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			// Unknown subject, never enrolled, and locked out all arrive here.
			// Telling them apart would confirm which accounts hold a second factor.
			return app.ErrNoTotpCredential
		}
		if scanErr != nil {
			return fmt.Errorf("identity/postgres: reading a TOTP credential: %w", scanErr)
		}

		id, err := ids.Parse[ids.Credential](credID)
		if err != nil {
			// NOT reported as "no credential". A row whose id does not parse was
			// written by something that is not this application, and answering
			// "wrong code" to it hides exactly the tampering the AAD binding exists
			// to surface.
			return fmt.Errorf("identity/postgres: credential id %q is unreadable: %w", credID, err)
		}
		if !sealed.Valid || sealed.String == "" {
			return fmt.Errorf("identity/postgres: credential %s is a TOTP method with no secret", credID)
		}

		out = app.TotpSecret{
			ID:         id,
			SubjectID:  subject,
			Sealed:     sealed.String,
			KeyVersion: keyVersion.Int32,
			// enabled_at is what the usable-credential lookup filters on, so it is
			// the same fact read two ways rather than a second flag that could
			// disagree with it.
			Enabled: enabledAt.Valid,
		}
		return nil
	})
	if err != nil {
		return app.TotpSecret{}, err
	}
	return out, nil
}

// Enable makes a provisioned authenticator usable.
func (s *SecondFactors) Enable(ctx context.Context, cred ids.CredentialID) error {
	if cred.IsZero() {
		// Without an id the statement matches nothing, and reporting success would
		// mean an enrolment the user completed and can never use.
		return errors.New("identity/postgres: enabling needs a credential id")
	}
	return s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Exec(ctx, identitydb.EnableCredential, cred.String())
		if err != nil {
			return fmt.Errorf("identity/postgres: enabling a credential: %w", err)
		}
		if rows == 0 {
			// Gone, or disabled between the verification and this write. Reported
			// rather than swallowed: enabling it anyway is not possible, and a silent
			// success would leave the log asserting a factor that does not exist.
			return app.ErrCredentialNotFound
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// Recovery codes
// ---------------------------------------------------------------------------

// Credential returns the recovery-code credential the subject's digests hang from.
func (s *SecondFactors) Credential(ctx context.Context, subjectID string) (ids.CredentialID, error) {
	if subjectID == "" {
		return ids.CredentialID{}, app.ErrNoRecoveryCode
	}

	var out ids.CredentialID
	err := s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		var (
			credID, subject, kind string
			verifier              pgtype.Text
			pepper                pgtype.Int4
			enabledAt             pgtype.Timestamptz
		)
		scanErr := q.QueryRow(ctx, identitydb.GetCredentialOfKind, subjectID, kindRecoveryCode).
			Scan(&credID, &subject, &kind, &verifier, &pepper, &enabledAt)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return app.ErrNoRecoveryCode
		}
		if scanErr != nil {
			return fmt.Errorf("identity/postgres: reading a recovery-code credential: %w", scanErr)
		}
		id, err := ids.Parse[ids.Credential](credID)
		if err != nil {
			return fmt.Errorf("identity/postgres: credential id %q is unreadable: %w", credID, err)
		}
		out = id
		return nil
	})
	if err != nil {
		return ids.CredentialID{}, err
	}
	return out, nil
}

// Replace swaps the whole set in one transaction.
//
// Three statements, one transaction, in this order: the credential row is
// upserted, the old digests are deleted, the new ones are inserted. The order is
// forced by the foreign key — recovery_code rows point at the credential — and
// the single transaction is what makes "replace" true. Split across two, there is
// an instant in which the account holds no codes while its holder believes they
// hold ten, and a crash in that instant leaves it there permanently.
//
// Deleting rather than marking the old rows spent is deliberate: a consumed row
// answers "you have used 7 of 10" for the CURRENT set, and keeping superseded
// sets would make that count meaningless while leaving digests around that no
// live code corresponds to.
func (s *SecondFactors) Replace(ctx context.Context, set app.NewRecoveryCodeSet) error {
	switch {
	case set.CredentialID.IsZero():
		return errors.New("identity/postgres: a recovery-code set needs a credential id")
	case set.SubjectID == "":
		return errors.New("identity/postgres: a recovery-code set needs a subject")
	case len(set.Digests) == 0:
		// An empty set would delete every live code and store nothing, leaving the
		// account with a recovery credential that can never be redeemed.
		return errors.New("identity/postgres: a recovery-code set needs at least one digest")
	case set.GeneratedAt.IsZero():
		// enabled_at NULL means the usable-credential lookup skips the row, so the
		// account has a code set the rest of the system cannot see.
		return errors.New("identity/postgres: a recovery-code set needs a generated-at instant")
	}
	for i, digest := range set.Digests {
		if len(digest) != digestBytes {
			return fmt.Errorf("identity/postgres: recovery-code digest %d is %d bytes, want %d",
				i, len(digest), digestBytes)
		}
	}

	return s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		// The credential row first: the digests carry a foreign key to it, and the
		// upsert is what makes a regenerated set land on the id the caller read back
		// rather than colliding with it.
		if _, err := q.Exec(ctx, identitydb.UpsertCredential,
			set.CredentialID.String(), set.SubjectID, kindRecoveryCode,
			pgtype.Text{}, pgtype.Int4{}, set.GeneratedAt.UTC(),
		); err != nil {
			return fmt.Errorf("identity/postgres: storing a recovery-code credential: %w", err)
		}
		if _, err := q.Exec(ctx, identitydb.DeleteRecoveryCodes, set.SubjectID); err != nil {
			return fmt.Errorf("identity/postgres: clearing the previous recovery codes: %w", err)
		}
		for _, digest := range set.Digests {
			if _, err := q.Exec(ctx, identitydb.InsertRecoveryCode,
				set.SubjectID, set.CredentialID.String(), digest); err != nil {
				return fmt.Errorf("identity/postgres: storing a recovery-code digest: %w", err)
			}
		}
		return nil
	})
}

// Consume redeems one digest exactly once.
//
// The decision is `consumed_at IS NULL` inside the UPDATE's WHERE clause, and
// nothing here reads first. A SELECT followed by an UPDATE lets two simultaneous
// presentations of one code both observe it unspent and both succeed — which is
// exactly what somebody working from a photographed sheet produces.
func (s *SecondFactors) Consume(
	ctx context.Context, subjectID string, digest []byte,
) (ids.CredentialID, error) {
	if subjectID == "" || len(digest) != digestBytes {
		// Reported as "no such code" rather than as a validation error, for the
		// reason the whole flow is shaped by: the caller must not be able to tell a
		// malformed presentation from a wrong one.
		return ids.CredentialID{}, app.ErrNoRecoveryCode
	}

	var out ids.CredentialID
	err := s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		var credID string
		scanErr := q.QueryRow(ctx, identitydb.ConsumeRecoveryCode, subjectID, digest).Scan(&credID)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			// Unknown, already spent, and belonging to another subject are one
			// answer. "That code was valid but you have already used it" tells
			// whoever is typing that they hold a real sheet.
			return app.ErrNoRecoveryCode
		}
		if scanErr != nil {
			return fmt.Errorf("identity/postgres: redeeming a recovery code: %w", scanErr)
		}
		id, err := ids.Parse[ids.Credential](credID)
		if err != nil {
			return fmt.Errorf("identity/postgres: credential id %q is unreadable: %w", credID, err)
		}
		out = id
		return nil
	})
	if err != nil {
		return ids.CredentialID{}, err
	}
	return out, nil
}

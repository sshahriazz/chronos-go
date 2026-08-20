package postgres

import (
	"context"
	"errors"
	"fmt"

	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/jackc/pgx/v5/pgtype"
)

// ResealStore implements identity's re-sealing port: the work list, the done
// check, and the compare-and-set that carries one credential onto a newer key.
//
// It is a SECOND adapter over the `credential` table, beside Credentials, and the
// split is deliberate rather than an accident of who wrote what. Credentials is
// the command handlers' store — it deals in one kind (`password`), because a
// store that took the kind as a parameter would invite a caller to fetch a
// passkey row and hand it to the password hasher. This one is the opposite by
// necessity: it is kind-agnostic, because the whole point is that every kind
// holding a sealed value gets rotated, and the previous bug in this area was a
// query that could see only one of them.
//
// It holds no key and opens nothing. The sealed values are opaque strings here;
// what they mean belongs to the argon2id and totpseal packages, and an adapter
// that peeked inside would be a second parser for a format with one authority.
//
// Every statement runs in a SYSTEM transaction. Identity's tables carry no RLS
// (see the package comment in guards.go), and a key rotation spans every tenant
// by nature.
type ResealStore struct{ tx db.SystemTX }

var _ app.ResealableCredentials = (*ResealStore)(nil)

// NewResealStore builds the adapter.
func NewResealStore(tx db.SystemTX) (*ResealStore, error) {
	if tx == nil {
		return nil, errors.New("identity/postgres: the re-sealing store needs a system " +
			"transaction; without one no credential is ever moved to a new key version and " +
			"a rotation can never be completed")
	}
	return &ResealStore{tx: tx}, nil
}

// ListToReseal returns credentials of one kind still sealed below version,
// starting strictly after a cursor.
//
// Rows whose credential id does not parse are DROPPED here rather than returned
// with a zero id. A row written by something that is not this application cannot
// be bound to — the id is half the AES-GCM additional data — so there is nothing
// the job could do with it except fail on every pass. It is logged by the caller
// only if it also blocks the done check, which it will: the count still sees it.
func (s *ResealStore) ListToReseal(
	ctx context.Context, kind string, below int32, after string, limit int,
) ([]app.SealedCredential, error) {
	switch {
	case kind == "":
		return nil, errors.New("identity/postgres: a re-sealing work list needs a credential " +
			"kind; without one it selects nothing and the caller reads a clean pass")
	case below < 1:
		// `pepper_version < 0` and `< 0` select nothing at all. Refused rather
		// than passed through, because a job bounded by a bogus version reports a
		// perfectly healthy empty page while every row stays on the old key —
		// which is the one answer that gets an operator to destroy it.
		return nil, fmt.Errorf("identity/postgres: key version %d is not a real version; a "+
			"work list bounded by it selects nothing and reports success", below)
	case limit <= 0:
		return nil, fmt.Errorf("identity/postgres: a re-sealing page size of %d returns "+
			"nothing", limit)
	case limit > maxResealPage:
		return nil, fmt.Errorf("identity/postgres: a re-sealing page size of %d exceeds the "+
			"%d cap; each row costs an AEAD open and a write, and an unbounded page turns "+
			"one pass into an unbounded transaction", limit, maxResealPage)
	}

	var out []app.SealedCredential
	err := s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		// The conversion is bounded by maxResealPage three checks above, so it
		// cannot wrap. Annotated rather than restructured, following the same
		// discipline argon2id's decode uses: the bound is enforced where the value
		// ENTERS, and the annotation points at it. gosec cannot see that far.
		//nolint:gosec // limit is bounded by maxResealPage above
		pageSize := int32(limit)

		rows, err := q.Query(ctx, identitydb.ListCredentialsToReseal,
			kind, pgtype.Int4{Int32: below, Valid: true}, after, pageSize)
		if err != nil {
			return fmt.Errorf("identity/postgres: listing %s credentials to re-seal: %w", kind, err)
		}
		defer rows.Close()

		for rows.Next() {
			var (
				credID, subject string
				userID          pgtype.Text
				verifier        pgtype.Text
			)
			if err := rows.Scan(&credID, &subject, &userID, &verifier); err != nil {
				return fmt.Errorf("identity/postgres: reading a re-sealing work item: %w", err)
			}
			id, err := ids.Parse[ids.Credential](credID)
			if err != nil {
				// Skipped, not failed: there is no binding to open it with, so no
				// pass will ever move it. It keeps counting against the done
				// check, which is the correct place for it to surface — as "the
				// rotation is stalled" rather than as a per-pass error nobody can
				// act on.
				continue
			}
			item := app.SealedCredential{ID: id, SubjectID: subject, Sealed: verifier.String}
			if userID.Valid {
				// A user id that does not parse is left ZERO rather than skipped.
				// For TOTP it is not needed at all; for a password the caller
				// reports the row as a failure, which is what a credential with no
				// readable account is.
				if uid, err := ids.Parse[ids.User](userID.String); err == nil {
					item.UserID = uid
				}
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// maxResealPage caps one page.
//
// Every row costs an AEAD open, an AEAD seal and an UPDATE, and for passwords the
// open is over a value whose salt and parameters must survive the round trip
// intact. 1000 is far above the 200 the job actually asks for; it is here so a
// misconfigured batch cannot turn one pass into a transaction that holds row
// locks across the whole table.
const maxResealPage = 1000

// CountToReseal answers "is anything of this kind still on an old key".
//
// It reuses CountCredentialsAtKeyVersion — the statement an operator runs by hand
// before destroying a key — rather than a count of its own. That is the point: a
// job whose completion test differs from the operator's check is a job that can
// report finished while the operator's query still returns rows, and the
// difference between those two answers is a destroyed key that rows still need.
func (s *ResealStore) CountToReseal(ctx context.Context, kind string, below int32) (int64, error) {
	switch {
	case kind == "":
		return 0, errors.New("identity/postgres: a re-sealing count needs a credential kind")
	case below < 1:
		return 0, fmt.Errorf("identity/postgres: key version %d is not a real version; a "+
			"count bounded by it returns zero and reads as 'safe to destroy the old key'", below)
	}

	var n int64
	err := s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		scanErr := q.QueryRow(ctx, identitydb.CountCredentialsAtKeyVersion,
			kind, pgtype.Int4{Int32: below, Valid: true}).Scan(&n)
		if scanErr != nil {
			return fmt.Errorf("identity/postgres: counting %s credentials below key version "+
				"%d: %w", kind, below, scanErr)
		}
		return nil
	})
	return n, err
}

// Reseal writes a re-sealed value, but only if the row still holds the old one
// and is still below the new version.
//
// Returns app.ErrCredentialMoved when nothing was affected. See the statement's
// own comment for why that is the normal outcome of a lost race rather than a
// fault: whoever won wrote a value under the current key, which is what this call
// was trying to achieve.
func (s *ResealStore) Reseal(
	ctx context.Context, cred ids.CredentialID, expected, replacement string, version int32,
) error {
	switch {
	case cred.IsZero():
		return errors.New("identity/postgres: re-sealing needs a credential id")
	case expected == "":
		// Without the expected value the compare-and-set degenerates into an
		// unconditional write, which is exactly the outcome it exists to prevent:
		// a re-seal landing on top of a password the user changed, or a TOTP
		// secret they re-enrolled, while the batch was in flight.
		return errors.New("identity/postgres: re-sealing needs the value that was opened, " +
			"or the write is unconditional and can undo a password change or a second-factor " +
			"re-enrollment")
	case replacement == "":
		return errors.New("identity/postgres: re-sealing needs a replacement value; writing " +
			"an empty one would satisfy the update while destroying the only copy of the secret")
	case replacement == expected:
		// A genuine re-seal can never reproduce its input — GCM's nonce is random
		// per call — so identical bytes mean nothing was re-sealed, and writing
		// them would stamp a new version onto a value the new key cannot open.
		return errors.New("identity/postgres: the replacement value is byte-identical to the " +
			"stored one, so nothing was re-sealed")
	case version < 1:
		return fmt.Errorf("identity/postgres: key version %d is not a real version; a row "+
			"written at it is invisible to the rotation job's `pepper_version < n` query and "+
			"is locked out permanently when the old key is destroyed", version)
	}

	return s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Exec(ctx, identitydb.ResealCredential,
			pgtype.Text{String: replacement, Valid: true},
			pgtype.Int4{Int32: version, Valid: true},
			cred.String(),
			pgtype.Text{String: expected, Valid: true})
		if err != nil {
			return fmt.Errorf("identity/postgres: re-sealing a credential: %w", err)
		}
		if rows == 0 {
			return app.ErrCredentialMoved
		}
		return nil
	})
}

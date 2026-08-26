package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/page"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// APIKeys is the PostgreSQL side of identity.md §10, and it is the one adapter
// in this module that holds BOTH kinds of transaction.
//
// # Why two, and which statement gets which
//
// Everything else in identity runs in a system transaction, because identity's
// tables carry no row-level security: an account exists before any organization
// does, so there is no tenant to scope it by. Keys are the exception. A key is
// bound to an organization, `api_key_view` and `service_account_view` therefore
// carry `org_id` and a `tenant_isolation` policy, and every read of them must go
// through `InTenantTx` or return nothing.
//
// `api_key_secret` is the other half and is deliberately NOT policy-protected
// (migration 00051). It is read by the AUTHENTICATOR, which runs before gate 1
// — before any organization is known, because establishing which organization a
// request is in is the next gate's job — so a policy on `app.org_id` would make
// every API key in the system fail to resolve. Its safety comes from its key
// being a 256-bit digest nobody can guess.
//
// The split is therefore mechanical rather than a judgement call:
//
//	api_key_secret                         SYSTEM transaction
//	api_key_view, service_account_view     TENANT transaction
type APIKeys struct {
	tx     db.SystemTX
	tenant db.TX
}

var (
	_ app.APIKeySecrets           = (*APIKeys)(nil)
	_ app.ServiceAccountDirectory = (*APIKeys)(nil)
	_ app.APIKeyDirectory         = (*APIKeys)(nil)
)

// NewAPIKeys builds the adapter.
//
// Both transactions are required and neither has a stand-in. Without the system
// one no secret can be stored, so a key is appended to the log and no caller is
// ever given a way to use it; without the tenant one every read returns an empty
// list, which is indistinguishable from an organization that holds no keys.
func NewAPIKeys(tx db.SystemTX, tenant db.TX) (*APIKeys, error) {
	switch {
	case tx == nil:
		return nil, errors.New("identity/postgres: API keys need a system transaction; " +
			"api_key_secret carries no row-level security because the authenticator reads " +
			"it before any organization is known")
	case tenant == nil:
		return nil, errors.New("identity/postgres: API keys need a tenant transaction; " +
			"api_key_view and service_account_view carry row-level security, and an " +
			"unscoped read of them returns nothing while looking exactly like an " +
			"organization that holds no keys")
	}
	return &APIKeys{tx: tx, tenant: tenant}, nil
}

// ---------------------------------------------------------------------------
// The authoritative half
// ---------------------------------------------------------------------------

// Issue records the digest of a freshly minted secret.
//
// A plain INSERT, not an upsert, for the reason Sessions.Issue gives: a digest
// is 256 bits of fresh randomness, so a conflict is not a retry — it is either
// the same secret being issued twice, which no correct caller does, or a
// collision that is not going to happen. Absorbing it would silently point one
// digest at whichever key wrote it first, and the second caller would hold a
// credential for somebody else's key.
func (a *APIKeys) Issue(ctx context.Context, secret app.NewAPIKeySecret) error {
	switch {
	case len(secret.Digest) != 32:
		// The column has a CHECK on the width. Refused here to say WHY rather
		// than surfacing a constraint name — a short digest means the caller
		// hashed something other than a token.
		return fmt.Errorf("identity/postgres: an API key digest is %d bytes, want 32",
			len(secret.Digest))
	case secret.KeyID.IsZero():
		return errors.New("identity/postgres: an API key secret needs the key it belongs to; " +
			"a row naming no key can never be revoked, because revocation works by key id")
	case secret.OrgID == "":
		// The authenticator reads this column to establish the tenant scope, so
		// an empty one is a credential that authenticates into no organization —
		// which every later gate would then have to guess at.
		return errors.New("identity/postgres: an API key secret needs its bound organization")
	case len(secret.Scopes) == 0:
		return errors.New("identity/postgres: an API key secret needs its scopes; a row with " +
			"none authenticates into a request that can do nothing, which reads as a " +
			"permission bug rather than as the missing write it is")
	case secret.ExpiresAt.IsZero():
		// The column is NOT NULL and the lookup compares against it, so a zero
		// value is year 1 — a deadline already in the past, so the key resolves
		// on no request at all and the caller is handed a token that never works.
		return errors.New("identity/postgres: an API key secret needs a deadline")
	}

	return a.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		if _, err := q.Exec(ctx, identitydb.IssueApiKeySecret,
			secret.Digest, secret.KeyID.String(), secret.OrgID,
			string(secret.Owner.Kind), secret.Owner.ID, secret.Scopes,
			secret.ExpiresAt.UTC(), secret.IssuedAt.UTC(),
		); err != nil {
			return fmt.Errorf("identity/postgres: issuing an API key secret: %w", err)
		}
		return nil
	})
}

// Retire puts a deadline on every CURRENT secret of a key.
//
// A zero deadline is refused rather than passed through: the column is nullable
// and NULL means "current", so writing year 1 would retire the secret in the
// past — which the lookup reads as dead, turning a rotation into an unannounced
// revocation of the secret every consumer is still using.
func (a *APIKeys) Retire(
	ctx context.Context, keyID ids.APIKeyID, retiresAt time.Time,
) (int, error) {
	if keyID.IsZero() {
		return 0, errors.New("identity/postgres: retiring API key secrets needs a key")
	}
	if retiresAt.IsZero() {
		return 0, errors.New("identity/postgres: retiring an API key secret needs the instant " +
			"it stops resolving; a zero one is in the past, which makes a rotation an " +
			"immediate revocation of the secret everybody is still using")
	}

	var n int64
	err := a.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Exec(ctx, identitydb.RetireApiKeySecrets, keyID.String(), retiresAt.UTC())
		if err != nil {
			return fmt.Errorf("identity/postgres: retiring API key secrets: %w", err)
		}
		n = rows
		return nil
	})
	return int(n), err
}

// Delete removes every secret a key ever had. This is the immediate half of a
// revocation.
func (a *APIKeys) Delete(ctx context.Context, keyID ids.APIKeyID) (int, error) {
	if keyID.IsZero() {
		// Refused rather than answered with zero. The statement has no other
		// predicate, so an empty key id would be a DELETE matching no rows that
		// reports a successful revocation — the caller then believes a
		// credential is dead and it is not.
		return 0, errors.New("identity/postgres: destroying API key secrets needs a key")
	}

	var n int64
	err := a.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Exec(ctx, identitydb.DeleteApiKeySecrets, keyID.String())
		if err != nil {
			return fmt.Errorf("identity/postgres: destroying API key secrets: %w", err)
		}
		n = rows
		return nil
	})
	return int(n), err
}

// ---------------------------------------------------------------------------
// The projected half
// ---------------------------------------------------------------------------

// Exists reports whether a service account is visible in the caller's tenant.
//
// "Visible" is doing the work: the read runs under the tenant scope, so
// row-level security answers "and is it this organization's" without a predicate
// anybody could forget to write. An account in another organization is
// indistinguishable here from one that does not exist, which is the answer
// ADR-036 wants a caller naming somebody else's principal to get.
func (a *APIKeys) Exists(ctx context.Context, id ids.ServiceAccountID) (bool, error) {
	if id.IsZero() {
		return false, nil
	}
	var found bool
	err := a.tenant.InTenantTx(ctx, func(ctx context.Context, q db.Querier) error {
		var (
			accountID, name, createdBy string
			createdAt                  time.Time
		)
		scanErr := q.QueryRow(ctx, identitydb.GetServiceAccount, id.String()).
			Scan(&accountID, &name, &createdBy, &createdAt)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return nil
		}
		if scanErr != nil {
			return fmt.Errorf("identity/postgres: resolving a service account: %w", scanErr)
		}
		found = true
		return nil
	})
	return found, err
}

// ServiceAccounts returns the tenant's non-human principals, newest first.
func (a *APIKeys) ServiceAccounts(
	ctx context.Context, cursor page.Keyset, limit int32,
) ([]app.ServiceAccountSummary, error) {
	at, id, err := orgCursorArgs(cursor, "service account")
	if err != nil {
		return nil, err
	}

	var out []app.ServiceAccountSummary
	err = a.tenant.InTenantTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Query(ctx, identitydb.ListServiceAccounts, at, id, limit)
		if err != nil {
			return fmt.Errorf("identity/postgres: listing service accounts: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var (
				accountID, name, createdBy string
				createdAt                  time.Time
			)
			if err := rows.Scan(&accountID, &name, &createdBy, &createdAt); err != nil {
				return fmt.Errorf("identity/postgres: reading a service account: %w", err)
			}
			parsed, err := ids.Parse[ids.ServiceAccount](accountID)
			if err != nil {
				// Refused, not skipped. A row whose id does not parse was written
				// by something that is not this application, and dropping it would
				// hide that from the one screen where somebody would notice a
				// principal they did not create.
				return fmt.Errorf("identity/postgres: service account id %q is unreadable: %w",
					accountID, err)
			}
			out = append(out, app.ServiceAccountSummary{
				ID:        parsed,
				Name:      name,
				CreatedBy: createdBy,
				CreatedAt: createdAt.UTC(),
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Keys returns the tenant's API keys, newest first, revoked ones included.
//
// Revoked keys are included deliberately — see ListApiKeys in the .sql. Nothing
// here can return a secret: the statement's select list has no digest column and
// the result type has no field that could hold one.
func (a *APIKeys) Keys(
	ctx context.Context, cursor page.Keyset, limit int32,
) ([]app.APIKeySummary, error) {
	at, id, err := orgCursorArgs(cursor, "API key")
	if err != nil {
		return nil, err
	}

	var out []app.APIKeySummary
	err = a.tenant.InTenantTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Query(ctx, identitydb.ListApiKeys, at, id, limit)
		if err != nil {
			return fmt.Errorf("identity/postgres: listing API keys: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var (
				keyID, ownerKind, ownerID, createdBy string
				scopes                               []string
				expiresAt, createdAt                 time.Time
				revokedAt, rotatedAt, lastUsedAt     pgtype.Timestamptz
			)
			if err := rows.Scan(&keyID, &ownerKind, &ownerID, &scopes, &expiresAt,
				&revokedAt, &createdBy, &createdAt, &rotatedAt, &lastUsedAt); err != nil {
				return fmt.Errorf("identity/postgres: reading an API key: %w", err)
			}
			parsed, err := ids.Parse[ids.APIKey](keyID)
			if err != nil {
				return fmt.Errorf("identity/postgres: API key id %q is unreadable: %w", keyID, err)
			}
			out = append(out, app.APIKeySummary{
				ID:         parsed,
				OwnerKind:  ownerKind,
				OwnerID:    ownerID,
				Scopes:     scopes,
				ExpiresAt:  expiresAt.UTC(),
				RevokedAt:  utcOrZero(revokedAt),
				RotatedAt:  utcOrZero(rotatedAt),
				LastUsedAt: utcOrZero(lastUsedAt),
				CreatedBy:  createdBy,
				CreatedAt:  createdAt.UTC(),
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// orgCursorArgs turns a keyset into the two bind values both org-scoped list
// statements expect.
//
// It reuses `beforeEverything` — the `timestamptz 'infinity'` sentinel
// queries.go already explains at length — rather than a second statement without
// the comparison. A second statement would be a second query plan and a second
// thing to keep in step with the index, and the OR-based alternative makes the
// predicate non-sargable so the index that exists for this exact ORDER BY stops
// being used on the one page every client asks for.
//
// The arity and the TYPES are checked rather than assumed, exactly as
// sessionCursorArgs checks them, and for the reason stated there: the
// interesting failure is not the cursor that refuses to bind, it is the
// mis-typed one that still produces rows and produces the WRONG ones.
//
// `what` names the list in the error, because both of them are (timestamp,
// text) and a message that did not say which would send a reader to the wrong
// statement.
func orgCursorArgs(after page.Keyset, what string) (pgtype.Timestamptz, string, error) {
	if after.IsStart() {
		return beforeEverything, "", nil
	}
	args := after.Args()
	if len(args) != 2 {
		return pgtype.Timestamptz{}, "", fmt.Errorf(
			"identity/postgres: a %s cursor has %d columns, want 2", what, len(args))
	}
	createdAt, ok := args[0].(time.Time)
	if !ok {
		return pgtype.Timestamptz{}, "", fmt.Errorf(
			"identity/postgres: a %s cursor's created_at is %T, want a timestamp", what, args[0])
	}
	id, ok := args[1].(string)
	if !ok {
		return pgtype.Timestamptz{}, "", fmt.Errorf(
			"identity/postgres: a %s cursor's id is %T, want a string", what, args[1])
	}
	return pgtype.Timestamptz{Time: createdAt.UTC(), Valid: true}, id, nil
}

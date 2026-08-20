// Package postgres implements identity's storage ports.
//
// Every statement runs in a SYSTEM transaction, never a tenant one. Identity's
// tables carry no RLS because a user exists before any organization — a
// registration happens with no org in context at all — so a policy on them could
// never be satisfied (see 00008_identity.sql).
//
// That makes db.SystemTX the entire boundary here, rather than the row. It is a
// separately named interface precisely so its use is a deliberate, greppable act
// rather than something that happens by default.
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
	"github.com/jackc/pgx/v5"
)

// Guards implements the two single-use ports: TOTP replay and emailed tokens.
//
// One type for both because they share the property that matters — a secret that
// must be spendable exactly once, decided in a single statement — and keeping
// them together makes it obvious that the discipline is the same.
type Guards struct{ tx db.SystemTX }

var (
	_ app.TOTPReplayGuard = (*Guards)(nil)
	_ app.TokenStore      = (*Guards)(nil)
)

// NewGuards builds the adapter.
func NewGuards(tx db.SystemTX) (*Guards, error) {
	if tx == nil {
		return nil, errors.New("identity/postgres: a system transaction is required; without " +
			"one the replay guard cannot be consulted and every observed code is replayable")
	}
	return &Guards{tx: tx}, nil
}

// Claim spends a TOTP time step, or reports that it was already spent.
//
// The decision is the affected-row count from one INSERT … ON CONFLICT DO
// NOTHING. Nothing here reads first: a SELECT followed by an INSERT lets two
// simultaneous presentations of the same code both observe it as unused, which
// is exactly the concurrency an attacker relaying a code produces.
func (g *Guards) Claim(
	ctx context.Context, cred ids.CredentialID, step int64, expiresAt time.Time,
) error {
	if cred.IsZero() {
		// Without a credential the claim is keyed on the step alone, so one
		// user's login would consume every other user's step at that instant.
		return errors.New("identity/postgres: a credential id is required to claim a time step")
	}
	if expiresAt.IsZero() {
		// The column is NOT NULL, so this would fail at the database anyway —
		// refused here to say why, rather than surfacing a constraint name.
		return errors.New("identity/postgres: a claimed step needs an expiry, or the row is " +
			"retained for the lifetime of the deployment")
	}

	return g.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Exec(ctx, identitydb.ClaimTOTPStep,
			cred.String(), step, expiresAt.UTC())
		if err != nil {
			return fmt.Errorf("identity/postgres: claiming a time step: %w", err)
		}
		if rows == 0 {
			// Already spent. NOT an error about the database — a specific,
			// actionable signal: somebody has observed a genuine code.
			return app.ErrCodeReplayed
		}
		return nil
	})
}

// Issue records a token digest.
func (g *Guards) Issue(
	ctx context.Context, purpose app.TokenPurpose, subjectID string, digest []byte, expiresAt time.Time,
) error {
	switch {
	case purpose == "":
		return errors.New("identity/postgres: a token needs a purpose; an unscoped token can " +
			"be redeemed in a flow it was never issued for")
	case subjectID == "":
		return errors.New("identity/postgres: a token needs a subject")
	case len(digest) != 32:
		return fmt.Errorf("identity/postgres: a token digest is %d bytes, want 32", len(digest))
	case expiresAt.IsZero():
		return errors.New("identity/postgres: a token needs an expiry")
	}

	return g.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		if _, err := q.Exec(ctx, identitydb.IssueToken,
			digest, string(purpose), subjectID, expiresAt.UTC()); err != nil {
			return fmt.Errorf("identity/postgres: issuing a token: %w", err)
		}
		return nil
	})
}

// Consume redeems a digest exactly once and returns whose it was.
//
// DELETE … RETURNING, in one statement. The two-step version — look it up, then
// delete it — lets two simultaneous clicks of the same reset link both find it
// valid, turning a single-use credential into a multi-use one for anyone who
// intercepted the mail.
func (g *Guards) Consume(
	ctx context.Context, purpose app.TokenPurpose, digest []byte, now time.Time,
) (string, error) {
	if purpose == "" || len(digest) != 32 {
		// Reported as "not found" rather than as a validation error, because the
		// caller can do nothing different with the distinction and the uniform
		// answer is what keeps the endpoint from being an oracle.
		return "", app.ErrTokenNotFound
	}

	var subjectID string
	err := g.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		scanErr := q.QueryRow(ctx, identitydb.ConsumeToken,
			digest, string(purpose), now.UTC()).Scan(&subjectID)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			// Unknown, already spent, or expired — all three land here, and
			// deliberately cannot be told apart. Reporting "this token was valid
			// but has expired" confirms that the address it was sent to has an
			// account.
			return app.ErrTokenNotFound
		}
		if scanErr != nil {
			return fmt.Errorf("identity/postgres: consuming a token: %w", scanErr)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return subjectID, nil
}

// RevokeAll drops every outstanding token of a purpose for a subject.
//
// identity.md §7 rule 7: verification, reset and recovery void every other
// outstanding token. Without it two reset links can be live at once, and using
// one leaves the other usable.
func (g *Guards) RevokeAll(ctx context.Context, purpose app.TokenPurpose, subjectID string) error {
	if purpose == "" || subjectID == "" {
		return errors.New("identity/postgres: revoking tokens needs a purpose and a subject")
	}
	return g.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		if _, err := q.Exec(ctx, identitydb.RevokeTokens, subjectID, string(purpose)); err != nil {
			return fmt.Errorf("identity/postgres: revoking tokens: %w", err)
		}
		return nil
	})
}

// RevokeAllPurposes drops every outstanding token for a subject, whatever it was
// issued for.
//
// ONE statement scoped by the subject, never a loop over the known purposes: a
// purpose added to app.TokenPurpose without being added to a loop would be a
// live token that survives a password reset, and nothing at runtime or in any
// test would notice, because the loop still passes. See identity.md §4.5.
func (g *Guards) RevokeAllPurposes(ctx context.Context, subjectID string) (int, error) {
	if subjectID == "" {
		// Refused rather than executed. An empty subject matches no row here, but
		// the same mistake against a store that treated it as a wildcard would
		// delete every outstanding token in the system — so the refusal belongs at
		// the boundary rather than in the WHERE clause's luck.
		return 0, errors.New("identity/postgres: revoking every token needs a subject")
	}
	var n int64
	err := g.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Exec(ctx, identitydb.RevokeAllTokensForSubject, subjectID)
		if err != nil {
			return fmt.Errorf("identity/postgres: revoking every outstanding token: %w", err)
		}
		n = rows
		return nil
	})
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// SweepTOTPReplay drops spent steps whose codes can no longer be presented.
//
// Retention, not correctness: a step past its expiry cannot be replayed anyway,
// so the row protects nothing and the table would otherwise grow for the
// lifetime of the deployment.
func (g *Guards) SweepTOTPReplay(ctx context.Context) (int64, error) {
	var n int64
	err := g.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Exec(ctx, identitydb.SweepTOTPReplay)
		if err != nil {
			return fmt.Errorf("identity/postgres: sweeping spent time steps: %w", err)
		}
		n = rows
		return nil
	})
	return n, err
}

// SweepTokens drops expired token digests.
func (g *Guards) SweepTokens(ctx context.Context) (int64, error) {
	var n int64
	err := g.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Exec(ctx, identitydb.SweepTokens)
		if err != nil {
			return fmt.Errorf("identity/postgres: sweeping tokens: %w", err)
		}
		n = rows
		return nil
	})
	return n, err
}

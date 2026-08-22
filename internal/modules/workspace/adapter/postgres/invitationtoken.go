package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	workspacedb "github.com/chronos/chronos-go/gen/sqlc/workspace"
	"github.com/chronos/chronos-go/internal/modules/workspace/app"
	"github.com/chronos/chronos-go/internal/platform/db"
)

// InvitationTokens holds the credential inside an invitation link.
//
// # Why a SYSTEM transaction throughout
//
// Redemption happens before any tenant scope exists — the person clicking the
// link may have no account at all, and working out which organization the
// invitation belongs to is precisely what the lookup does. `invitation_token`
// carries no row security for that reason (migration 00023), and containment is
// the key itself: a 256-bit value from crypto/rand that exists only in the
// recipient's mail.
//
// Issue runs in the same kind of transaction for a duller reason. It happens
// inside a request that DOES have a scope, but using it would make the two paths
// disagree about which transaction shape this table lives in, and the row it
// writes has no policy to satisfy either way.
type InvitationTokens struct{ system db.SystemTX }

var _ app.InvitationTokenStore = (*InvitationTokens)(nil)

func NewInvitationTokens(system db.SystemTX) (*InvitationTokens, error) {
	if system == nil {
		return nil, fmt.Errorf("workspace: a system transaction source is required; an " +
			"invitation is redeemed before any tenant scope exists")
	}
	return &InvitationTokens{system: system}, nil
}

// Issue records a digest against an invitation.
func (t *InvitationTokens) Issue(
	ctx context.Context, digest []byte, invitationID, orgID string, expiresAt time.Time,
) error {
	if len(digest) != 32 {
		// The column constraint says the same thing. Refusing here as well turns
		// a wiring mistake into a message that names the caller's mistake rather
		// than a constraint violation from the driver.
		return fmt.Errorf("workspace: an invitation digest is %d bytes, want 32", len(digest))
	}
	return t.system.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx, workspacedb.IssueInvitationToken,
			digest, string(app.PurposeInvitation), invitationID, orgID, expiresAt.UTC())
		if err != nil {
			return fmt.Errorf("workspace: issuing an invitation token: %w", err)
		}
		return nil
	})
}

// Consume redeems a digest exactly once and reports which invitation it names.
//
// Returns app.ErrInvitationTokenNotFound for a digest that is unknown, already
// spent, or expired. The three are deliberately indistinguishable — see the
// query, which checks the expiry itself for exactly that reason.
func (t *InvitationTokens) Consume(
	ctx context.Context, digest []byte, now time.Time,
) (invitationID, orgID string, err error) {
	if len(digest) != 32 {
		// Not an error worth distinguishing. A presented value of the wrong
		// length cannot match any row, so answering as though it simply did not
		// match keeps every rejection on this path identical.
		return "", "", app.ErrInvitationTokenNotFound
	}
	err = t.system.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		row := q.QueryRow(ctx, workspacedb.ConsumeInvitationToken,
			digest, string(app.PurposeInvitation), now.UTC())
		return row.Scan(&invitationID, &orgID)
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "", "", app.ErrInvitationTokenNotFound
	case err != nil:
		return "", "", fmt.Errorf("workspace: consuming an invitation token: %w", err)
	}
	return invitationID, orgID, nil
}

// RevokeAll drops every outstanding digest for one invitation.
//
// Called by a resend, so exactly one link is live afterwards, and by every
// settlement, so none is. Reporting the count rather than swallowing it, because
// a resend that revoked nothing means the previous digest is still live and the
// caller has just created a second one.
func (t *InvitationTokens) RevokeAll(ctx context.Context, invitationID string) (int64, error) {
	var removed int64
	err := t.system.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Exec(ctx, workspacedb.RevokeInvitationTokens, invitationID)
		if err != nil {
			return err
		}
		removed = rows
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("workspace: revoking invitation tokens for %s: %w", invitationID, err)
	}
	return removed, nil
}

// Sweep deletes digests past their expiry.
func (t *InvitationTokens) Sweep(ctx context.Context) (int64, error) {
	var removed int64
	err := t.system.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Exec(ctx, workspacedb.SweepInvitationTokens)
		if err != nil {
			return err
		}
		removed = rows
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("workspace: sweeping invitation tokens: %w", err)
	}
	return removed, nil
}

package postgres

import (
	"context"
	"fmt"
	"math"
	"time"

	workspacedb "github.com/chronos/chronos-go/gen/sqlc/workspace"
	"github.com/chronos/chronos-go/internal/modules/workspace/app"
	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/modules/workspace/domain"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/page"
)

// InvitationReads is the read side of invitation_view.
//
// A TENANT transaction: every caller reaches it after gate 1 has resolved a
// scope, so the row security policy applies and another organization's
// invitations are invisible rather than merely unmatched.
type InvitationReads struct{ tx db.TX }

var _ app.InvitationReader = (*InvitationReads)(nil)

func NewInvitationReads(tx db.TX) (*InvitationReads, error) {
	if tx == nil {
		return nil, fmt.Errorf("workspace: a transaction source is required")
	}
	return &InvitationReads{tx: tx}, nil
}

// ListByWorkspace returns one page, keyset-ordered by (expires_at, invitation_id).
//
// The cursor's values are passed as the comparison's right-hand side. A START
// cursor uses the zero time and the empty id, which sorts before every real row
// — so "first page" and "resume" are ONE query rather than two, and there is no
// second statement to drift out of step with this one.
func (r *InvitationReads) ListByWorkspace(
	ctx context.Context, workspaceID string, status domain.InvitationStatus,
	after page.Keyset, size page.Size,
) ([]app.InvitationSummary, error) {
	afterExpiry := time.Time{}
	afterID := ""
	if !after.IsStart() {
		values := after.Args()
		if len(values) != 2 {
			return nil, fmt.Errorf("workspace: a cursor for this list needs 2 keys, got %d",
				len(values))
		}
		ts, ok := values[0].(time.Time)
		if !ok {
			return nil, fmt.Errorf("workspace: the cursor's expiry is %T, not a time", values[0])
		}
		id, ok := values[1].(string)
		if !ok {
			return nil, fmt.Errorf("workspace: the cursor's id is %T, not a string", values[1])
		}
		afterExpiry, afterID = ts.UTC(), id
	}

	var out []app.InvitationSummary
	err := r.tx.InTenantTx(ctx, func(ctx context.Context, q db.Querier) error {
		// page.Clamp bounds size at MaxSize, and the caller adds one for the
		// has-more probe, so this cannot overflow — but the conversion is written
		// explicitly rather than left to a linter suppression, because the day
		// somebody raises MaxSize is the day a silent wrap would return a
		// negative LIMIT.
		var limit int32
		if size > page.Size(math.MaxInt32) {
			return fmt.Errorf("workspace: a page size of %d does not fit a query limit", size)
		}
		limit = int32(size) //nolint:gosec // bounded on the line above

		rows, err := q.Query(ctx, workspacedb.ListWorkspaceInvitations,
			workspaceID, string(status), afterExpiry, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var (
				summary             app.InvitationSummary
				role, rowStatus     string
				expiresAt, issuedAt time.Time
			)
			if err := rows.Scan(&summary.InvitationID, &summary.SubjectID,
				&summary.InvitedBy, &role, &rowStatus, &expiresAt, &issuedAt); err != nil {
				return err
			}
			summary.Role = contract.MemberRole(role)
			summary.Status = domain.InvitationStatus(rowStatus)
			summary.ExpiresAt = expiresAt.UTC()
			summary.IssuedAt = issuedAt.UTC()
			out = append(out, summary)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("workspace: listing invitations for %s: %w", workspaceID, err)
	}
	return out, nil
}

// DueReads is the sweep's work list.
//
// A SYSTEM transaction, unlike every other read of this table. The sweep asks
// "which invitations anywhere have run out", and a seat held by a lapsed
// invitation is held whether or not anybody is looking at that tenant — a
// tenant-scoped sweep would free only the organizations somebody happened to
// visit, which is the same as not having one.
//
// invitation_view carries row security, so this is precisely the read that the
// policy would otherwise return nothing for, silently, and the sweep would
// report a clean system forever.
type DueReads struct{ system db.SystemTX }

var _ app.DueInvitations = (*DueReads)(nil)

func NewDueReads(system db.SystemTX) (*DueReads, error) {
	if system == nil {
		return nil, fmt.Errorf("workspace: a system transaction source is required; the " +
			"sweep spans every tenant")
	}
	return &DueReads{system: system}, nil
}

// ListDue returns pending invitations whose deadline has passed.
func (r *DueReads) ListDue(
	ctx context.Context, deadline time.Time, limit int,
) ([]app.DueInvitation, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("workspace: a sweep batch of %d would scan nothing", limit)
	}
	if limit > math.MaxInt32 {
		return nil, fmt.Errorf("workspace: a sweep batch of %d does not fit a query limit", limit)
	}

	var out []app.DueInvitation
	err := r.system.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Query(ctx, workspacedb.ListDueInvitations,
			deadline.UTC(), int32(limit)) //nolint:gosec // bounded above
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var due app.DueInvitation
			var expiresAt time.Time
			if err := rows.Scan(&due.InvitationID, &due.OrgID,
				&due.WorkspaceID, &expiresAt); err != nil {
				return err
			}
			due.ExpiresAt = expiresAt.UTC()
			out = append(out, due)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("workspace: listing due invitations: %w", err)
	}
	return out, nil
}

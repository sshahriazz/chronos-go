// Package postgres is workspace's read-model adapter.
package postgres

import (
	"context"
	"fmt"

	workspacedb "github.com/chronos/chronos-go/gen/sqlc/workspace"
	"github.com/chronos/chronos-go/internal/platform/db"
)

// Membership counts what the seat rule turns on.
type Membership struct{ tx db.TX }

func NewMembership(tx db.TX) (*Membership, error) {
	if tx == nil {
		return nil, fmt.Errorf("workspace: a transaction source is required")
	}
	return &Membership{tx: tx}, nil
}

// WorkspaceCount is how many workspaces of this organization the person is in.
//
// # Why a TENANT transaction and not a system one
//
// Gate 1 has already resolved the scope by the time any use case calls this, so
// the ordinary rule applies: every query runs in a transaction opened with
// `SET LOCAL app.workspace_id` (ADR-011), reads included. The row security
// policy on `workspace_member_view` then makes another organization's rows
// invisible rather than merely unmatched — which matters here because the answer
// is a COUNT, and a count is the one shape where a missing filter produces a
// plausible number instead of an empty result.
func (m *Membership) WorkspaceCount(ctx context.Context, orgID, subjectID string) (int, error) {
	if orgID == "" || subjectID == "" {
		return 0, fmt.Errorf("workspace: counting memberships needs both an organization " +
			"and a subject")
	}
	var n int64
	err := m.tx.InTenantTx(ctx, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx, workspacedb.CountWorkspaceMemberships, orgID, subjectID).Scan(&n)
	})
	if err != nil {
		return 0, fmt.Errorf("workspace: counting memberships for %s: %w", subjectID, err)
	}
	return int(n), nil
}

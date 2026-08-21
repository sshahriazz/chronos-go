// Package postgres implements organization's read ports against the read model.
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	organizationdb "github.com/chronos/chronos-go/gen/sqlc/organization"
	"github.com/chronos/chronos-go/internal/modules/organization/app"
	"github.com/chronos/chronos-go/internal/modules/organization/domain"
	"github.com/chronos/chronos-go/internal/platform/db"
)

// StatusReader answers gate 3's question from `org_status_view`.
type StatusReader struct{ tx db.TX }

var _ app.StatusReader = (*StatusReader)(nil)

func NewStatusReader(tx db.TX) (*StatusReader, error) {
	if tx == nil {
		return nil, fmt.Errorf("organization: a transaction source is required")
	}
	return &StatusReader{tx: tx}, nil
}

// StatusOf reads one organization's subscription status.
//
// # Why a missing row is an ERROR and not StatusUnknown
//
// Returning the zero status would be tidy and wrong. StatusUnknown denies
// everything, so a missing row and a suspended organization would produce the
// same refusal — and the two have completely different causes. A row that is
// absent means the projection has not caught up with an organization that
// exists, or that RLS hid it because the request is scoped to a different
// tenant. Both are faults worth seeing; neither is a subscription state.
//
// The gate turns any error here into a refusal anyway (it fails closed), so
// nothing is permitted that should not be. What this buys is that the log says
// which of the two happened.
func (r *StatusReader) StatusOf(ctx context.Context, orgID string) (domain.Status, error) {
	if orgID == "" {
		return domain.StatusUnknown, fmt.Errorf("organization: no organization id to read")
	}

	var status string
	// A TENANT transaction, not a system one. The table carries
	// `tenant_isolation`, so the scope is what makes the row visible at all —
	// and reading it under the caller's own scope is what stops this query ever
	// answering with another organization's status (ADR-011).
	err := r.tx.InTenantTx(ctx, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx, organizationdb.GetOrgStatus, orgID).Scan(&status)
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return domain.StatusUnknown, fmt.Errorf("organization: %s has no row in "+
			"org_status_view; either the projection has not caught up or this request is "+
			"scoped to a different tenant", orgID)
	case err != nil:
		return domain.StatusUnknown, fmt.Errorf("organization: reading status: %w", err)
	}
	return domain.Status(status), nil
}

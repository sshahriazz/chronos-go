package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	organizationdb "github.com/chronos/chronos-go/gen/sqlc/organization"
	"github.com/chronos/chronos-go/internal/platform/db"
)

// Membership answers which organizations a subject belongs to.
type Membership struct{ system db.SystemTX }

func NewMembership(system db.SystemTX) (*Membership, error) {
	if system == nil {
		return nil, fmt.Errorf("organization: a system transaction source is required")
	}
	return &Membership{system: system}, nil
}

// ErrNotAMember is the caller naming an organization they do not belong to.
//
// Distinguished from "no such organization" nowhere above this line: gate 1
// answers both as NOT_FOUND, because telling somebody an organization exists but
// is not theirs is an existence oracle (ADR-036).
var ErrNotAMember = errors.New("not a member of that organization")

// RoleIn returns the caller's role, or ErrNotAMember.
//
// # Why a SYSTEM transaction
//
// This runs inside gate 1, whose whole job is to establish the tenant scope — so
// there is no scope yet to run under. `org_member_index` carries no row security
// for exactly that reason (migration 00021), and containment is the query: it
// filters on the subject the authn gate resolved, which no request can name.
func (m *Membership) RoleIn(ctx context.Context, orgID, subjectID string) (string, error) {
	if orgID == "" || subjectID == "" {
		return "", ErrNotAMember
	}
	var role string
	err := m.system.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx, organizationdb.OrgMembership, orgID, subjectID).Scan(&role)
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "", ErrNotAMember
	case err != nil:
		return "", fmt.Errorf("organization: reading membership: %w", err)
	}
	return role, nil
}

// OrgsFor returns every organization a subject belongs to, oldest first.
func (m *Membership) OrgsFor(ctx context.Context, subjectID string) ([]string, error) {
	if subjectID == "" {
		return nil, nil
	}
	var out []string
	err := m.system.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Query(ctx, organizationdb.OrgsForSubject, subjectID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var orgID, role string
			if err := rows.Scan(&orgID, &role); err != nil {
				return err
			}
			out = append(out, orgID)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("organization: listing memberships: %w", err)
	}
	return out, nil
}

// Package postgres provides the pooled, tenant-scoped access path to the read
// model (ADR-011).
package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// VerifyNotPrivileged fails if the connected role can bypass row-level security.
//
// This exists because the failure is invisible. A superuser — which the default
// POSTGRES_USER is — ignores RLS completely: FORCE ROW LEVEL SECURITY removes
// the table-owner exemption but NOT the superuser bypass. Connect as one and
// every policy silently stops applying while every test still passes, because
// the application also scopes its own queries. Layer 3 of ADR-015 is simply
// gone, and nothing says so.
//
// Verified on this stack: as the owner a cross-tenant query returned 2 rows;
// as chronos_app it returned 0.
func VerifyNotPrivileged(ctx context.Context, pool *pgxpool.Pool) error {
	var role string
	var superuser, bypassRLS bool

	err := pool.QueryRow(ctx, `
		SELECT rolname, rolsuper, rolbypassrls
		FROM pg_roles
		WHERE rolname = current_user`).Scan(&role, &superuser, &bypassRLS)
	if err != nil {
		return fmt.Errorf("postgres: checking role privileges: %w", err)
	}

	if superuser || bypassRLS {
		return fmt.Errorf(
			"postgres: the application is connected as %q which has rolsuper=%t rolbypassrls=%t — "+
				"such a role IGNORES row-level security, disabling tenant isolation at the database. "+
				"Connect as POSTGRES_APP_USER instead (ADR-011, ADR-015)",
			role, superuser, bypassRLS)
	}
	return nil
}

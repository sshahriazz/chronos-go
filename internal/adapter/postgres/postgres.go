// Package postgres provides the pooled, tenant-scoped access path to the read
// model (ADR-011).
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPool builds the connection pool every binary uses.
//
// It does NOT connect: the first acquisition does. That is what lets a process
// start while PostgreSQL is still coming up (ADR-010), and it is why a
// malformed DSN — a real configuration error — is the only failure here.
func NewPool(ctx context.Context, dsn string, maxConns int32) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}
	cfg.MaxConns = maxConns
	cfg.MaxConnLifetime = time.Hour
	cfg.HealthCheckPeriod = 30 * time.Second
	return pgxpool.NewWithConfig(ctx, cfg)
}

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
// VerifyRole asserts that a pool connected as the role it was meant to.
//
// # Why this exists beside VerifyNotPrivileged rather than in the caller
//
// The two are the same check pointed at different failures. That one catches a
// connection made as the OWNER, which silently ignores row-level security. This
// one catches a connection made as the WRONG NON-OWNER — specifically
// cmd/operator connecting as chronos_app, which would compile, connect, and
// hand the operator plane every tenant table (ADR-024, migration 00037).
//
// It lives here because this file is the SQL carve-out: CONVENTIONS §8 keeps
// SQL out of Go source, and the exception is the handful of statements that
// are about the CONNECTION rather than about data — there is no sqlc query for
// "who am I", because it reads no table this schema owns.
func VerifyRole(ctx context.Context, pool *pgxpool.Pool, want string) error {
	var got string
	if err := pool.QueryRow(ctx, `SELECT current_user`).Scan(&got); err != nil {
		return fmt.Errorf("postgres: reading the connected role: %w", err)
	}
	if got != want {
		return fmt.Errorf(
			"postgres: connected as %q, not %q — the grants in effect are that role's, "+
				"not the ones this process was designed against",
			got, want)
	}
	return nil
}

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

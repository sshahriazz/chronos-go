package db

import "context"

// Querier is what generated query code is bound to. It is satisfied by a
// transaction, never by a bare pool: there is no way to reach the database
// outside a transaction, because outside a transaction there is no SET LOCAL
// and therefore no RLS scope.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (int64, error)
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) Row
}

// Rows and Row keep the kernel free of a driver type (ADR-001).
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Close()
	Err() error
}

type Row interface {
	Scan(dest ...any) error
}

// TX runs tenant-scoped work.
//
// There is deliberately no method here that runs a query without a scope. The
// escape hatch for genuinely cross-tenant work is SystemTX, which is separately
// named so it is visible in review and greppable in audit.
type TX interface {
	// InTenantTx opens a transaction, applies the tenant scope from ctx via
	// SET LOCAL, and runs fn. It fails with ErrNoTenant if the context carries
	// no scope.
	InTenantTx(ctx context.Context, fn func(context.Context, Querier) error) error
}

// SystemTX runs work that legitimately spans tenants: projectors writing rows
// for every tenant, retention sweeps, reconciliation.
//
// It is a separate interface so that using it is a deliberate, reviewable act.
// A projector sets the tenant scope per event rather than bypassing RLS
// wholesale, so even projections are written under policy (organization.md §5.4).
type SystemTX interface {
	InSystemTx(ctx context.Context, fn func(context.Context, Querier) error) error
}

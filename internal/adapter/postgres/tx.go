package postgres

import (
	"context"
	"fmt"

	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DB is the tenant-scoped access path (ADR-011).
//
// It exposes no way to run a query outside a transaction, because outside a
// transaction there is no SET LOCAL and therefore no RLS scope.
type DB struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *DB { return &DB{pool: pool} }

var (
	_ db.TX       = (*DB)(nil)
	_ db.SystemTX = (*DB)(nil)
)

// InTenantTx opens a transaction, applies the tenant scope, and runs fn.
//
// SET LOCAL — not SET. SET would persist on the pooled connection after the
// transaction ends and be inherited by whoever borrows it next, which is a
// cross-tenant read. SET LOCAL is scoped to the transaction and reverts on
// COMMIT or ROLLBACK, so the leak is impossible rather than merely avoided.
func (d *DB) InTenantTx(ctx context.Context, fn func(context.Context, db.Querier) error) error {
	tenant, err := db.RequireTenant(ctx)
	if err != nil {
		return err
	}
	return d.inTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		// set_config(..., true) is SET LOCAL in function form, which lets the
		// values be bound as parameters instead of interpolated into SQL.
		if _, err := tx.Exec(ctx, `
			SELECT set_config('app.org_id',       $1, true),
			       set_config('app.workspace_id', $2, true),
			       set_config('app.user_id',      $3, true),
			       set_config('app.residency',    $4, true)`,
			tenant.OrgID, tenant.WorkspaceID, tenant.UserID, tenant.Residency,
		); err != nil {
			return fmt.Errorf("postgres: applying tenant scope: %w", err)
		}
		return fn(ctx, querier{tx})
	})
}

// InSystemTx runs work that legitimately spans tenants — a projector writing
// rows for every tenant, a retention sweep, reconciliation.
//
// It sets NO tenant scope, so RLS-protected tables return nothing unless the
// caller sets a scope per row. That is the intended discipline: a projector
// knows the org for each event and scopes to it, so even projections are
// written under policy rather than around it.
func (d *DB) InSystemTx(ctx context.Context, fn func(context.Context, db.Querier) error) error {
	return d.inTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return fn(ctx, querier{tx})
	})
}

// SetTenantScope applies a scope inside an already-open system transaction.
//
// The per-event projector path does NOT use this — it scopes through
// InTenantBatch, which queues the scope with the writes so both cost one round
// trip together. This remains for work that legitimately spans tenants inside a
// single transaction, such as a retention sweep.
func SetTenantScope(ctx context.Context, q db.Querier, t db.Tenant) error {
	if err := t.Validate(); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `
		SELECT set_config('app.org_id',       $1, true),
		       set_config('app.workspace_id', $2, true),
		       set_config('app.user_id',      $3, true),
		       set_config('app.residency',    $4, true)`,
		t.OrgID, t.WorkspaceID, t.UserID, t.Residency)
	return err
}

func (d *DB) inTx(ctx context.Context, fn func(context.Context, pgx.Tx) error) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin: %w", err)
	}
	// Rollback after a successful commit is a no-op, so this is safe and means
	// no path can leave a transaction open.
	defer func() { _ = tx.Rollback(ctx) }()

	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit: %w", err)
	}
	return nil
}

// querier adapts pgx to the kernel's driver-free interface (ADR-001).
type querier struct{ tx pgx.Tx }

func (q querier) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	tag, err := q.tx.Exec(ctx, sql, args...)
	return tag.RowsAffected(), err
}

func (q querier) Query(ctx context.Context, sql string, args ...any) (db.Rows, error) {
	rows, err := q.tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgxRows{rows}, nil
}

func (q querier) QueryRow(ctx context.Context, sql string, args ...any) db.Row {
	return q.tx.QueryRow(ctx, sql, args...)
}

type pgxRows struct{ rows pgx.Rows }

func (r pgxRows) Next() bool             { return r.rows.Next() }
func (r pgxRows) Scan(dest ...any) error { return r.rows.Scan(dest...) }
func (r pgxRows) Close()                 { r.rows.Close() }
func (r pgxRows) Err() error             { return r.rows.Err() }

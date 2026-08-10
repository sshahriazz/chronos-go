//go:build integration

package postgres_test

import (
	"context"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/db"
)

// The batch path establishes tenant scope differently from the transaction
// path: `set_config(..., true)` inside an IMPLICIT transaction, created by a
// pipelined batch with one trailing Sync, rather than `SET LOCAL` inside an
// explicit BEGIN/COMMIT.
//
// That difference is why this test exists separately. The no-leak property was
// asserted for InTenantTx and ASSUMED for InTenantBatch — and the batch is the
// hot path, running once per projected event. A leak here is a cross-tenant
// breach on a pooled connection, not a style issue (ADR-011).
//
// The pool is capped at one connection, so the second operation is guaranteed to
// borrow the same connection the batch used.
func TestInTenantBatch_ScopeDoesNotLeakToTheNextUser(t *testing.T) {
	_, d := newDB(t)
	ctx := context.Background()

	if err := d.InTenantBatch(ctx, tenant("org_batch_leak", "ws_1"), db.Replayable,
		func(w db.Writer) error {
			w.Exec(`INSERT INTO tenant_probe (id, org_id, workspace_id, label)
			        VALUES ($1,$2,$3,$4)
			        ON CONFLICT (id) DO NOTHING`,
				"tp_batch_leak", "org_batch_leak", "ws_1", "written in a batch")
			return nil
		}); err != nil {
		t.Fatalf("batch: %v", err)
	}

	// Same connection, no scope. If the batch's settings survived it, this reads
	// another tenant's rows.
	var leaked string
	err := d.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx,
			`SELECT coalesce(current_setting('app.org_id', true), '')`).Scan(&leaked)
	})
	if err != nil {
		t.Fatalf("reading settings after the batch: %v", err)
	}
	if leaked != "" {
		t.Fatalf("the batch's tenant scope leaked onto the pooled connection as %q: "+
			"the next borrower of this connection reads another tenant's rows", leaked)
	}

	// And the row really was written under scope, so the test above is not
	// passing merely because nothing happened.
	var seen int
	if err := d.InTenantTx(db.WithTenant(ctx, tenant("org_batch_leak", "ws_1")),
		func(ctx context.Context, q db.Querier) error {
			return q.QueryRow(ctx,
				`SELECT count(*) FROM tenant_probe WHERE id = 'tp_batch_leak'`).Scan(&seen)
		}); err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if seen != 1 {
		t.Fatalf("the batch wrote no row, so the leak assertion above proves nothing")
	}

	t.Cleanup(func() {
		_ = d.InTenantTx(db.WithTenant(context.Background(), tenant("org_batch_leak", "ws_1")),
			func(ctx context.Context, q db.Querier) error {
				_, err := q.Exec(ctx, `DELETE FROM tenant_probe WHERE id = 'tp_batch_leak'`)
				return err
			})
	})
}

// A batch carrying no tenant still sets durability, and must not write rows into
// a tenant table — RLS has no scope to satisfy, so the write must be refused
// rather than land unscoped.
func TestInTenantBatch_UnscopedCannotWriteTenantRows(t *testing.T) {
	_, d := newDB(t)

	err := d.InTenantBatch(context.Background(), db.Tenant{}, db.Replayable,
		func(w db.Writer) error {
			w.Exec(`INSERT INTO tenant_probe (id, org_id, workspace_id, label)
			        VALUES ($1,$2,$3,$4)`,
				"tp_unscoped", "org_x", "ws_x", "should never land")
			return nil
		})
	if err == nil {
		t.Fatal("an unscoped batch wrote a row into a tenant-scoped table")
	}
}

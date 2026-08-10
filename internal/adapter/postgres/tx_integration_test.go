//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/jackc/pgx/v5/pgxpool"
)

func appDSN() string {
	if v := os.Getenv("APP_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://chronos_app:chronos_app_dev_password@localhost:5432/chronos?sslmode=disable"
}

func newDB(t *testing.T) (*pgxpool.Pool, *pgadapter.DB) {
	t.Helper()
	// MaxConns=1 forces every transaction onto the SAME connection, which is
	// what makes the leak test below meaningful.
	cfg, err := pgxpool.ParseConfig(appDSN())
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool, pgadapter.New(pool)
}

func tenant(org, ws string) db.Tenant {
	return db.Tenant{OrgID: org, WorkspaceID: ws, UserID: "usr_test", Residency: "eu"}
}

func TestAppRoleCannotBypassRLS(t *testing.T) {
	pool, _ := newDB(t)
	if err := pgadapter.VerifyNotPrivileged(context.Background(), pool); err != nil {
		t.Fatalf("the application role must not be privileged: %v", err)
	}
}

func TestInTenantTx_RefusesWithoutScope(t *testing.T) {
	_, d := newDB(t)
	err := d.InTenantTx(context.Background(), func(context.Context, db.Querier) error {
		t.Fatal("the callback must never run without a tenant scope")
		return nil
	})
	if !errors.Is(err, db.ErrNoTenant) {
		t.Fatalf("got %v want ErrNoTenant", err)
	}
}

func TestInTenantTx_ScopesReadsAndWrites(t *testing.T) {
	_, d := newDB(t)
	ctx := context.Background()

	seed := func(org, ws, id string) {
		tctx := db.WithTenant(ctx, tenant(org, ws))
		if err := d.InTenantTx(tctx, func(ctx context.Context, q db.Querier) error {
			_, err := q.Exec(ctx, `INSERT INTO tenant_probe (id, org_id, workspace_id, label)
				VALUES ($1,$2,$3,$4) ON CONFLICT (id) DO NOTHING`, id, org, ws, "row "+id)
			return err
		}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	seed("org_X", "ws_X", "x1")
	seed("org_Y", "ws_Y", "y1")

	count := func(org, ws string) int {
		var n int
		tctx := db.WithTenant(ctx, tenant(org, ws))
		if err := d.InTenantTx(tctx, func(ctx context.Context, q db.Querier) error {
			return q.QueryRow(ctx, `SELECT count(*) FROM tenant_probe`).Scan(&n)
		}); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}

	if got := count("org_X", "ws_X"); got != 1 {
		t.Errorf("org_X should see exactly its own row, got %d", got)
	}
	if got := count("org_Y", "ws_Y"); got != 1 {
		t.Errorf("org_Y should see exactly its own row, got %d", got)
	}
	// ADR-020: org_id AND workspace_id are both checked, so a workspace id
	// borrowed from another tenant resolves to nothing.
	if got := count("org_X", "ws_Y"); got != 0 {
		t.Errorf("a forged workspace_id must resolve to nothing, got %d", got)
	}
}

// The reason SET LOCAL exists. With a single pooled connection, a scope set by
// one transaction must not survive into the next.
func TestScopeDoesNotLeakAcrossTransactions(t *testing.T) {
	_, d := newDB(t)
	ctx := context.Background()

	if err := d.InTenantTx(db.WithTenant(ctx, tenant("org_X", "ws_X")),
		func(ctx context.Context, q db.Querier) error {
			var org string
			return q.QueryRow(ctx, `SELECT current_setting('app.org_id', true)`).Scan(&org)
		}); err != nil {
		t.Fatalf("first tx: %v", err)
	}

	// Same connection (MaxConns=1), new transaction, no scope applied.
	var leaked string
	if err := d.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx, `SELECT coalesce(current_setting('app.org_id', true), '')`).Scan(&leaked)
	}); err != nil {
		t.Fatalf("second tx: %v", err)
	}
	if leaked != "" {
		t.Fatalf("tenant scope LEAKED across transactions on a pooled connection: %q. "+
			"This is a cross-tenant read; SET LOCAL is not being used.", leaked)
	}
}

// A system transaction sets no scope, so RLS-protected tables return nothing
// until the caller scopes per row.
func TestInSystemTx_SeesNothingUntilScoped(t *testing.T) {
	_, d := newDB(t)
	ctx := context.Background()

	var unscoped, scoped int
	err := d.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		if err := q.QueryRow(ctx, `SELECT count(*) FROM tenant_probe`).Scan(&unscoped); err != nil {
			return err
		}
		if err := pgadapter.SetTenantScope(ctx, q, tenant("org_X", "ws_X")); err != nil {
			return err
		}
		return q.QueryRow(ctx, `SELECT count(*) FROM tenant_probe`).Scan(&scoped)
	})
	if err != nil {
		t.Fatalf("system tx: %v", err)
	}
	if unscoped != 0 {
		t.Errorf("an unscoped system tx must see nothing in an RLS table, got %d", unscoped)
	}
	if scoped != 1 {
		t.Errorf("after scoping it must see that tenant's rows, got %d", scoped)
	}
}

func TestInTenantTx_RollsBackOnError(t *testing.T) {
	_, d := newDB(t)
	ctx := db.WithTenant(context.Background(), tenant("org_Z", "ws_Z"))
	boom := errors.New("boom")

	err := d.InTenantTx(ctx, func(ctx context.Context, q db.Querier) error {
		if _, err := q.Exec(ctx, `INSERT INTO tenant_probe (id, org_id, workspace_id, label)
			VALUES ('z1','org_Z','ws_Z','doomed')`); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("got %v want boom", err)
	}

	var n int
	if err := d.InTenantTx(ctx, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx, `SELECT count(*) FROM tenant_probe WHERE id='z1'`).Scan(&n)
	}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if n != 0 {
		t.Fatal("a failing callback must roll the transaction back")
	}
}

func TestMain(m *testing.M) {
	fmt.Println("integration: requires postgres + migrations (make up && make migrate)")
	os.Exit(m.Run())
}

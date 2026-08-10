//go:build integration

package postgres_test

import (
	"context"
	"testing"
	"time"

	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/jackc/pgx/v5/pgxpool"
)

func poolWith(t *testing.T, maxConns int32) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(appDSN())
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = maxConns
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// A Postgres advisory lock is bound to its connection, so a held lease pins one
// for the life of the projection. Sharing the work pool with leases means N
// projections consume N connections, and at N = MaxConns nothing can run at all.
//
// This test pins the SEPARATION: leases come from their own pool, and the work
// pool stays fully available no matter how many leases are held.
func TestLeasesDoNotStarveTheWorkPool(t *testing.T) {
	leasePool := poolWith(t, 4)
	workPool := poolWith(t, 4)

	lease := pgadapter.NewLease(leasePool)
	work := pgadapter.New(workPool)
	ctx := context.Background()

	// Pin every connection in the lease pool.
	for i := range 4 {
		rel, held, err := lease.Acquire(ctx, "starve_probe_"+string(rune('a'+i)))
		if err != nil || !held {
			t.Fatalf("lease %d: held=%v err=%v", i, held, err)
		}
		defer rel(ctx)
	}

	// The work pool must be entirely unaffected.
	timed, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for i := range 4 {
		err := work.InSystemTx(timed, func(ctx context.Context, q db.Querier) error {
			var n int
			return q.QueryRow(ctx, `SELECT 1`).Scan(&n)
		})
		if err != nil {
			t.Fatalf("query %d failed while leases were held: %v — "+
				"leases and work are sharing a pool again, which deadlocks at "+
				"projections = MaxConns", i, err)
		}
	}
}

// Two Lease instances on different pools must still exclude each other: the
// lock lives in the server, not in the process.
func TestLeaseIsExclusiveAcrossPools(t *testing.T) {
	a := pgadapter.NewLease(poolWith(t, 2))
	b := pgadapter.NewLease(poolWith(t, 2))
	ctx := context.Background()

	rel, held, err := a.Acquire(ctx, "exclusive_probe")
	if err != nil || !held {
		t.Fatalf("first acquire: held=%v err=%v", held, err)
	}

	_, held2, err := b.Acquire(ctx, "exclusive_probe")
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if held2 {
		rel(ctx)
		t.Fatal("two holders of one projection lease: both would write the same rows")
	}

	rel(ctx)

	// Once released, the other side can take it — this is how failover works.
	rel2, held3, err := b.Acquire(ctx, "exclusive_probe")
	if err != nil || !held3 {
		t.Fatalf("after release the lease must be available: held=%v err=%v", held3, err)
	}
	rel2(ctx)
}

// Release must be idempotent: advisory locks are counted per session, so a
// second unlock would surrender a lock this process may have re-acquired.
func TestLeaseReleaseIsIdempotent(t *testing.T) {
	pool := poolWith(t, 2)
	lease := pgadapter.NewLease(pool)
	ctx := context.Background()

	rel, held, err := lease.Acquire(ctx, "idempotent_probe")
	if err != nil || !held {
		t.Fatalf("acquire: held=%v err=%v", held, err)
	}
	rel(ctx)
	rel(ctx)
	rel(ctx)

	rel2, held2, err := lease.Acquire(ctx, "idempotent_probe")
	if err != nil || !held2 {
		t.Fatalf("the lease was not cleanly released: held=%v err=%v", held2, err)
	}
	rel2(ctx)
}

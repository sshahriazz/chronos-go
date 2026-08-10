//go:build integration

package projectionit_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Can we collapse the five round trips into one WITHOUT giving up atomicity?
//
// pgx SendBatch pipelines every queued statement in a single packet with one
// trailing Sync, which PostgreSQL executes as an implicit transaction. This
// test is the load-bearing question: if a later statement fails, is an earlier
// one rolled back? If not, batching is off the table — a projection could
// commit rows without its checkpoint, which is the one failure mode the whole
// design exists to prevent.
func TestBatchIsAtomic(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	org, ws := "org_"+h.suffix, "ws_"+h.suffix
	id := h.suffix + "_batch"

	conn, err := h.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()

	b := &pgx.Batch{}
	b.Queue(`SELECT set_config('app.org_id',$1,true), set_config('app.workspace_id',$2,true),
	                set_config('app.user_id','',true), set_config('app.residency','eu',true)`, org, ws)
	b.Queue(`INSERT INTO projection_probe (id, org_id, workspace_id, name, revision)
	         VALUES ($1,$2,$3,'should not survive',1)`, id, org, ws)
	// The failure must happen at EXECUTION, not at prepare. A bad column name
	// is rejected while the batch is being prepared, before any statement runs,
	// which would make this test pass without proving anything about rollback.
	// A CHECK violation is well-formed SQL that fails only when it executes.
	b.Queue(`INSERT INTO projection_checkpoint (name, commit_position, prepare_position)
	         VALUES ($1, -1, -1)`, h.viewName)

	res := conn.SendBatch(ctx, b)
	var batchErr error
	for range 3 {
		if _, err := res.Exec(); err != nil && batchErr == nil {
			batchErr = err
		}
	}
	if err := res.Close(); err != nil && batchErr == nil {
		batchErr = err
	}
	if batchErr == nil {
		t.Fatal("the failing statement did not fail")
	}
	t.Logf("batch failed as expected: %v", batchErr)
	if strings.Contains(batchErr.Error(), "preprocessing batch") {
		t.Fatalf("the batch failed during PREPARE, so nothing executed and this "+
			"test proves nothing about rollback: %v", batchErr)
	}

	if got := h.rows(t, org, ws); len(got) != 0 {
		t.Fatalf("BATCH IS NOT ATOMIC: %d row(s) survived a failed batch. "+
			"Pipelining would let rows commit without their checkpoint.", len(got))
	}
}

// And the happy path: does a single batched round trip actually persist?
func TestBatchCommits(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	org, ws := "org_"+h.suffix, "ws_"+h.suffix

	conn, err := h.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()

	b := &pgx.Batch{}
	b.Queue(`SELECT set_config('app.org_id',$1,true), set_config('app.workspace_id',$2,true),
	                set_config('app.user_id','',true), set_config('app.residency','eu',true)`, org, ws)
	b.Queue(`INSERT INTO projection_probe (id, org_id, workspace_id, name, revision)
	         VALUES ($1,$2,$3,'batched',1) ON CONFLICT (id) DO NOTHING`, h.suffix+"_ok", org, ws)
	b.Queue(`INSERT INTO projection_checkpoint (name, commit_position, prepare_position, events_processed)
	         VALUES ($1,1,1,1) ON CONFLICT (name) DO UPDATE SET commit_position = 1`, h.viewName)

	res := conn.SendBatch(ctx, b)
	for range 3 {
		if _, err := res.Exec(); err != nil {
			t.Fatalf("batch exec: %v", err)
		}
	}
	if err := res.Close(); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("batch close: %v", err)
	}

	if got := h.rows(t, org, ws); len(got) != 1 {
		t.Fatalf("batched write produced %d rows, want 1", len(got))
	}
}

// The number that decides whether this is worth doing: one round trip instead
// of five, same atomicity.
func BenchmarkProjectOneEventBatched(b *testing.B) {
	h := newHarness(b)
	ctx := context.Background()
	org, ws := "org_"+h.suffix, "ws_"+h.suffix
	id := h.suffix + "_bench"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := h.pool.Acquire(ctx)
		if err != nil {
			b.Fatal(err)
		}
		batch := &pgx.Batch{}
		batch.Queue(`SELECT set_config('app.org_id',$1,true), set_config('app.workspace_id',$2,true),
		                    set_config('app.user_id','',true), set_config('app.residency','eu',true)`, org, ws)
		batch.Queue(`INSERT INTO projection_probe (id, org_id, workspace_id, name, revision, updated_at)
		             VALUES ($1,$2,$3,'benchmark',1,now())
		             ON CONFLICT (id) DO UPDATE SET revision = EXCLUDED.revision, updated_at = EXCLUDED.updated_at`,
			id, org, ws)
		batch.Queue(`INSERT INTO projection_checkpoint (name, commit_position, prepare_position, events_processed, updated_at)
		             VALUES ($1,1,1,1,now())
		             ON CONFLICT (name) DO UPDATE SET commit_position = 1, updated_at = now()`, h.viewName)

		res := conn.SendBatch(ctx, batch)
		for range 3 {
			if _, err := res.Exec(); err != nil {
				b.Fatal(err)
			}
		}
		if err := res.Close(); err != nil {
			b.Fatal(err)
		}
		conn.Release()
	}
}

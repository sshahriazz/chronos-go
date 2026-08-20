//go:build integration

package projectionit_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// The number a user actually experiences: from "the command committed" to "the
// change is visible in the read model".
//
// Throughput is the wrong question for a control plane — nobody invites 7,000
// members a second. This is the right one, because every screen in the product
// reads a projection, and a stale projection is a user watching a spinner after
// clicking Save.
func TestEndToEndLag(t *testing.T) {
	h := newHarness(t)
	org, ws := "org_"+h.suffix, "ws_"+h.suffix
	ctx := db.WithTenant(context.Background(), db.Tenant{
		OrgID: org, WorkspaceID: ws, UserID: "usr_test", Residency: "eu",
	})

	// Start the projector and let it catch up to live before timing anything:
	// measuring while it is still replaying history would measure the replay.
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := projection.NewRunner(newProbeView(h.viewName, h.category, h.codec), h.deps())
	done := make(chan error, 1)
	go func() { done <- r.Run(runCtx) }()

	h.append(t, "warmup", org, ws, ThingRecorded{ID: h.suffix + "_warm", Name: "warm"}, 0)
	waitForRow(t, h, ctx, h.suffix+"_warm", 30*time.Second)

	const samples = 40
	lags := make([]time.Duration, 0, samples)
	for i := range samples {
		id := h.suffix + "_lag" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		start := time.Now()
		h.append(t, "lag", org, ws, ThingRecorded{ID: id, Name: "lag"}, i+1)
		waitForRow(t, h, ctx, id, 30*time.Second)
		lags = append(lags, time.Since(start))
	}
	cancel()
	<-done

	slices.Sort(lags)
	p50 := lags[len(lags)/2]
	p95 := lags[len(lags)*95/100]
	worst := lags[len(lags)-1]

	t.Logf("append → visible in the read model over %d samples: p50=%v p95=%v max=%v",
		samples, p50.Round(time.Microsecond), p95.Round(time.Microsecond), worst.Round(time.Microsecond))

	// Not a performance assertion — a regression tripwire. Anything approaching
	// a second means the pipeline has stalled, not merely slowed.
	if p95 > time.Second {
		t.Errorf("p95 propagation lag is %v; the read model is not keeping up with the log", p95)
	}
}

// waitForRow polls the read model through the ordinary tenant-scoped path.
func waitForRow(t *testing.T, h *harness, ctx context.Context, id string, limit time.Duration) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		var n int
		err := h.pg.InTenantTx(ctx, func(ctx context.Context, q db.Querier) error {
			return q.QueryRow(ctx, `SELECT count(*) FROM projection_probe WHERE id = $1`, id).Scan(&n)
		})
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if n == 1 {
			return
		}
		time.Sleep(200 * time.Microsecond)
	}
	t.Fatalf("row %q never appeared within %v", id, limit)
}

// Append latency is what a command handler pays before it can answer the user.
func BenchmarkAppendEvent(b *testing.B) {
	h := newHarness(b)
	ctx := context.Background()
	stream, err := eventsourcing.NewStreamID(h.category, "bench_"+h.suffix)
	if err != nil {
		b.Fatal(err)
	}
	meta := eventsourcing.Metadata{
		SchemaVersion: 1, OrgID: "org_" + h.suffix, WorkspaceID: "ws_" + h.suffix,
		Residency: "eu", OccurredAt: time.Now().UTC(),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := h.store.Append(ctx, stream, eventsourcing.AnyRevision(),
			[]eventsourcing.PendingEvent{{
				ID:    eventsourcing.DeriveEventID(h.suffix+"bench", i),
				Event: &ThingRecorded{ID: "x", Name: "bench"},
				Meta:  meta,
			}})
		if err != nil {
			b.Fatal(err)
		}
	}
}

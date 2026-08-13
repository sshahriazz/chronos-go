//go:build integration

// Package projectionit holds the end-to-end proof of the projection pipeline.
//
// It lives outside both adapters on purpose: the property under test — an event
// appended to KurrentDB becomes a Postgres row, under the right tenant, with a
// checkpoint that commits alongside it — spans two adapters and the kernel, and
// no single package owns it.
package projectionit_test

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	kurrentadapter "github.com/chronos/chronos-go/internal/adapter/kurrentdb"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/projection"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ---------------------------------------------------------------------------
// the projection under test
// ---------------------------------------------------------------------------

// ThingRecorded is a domain fact in the shape a real one has: a plain struct
// with no wire concerns beyond the tags its codec needs.
type ThingRecorded struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (*ThingRecorded) EventType() string { return "probe.ThingRecorded.v1" }

// probeView projects ThingRecorded into projection_probe.
type probeView struct {
	name     string
	category eventsourcing.Category
	dispatch *projection.Dispatch
}

func newProbeView(name string, category eventsourcing.Category, codec eventsourcing.Codec) *probeView {
	d := projection.NewDispatch(codec)
	projection.On[ThingRecorded](d, func(
		ctx context.Context, w db.Writer, env projection.Envelope, e *ThingRecorded,
	) error {
		// Upsert, not insert. A projector is replayed on restart and on
		// rebuild, so the same event WILL arrive twice; an insert would fail
		// the second time and stall the projection forever.
		w.Exec(`
			INSERT INTO projection_probe (id, org_id, workspace_id, name, revision, updated_at)
			VALUES ($1, $2, $3, $4, $5, now())
			ON CONFLICT (id) DO UPDATE SET
				name       = EXCLUDED.name,
				revision   = EXCLUDED.revision,
				updated_at = EXCLUDED.updated_at`,
			e.ID, env.Meta.OrgID, env.Meta.WorkspaceID, e.Name, int64(env.Revision))
		return nil
	})
	return &probeView{name: name, category: category, dispatch: d}
}

func (p *probeView) Name() string { return p.name }

func (p *probeView) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{StreamPrefixes: []string{string(p.category) + "-"}}
}

func (p *probeView) Apply(ctx context.Context, w db.Writer, env projection.Envelope) error {
	return p.dispatch.Apply(ctx, w, env)
}

func (p *probeView) Reset(ctx context.Context, q db.Querier) error {
	// See migration 00002: DELETE from an unscoped system transaction would
	// remove nothing, because RLS hides every row from it.
	_, err := q.Exec(ctx, `TRUNCATE TABLE projection_probe`)
	return err
}

// ---------------------------------------------------------------------------
// the test
// ---------------------------------------------------------------------------

type row struct {
	id, org, workspace, name string
	revision                 int64
}

func TestProjectionPipeline(t *testing.T) {
	h := newHarness(t)

	orgA := "org_" + h.suffix + "a"
	orgB := "org_" + h.suffix + "b"
	wsA := "ws_" + h.suffix + "a"
	wsB := "ws_" + h.suffix + "b"

	// Two orgs, so the per-event tenant scoping is exercised rather than
	// assumed. Six events across four streams.
	appended := []struct {
		stream         string
		org, workspace string
		thing          ThingRecorded
	}{
		{"s1", orgA, wsA, ThingRecorded{ID: h.suffix + "_1", Name: "alpha"}},
		{"s1", orgA, wsA, ThingRecorded{ID: h.suffix + "_2", Name: "beta"}},
		{"s2", orgA, wsA, ThingRecorded{ID: h.suffix + "_3", Name: "gamma"}},
		{"s3", orgB, wsB, ThingRecorded{ID: h.suffix + "_4", Name: "delta"}},
		{"s3", orgB, wsB, ThingRecorded{ID: h.suffix + "_5", Name: "epsilon"}},
		{"s4", orgB, wsB, ThingRecorded{ID: h.suffix + "_6", Name: "zeta"}},
	}
	for i, a := range appended {
		h.append(t, a.stream, a.org, a.workspace, a.thing, i)
	}

	// --- 1. events reach Postgres -----------------------------------------
	h.runUntil(t, 6)

	first := h.rows(t, orgA, wsA)
	if len(first) != 3 {
		t.Fatalf("org A projected %d rows, want 3", len(first))
	}
	if got := len(h.rows(t, orgB, wsB)); got != 3 {
		t.Fatalf("org B projected %d rows, want 3", got)
	}
	if first[0].name != "alpha" || first[2].name != "gamma" {
		t.Errorf("rows out of order or wrong: %+v", first)
	}

	// --- 2. the checkpoint advanced ----------------------------------------
	cp := h.checkpoint(t)
	if cp.EventsProcessed != 6 {
		t.Errorf("checkpoint records %d events, want 6", cp.EventsProcessed)
	}
	if cp.Position.Commit == 0 {
		t.Error("checkpoint position is still zero after projecting six events")
	}

	// --- 3. a restart does not replay the log ------------------------------
	before := h.subscribeCalls()
	h.runFor(t, 300*time.Millisecond)
	if got := h.checkpoint(t).EventsProcessed; got != 6 {
		t.Errorf("a restart reprocessed events: counter is %d, want 6", got)
	}
	if h.subscribeCalls() == before {
		t.Error("the restart never subscribed, so this proved nothing")
	}

	// --- 4. rebuild from zero reproduces the same rows ----------------------
	h.rebuild(t, 6)

	rebuilt := h.rows(t, orgA, wsA)
	if len(rebuilt) != len(first) {
		t.Fatalf("rebuild produced %d rows for org A, want %d", len(rebuilt), len(first))
	}
	for i := range first {
		if first[i] != rebuilt[i] {
			t.Errorf("row %d differs after rebuild:\n  before %+v\n  after  %+v", i, first[i], rebuilt[i])
		}
	}
	if got := h.checkpoint(t).EventsProcessed; got != 6 {
		t.Errorf("after a rebuild the counter is %d, want 6", got)
	}

	// --- 5. cross-tenant reads still return nothing -------------------------
	if got := h.rows(t, orgA, wsB); len(got) != 0 {
		t.Errorf("org A with org B's workspace read %d rows; RLS did not hold on projected data", len(got))
	}
}

// A projection that fails on an event must stop rather than skip it: a skipped
// event is a read model that is permanently, silently wrong.
func TestProjectorStopsOnApplyFailure(t *testing.T) {
	h := newHarness(t)
	org := "org_" + h.suffix + "f"
	ws := "ws_" + h.suffix + "f"
	h.append(t, "s1", org, ws, ThingRecorded{ID: h.suffix + "_f1", Name: "before"}, 0)

	broken := &brokenView{probeView: newProbeView(h.viewName, h.category, h.codec)}
	r := projection.NewRunner(broken, h.deps())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := r.Run(ctx)
	if err == nil {
		t.Fatal("the runner returned cleanly after the projection rejected an event")
	}

	if got := h.checkpoint(t); got.EventsProcessed != 0 {
		t.Errorf("the checkpoint advanced past a failed event: %+v", got)
	}
	if got := h.rows(t, org, ws); len(got) != 0 {
		t.Errorf("the failed transaction left %d rows behind", len(got))
	}
}

type brokenView struct{ *probeView }

func (b *brokenView) Apply(context.Context, db.Writer, projection.Envelope) error {
	return errors.New("column \"nope\" does not exist")
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

type harness struct {
	pool     *pgxpool.Pool
	pg       *pgadapter.DB
	store    *kurrentadapter.Store
	codec    *eventcodec.JSON
	sub      *countingSubscriber
	suffix   string
	category eventsourcing.Category
	viewName string
}

// newHarness takes testing.TB so benchmarks and tests share one setup path
// rather than growing a second, subtly different copy.
func newHarness(t testing.TB) *harness {
	t.Helper()

	// A per-run suffix isolates streams, orgs and the checkpoint, so runs do not
	// see each other's events through the $all subscription.
	var b [4]byte
	if _, err := io.ReadFull(ids.Entropy(), b[:]); err != nil {
		t.Fatalf("entropy: %v", err)
	}
	suffix := hex.EncodeToString(b[:])

	cfg, err := pgxpool.ParseConfig(appDSN())
	if err != nil {
		t.Fatalf("dsn: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	codec := eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry())
	eventcodec.Register[ThingRecorded](codec)

	client, err := kurrentadapter.Dial(kurrentDSN())
	if err != nil {
		t.Fatalf("kurrentdb: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	h := &harness{
		pool:     pool,
		pg:       pgadapter.New(pool),
		store:    kurrentadapter.NewStore(client, codec),
		codec:    codec,
		suffix:   suffix,
		category: eventsourcing.Category("probe" + suffix),
		viewName: "probe_view_" + suffix,
	}
	h.sub = &countingSubscriber{inner: h.store}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.pg.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
			_, _ = q.Exec(ctx, `DELETE FROM projection_checkpoint WHERE name = $1`, h.viewName)
			return nil
		})
	})
	return h
}

func (h *harness) deps() projection.Deps {
	return projection.Deps{
		Subscriber:     h.sub,
		Codec:          h.codec,
		Categories:     h.store,
		Types:          h.store,
		Batch:          h.pg,
		TX:             h.pg,
		Checkpoints:    pgadapter.Checkpoints{},
		Lease:          pgadapter.NewLease(h.pool),
		Clock:          clock.System{},
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Holder:         "integration-test",
		LeaseRetry:     50 * time.Millisecond,
		SubscribeRetry: 50 * time.Millisecond,
	}
}

func (h *harness) append(t *testing.T, key, org, workspace string, e ThingRecorded, seq int) {
	t.Helper()
	stream, err := eventsourcing.NewStreamID(h.category, key+"_"+h.suffix)
	if err != nil {
		t.Fatalf("stream id: %v", err)
	}
	_, err = h.store.Append(context.Background(), stream, eventsourcing.AnyRevision(),
		[]eventsourcing.PendingEvent{{
			ID:    eventsourcing.DeriveEventID(h.suffix, seq),
			Event: &e,
			Meta: eventsourcing.Metadata{
				SchemaVersion: 1,
				OccurredAt:    time.Now().UTC(),
				OrgID:         org,
				WorkspaceID:   workspace,
				Residency:     "eu",
			},
		}})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
}

// runUntil starts the projector and stops it once the checkpoint reports the
// expected number of events, or fails after a deadline.
func (h *harness) runUntil(t *testing.T, want int64) {
	t.Helper()
	r := projection.NewRunner(newProbeView(h.viewName, h.category, h.codec), h.deps())
	h.driveUntil(t, r.Run, want)
}

func (h *harness) rebuild(t *testing.T, want int64) {
	t.Helper()
	r := projection.NewRunner(newProbeView(h.viewName, h.category, h.codec), h.deps())
	h.driveUntil(t, r.Rebuild, want)
}

func (h *harness) driveUntil(t *testing.T, run func(context.Context) error, want int64) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- run(ctx) }()

	deadline := time.After(30 * time.Second)
	for {
		select {
		case err := <-done:
			t.Fatalf("the projector stopped early: %v", err)
		case <-deadline:
			t.Fatalf("timed out: checkpoint reached %d of %d events", h.checkpoint(t).EventsProcessed, want)
		case <-time.After(100 * time.Millisecond):
			if h.checkpoint(t).EventsProcessed >= want {
				cancel()
				select {
				case err := <-done:
					if err != nil && !errors.Is(err, context.Canceled) {
						t.Fatalf("shutdown: %v", err)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("the projector did not stop when cancelled")
				}
				return
			}
		}
	}
}

func (h *harness) runFor(t *testing.T, d time.Duration) {
	t.Helper()
	r := projection.NewRunner(newProbeView(h.viewName, h.category, h.codec), h.deps())
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	if err := r.Run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
}

func (h *harness) checkpoint(t *testing.T) projection.Checkpoint {
	t.Helper()
	var cp projection.Checkpoint
	err := h.pg.InSystemTx(context.Background(), func(ctx context.Context, q db.Querier) error {
		got, err := pgadapter.Checkpoints{}.Load(ctx, q, h.viewName)
		if errors.Is(err, projection.ErrNoCheckpoint) {
			return nil
		}
		cp = got
		return err
	})
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	return cp
}

// rows reads through the ordinary tenant-scoped path, so what the test sees is
// exactly what an application request would see.
func (h *harness) rows(t *testing.T, org, workspace string) []row {
	t.Helper()
	ctx := db.WithTenant(context.Background(), db.Tenant{
		OrgID: org, WorkspaceID: workspace, UserID: "usr_test", Residency: "eu",
	})

	var out []row
	err := h.pg.InTenantTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Query(ctx, `
			SELECT id, org_id, workspace_id, name, revision
			FROM projection_probe ORDER BY id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.org, &r.workspace, &r.name, &r.revision); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return out
}

func (h *harness) subscribeCalls() int { return h.sub.calls }

// countingSubscriber records how often a subscription was opened, so a test can
// tell "it resumed and saw nothing" from "it never ran".
type countingSubscriber struct {
	inner eventsourcing.CatchUpSubscriber
	calls int
}

func (c *countingSubscriber) SubscribeAll(
	ctx context.Context, from eventsourcing.StartFrom,
	opts eventsourcing.SubscribeOptions, h eventsourcing.Handler,
) error {
	c.calls++
	return c.inner.SubscribeAll(ctx, from, opts, h)
}

func appDSN() string {
	if v := os.Getenv("APP_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://chronos_app:chronos_app_dev_password@localhost:5432/chronos?sslmode=disable"
}

func kurrentDSN() string {
	if v := os.Getenv("KURRENTDB_URL"); v != "" {
		return v
	}
	return "kurrentdb://localhost:2113?tls=false"
}

// ---------------------------------------------------------------------------
// benchmarks
// ---------------------------------------------------------------------------

var sinkErr error

// The number that governs LIVE projector throughput: one event = one
// transaction containing SET LOCAL, the projection's own write, and the
// checkpoint upsert.
//
// Live is deliberately unbatched. Once caught up, events arrive one at a time
// and batching would only add latency between a write landing in the log and
// appearing in the read model. Catching up is the opposite case and is measured
// by BenchmarkProjectBatchOfEvents below.
func BenchmarkProjectOneEvent(b *testing.B) {
	h := newHarness(b)
	view := newProbeView(h.viewName, h.category, h.codec)
	org, ws := "org_"+h.suffix, "ws_"+h.suffix

	env := projection.Envelope{
		Type:     "probe.ThingRecorded.v1",
		Stream:   eventsourcing.StreamID(string(h.category) + "-bench"),
		Revision: 1,
		Position: eventsourcing.Position{Commit: 1, Prepare: 1},
		Meta:     eventsourcing.Metadata{OrgID: org, WorkspaceID: ws, Residency: "eu"},
		Payload:  []byte(`{"id":"` + h.suffix + `_bench","name":"benchmark"}`),
	}
	cp := projection.Checkpoint{Position: env.Position, EventsProcessed: 1}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkErr = h.pg.InTenantBatch(ctx, projection.ScopeOf(env.Meta), db.Replayable, func(w db.Writer) error {
			if err := view.Apply(ctx, w, env); err != nil {
				return err
			}
			pgadapter.Checkpoints{}.Save(ctx, w, h.viewName, cp, "bench")
			return nil
		})
		if sinkErr != nil {
			b.Fatalf("project: %v", sinkErr)
		}
	}
}

// The catch-up path: CatchUpBatch events and ONE checkpoint in a single
// transaction, priced per event.
//
// The comparison against BenchmarkProjectOneEvent is the whole justification for
// batching a projector that is behind. Atomicity is unchanged — rows and
// checkpoint still commit together — and the only property traded is that a
// crash reapplies the batch rather than one event, which Apply already has to
// tolerate for restarts and rebuilds.
func BenchmarkProjectBatchOfEvents(b *testing.B) {
	const batch = 64

	h := newHarness(b)
	view := newProbeView(h.viewName, h.category, h.codec)
	org, ws := "org_"+h.suffix, "ws_"+h.suffix
	meta := eventsourcing.Metadata{OrgID: org, WorkspaceID: ws, Residency: "eu"}

	envs := make([]projection.Envelope, batch)
	for i := range envs {
		envs[i] = projection.Envelope{
			Type:     "probe.ThingRecorded.v1",
			Stream:   eventsourcing.StreamID(string(h.category) + "-bench"),
			Revision: eventsourcing.Revision(i),
			Position: eventsourcing.Position{Commit: uint64(i + 1), Prepare: uint64(i + 1)},
			Meta:     meta,
			Payload:  []byte(`{"id":"` + h.suffix + `_bench","name":"benchmark"}`),
		}
	}
	cp := projection.Checkpoint{Position: envs[batch-1].Position, EventsProcessed: batch}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkErr = h.pg.InTenantBatch(ctx, projection.ScopeOf(meta), db.Replayable, func(w db.Writer) error {
			for j := range envs {
				if err := view.Apply(ctx, w, envs[j]); err != nil {
					return err
				}
			}
			pgadapter.Checkpoints{}.Save(ctx, w, h.viewName, cp, "bench")
			return nil
		})
		if sinkErr != nil {
			b.Fatalf("project: %v", sinkErr)
		}
	}
	// Per EVENT, so it compares directly with BenchmarkProjectOneEvent.
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*batch), "ns/event")
}

// The same event with a DURABLE commit, to price what Replayable buys. Both
// are correct; only one is appropriate for data the event log can rebuild.
func BenchmarkProjectOneEventDurable(b *testing.B) {
	h := newHarness(b)
	view := newProbeView(h.viewName, h.category, h.codec)
	org, ws := "org_"+h.suffix, "ws_"+h.suffix

	env := projection.Envelope{
		Type:     "probe.ThingRecorded.v1",
		Revision: 1,
		Position: eventsourcing.Position{Commit: 1, Prepare: 1},
		Meta:     eventsourcing.Metadata{OrgID: org, WorkspaceID: ws, Residency: "eu"},
		Payload:  []byte(`{"id":"` + h.suffix + `_bench","name":"benchmark"}`),
	}
	cp := projection.Checkpoint{Position: env.Position, EventsProcessed: 1}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkErr = h.pg.InTenantBatch(ctx, projection.ScopeOf(env.Meta), db.Durable, func(w db.Writer) error {
			if err := view.Apply(ctx, w, env); err != nil {
				return err
			}
			pgadapter.Checkpoints{}.Save(ctx, w, h.viewName, cp, "bench")
			return nil
		})
		if sinkErr != nil {
			b.Fatalf("project: %v", sinkErr)
		}
	}
}

// Lease acquisition happens once per projector per failover, not per event, but
// it holds a pooled connection for its lifetime — worth knowing.
func BenchmarkLeaseAcquireRelease(b *testing.B) {
	h := newHarness(b)
	lease := pgadapter.NewLease(h.pool)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rel, held, err := lease.Acquire(ctx, h.viewName)
		if err != nil || !held {
			b.Fatalf("acquire: held=%v err=%v", held, err)
		}
		rel(ctx)
	}
}

// Baselines, so the per-event number above can be attributed rather than
// guessed at. Everything here is round-trip bound: Docker Desktop's loopback on
// macOS is slow, and these two numbers say how much of the cost is ours.
func BenchmarkBareRoundTrip(b *testing.B) {
	h := newHarness(b)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := h.pool.Exec(ctx, `SELECT 1`); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEmptyTransaction(b *testing.B) {
	h := newHarness(b)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkErr = h.pg.InSystemTx(ctx, func(context.Context, db.Querier) error { return nil })
		if sinkErr != nil {
			b.Fatal(sinkErr)
		}
	}
}

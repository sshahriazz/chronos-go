package projection_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
	"github.com/chronos/chronos-go/internal/platform/realtime"
)

// ---------------------------------------------------------------------------
// test events
// ---------------------------------------------------------------------------

type thingHappened struct {
	Name string `json:"name"`
}

func (*thingHappened) EventType() string { return "test.ThingHappened.v1" }

type otherHappened struct{}

func (*otherHappened) EventType() string { return "test.OtherHappened.v1" }

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

func TestDispatchRoutesByType(t *testing.T) {
	d := projection.NewDispatch(fakeCodec{})

	var got string
	d.On[thingHappened](func(_ context.Context, _ db.Writer, _ projection.Envelope, e *thingHappened) error {
		got = e.Name
		return nil
	})

	env := projection.Envelope{Type: "test.ThingHappened.v1", Payload: []byte(`{"name":"kettle"}`)}
	if err := d.Apply(context.Background(), nil, env); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got != "kettle" {
		t.Fatalf("handler received %q, want %q", got, "kettle")
	}
}

// $all is filtered by stream prefix, so a projection is routinely offered
// events from its own module that it does not care about. Those must cost
// nothing, not fail.
func TestDispatchSkipsUnregisteredTypes(t *testing.T) {
	codec := &countingCodec{}
	d := projection.NewDispatch(codec)
	d.On[thingHappened](func(context.Context, db.Writer, projection.Envelope, *thingHappened) error {
		t.Fatal("the wrong handler ran")
		return nil
	})

	env := projection.Envelope{Type: eventsourcing.TypeOf[otherHappened](), Payload: []byte(`{}`)}
	if err := d.Apply(context.Background(), nil, env); err != nil {
		t.Fatalf("an unhandled type must be skipped, got %v", err)
	}
	if codec.calls != 0 {
		t.Fatalf("an unhandled type must not be decoded, decoded %d times", codec.calls)
	}
	if d.Handles(eventsourcing.TypeOf[otherHappened]()) {
		t.Fatal("Handles reported a type with no handler")
	}
}

func TestDispatchRejectsDuplicateRegistration(t *testing.T) {
	d := projection.NewDispatch(fakeCodec{})
	d.On[thingHappened](func(context.Context, db.Writer, projection.Envelope, *thingHappened) error { return nil })

	defer func() {
		if recover() == nil {
			t.Fatal("registering the same event type twice must panic at wiring time")
		}
	}()
	d.On[thingHappened](func(context.Context, db.Writer, projection.Envelope, *thingHappened) error { return nil })
}

// A handler is registered by Go TYPE; the codec answers by event-type NAME. If
// the two disagree the handler would be called with a value it was never
// written for, so Apply refuses the event instead.
//
// This is a registry mismatch, not bad data: the fix is a wiring change, and
// surfacing it as an error stops the projector rather than letting it build a
// read model that is wrong with nothing recording why.
func TestDispatchRefusesAnEventDecodedAsTheWrongType(t *testing.T) {
	d := projection.NewDispatch(mismatchedCodec{})
	d.On[thingHappened](func(context.Context, db.Writer, projection.Envelope, *thingHappened) error {
		t.Fatal("a handler must not run for an event decoded as a different type")
		return nil
	})

	env := projection.Envelope{
		Type:    eventsourcing.TypeOf[thingHappened](),
		Stream:  "test-1",
		Payload: []byte(`{}`),
	}
	err := d.Apply(context.Background(), nil, env)
	if err == nil {
		t.Fatal("a codec returning a different Go type than the handler was registered " +
			"for must be an error, not a silent skip")
	}
	if !strings.Contains(err.Error(), eventsourcing.TypeOf[thingHappened]()) {
		t.Errorf("the error must name the event type that mismatched, got: %v", err)
	}
}

func TestDispatchSurfacesDecodeErrors(t *testing.T) {
	d := projection.NewDispatch(fakeCodec{})
	d.On[thingHappened](func(context.Context, db.Writer, projection.Envelope, *thingHappened) error { return nil })

	env := projection.Envelope{Type: "test.ThingHappened.v1", Stream: "test-1", Payload: []byte(`{not json`)}
	err := d.Apply(context.Background(), nil, env)
	if err == nil {
		t.Fatal("a payload that will not decode must be an error, not a skip")
	}
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

func TestRunnerAppliesAndCheckpointsAtomically(t *testing.T) {
	proj := &spyProjection{name: "test_view"}
	cps := &fakeCheckpoints{}
	tx := &fakeTX{}
	sub := newSubscriber(
		recorded("test-1", 0, 10, "org_A"),
		recorded("test-1", 1, 20, "org_A"),
	)

	r := newRunner(t, proj, sub, tx, cps)
	runUntilDrained(t, r, sub)

	if len(proj.applied) != 2 {
		t.Fatalf("applied %d events, want 2", len(proj.applied))
	}
	if got := cps.saved.Position.Commit; got != 20 {
		t.Errorf("checkpoint at commit %d, want 20", got)
	}
	if got := cps.saved.EventsProcessed; got != 2 {
		t.Errorf("events processed %d, want 2", got)
	}
	// The property the whole design rests on: every event's rows were written by
	// a transaction that ALSO carried a checkpoint. Not one checkpoint per event
	// — while catching up, many events share a transaction — but never rows in a
	// transaction that checkpointed nothing, which is how an event is lost
	// forever rather than reapplied.
	checkpointed := make(map[int]bool, len(cps.saveTxs))
	for _, tx := range cps.saveTxs {
		checkpointed[tx] = true
	}
	for i, tx := range proj.applyTxs {
		if !checkpointed[tx] {
			t.Errorf("event %d applied in tx %d, which never checkpointed — a crash after it loses the event forever", i, tx)
		}
	}
	if cps.savedOutsideTx {
		t.Error("the checkpoint was saved outside the batch that applied the rows")
	}
	// Both events were behind the head of the log, so they share ONE
	// transaction: two writes plus the single checkpoint that covers them.
	if len(tx.batches) != 1 {
		t.Fatalf("%d transactions for two catch-up events, want 1", len(tx.batches))
	}
	if got := len(tx.batches[0].queued); got != 3 {
		t.Errorf("batch queued %d statements, want 3 (two writes and the checkpoint)", got)
	}
}

// Batching is for catching up only. Once live, an event must reach the read
// model without waiting for the next 63 to arrive.
func TestRunnerCommitsEachEventOnItsOwnWhenLive(t *testing.T) {
	proj := &spyProjection{name: "test_view"}
	cps := &fakeCheckpoints{}
	tx := &fakeTX{}
	sub := newSubscriber(
		recorded("test-1", 0, 10, "org_A"),
		recorded("test-1", 1, 20, "org_A"),
	)
	sub.liveBeforeDelivery = true

	r := newRunner(t, proj, sub, tx, cps)
	runUntilDrained(t, r, sub)

	if len(tx.batches) != 2 {
		t.Fatalf("%d transactions for two live events, want one each", len(tx.batches))
	}
	if got := cps.saved.Position.Commit; got != 20 {
		t.Errorf("checkpoint at commit %d, want 20", got)
	}
}

// The point of batching, stated as a number: a catching-up projector pays one
// round trip per BATCH, not per event. The round trip is 63% of per-event
// latency here, so this is the difference between a rebuild that takes minutes
// and one that takes seconds.
func TestCatchUpCostsOneRoundTripPerBatch(t *testing.T) {
	const events = 1000
	const batch = 64

	proj := &spyProjection{name: "test_view"}
	tx := &fakeTX{}
	sub := &fakeSubscriber{drained: make(chan struct{})}
	for i := range events {
		sub.events = append(sub.events, recorded("test-1", int64(i), uint64(i+1)*10, "org_A"))
	}

	r := projection.NewRunner(proj, projection.Deps{
		Subscriber: sub, Codec: fakeCodec{}, Batch: tx, TX: tx,
		Checkpoints: &fakeCheckpoints{}, Lease: grantingLease{}, Log: quiet(),
		CatchUpBatch: batch,
	})
	runUntilDrained(t, r, sub)

	if len(proj.applied) != events {
		t.Fatalf("applied %d events, want %d", len(proj.applied), events)
	}
	want := events / batch // 1000/64 = 15 full batches, and the tail flushes at OnLive
	if got := len(tx.batches); got < want || got > want+1 {
		t.Errorf("%d transactions for %d events at a batch of %d, want %d or %d",
			got, events, batch, want, want+1)
	}
}

// A batch may not span tenants: every statement runs under a scope set by SET
// LOCAL, so two orgs in one transaction would project one org's event under the
// other's policy.
func TestCatchUpBatchNeverSpansTenants(t *testing.T) {
	proj := &spyProjection{name: "test_view"}
	tx := &fakeTX{}
	sub := newSubscriber(
		recorded("test-1", 0, 10, "org_A"),
		recorded("test-2", 0, 20, "org_A"),
		recorded("test-3", 0, 30, "org_B"),
		recorded("test-4", 0, 40, "org_A"),
	)

	r := projection.NewRunner(proj, projection.Deps{
		Subscriber: sub, Codec: fakeCodec{}, Batch: tx, TX: tx,
		Checkpoints: &fakeCheckpoints{}, Lease: grantingLease{}, Log: quiet(),
	})
	runUntilDrained(t, r, sub)

	// A, A | B | A — the scope change ends the batch, and the next one starts a
	// new scope rather than inheriting it.
	want := []string{"org_A", "org_B", "org_A"}
	if len(tx.batches) != len(want) {
		t.Fatalf("%d transactions, want %d (one per contiguous tenant run)", len(tx.batches), len(want))
	}
	for i, w := range want {
		if got := tx.batches[i].tenant.OrgID; got != w {
			t.Errorf("transaction %d scoped to %q, want %q", i, got, w)
		}
	}
}

// A server checkpoint names a position PAST the events buffered behind it.
// Writing it while they are still in memory would leave a checkpoint claiming
// work no transaction ever did — the one way a projection loses an event
// instead of reapplying it.
func TestAServerCheckpointNeverLeapsOverBufferedEvents(t *testing.T) {
	proj := &spyProjection{name: "test_view"}
	cps := &fakeCheckpoints{}
	tx := &fakeTX{}
	sub := newSubscriber(recorded("test-1", 0, 10, "org_A"))
	// The server scanned to 99 and found nothing else this projection wants.
	sub.checkpointAt = 99

	r := newRunner(t, proj, sub, tx, cps)
	runUntilDrained(t, r, sub)

	if len(proj.applied) != 1 {
		t.Fatalf("applied %d events, want 1", len(proj.applied))
	}
	// The buffered event's rows were committed before the skip was recorded, so
	// the checkpoint that ends at 99 sits above work that actually happened.
	cps.mu.Lock()
	order := append([]uint64(nil), cps.order...)
	cps.mu.Unlock()
	if len(order) != 2 || order[0] != 10 || order[1] != 99 {
		t.Errorf("checkpoint positions committed in order %v, want [10 99] — the event's rows "+
			"must commit before the scan that jumps past them", order)
	}
	if got := cps.saved.Position.Commit; got != 99 {
		t.Errorf("final checkpoint at %d, want the scanned position 99", got)
	}
	// A scan is not an event: it moves the resume point and nothing else.
	if got := cps.saved.EventsProcessed; got != 1 {
		t.Errorf("events processed %d, want 1 — a checkpoint is not an event", got)
	}
}

func TestRunnerScopesEachEventToItsOwnTenant(t *testing.T) {
	proj := &spyProjection{name: "test_view"}
	tx := &fakeTX{}
	sub := newSubscriber(
		recorded("test-1", 0, 10, "org_A"),
		recorded("test-2", 0, 20, "org_B"),
		recorded("test-3", 0, 30, ""), // a system-wide fact
	)

	r := projection.NewRunner(proj, projection.Deps{
		Subscriber: sub, Codec: fakeCodec{}, Batch: tx, TX: tx,
		Checkpoints: &fakeCheckpoints{}, Lease: grantingLease{}, Log: quiet(),
	})
	runUntilDrained(t, r, sub)

	want := []string{"org_A", "org_B", ""}
	if len(tx.batches) != len(want) {
		t.Fatalf("%d batches, want %d", len(tx.batches), len(want))
	}
	for i, w := range want {
		if got := tx.batches[i].tenant.OrgID; got != w {
			t.Errorf("event %d scoped to %q, want %q", i, got, w)
		}
		// Projections are derived and replayable, so they must never pay for a
		// durable commit (ADR-013).
		if tx.batches[i].durability != db.Replayable {
			t.Errorf("event %d committed durably; projections are rebuildable", i)
		}
	}
}

func TestRunnerSkipsSystemStreams(t *testing.T) {
	proj := &spyProjection{name: "test_view"}
	sub := newSubscriber(
		recorded("$$test-1", 0, 10, "org_A"),
		recorded("$scavenges", 0, 20, ""),
		recorded("test-1", 0, 30, "org_A"),
	)

	r := newRunner(t, proj, sub, &fakeTX{}, &fakeCheckpoints{})
	runUntilDrained(t, r, sub)

	if len(proj.applied) != 1 {
		t.Fatalf("applied %d events, want 1 — system streams are not domain facts", len(proj.applied))
	}
	if proj.applied[0].Stream != "test-1" {
		t.Errorf("applied %q", proj.applied[0].Stream)
	}
}

func TestRunnerResumesFromStoredCheckpoint(t *testing.T) {
	cps := &fakeCheckpoints{
		stored:   projection.Checkpoint{Position: eventsourcing.Position{Commit: 99, Prepare: 99}, EventsProcessed: 7},
		hasValue: true,
	}
	sub := newSubscriber()

	r := newRunner(t, &spyProjection{name: "test_view"}, sub, &fakeTX{}, cps)
	runUntilDrained(t, r, sub)

	if sub.from.IsBeginning() {
		t.Fatal("a restart with a stored checkpoint must not replay from the head of the log")
	}
	if got := sub.from.Position().Commit; got != 99 {
		t.Fatalf("subscribed from commit %d, want 99", got)
	}
}

// The bug this pins: a checkpoint AT position zero is not the same as no
// checkpoint. Collapsing them replays the entire log on every restart.
func TestRunnerDistinguishesCheckpointZeroFromNeverRun(t *testing.T) {
	atZero := &fakeCheckpoints{
		stored:   projection.Checkpoint{Position: eventsourcing.Position{}, EventsProcessed: 1},
		hasValue: true,
	}
	sub := newSubscriber()
	r := newRunner(t, &spyProjection{name: "test_view"}, sub, &fakeTX{}, atZero)
	runUntilDrained(t, r, sub)

	if sub.from.IsBeginning() {
		t.Fatal("a projector checkpointed at position zero resumed from the head of the log — " +
			"every restart would replay everything")
	}

	never := &fakeCheckpoints{}
	sub2 := newSubscriber()
	r2 := newRunner(t, &spyProjection{name: "test_view"}, sub2, &fakeTX{}, never)
	runUntilDrained(t, r2, sub2)

	if !sub2.from.IsBeginning() {
		t.Fatal("a projector that has never run must start at the head of the log")
	}
}

// "No events recently" is ambiguous between an idle system and a projector that
// is hours behind. Only the server's caught-up signal separates them.
func TestRunnerTracksLiveness(t *testing.T) {
	proj := &spyProjection{name: "test_view"}
	sub := newSubscriber(recorded("test-1", 0, 10, "org_A"))
	tx := &fakeTX{}
	r := newRunner(t, proj, sub, tx, &fakeCheckpoints{})

	if r.Live() {
		t.Fatal("a projector reports itself current before it has even subscribed")
	}
	runUntilDrained(t, r, sub)
	if !r.Live() {
		t.Fatal("the subscription reached the head of the log but the projector still reports itself behind")
	}
}

// A projection that rejects an event is a bug. Retrying cannot help and
// skipping builds a read model that is silently wrong, so the runner stops.
func TestRunnerStopsWhenTheProjectionRejectsAnEvent(t *testing.T) {
	boom := errors.New("column does not exist")
	proj := &spyProjection{name: "test_view", failOn: 1}
	proj.failWith = boom
	sub := newSubscriber(
		recorded("test-1", 0, 10, "org_A"),
		recorded("test-1", 1, 20, "org_A"),
		recorded("test-1", 2, 30, "org_A"),
	)
	cps := &fakeCheckpoints{}
	tx := &fakeTX{}

	r := newRunner(t, proj, sub, tx, cps)
	err := r.Run(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want the projection's own error", err)
	}
	// The checkpoint must never reach the failing event. It may sit BEHIND the
	// event before it — that event shared the rolled-back transaction, so its
	// rows are gone too and the pair is replayed together — but a checkpoint at
	// or past 20 would mean the read model skipped an event nothing applied.
	if got := cps.saved.Position.Commit; got >= 20 {
		t.Errorf("checkpoint at %d covers the failing event at 20; it must stay behind it", got)
	}
	if tx.rolledBack != 1 {
		t.Errorf("%d transactions rolled back, want 1", tx.rolledBack)
	}
}

func TestRunnerStandsByWithoutTheLease(t *testing.T) {
	proj := &spyProjection{name: "test_view"}
	sub := newSubscriber(recorded("test-1", 0, 10, "org_A"))

	r := projection.NewRunner(proj, projection.Deps{
		Subscriber: sub, Codec: fakeCodec{}, Batch: &fakeTX{}, TX: &fakeTX{},
		Checkpoints: &fakeCheckpoints{}, Lease: refusingLease{}, Log: quiet(),
		LeaseRetry: time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := r.Run(ctx); err != nil {
		t.Fatalf("standing by is not a failure, got %v", err)
	}
	if len(proj.applied) != 0 {
		t.Fatal("a runner without the lease must not project anything: two writers race on the checkpoint")
	}
	if sub.calls != 0 {
		t.Fatal("a runner without the lease must not even subscribe")
	}
}

func TestRunnerRebuildResetsAndClearsInOneTransaction(t *testing.T) {
	proj := &spyProjection{name: "test_view"}
	cps := &fakeCheckpoints{
		stored:   projection.Checkpoint{Position: eventsourcing.Position{Commit: 500}, EventsProcessed: 42},
		hasValue: true,
	}
	tx := &fakeTX{}
	sub := newSubscriber(recorded("test-1", 0, 10, "org_A"))

	r := newRunner(t, proj, sub, tx, cps)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Rebuild(ctx) }()
	select {
	case <-sub.drained:
	case <-time.After(2 * time.Second):
		t.Fatal("rebuild did not reach the subscription")
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("rebuild: %v", err)
	}

	if proj.resets != 1 {
		t.Errorf("Reset called %d times, want 1", proj.resets)
	}
	if !cps.cleared {
		t.Error("the checkpoint was not cleared, so the rebuild would resume mid-log")
	}
	if proj.resetTx != cps.clearTx {
		t.Error("Reset and Clear ran in different transactions: a crash between them leaves a half-rebuilt projection")
	}
	if !sub.from.IsBeginning() {
		t.Errorf("rebuild subscribed from %+v, want the head of the log", sub.from.Position())
	}
}

func TestRunnerRefusesToRebuildWhileAnotherInstanceRuns(t *testing.T) {
	r := projection.NewRunner(&spyProjection{name: "test_view"}, projection.Deps{
		Subscriber: newSubscriber(), Codec: fakeCodec{}, Batch: &fakeTX{}, TX: &fakeTX{},
		Checkpoints: &fakeCheckpoints{}, Lease: refusingLease{}, Log: quiet(),
	})
	if err := r.Rebuild(context.Background()); err == nil {
		t.Fatal("rebuilding under another instance would truncate tables it is writing to")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newRunner(t *testing.T, p projection.Projection, sub *fakeSubscriber, tx *fakeTX, cps *fakeCheckpoints) *projection.Runner {
	t.Helper()
	return projection.NewRunner(p, projection.Deps{
		Subscriber: sub, Codec: fakeCodec{}, Batch: tx, TX: tx,
		Checkpoints: cps, Lease: grantingLease{}, Log: quiet(), Holder: "test",
	})
}

// runUntilDrained starts the runner, waits for the fake subscriber to finish
// replaying, then shuts it down — the same shape as a real projector, which
// runs until its process is told to stop.
func runUntilDrained(t *testing.T, r *projection.Runner, sub *fakeSubscriber) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	select {
	case <-sub.drained:
	case err := <-done:
		t.Fatalf("the runner stopped before draining: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the subscriber to drain")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the runner did not stop when its context was cancelled")
	}
}

func recorded(stream string, rev int64, commit uint64, org string) eventsourcing.RecordedEvent {
	meta, _ := codec.Marshal(map[string]any{"orgId": org, "residency": "eu"})
	return eventsourcing.RecordedEvent{
		Type:     "test.ThingHappened.v1",
		Stream:   eventsourcing.StreamID(stream),
		Revision: eventsourcing.Revision(rev),
		Position: eventsourcing.Position{Commit: commit, Prepare: commit},
		Payload:  []byte(`{"name":"x"}`),
		Metadata: meta,
	}
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type spyProjection struct {
	name     string
	applied  []projection.Envelope
	applyTxs []int
	resets   int
	resetTx  int
	failOn   int
	failWith error
}

func (p *spyProjection) Name() string { return p.name }
func (p *spyProjection) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{StreamPrefixes: []string{"test-"}}
}

func (p *spyProjection) Apply(_ context.Context, w db.Writer, env projection.Envelope) error {
	if p.failWith != nil && len(p.applied) == p.failOn {
		return p.failWith
	}
	p.applied = append(p.applied, env)
	p.applyTxs = append(p.applyTxs, w.(*fakeBatch).id)
	w.Exec("INSERT INTO spy (id) VALUES ($1)", env.ID)
	return nil
}

func (p *spyProjection) Reset(_ context.Context, q db.Querier) error {
	p.resets++
	p.resetTx = q.(*fakeQuerier).txID
	return nil
}

type fakeCodec struct{}

func (fakeCodec) Marshal(eventsourcing.Event) ([]byte, error) { return nil, nil }

func (fakeCodec) Unmarshal(_ string, payload []byte) (eventsourcing.Event, error) {
	e := &thingHappened{}
	// TOLERANT, matching the real codec: a stored payload may carry a newer
	// producer's fields (ADR-029). A stricter double would let a projector pass
	// here and stall against the real one.
	if err := codec.IntoTolerant(payload, e); err != nil {
		return nil, err
	}
	return e, nil
}

func (fakeCodec) MarshalMetadata(eventsourcing.Metadata) ([]byte, error) { return nil, nil }

func (fakeCodec) UnmarshalMetadata(b []byte) (eventsourcing.Metadata, error) {
	var w struct {
		OrgID     string `json:"orgId"`
		Residency string `json:"residency"`
	}
	if len(b) > 0 {
		// Tolerant: stored metadata carries keys this double does not model —
		// KurrentDB adds its own — and the real codec reads it that way.
		if err := codec.IntoTolerant(b, &w); err != nil {
			return eventsourcing.Metadata{}, err
		}
	}
	return eventsourcing.Metadata{OrgID: w.OrgID, Residency: w.Residency}, nil
}

// mismatchedCodec decodes every payload as *otherHappened whatever the
// envelope's type name says — a registry that disagrees with the dispatcher.
type mismatchedCodec struct{ fakeCodec }

func (mismatchedCodec) Unmarshal(string, []byte) (eventsourcing.Event, error) {
	return &otherHappened{}, nil
}

type countingCodec struct {
	fakeCodec
	calls int
}

func (c *countingCodec) Unmarshal(t string, payload []byte) (eventsourcing.Event, error) {
	c.calls++
	return c.fakeCodec.Unmarshal(t, payload)
}

// fakeTX models the one property that matters: work inside a failed callback is
// discarded, and the querier identifies which transaction it belongs to.
type fakeTX struct {
	// mu guards the bookkeeping below, which a sharded rebuild writes from
	// several goroutines at once.
	mu         sync.Mutex
	next       int
	committed  int
	rolledBack int
	discarded  []int
	batches    []*fakeBatch

	// sendFailsAt makes the batch fail when it is SENT, at this zero-based
	// statement index. nil means it never fails. See InTenantBatch.
	sendFailsAt *int
}

func (f *fakeTX) InSystemTx(ctx context.Context, fn func(context.Context, db.Querier) error) error {
	f.next++
	q := &fakeQuerier{txID: f.next}
	if err := fn(ctx, q); err != nil {
		f.rolledBack++
		// Anything this querier wrote is gone, including a checkpoint save.
		f.discarded = append(f.discarded, q.txID)
		return err
	}
	f.committed++
	return nil
}

type fakeQuerier struct {
	txID int
}

// fakeBatch models the real thing: statements are QUEUED, and a callback that
// returns an error means nothing is sent at all.
type fakeBatch struct {
	id         int
	durability db.Durability
	tenant     db.Tenant
	queued     []string
	sent       bool
	// onSend carries the effects a queued statement would have. They fire only
	// when the batch actually reaches the server, which is the property under
	// test: a callback that fails sends nothing, so nothing takes effect.
	onSend []func()
}

func (b *fakeBatch) Exec(sql string, _ ...any) { b.queued = append(b.queued, sql) }

// Queued makes the fake behave like the real batch writer, which reports its
// position so a failure can be attributed to the event that queued the failing
// statement (db.StatementCounter).
func (b *fakeBatch) Queued() int { return len(b.queued) }

// InTenantBatch is guarded because a SHARDED rebuild calls it from several
// goroutines at once. The real implementation acquires its own pooled connection
// per call and is safe by construction; this one would race on the bookkeeping
// it keeps for assertions, and a racy fake fails the very tests that prove the
// production path is sound.
func (f *fakeTX) InTenantBatch(
	_ context.Context, t db.Tenant, d db.Durability, fn func(db.Writer) error,
) error {
	f.mu.Lock()
	f.next++
	b := &fakeBatch{id: f.next, durability: d, tenant: t}
	f.batches = append(f.batches, b)
	f.mu.Unlock()

	// fn runs OUTSIDE the lock: it is the caller's work, and holding a lock
	// across it would serialise the shards and hide any ordering bug.
	if err := fn(b); err != nil {
		f.mu.Lock()
		f.rolledBack++
		f.mu.Unlock()
		return err
	}

	// A failure at SEND time, which is the only kind a real batch has: Exec
	// queues and returns nothing, so PostgreSQL's rejection arrives here, after
	// every handler has already returned nil.
	if f.sendFailsAt != nil {
		f.mu.Lock()
		f.rolledBack++
		f.mu.Unlock()
		return fmt.Errorf("postgres: %w", &db.BatchStatementError{
			Index: *f.sendFailsAt, Count: len(b.queued),
			SQL: "INSERT INTO spy …", Err: errSendFailed,
		})
	}

	f.mu.Lock()
	b.sent = true
	effects := b.onSend
	f.committed++
	f.mu.Unlock()
	for _, effect := range effects {
		effect()
	}
	return nil
}

var errSendFailed = errors.New("duplicate key value violates unique constraint")

func (q *fakeQuerier) Exec(context.Context, string, ...any) (int64, error) { return 0, nil }
func (q *fakeQuerier) Query(context.Context, string, ...any) (db.Rows, error) {
	return nil, errors.New("not used")
}
func (q *fakeQuerier) QueryRow(context.Context, string, ...any) db.Row { return nil }

type fakeCheckpoints struct {
	// mu guards the fields a sharded rebuild writes from its worker goroutines.
	mu       sync.Mutex
	saves    int
	stored   projection.Checkpoint
	hasValue bool
	saved    projection.Checkpoint
	// order is every position that actually COMMITTED, in the order it did, so a
	// test can assert that rows land before the scan that jumps past them.
	order          []uint64
	saveTxs        []int
	savedOutsideTx bool
	cleared        bool
	clearTx        int
}

func (c *fakeCheckpoints) Load(context.Context, db.Querier, string) (projection.Checkpoint, error) {
	if !c.hasValue {
		return projection.Checkpoint{}, projection.ErrNoCheckpoint
	}
	return c.stored, nil
}

func (c *fakeCheckpoints) Save(_ context.Context, w db.Writer, _ string, cp projection.Checkpoint, _ string) {
	b, ok := w.(*fakeBatch)
	if !ok {
		// Not every checkpoint rides in a batch. A server checkpoint has no rows
		// to be atomic with, and a sharded rebuild writes one position at the end
		// — both use a plain querier-backed Writer. Dereferencing b here would
		// nil-panic and, worse, would make those paths untestable, which is how a
		// path ends up with no test at all.
		c.savedOutsideTx = true
		w.Exec("INSERT INTO projection_checkpoint ...")
		c.mu.Lock()
		c.saved, c.stored, c.hasValue = cp, cp, true
		c.order = append(c.order, cp.Position.Commit)
		c.saves++
		c.mu.Unlock()
		return
	}
	c.saveTxs = append(c.saveTxs, b.id)
	b.Exec("INSERT INTO projection_checkpoint ...")
	b.onSend = append(b.onSend, func() {
		c.mu.Lock()
		c.saved, c.stored, c.hasValue = cp, cp, true
		c.order = append(c.order, cp.Position.Commit)
		c.saves++
		c.mu.Unlock()
	})
}

// saveCount and lastSaved read the fields a concurrent rebuild writes.
func (c *fakeCheckpoints) saveCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.saves
}

func (c *fakeCheckpoints) lastSaved() projection.Checkpoint {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.saved
}

func (c *fakeCheckpoints) Clear(_ context.Context, q db.Querier, _ string) error {
	c.cleared = true
	c.clearTx = q.(*fakeQuerier).txID
	c.stored, c.hasValue = projection.Checkpoint{}, false
	return nil
}

// fakeSubscriber replays a fixed slice then reports the subscription ended.
type fakeSubscriber struct {
	// liveBeforeDelivery signals caught-up BEFORE delivering, which is the
	// steady state; the default signals after, which is a replay.
	liveBeforeDelivery bool
	// checkpointAt, when non-zero, is a position the server scanned past without
	// finding a match — reported after the events, as the real one does.
	checkpointAt uint64
	events       []eventsourcing.RecordedEvent
	from         eventsourcing.StartFrom
	calls        int
	drained      chan struct{}
}

func newSubscriber(events ...eventsourcing.RecordedEvent) *fakeSubscriber {
	return &fakeSubscriber{events: events, drained: make(chan struct{})}
}

func (s *fakeSubscriber) SubscribeAll(
	ctx context.Context, from eventsourcing.StartFrom,
	opts eventsourcing.SubscribeOptions, h eventsourcing.Handler,
) error {
	s.calls++
	s.from = from
	if s.liveBeforeDelivery && opts.OnLive != nil {
		if err := opts.OnLive(ctx); err != nil {
			return err
		}
	}
	for _, e := range s.events {
		if !from.IsBeginning() && e.Position.Commit <= from.Position().Commit {
			continue // resuming is exclusive, as it is on the real subscription
		}
		if err := h(ctx, e); err != nil {
			return err
		}
	}
	if s.checkpointAt > 0 && opts.OnCheckpoint != nil {
		if err := opts.OnCheckpoint(ctx, eventsourcing.Position{
			Commit: s.checkpointAt, Prepare: s.checkpointAt,
		}); err != nil {
			return err
		}
	}
	// A real subscription reports reaching the head of the log before going
	// quiet, which is what tells a projector it is current.
	if opts.OnLive != nil {
		// Reaching the head is where a projector commits whatever it buffered
		// while behind, so a failure here ends the subscription exactly as it
		// does against the real server.
		if err := opts.OnLive(ctx); err != nil {
			return err
		}
	}
	close(s.drained)
	// A live subscription does not end when it catches up.
	<-ctx.Done()
	return ctx.Err()
}

type grantingLease struct{}

func (grantingLease) Acquire(context.Context, string) (projection.Release, bool, error) {
	return func(context.Context) {}, true, nil
}

type refusingLease struct{}

func (refusingLease) Acquire(context.Context, string) (projection.Release, bool, error) {
	return nil, false, nil
}

// countingMetrics records only what the announcement tests assert on; every
// other method is inert.
type countingMetrics struct {
	mu      sync.Mutex
	dropped int
}

func (*countingMetrics) Applied(string, float64) {}
func (*countingMetrics) Skipped(string)          {}
func (*countingMetrics) Failed(string)           {}
func (*countingMetrics) Live(string, bool)       {}
func (*countingMetrics) Position(string, uint64) {}

func (m *countingMetrics) AnnouncementsDropped(_ string, messages int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dropped += messages
}

func (m *countingMetrics) drops() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dropped
}

// ---------------------------------------------------------------------------
// realtime announcements
// ---------------------------------------------------------------------------

// A rebuild replays every event a projection ever saw. Announcing those would
// fire one toast per notification a user has ever received, all at once.
func TestNothingIsAnnouncedWhileCatchingUp(t *testing.T) {
	pub := &spyPublisher{}
	proj := &emittingProjection{spyProjection: spyProjection{name: "test_view"}}
	sub := newSubscriber(
		recorded("test-1", 0, 10, "org_A"),
		recorded("test-1", 1, 20, "org_A"),
	)
	tx := &fakeTX{}

	// The subscriber signals caught-up only AFTER delivering, so both events
	// arrive while still replaying.
	r := projection.NewRunner(proj, projection.Deps{
		Subscriber: sub, Codec: fakeCodec{}, Batch: tx, TX: tx,
		Checkpoints: &fakeCheckpoints{}, Lease: grantingLease{},
		Realtime: pub, Log: quiet(),
	})
	runUntilDrained(t, r, sub)

	if len(proj.applied) != 2 {
		t.Fatalf("applied %d events, want 2", len(proj.applied))
	}
	if pub.count() != 0 {
		t.Fatalf("announced %d messages while catching up — a rebuild would toast "+
			"every notification in a user's history at once", pub.count())
	}
}

// Once live, changes are announced.
func TestLiveEventsAreAnnounced(t *testing.T) {
	pub := &spyPublisher{}
	proj := &emittingProjection{spyProjection: spyProjection{name: "test_view"}}
	sub := newSubscriber()
	sub.liveBeforeDelivery = true
	sub.events = []eventsourcing.RecordedEvent{recorded("test-1", 0, 10, "org_A")}
	tx := &fakeTX{}

	r := projection.NewRunner(proj, projection.Deps{
		Subscriber: sub, Codec: fakeCodec{}, Batch: tx, TX: tx,
		Checkpoints: &fakeCheckpoints{}, Lease: grantingLease{},
		Realtime: pub, Log: quiet(),
	})
	runUntilDrained(t, r, sub)

	if pub.count() != 1 {
		t.Fatalf("announced %d messages, want 1", pub.count())
	}
}

// A failed publish must not fail the projection: the rows are already durable
// and the browser recovers by reading them.
func TestFailedAnnouncementDoesNotStopTheProjection(t *testing.T) {
	pub := &spyPublisher{err: errors.New("centrifugo: unreachable")}
	proj := &emittingProjection{spyProjection: spyProjection{name: "test_view"}}
	sub := newSubscriber()
	sub.liveBeforeDelivery = true
	sub.events = []eventsourcing.RecordedEvent{recorded("test-1", 0, 10, "org_A")}
	tx := &fakeTX{}
	cps := &fakeCheckpoints{}

	r := projection.NewRunner(proj, projection.Deps{
		Subscriber: sub, Codec: fakeCodec{}, Batch: tx, TX: tx,
		Checkpoints: cps, Lease: grantingLease{}, Realtime: pub, Log: quiet(),
	})
	runUntilDrained(t, r, sub)

	if len(proj.applied) != 1 {
		t.Fatal("a failed announcement stopped the projection")
	}
	if cps.saved.Position.Commit != 10 {
		t.Error("a failed announcement prevented the checkpoint from advancing")
	}
}

// A publisher that has stopped answering must not stop the read model. The
// queue fills, further announcements are DROPPED and counted, and events keep
// being applied — which is the whole reason publishing left the per-event path.
func TestAStalledPublisherDropsRatherThanBlocksTheProjection(t *testing.T) {
	// The publisher hangs long enough to fill the queue, then recovers. Hanging
	// forever would instead test announceDrainTimeout, which is a different
	// property with its own cost in wall-clock time.
	stuck := make(chan struct{})
	time.AfterFunc(200*time.Millisecond, func() { close(stuck) })

	pub := &spyPublisher{block: stuck}
	metrics := &countingMetrics{}
	proj := &emittingProjection{spyProjection: spyProjection{name: "test_view"}}

	const events = 40
	sub := &fakeSubscriber{drained: make(chan struct{}), liveBeforeDelivery: true}
	for i := range events {
		sub.events = append(sub.events, recorded("test-1", int64(i), uint64(i+1)*10, "org_A"))
	}
	tx := &fakeTX{}
	cps := &fakeCheckpoints{}

	r := projection.NewRunner(proj, projection.Deps{
		Subscriber: sub, Codec: fakeCodec{}, Batch: tx, TX: tx,
		Checkpoints: cps, Lease: grantingLease{}, Realtime: pub, Log: quiet(),
		Metrics: metrics,
		// One in flight, one queued: everything after that has nowhere to go.
		AnnounceBuffer: 1,
	})
	runUntilDrained(t, r, sub)

	if len(proj.applied) != events {
		t.Fatalf("applied %d of %d events; a stalled publisher held up the read model",
			len(proj.applied), events)
	}
	if got := cps.saved.Position.Commit; got != events*10 {
		t.Errorf("checkpoint at %d, want %d — announcements must not gate the position",
			got, events*10)
	}
	if metrics.drops() == 0 {
		t.Error("announcements were discarded without being counted; a failing realtime " +
			"path would leave no signal at all")
	}
}

// A projection with no Emitter must be unaffected by a configured publisher.
func TestProjectionWithoutAnEmitterAnnouncesNothing(t *testing.T) {
	pub := &spyPublisher{}
	sub := newSubscriber()
	sub.liveBeforeDelivery = true
	sub.events = []eventsourcing.RecordedEvent{recorded("test-1", 0, 10, "org_A")}
	tx := &fakeTX{}

	r := projection.NewRunner(&spyProjection{name: "test_view"}, projection.Deps{
		Subscriber: sub, Codec: fakeCodec{}, Batch: tx, TX: tx,
		Checkpoints: &fakeCheckpoints{}, Lease: grantingLease{},
		Realtime: pub, Log: quiet(),
	})
	runUntilDrained(t, r, sub)

	if pub.count() != 0 {
		t.Fatal("announced for a projection that emits nothing")
	}
}

type emittingProjection struct{ spyProjection }

func (e *emittingProjection) Emit(env projection.Envelope) []realtime.Message {
	return []realtime.Message{{
		Channel: realtime.UserChannel("sub_1"),
		Type:    "test.event",
		Data:    []byte(`{}`),
	}}
}

type spyPublisher struct {
	mu sync.Mutex
	n  int
	// block holds the publisher inside PublishMany until it is closed, standing
	// in for a Centrifugo that has stopped answering.
	block <-chan struct{}
	err   error
}

func (p *spyPublisher) Publish(_ context.Context, _ realtime.Message) error {
	return p.record(1)
}

func (p *spyPublisher) PublishMany(_ context.Context, msgs []realtime.Message) error {
	if p.block != nil {
		<-p.block
	}
	return p.record(len(msgs))
}

func (p *spyPublisher) record(n int) error {
	if p.err != nil {
		return p.err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n += n
	return nil
}

func (p *spyPublisher) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.n
}

// ---------------------------------------------------------------------------
// rebuild source selection
// ---------------------------------------------------------------------------

// recordingReaders note which link stream a rebuild chose.
type recordingReaders struct {
	categories []string
	types      []string
}

func (r *recordingReaders) ReadCategory(_ context.Context, c eventsourcing.Category, _ eventsourcing.Handler) error {
	r.categories = append(r.categories, string(c))
	return nil
}

func (r *recordingReaders) ReadEventType(_ context.Context, t string, _ eventsourcing.Handler) error {
	r.types = append(r.types, t)
	return nil
}

// filteredProjection is a projection whose only interesting property is its
// filter, which is what the rebuild source is chosen from.
type filteredProjection struct {
	name   string
	filter eventsourcing.SubscriptionFilter
}

func (p *filteredProjection) Name() string                                                { return p.name }
func (p *filteredProjection) Filter() eventsourcing.SubscriptionFilter                    { return p.filter }
func (p *filteredProjection) Apply(context.Context, db.Writer, projection.Envelope) error { return nil }
func (p *filteredProjection) Reset(context.Context, db.Querier) error                     { return nil }

// A rebuild must pick the NARROWEST source the filter allows.
//
// $et- is strictly narrower than $ce-: a category stream carries every type its
// aggregate emits, so a projection wanting one of them reads and discards the
// rest. Measured on the running server, 2000 events in a category of which 200
// were the wanted type — $et- 7.1ms versus $ce- 105.3ms, 14.7x.
//
// Anything the filter cannot resolve to exactly ONE stream falls back to $all,
// which is always correct and always slower. Two streams read in sequence would
// apply all of the first before any of the second, losing global commit order.
func TestRebuildPicksTheNarrowestSource(t *testing.T) {
	cases := []struct {
		name      string
		filter    eventsourcing.SubscriptionFilter
		wantTypes []string
		wantCats  []string
	}{
		{
			name:      "one whole event type reads $et-",
			filter:    eventsourcing.SubscriptionFilter{EventTypes: []string{"probe.Thing.v1"}},
			wantTypes: []string{"probe.Thing.v1"},
		},
		{
			name:     "one category reads $ce-",
			filter:   eventsourcing.SubscriptionFilter{StreamPrefixes: []string{"probe-"}},
			wantCats: []string{"probe"},
		},
		{
			name:   "two event types fall back to $all",
			filter: eventsourcing.SubscriptionFilter{EventTypes: []string{"a.v1", "b.v1"}},
		},
		{
			name:   "two categories fall back to $all",
			filter: eventsourcing.SubscriptionFilter{StreamPrefixes: []string{"a-", "b-"}},
		},
		{
			// A prefix cannot name a $et- stream, and "x.Created.v1" as a prefix
			// would also select "x.Created.v10".
			name:   "an event-type PREFIX falls back to $all",
			filter: eventsourcing.SubscriptionFilter{EventTypePrefixes: []string{"probe."}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			readers := &recordingReaders{}
			tx := &fakeTX{}
			sub := newSubscriber()
			r := projection.NewRunner(&filteredProjection{name: "sel_view", filter: tc.filter},
				projection.Deps{
					Subscriber: sub, Codec: fakeCodec{}, Batch: tx, TX: tx,
					Categories: readers, Types: readers,
					Checkpoints: &fakeCheckpoints{}, Lease: grantingLease{},
					Log: quiet(), Holder: "test",
				})

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- r.Rebuild(ctx) }()
			// The rebuild reads its link stream, then subscribes. Waiting for
			// the subscription is how we know the source was already chosen.
			select {
			case <-sub.drained:
			case <-time.After(5 * time.Second):
				t.Fatal("the rebuild never reached its subscription")
			}
			cancel()
			<-done

			if got := readers.types; !equalStrings(got, tc.wantTypes) {
				t.Errorf("type streams read = %v, want %v", got, tc.wantTypes)
			}
			if got := readers.categories; !equalStrings(got, tc.wantCats) {
				t.Errorf("category streams read = %v, want %v", got, tc.wantCats)
			}
		})
	}
}

// A filter naming two dimensions cannot be expressed server-side: KurrentDB
// matches streams OR event types. The adapter would honour one and drop the
// other, and the projection would run looking perfectly healthy while never
// receiving the events it declared — so the runner refuses to start at all.
func TestRunnerRefusesAFilterThatMixesSelectors(t *testing.T) {
	mixed := eventsourcing.SubscriptionFilter{
		EventTypes: []string{"a.v1"}, StreamPrefixes: []string{"probe-"},
	}
	tx := &fakeTX{}
	sub := newSubscriber()
	proj := &filteredProjection{name: "sel_view", filter: mixed}

	newFor := func() *projection.Runner {
		return projection.NewRunner(proj, projection.Deps{
			Subscriber: sub, Codec: fakeCodec{}, Batch: tx, TX: tx,
			Checkpoints: &fakeCheckpoints{}, Lease: grantingLease{},
			Log: quiet(), Holder: "test",
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	for name, run := range map[string]func(*projection.Runner) error{
		"Run":     func(r *projection.Runner) error { return r.Run(ctx) },
		"Rebuild": func(r *projection.Runner) error { return r.Rebuild(ctx) },
	} {
		err := run(newFor())
		if !errors.Is(err, eventsourcing.ErrAmbiguousFilter) {
			t.Errorf("%s returned %v, want ErrAmbiguousFilter", name, err)
		}
	}
	if sub.calls != 0 {
		t.Errorf("subscribed %d times with a filter that cannot be expressed; it must never reach the server", sub.calls)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// sharded rebuild
// ---------------------------------------------------------------------------

// orderRecorder notes, per stream, the order in which revisions were applied.
type orderRecorder struct {
	mu    sync.Mutex
	seen  map[eventsourcing.StreamID][]eventsourcing.Revision
	total int
}

func newOrderRecorder() *orderRecorder {
	return &orderRecorder{seen: map[eventsourcing.StreamID][]eventsourcing.Revision{}}
}

func (o *orderRecorder) Name() string { return "order_view" }

func (o *orderRecorder) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{StreamPrefixes: []string{"probe-"}}
}

func (o *orderRecorder) Apply(_ context.Context, _ db.Writer, env projection.Envelope) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.seen[env.Stream] = append(o.seen[env.Stream], env.Revision)
	o.total++
	return nil
}

func (o *orderRecorder) Reset(context.Context, db.Querier) error { return nil }

// A sharded rebuild must preserve per-aggregate order.
//
// This is the property that makes stream-hash partitioning safe and revision-range
// slicing unsafe. Every projection here upserts by row, so if two events for one
// aggregate are applied out of order the surviving row is whichever committed
// last — a read model wrong in a way nothing detects.
func TestShardedRebuildPreservesPerAggregateOrder(t *testing.T) {
	const streams, perStream = 12, 25

	var events []eventsourcing.RecordedEvent
	pos := uint64(1)
	// Interleaved across streams, exactly as a link stream delivers them.
	for rev := range perStream {
		for s := range streams {
			events = append(events, eventsourcing.RecordedEvent{
				Type:     "probe.Thing.v1",
				Stream:   eventsourcing.StreamID(fmt.Sprintf("probe-%d", s)),
				Revision: eventsourcing.Revision(rev),
				Position: eventsourcing.Position{Commit: pos, Prepare: pos},
				Payload:  []byte(`{}`),
				Metadata: []byte(`{"schema_version":1,"org_id":"org_1","workspace_id":"ws_1"}`),
			})
			pos++
		}
	}

	rec := newOrderRecorder()
	tx := &fakeTX{}
	cps := &fakeCheckpoints{}
	r := projection.NewRunner(rec, projection.Deps{
		Subscriber: newSubscriber(), Codec: fakeCodec{}, Batch: tx, TX: tx,
		Categories:  &staticCategoryReader{events: events},
		Checkpoints: cps, Lease: grantingLease{}, Log: quiet(), Holder: "test",
		RebuildShards: 8,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Rebuild(ctx) }()
	waitFor(t, func() bool { return rec.count() == streams*perStream })
	cancel()
	<-done

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.seen) != streams {
		t.Fatalf("saw %d streams, want %d", len(rec.seen), streams)
	}
	for stream, revs := range rec.seen {
		if len(revs) != perStream {
			t.Errorf("%s: applied %d events, want %d", stream, len(revs), perStream)
			continue
		}
		for i, rev := range revs {
			if int(rev) != i {
				t.Fatalf("%s: applied revision %d at position %d — a sharded rebuild "+
					"reordered one aggregate's history, so its final row is whichever "+
					"event committed last, not its latest", stream, rev, i)
			}
		}
	}
}

func (o *orderRecorder) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.total
}

// The checkpoint must be written ONCE, at the end, and must name the furthest
// position reached.
//
// A per-event checkpoint during a sharded rebuild would name a position whose
// predecessors have not all been applied — and a crash would resume from it and
// skip them permanently.
func TestShardedRebuildCheckpointsOnceAtTheEnd(t *testing.T) {
	var events []eventsourcing.RecordedEvent
	for i := range 40 {
		events = append(events, eventsourcing.RecordedEvent{
			Type:     "probe.Thing.v1",
			Stream:   eventsourcing.StreamID(fmt.Sprintf("probe-%d", i%7)),
			Revision: eventsourcing.Revision(i / 7),
			Position: eventsourcing.Position{Commit: uint64(i + 1), Prepare: uint64(i + 1)},
			Payload:  []byte(`{}`),
			Metadata: []byte(`{"schema_version":1,"org_id":"org_1","workspace_id":"ws_1"}`),
		})
	}

	rec := newOrderRecorder()
	tx := &fakeTX{}
	cps := &fakeCheckpoints{}
	r := projection.NewRunner(rec, projection.Deps{
		Subscriber: newSubscriber(), Codec: fakeCodec{}, Batch: tx, TX: tx,
		Categories:  &staticCategoryReader{events: events},
		Checkpoints: cps, Lease: grantingLease{}, Log: quiet(), Holder: "test",
		RebuildShards: 4,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Rebuild(ctx) }()
	waitFor(t, func() bool { return rec.count() == len(events) })
	waitFor(t, func() bool { return cps.saveCount() > 0 })
	cancel()
	<-done

	// One save for the rebuild itself. The live subscription that follows may add
	// its own, so the assertion is on the rebuild's value, not a strict count.
	if got := cps.lastSaved().Position.Commit; got != uint64(len(events)) {
		t.Fatalf("checkpoint commit = %d, want %d (the furthest position applied)",
			got, len(events))
	}
	if got := cps.lastSaved().EventsProcessed; got != int64(len(events)) {
		t.Fatalf("EventsProcessed = %d, want %d", got, len(events))
	}
}

// A sharded rebuild buffers per worker, so it pays one round trip per shard per
// batch — not one per event. Without this the shard path is the slowest way to
// run the operation that needs speed most.
func TestShardedRebuildBatchesPerWorker(t *testing.T) {
	const events, shards = 200, 4

	var recs []eventsourcing.RecordedEvent
	for i := range events {
		recs = append(recs, eventsourcing.RecordedEvent{
			Type:     "probe.Thing.v1",
			Stream:   eventsourcing.StreamID(fmt.Sprintf("probe-%d", i%shards)),
			Revision: eventsourcing.Revision(i / shards),
			Position: eventsourcing.Position{Commit: uint64(i + 1), Prepare: uint64(i + 1)},
			Payload:  []byte(`{}`),
			Metadata: []byte(`{"schema_version":1,"org_id":"org_1","workspace_id":"ws_1"}`),
		})
	}

	rec := newOrderRecorder()
	tx := &fakeTX{}
	cps := &fakeCheckpoints{}
	r := projection.NewRunner(rec, projection.Deps{
		Subscriber: newSubscriber(), Codec: fakeCodec{}, Batch: tx, TX: tx,
		Categories:  &staticCategoryReader{events: recs},
		Checkpoints: cps, Lease: grantingLease{}, Log: quiet(), Holder: "test",
		RebuildShards: shards, CatchUpBatch: 64,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Rebuild(ctx) }()
	waitFor(t, func() bool { return rec.count() == len(recs) })
	waitFor(t, func() bool { return cps.saveCount() > 0 })
	cancel()
	<-done

	// 200 events over 4 shards at 64 per batch: one batch each, plus the tail
	// flush. Anything near 200 means the workers went back to one transaction
	// per event.
	tx.mu.Lock()
	got := len(tx.batches)
	tx.mu.Unlock()
	if got > shards*2 {
		t.Errorf("%d transactions for %d events across %d shards, want at most %d",
			got, len(recs), shards, shards*2)
	}
}

// A rebuild writes through the same pool the API uses, so it has to be
// pace-able. The limit is an average: this asserts the replay took at least as
// long as the configured rate allows, not that each event was evenly spaced.
func TestRebuildIsPacedByTheConfiguredRate(t *testing.T) {
	const events, perSecond = 60, 300 // 60 events at 300/s ≈ 200ms

	var recs []eventsourcing.RecordedEvent
	for i := range events {
		recs = append(recs, eventsourcing.RecordedEvent{
			Type:     "probe.Thing.v1",
			Stream:   eventsourcing.StreamID(fmt.Sprintf("probe-%d", i%3)),
			Revision: eventsourcing.Revision(i / 3),
			Position: eventsourcing.Position{Commit: uint64(i + 1), Prepare: uint64(i + 1)},
			Payload:  []byte(`{}`),
			Metadata: []byte(`{"schema_version":1,"org_id":"org_1","workspace_id":"ws_1"}`),
		})
	}

	rec := newOrderRecorder()
	tx := &fakeTX{}
	r := projection.NewRunner(rec, projection.Deps{
		Subscriber: newSubscriber(), Codec: fakeCodec{}, Batch: tx, TX: tx,
		Categories:  &staticCategoryReader{events: recs},
		Checkpoints: &fakeCheckpoints{}, Lease: grantingLease{}, Log: quiet(), Holder: "test",
		RebuildEventsPerSecond: perSecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	started := time.Now()
	done := make(chan error, 1)
	go func() { done <- r.Rebuild(ctx) }()
	waitFor(t, func() bool { return rec.count() == len(recs) })
	elapsed := time.Since(started)
	cancel()
	<-done

	// The floor, with slack for the sub-millisecond deficits the throttle
	// deliberately does not sleep on.
	floor := time.Duration(float64(events)/float64(perSecond)*float64(time.Second)) / 2
	if elapsed < floor {
		t.Errorf("replayed %d events in %s at a %d/s limit; the throttle did not pace it (floor %s)",
			events, elapsed, perSecond, floor)
	}
}

// Unthrottled is the default, and it must cost nothing: a rebuild nobody
// configured a limit for must not be slowed by the mechanism that limits one.
func TestRebuildIsUnthrottledByDefault(t *testing.T) {
	var recs []eventsourcing.RecordedEvent
	for i := range 200 {
		recs = append(recs, eventsourcing.RecordedEvent{
			Type:     "probe.Thing.v1",
			Stream:   eventsourcing.StreamID(fmt.Sprintf("probe-%d", i%3)),
			Revision: eventsourcing.Revision(i / 3),
			Position: eventsourcing.Position{Commit: uint64(i + 1), Prepare: uint64(i + 1)},
			Payload:  []byte(`{}`),
			Metadata: []byte(`{"schema_version":1,"org_id":"org_1","workspace_id":"ws_1"}`),
		})
	}

	rec := newOrderRecorder()
	tx := &fakeTX{}
	r := projection.NewRunner(rec, projection.Deps{
		Subscriber: newSubscriber(), Codec: fakeCodec{}, Batch: tx, TX: tx,
		Categories:  &staticCategoryReader{events: recs},
		Checkpoints: &fakeCheckpoints{}, Lease: grantingLease{}, Log: quiet(), Holder: "test",
	})

	ctx, cancel := context.WithCancel(context.Background())
	started := time.Now()
	done := make(chan error, 1)
	go func() { done <- r.Rebuild(ctx) }()
	waitFor(t, func() bool { return rec.count() == len(recs) })
	elapsed := time.Since(started)
	cancel()
	<-done

	if elapsed > 2*time.Second {
		t.Errorf("an unthrottled rebuild of %d events took %s", len(recs), elapsed)
	}
}

// staticCategoryReader replays a fixed slice, standing in for a link stream.
type staticCategoryReader struct{ events []eventsourcing.RecordedEvent }

func (s *staticCategoryReader) ReadCategory(
	ctx context.Context, _ eventsourcing.Category, h eventsourcing.Handler,
) error {
	for _, e := range s.events {
		if err := h(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met within 10s")
}

// A batch failure must name the event whose statement failed, not the event that
// happened to close the batch.
//
// This drives the real Runner rather than the mapping in isolation, because the
// mapping is only half of it: the buffer that holds the envelopes is CLEARED IN
// PLACE on the failure path, so reading the culprit after the reset yields a
// zeroed envelope and an error that names nothing at all. That happened — the
// message read "apply failed:  at #0" against a live rebuild — and only a test
// that exercises flush's ordering can catch it.
func TestBatchFailureAtSendNamesTheEventThatQueuedTheStatement(t *testing.T) {
	// spyProjection queues exactly one statement per event and this fake queues
	// no scope statement of its own, so statement index 3 belongs to the event
	// at revision 3. (The real batch queues its tenant scope first; that offset
	// is covered by TestBatchFailureNamesTheEventThatQueuedTheStatement.)
	const failAt = 3
	at := failAt

	proj := &spyProjection{name: "test_view"}
	tx := &fakeTX{sendFailsAt: &at}
	sub := &fakeSubscriber{drained: make(chan struct{})}
	for i := range 8 {
		sub.events = append(sub.events, recorded("test-1", int64(i), uint64(i+1)*10, "org_A"))
	}

	r := projection.NewRunner(proj, projection.Deps{
		Subscriber: sub, Codec: fakeCodec{}, Batch: tx, TX: tx,
		Checkpoints: &fakeCheckpoints{}, Lease: grantingLease{}, Log: quiet(),
		CatchUpBatch: 8,
	})
	err := r.Run(context.Background())
	if err == nil {
		t.Fatal("a batch that failed at send did not stop the projector")
	}
	if !errors.Is(err, errSendFailed) {
		t.Fatalf("got %v, want the send failure", err)
	}

	// The batch's LAST event is revision 7, and that is the name the old code
	// reported for every failure in the batch. A zeroed envelope — the reset
	// bug — produces "at #0", which this also rejects.
	const want = "test-1#3"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("the failure names the wrong event.\n got: %v\nwant it to contain %q — "+
			"statement %d was queued by that event, and naming any other one sends a reader "+
			"to an event that did nothing wrong", err, want, failAt)
	}
	if strings.Contains(err.Error(), "could not be attributed") {
		t.Errorf("the attribution was reported as uncertain although the Writer counts "+
			"statements: %v", err)
	}
}

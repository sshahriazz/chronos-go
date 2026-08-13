package temporal_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/testsuite"
)

// ---------------------------------------------------------------------------
// Fakes for the two ports the sweep needs.
// ---------------------------------------------------------------------------

// fakeList hands out one batch per call, so a test can say "the first pass fills
// its limit and the second does not" — which is the only thing that makes the
// workflow's loop observable.
type fakeList struct {
	batches [][]app.LapsedReservation
	calls   int
	err     error
	limits  []int
}

func (f *fakeList) ListLapsed(
	_ context.Context, _ time.Time, limit int,
) ([]app.LapsedReservation, error) {
	f.calls++
	f.limits = append(f.limits, limit)
	if f.err != nil {
		return nil, f.err
	}
	if f.calls > len(f.batches) {
		return nil, nil
	}
	return f.batches[f.calls-1], nil
}

// saved records one append: which stream key, under which idempotency key, and
// which events. The idempotency key is recorded because it is what makes a
// redelivered activity collapse into the original append instead of writing a
// second release.
type saved struct {
	key            string
	idempotencyKey string
	events         []eventsourcing.Event
	meta           eventsourcing.Metadata
}

type fakeRepo struct {
	aggs     map[string]*domain.EmailReservation
	appends  []saved
	loadErr  map[string]error
	saveErr  map[string]error
	loadCall int
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		aggs:    map[string]*domain.EmailReservation{},
		loadErr: map[string]error{},
		saveErr: map[string]error{},
	}
}

func (r *fakeRepo) Load(_ context.Context, key string) (*domain.EmailReservation, error) {
	r.loadCall++
	if err := r.loadErr[key]; err != nil {
		return nil, err
	}
	if agg, ok := r.aggs[key]; ok {
		return agg, nil
	}
	return domain.NewReservation(), nil
}

func (r *fakeRepo) Save(
	_ context.Context, key string, agg *domain.EmailReservation,
	idempotencyKey string, meta eventsourcing.Metadata,
) (eventsourcing.AppendResult, error) {
	if err := r.saveErr[key]; err != nil {
		return eventsourcing.AppendResult{}, err
	}
	r.appends = append(r.appends, saved{
		key: key, idempotencyKey: idempotencyKey,
		events: append([]eventsourcing.Event(nil), agg.Uncommitted()...),
		meta:   meta,
	})
	agg.ClearUncommitted()
	return eventsourcing.AppendResult{Revision: 1}, nil
}

// held builds a reservation in the state a registration leaves it in: claimed,
// unverified, with a deadline. The reserving event is cleared, so anything the
// sweep records is the only thing in the buffer.
func held(t *testing.T, index, subject string, expires time.Time) *domain.EmailReservation {
	t.Helper()
	r := domain.NewReservation()
	if err := r.Reserve(contract.EmailIndex(index), subject, expires, expires.Add(-time.Hour)); err != nil {
		t.Fatalf("reserving: %v", err)
	}
	r.ClearUncommitted()
	return r
}

func confirmed(t *testing.T, index, subject string, expires time.Time) *domain.EmailReservation {
	t.Helper()
	r := held(t, index, subject, expires)
	if err := r.Confirm(subject, expires.Add(-time.Minute)); err != nil {
		t.Fatalf("confirming: %v", err)
	}
	r.ClearUncommitted()
	return r
}

func row(index, subject string, expires time.Time) app.LapsedReservation {
	return app.LapsedReservation{Index: contract.EmailIndex(index), SubjectID: subject, ExpiresAt: expires}
}

// sweeper is the same shim cmd/worker builds: the identity use case presented as
// the durable-work port.
type sweeper struct{ s *app.ReservationSweep }

func (a sweeper) SweepOnce(
	ctx context.Context, now time.Time, limit int,
) (temporaladapter.SweepPass, error) {
	r, err := a.s.SweepOnce(ctx, now, limit)
	return temporaladapter.SweepPass{
		Scanned: r.Scanned, Released: r.Released, Stale: r.Stale, Failed: r.Failed, More: r.More,
	}, err
}

func newSweep(t *testing.T, list app.LapsedReservations, repo app.ReservationRepository) *app.ReservationSweep {
	t.Helper()
	s, err := app.NewReservationSweep(list, repo, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("building the sweep: %v", err)
	}
	return s
}

// counting is a sweeper that reports whatever a test tells it to, for the
// workflow-shape tests where the use case is not what is under test.
type counting struct {
	passes []temporaladapter.SweepPass
	calls  int
	err    error
	limits []int
	times  []time.Time
}

func (c *counting) SweepOnce(
	_ context.Context, now time.Time, limit int,
) (temporaladapter.SweepPass, error) {
	c.calls++
	c.limits = append(c.limits, limit)
	c.times = append(c.times, now)
	if c.err != nil {
		return temporaladapter.SweepPass{}, c.err
	}
	if c.calls > len(c.passes) {
		return temporaladapter.SweepPass{}, nil
	}
	return c.passes[c.calls-1], nil
}

func runSweep(
	t *testing.T, s temporaladapter.ReservationSweeper, in temporaladapter.SweepReservationsInput,
) (temporaladapter.SweepReservationsResult, error) {
	t.Helper()
	return runSweepAt(t, s, in, time.Time{})
}

// runSweepAt pins the environment's workflow clock, which is what makes the
// difference between workflow.Now and time.Now OBSERVABLE. Without a pinned
// start time the two agree on a first execution and only diverge on replay,
// where no unit test looks.
func runSweepAt(
	t *testing.T, s temporaladapter.ReservationSweeper,
	in temporaladapter.SweepReservationsInput, startAt time.Time,
) (temporaladapter.SweepReservationsResult, error) {
	t.Helper()
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	if !startAt.IsZero() {
		env.SetStartTime(startAt)
	}

	activities, err := temporaladapter.NewReservationActivities(s)
	if err != nil {
		t.Fatalf("activities: %v", err)
	}
	temporaladapter.RegisterSweepForTest(env, activities)

	env.ExecuteWorkflow(temporaladapter.SweepReservations, in)
	if !env.IsWorkflowCompleted() {
		t.Fatal("the workflow did not complete")
	}
	var out temporaladapter.SweepReservationsResult
	if err := env.GetWorkflowError(); err != nil {
		return out, err
	}
	if err := env.GetWorkflowResult(&out); err != nil {
		t.Fatalf("reading the result: %v", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// The workflow.
// ---------------------------------------------------------------------------

// The workflow's whole job: run the release as an ACTIVITY. The test
// environment fails the run if the workflow does I/O, reads the wall clock, or
// is otherwise non-deterministic — which is what makes this test worth having
// beyond "it returned a number".
func TestTheSweepReleasesThroughAnActivity(t *testing.T) {
	deadline := time.Date(2026, 8, 13, 9, 0, 0, 0, time.UTC)
	list := &fakeList{batches: [][]app.LapsedReservation{{
		row("aa11", "sub_1", deadline),
		row("bb22", "sub_2", deadline),
	}}}
	repo := newFakeRepo()
	repo.aggs["aa11"] = held(t, "aa11", "sub_1", deadline)
	repo.aggs["bb22"] = held(t, "bb22", "sub_2", deadline)

	got, err := runSweep(t, sweeper{newSweep(t, list, repo)},
		temporaladapter.SweepReservationsInput{Batch: 10, MaxPasses: 3})
	if err != nil {
		t.Fatalf("workflow: %v", err)
	}

	if got.Released != 2 {
		t.Errorf("released %d, want 2 — a lapsed claim that is not released holds an "+
			"address its owner can never register", got.Released)
	}
	if len(repo.appends) != 2 {
		t.Fatalf("appended %d releases, want 2", len(repo.appends))
	}
	for _, a := range repo.appends {
		if len(a.events) != 1 {
			t.Fatalf("%s appended %d events, want 1", a.key, len(a.events))
		}
		e, ok := a.events[0].(*contract.EmailReleased)
		if !ok {
			t.Fatalf("%s appended %T, want *contract.EmailReleased", a.key, a.events[0])
		}
		if e.Reason != domain.ReleaseExpired {
			t.Errorf("%s released for reason %q, want %q", a.key, e.Reason, domain.ReleaseExpired)
		}
		if !e.ReleasedAt.Equal(e.ReleasedAt.UTC()) {
			t.Errorf("%s released at %s, which is not UTC", a.key, e.ReleasedAt)
		}
	}
}

// The list is the ONLY thing the sweep reads and the stream is the only thing it
// writes. A sweep that also updated email_reservation_view could mark a
// reservation released with no event saying so, and the projection would stop
// being reconstructable from the log (ADR-019).
func TestTheWorkListIsReadOnly(t *testing.T) {
	var port app.LapsedReservations = &fakeList{}
	if _, ok := port.(interface {
		Release(context.Context, string) error
	}); ok {
		t.Fatal("the work-list port can write")
	}
	// The projector applies the release; the sweep never touches the view. What
	// this asserts is the observable half: the only effect of a pass is appends.
	deadline := time.Date(2026, 8, 13, 9, 0, 0, 0, time.UTC)
	list := &fakeList{batches: [][]app.LapsedReservation{{row("aa11", "sub_1", deadline)}}}
	repo := newFakeRepo()
	repo.aggs["aa11"] = held(t, "aa11", "sub_1", deadline)

	if _, err := runSweep(t, sweeper{newSweep(t, list, repo)},
		temporaladapter.SweepReservationsInput{Batch: 5, MaxPasses: 2}); err != nil {
		t.Fatalf("workflow: %v", err)
	}
	if repo.appends[0].key != "aa11" {
		t.Errorf("the release went to stream key %q, want the blind index", repo.appends[0].key)
	}
}

// A pass that fills its batch has almost certainly left work behind. Stopping
// there would report success over a backlog, which is the failure this loop
// exists to prevent.
func TestTheSweepLoopsWhileBatchesKeepFilling(t *testing.T) {
	c := &counting{passes: []temporaladapter.SweepPass{
		{Scanned: 2, Released: 2, More: true},
		{Scanned: 2, Released: 1, Stale: 1, More: true},
		{Scanned: 1, Released: 1},
	}}

	got, err := runSweep(t, c, temporaladapter.SweepReservationsInput{Batch: 2, MaxPasses: 5})
	if err != nil {
		t.Fatalf("workflow: %v", err)
	}
	if c.calls != 3 {
		t.Fatalf("the activity ran %d times, want 3: a full batch must be followed by "+
			"another pass, or the rest of the backlog is silently left held", c.calls)
	}
	if got.Passes != 3 || got.Released != 4 || got.Scanned != 5 || got.Stale != 1 {
		t.Errorf("totals did not accumulate across passes: %+v", got)
	}
	if got.Truncated {
		t.Error("a run that drained the list reported truncation")
	}
	for i, l := range c.limits {
		if l != 2 {
			t.Errorf("pass %d used limit %d, want the configured batch of 2", i+1, l)
		}
	}
}

// Silent truncation reads as "we swept everything" when it did not. The pass cap
// is necessary — an unbounded loop would extend one execution's history without
// limit — so what matters is that hitting it is REPORTED.
func TestTruncationIsReportedRatherThanHidden(t *testing.T) {
	c := &counting{passes: []temporaladapter.SweepPass{
		{Scanned: 2, Released: 2, More: true},
		{Scanned: 2, Released: 2, More: true},
	}}

	got, err := runSweep(t, c, temporaladapter.SweepReservationsInput{Batch: 2, MaxPasses: 2})
	if err != nil {
		t.Fatalf("workflow: %v", err)
	}
	if c.calls != 2 {
		t.Fatalf("the activity ran %d times, want the 2-pass cap", c.calls)
	}
	if !got.Truncated {
		t.Fatal("the run stopped at its pass limit with a full batch and did not say so; " +
			"a caller reading this result would conclude the list was drained")
	}
	if got.Released != 4 {
		t.Errorf("released %d, want 4", got.Released)
	}
}

// The instant the sweep measures deadlines against comes from the WORKFLOW
// clock, not the wall clock.
//
// time.Now inside workflow code produces a different value on replay, and a
// replay that disagrees with history is the one thing a workflow may not do.
// That divergence is invisible on a first execution — the two clocks agree —
// which is why this pins the environment's start time to an instant nowhere near
// today and asserts the activity received THAT one.
func TestTheSweepMeasuresAgainstTheWorkflowClock(t *testing.T) {
	started := time.Date(2031, 3, 4, 5, 6, 7, 0, time.UTC)
	c := &counting{passes: []temporaladapter.SweepPass{
		{Scanned: 1, Released: 1, More: true},
		{Scanned: 1, Released: 1},
	}}

	if _, err := runSweepAt(t, c,
		temporaladapter.SweepReservationsInput{Batch: 1, MaxPasses: 4}, started); err != nil {
		t.Fatalf("workflow: %v", err)
	}
	if len(c.times) == 0 {
		t.Fatal("the activity never ran")
	}
	if !c.times[0].Equal(started) {
		t.Errorf("the sweep measured against %s, not the workflow clock's %s: a wall-clock "+
			"read produces a different value on replay, and history stops matching",
			c.times[0], started)
	}
}

// Every pass of one run measures deadlines against the same instant, so two
// passes cannot disagree about which reservations had lapsed.
func TestEveryPassSharesOneInstant(t *testing.T) {
	c := &counting{passes: []temporaladapter.SweepPass{
		{Scanned: 1, Released: 1, More: true},
		{Scanned: 1, Released: 1},
	}}

	if _, err := runSweep(t, c, temporaladapter.SweepReservationsInput{Batch: 1, MaxPasses: 4}); err != nil {
		t.Fatalf("workflow: %v", err)
	}
	if len(c.times) != 2 {
		t.Fatalf("the activity ran %d times, want 2", len(c.times))
	}
	if !c.times[0].Equal(c.times[1]) {
		t.Errorf("two passes of one run measured against %s and %s", c.times[0], c.times[1])
	}
	if c.times[0].Location() != time.UTC {
		t.Errorf("the sweep instant is in %s, not UTC", c.times[0].Location())
	}
}

// A run that could not sweep must FAIL. "The sweep is broken" and "there was
// nothing to sweep" look identical from the outside otherwise.
func TestAnUnreadableWorkListFailsTheRun(t *testing.T) {
	list := &fakeList{err: errors.New("read model unreachable")}
	_, err := runSweep(t, sweeper{newSweep(t, list, newFakeRepo())},
		temporaladapter.SweepReservationsInput{Batch: 5, MaxPasses: 2})
	if err == nil {
		t.Fatal("a sweep that could not read its work list reported success")
	}
}

// A start that names neither bound must still be bounded. A schedule is created
// once and its arguments are server-side state, so an empty input is what a
// hand-triggered run and an older schedule both send.
func TestAnEmptyInputStillBoundsTheRun(t *testing.T) {
	c := &counting{}
	if _, err := runSweep(t, c, temporaladapter.SweepReservationsInput{}); err != nil {
		t.Fatalf("workflow: %v", err)
	}
	if len(c.limits) != 1 {
		t.Fatalf("the activity ran %d times, want 1", len(c.limits))
	}
	if c.limits[0] <= 0 {
		t.Errorf("an unset batch produced a limit of %d, which releases nothing", c.limits[0])
	}
}

// A limit of zero fails identically forever. Retrying it for the whole schedule
// interval reaches the same answer, so it is refused permanently and at once.
func TestAZeroLimitIsNotRetried(t *testing.T) {
	a, err := temporaladapter.NewReservationActivities(&counting{})
	if err != nil {
		t.Fatalf("activities: %v", err)
	}
	if _, err := a.ReleaseLapsed(context.Background(),
		temporaladapter.ReleaseLapsedInput{Now: time.Now(), Limit: 0}); err == nil {
		t.Error("a zero limit was accepted; the pass would release nothing and report success")
	}
	if _, err := a.ReleaseLapsed(context.Background(),
		temporaladapter.ReleaseLapsedInput{Limit: 10}); err == nil {
		t.Error("a pass with no instant was accepted; it has nothing to measure deadlines against")
	}
}

// The activity set refuses to exist without a sweeper. Built without one, every
// run would report success while releasing nothing — the exact shape of failure
// this control exists to prevent, arriving through the wiring.
func TestSweepActivitiesRequireASweeper(t *testing.T) {
	if _, err := temporaladapter.NewReservationActivities(nil); err == nil {
		t.Fatal("the sweep activity set was built with no sweeper")
	}
}

// The name is written into workflow history AND into the schedule that starts
// it. This test exists so changing it is a deliberate act with a visible
// failure, rather than a rename that leaves the schedule pointing at a workflow
// no worker answers to.
func TestTheSweepWorkflowNameIsPermanent(t *testing.T) {
	if temporaladapter.SweepReservationsWorkflow != "chronos.identity.SweepEmailReservations.v1" {
		t.Errorf("the workflow name changed to %q; the schedule now starts a workflow no "+
			"worker answers to, and lapsed reservations stop being released",
			temporaladapter.SweepReservationsWorkflow)
	}
	if temporaladapter.SweepActivityNameForTest != "chronos.identity.ReleaseLapsedReservations.v1" {
		t.Errorf("the activity name changed to %q; every in-flight run now names an "+
			"activity no worker answers to", temporaladapter.SweepActivityNameForTest)
	}
	if temporaladapter.SweepReservationsScheduleID != "chronos.identity.email-reservation-sweep" {
		t.Errorf("the schedule id changed to %q; the next deployment creates a SECOND "+
			"schedule beside the first rather than moving it",
			temporaladapter.SweepReservationsScheduleID)
	}
}

// The schedule must start the workflow the worker registers, on the queue the
// worker polls. Either one wrong creates a run that is queued where nothing is
// listening: the schedule fires on time, the run is created, every metric stays
// green, and no reservation is ever released.
func TestTheScheduleStartsTheRegisteredWorkflow(t *testing.T) {
	opts := temporaladapter.SweepScheduleOptionsForTest(
		"chronos", temporaladapter.SweepReservationsInput{}, time.Hour)

	action, ok := opts.Action.(*client.ScheduleWorkflowAction)
	if !ok {
		t.Fatalf("the schedule's action is %T, not a workflow start", opts.Action)
	}
	if action.Workflow != temporaladapter.SweepReservationsWorkflow {
		t.Errorf("the schedule starts %v, but the worker registers %s",
			action.Workflow, temporaladapter.SweepReservationsWorkflow)
	}
	if action.TaskQueue != "chronos" {
		t.Errorf("the schedule queues on %q, not the queue the worker polls", action.TaskQueue)
	}
	if opts.ID != temporaladapter.SweepReservationsScheduleID {
		t.Errorf("schedule id %q", opts.ID)
	}
	if len(opts.Spec.Intervals) != 1 || opts.Spec.Intervals[0].Every != time.Hour {
		t.Errorf("the schedule does not recur at the interval it was given: %+v", opts.Spec)
	}
	// An unbounded run is what the pass and batch caps exist to prevent, and a
	// schedule created with an empty input is the one start that would produce
	// one if the defaults were not applied before the argument was stored.
	args, _ := opts.Action.(*client.ScheduleWorkflowAction)
	in, ok := args.Args[0].(temporaladapter.SweepReservationsInput)
	if !ok {
		t.Fatalf("the schedule passes %T as its argument", args.Args[0])
	}
	if in.Batch <= 0 || in.MaxPasses <= 0 {
		t.Errorf("the schedule stores an unbounded input %+v; its arguments are server-side "+
			"state, so this is what every future run gets", in)
	}
}

// A schedule cannot be created without a client, and saying so is the whole
// point: the failure is otherwise invisible, because a registered workflow that
// nothing ever starts looks exactly like a working one.
func TestSchedulingRequiresAClient(t *testing.T) {
	if _, err := temporaladapter.EnsureSweepSchedule(context.Background(), nil,
		temporaladapter.SweepReservationsInput{}, time.Minute); err == nil {
		t.Fatal("a schedule was reported as created with no client")
	}
}

// ---------------------------------------------------------------------------
// The use case: which claims may be freed, and which may not.
// ---------------------------------------------------------------------------

// Freeing an address whose owner has PROVEN control of it is the worst outcome
// this table can cause. The query already excludes verified rows; the view lags
// the log, so the row can be confirmed between the query and the load, and it
// should take two mistakes rather than one to give somebody's address away.
func TestAConfirmedClaimIsNeverReleased(t *testing.T) {
	deadline := time.Date(2026, 8, 13, 9, 0, 0, 0, time.UTC)
	list := &fakeList{batches: [][]app.LapsedReservation{{row("aa11", "sub_1", deadline)}}}
	repo := newFakeRepo()
	repo.aggs["aa11"] = confirmed(t, "aa11", "sub_1", deadline)

	got, err := newSweep(t, list, repo).SweepOnce(context.Background(), deadline.Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(repo.appends) != 0 {
		t.Fatalf("a VERIFIED address was released from a stale row; its owner has proven " +
			"control of it and has just lost it")
	}
	if got.Stale != 1 {
		t.Errorf("stale %d, want 1", got.Stale)
	}
}

// The row can name a claim that has since been re-reserved by somebody else.
// Releasing then takes the address from its current, legitimate holder.
func TestAClaimHeldByAnotherSubjectIsNeverReleased(t *testing.T) {
	deadline := time.Date(2026, 8, 13, 9, 0, 0, 0, time.UTC)
	list := &fakeList{batches: [][]app.LapsedReservation{{row("aa11", "sub_old", deadline)}}}
	repo := newFakeRepo()
	repo.aggs["aa11"] = held(t, "aa11", "sub_new", deadline)

	got, err := newSweep(t, list, repo).SweepOnce(context.Background(), deadline.Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(repo.appends) != 0 {
		t.Fatal("a claim was released on behalf of a subject that no longer holds it")
	}
	if got.Stale != 1 || got.Failed != 0 {
		t.Errorf("got %+v, want one stale row and no failure", got)
	}
}

// A stale row can name a lease that has since been extended or renewed. The
// deadline that decides is the STREAM's, never the projection's.
func TestALeaseThatHasNotRunOutIsNeverReleased(t *testing.T) {
	stale := time.Date(2026, 8, 13, 9, 0, 0, 0, time.UTC)
	live := stale.Add(48 * time.Hour)
	list := &fakeList{batches: [][]app.LapsedReservation{{row("aa11", "sub_1", stale)}}}
	repo := newFakeRepo()
	repo.aggs["aa11"] = held(t, "aa11", "sub_1", live)

	got, err := newSweep(t, list, repo).SweepOnce(context.Background(), stale.Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(repo.appends) != 0 {
		t.Fatal("a live lease was released because a stale row said it had expired")
	}
	if got.Stale != 1 {
		t.Errorf("stale %d, want 1", got.Stale)
	}
}

// A redelivered activity must not fail. Releasing a claim that is already gone
// is a no-op by construction, and the sweep has to treat it as one.
func TestAnAlreadyReleasedClaimIsANoOpRatherThanAFailure(t *testing.T) {
	deadline := time.Date(2026, 8, 13, 9, 0, 0, 0, time.UTC)
	list := &fakeList{batches: [][]app.LapsedReservation{{row("aa11", "sub_1", deadline)}}}
	repo := newFakeRepo() // no aggregate: an empty stream, i.e. nothing held

	got, err := newSweep(t, list, repo).SweepOnce(context.Background(), deadline.Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("a redelivered sweep failed: %v", err)
	}
	if got.Failed != 0 || got.Released != 0 || got.Stale != 1 {
		t.Errorf("got %+v, want one stale row and no failure", got)
	}
}

// One address whose stream cannot be read must not stop the rest of the batch
// from being freed. The alternative is that a single broken reservation holds
// every other lapsed address hostage until somebody notices.
func TestOneFailingReservationDoesNotAbortTheBatch(t *testing.T) {
	deadline := time.Date(2026, 8, 13, 9, 0, 0, 0, time.UTC)
	list := &fakeList{batches: [][]app.LapsedReservation{{
		row("aa11", "sub_1", deadline),
		row("bb22", "sub_2", deadline),
		row("cc33", "sub_3", deadline),
	}}}
	repo := newFakeRepo()
	repo.aggs["aa11"] = held(t, "aa11", "sub_1", deadline)
	repo.aggs["bb22"] = held(t, "bb22", "sub_2", deadline)
	repo.aggs["cc33"] = held(t, "cc33", "sub_3", deadline)
	repo.loadErr["bb22"] = errors.New("stream unreadable")

	got, err := newSweep(t, list, repo).SweepOnce(context.Background(), deadline.Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("one failing reservation failed the whole pass: %v", err)
	}
	if got.Released != 2 || got.Failed != 1 {
		t.Errorf("got %+v, want 2 released and 1 failed", got)
	}
	if len(repo.appends) != 2 {
		t.Errorf("appended %d releases, want the 2 that could be read", len(repo.appends))
	}
}

// The activity is at-least-once, and two sweeps can overlap. Both must derive
// the SAME event id for one lapsed claim, so the store collapses the duplicate
// rather than recording the same release twice.
func TestTheSameLapsedClaimAlwaysDerivesTheSameIdempotencyKey(t *testing.T) {
	deadline := time.Date(2026, 8, 13, 9, 0, 0, 0, time.UTC)
	repo := newFakeRepo()

	keys := make([]string, 0, 2)
	for _, at := range []time.Time{deadline.Add(time.Hour), deadline.Add(9 * time.Hour)} {
		list := &fakeList{batches: [][]app.LapsedReservation{{row("aa11", "sub_1", deadline)}}}
		repo.aggs["aa11"] = held(t, "aa11", "sub_1", deadline)
		if _, err := newSweep(t, list, repo).SweepOnce(context.Background(), at, 10); err != nil {
			t.Fatalf("sweep: %v", err)
		}
		keys = append(keys, repo.appends[len(repo.appends)-1].idempotencyKey)
	}
	if keys[0] != keys[1] {
		t.Errorf("two sweeps of one lapsed claim derived %q and %q; the second append "+
			"would be a SECOND release event rather than a collapsed duplicate",
			keys[0], keys[1])
	}
	if keys[0] == "" {
		t.Error("the release was appended with no idempotency key, so a retry writes again")
	}
}

// A later lease on the same address is a DIFFERENT claim. If it derived the same
// id, its release would be discarded as a duplicate of the first one and the
// address would stay held with nothing reporting it.
func TestALaterLeaseOnTheSameAddressDerivesADifferentKey(t *testing.T) {
	first := time.Date(2026, 8, 13, 9, 0, 0, 0, time.UTC)
	second := first.Add(72 * time.Hour)
	repo := newFakeRepo()

	keys := make([]string, 0, 2)
	for _, deadline := range []time.Time{first, second} {
		list := &fakeList{batches: [][]app.LapsedReservation{{row("aa11", "sub_1", deadline)}}}
		repo.aggs["aa11"] = held(t, "aa11", "sub_1", deadline)
		if _, err := newSweep(t, list, repo).SweepOnce(context.Background(), deadline.Add(time.Hour), 10); err != nil {
			t.Fatalf("sweep: %v", err)
		}
		keys = append(keys, repo.appends[len(repo.appends)-1].idempotencyKey)
	}
	if keys[0] == keys[1] {
		t.Error("two different leases on one address derived the same id; the second " +
			"release would be silently discarded as a duplicate")
	}
}

// The batch is full, so there is very likely more. Saying so is what makes the
// workflow loop instead of reporting a drained list.
func TestAFullBatchReportsMore(t *testing.T) {
	deadline := time.Date(2026, 8, 13, 9, 0, 0, 0, time.UTC)
	list := &fakeList{batches: [][]app.LapsedReservation{{
		row("aa11", "sub_1", deadline), row("bb22", "sub_2", deadline),
	}}}
	repo := newFakeRepo()
	repo.aggs["aa11"] = held(t, "aa11", "sub_1", deadline)
	repo.aggs["bb22"] = held(t, "bb22", "sub_2", deadline)

	got, err := newSweep(t, list, repo).SweepOnce(context.Background(), deadline.Add(time.Hour), 2)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if !got.More {
		t.Fatal("a pass that filled its limit reported nothing left; the rest of the " +
			"backlog stays held with nothing saying so")
	}
}

// Nothing personal may cross into workflow history or into a released event.
// The index is a keyed HMAC and the subject is a pseudonym; an address is
// neither, and crypto-shredding cannot reach a durable, replicated history
// (ADR-002).
func TestNothingPersonalCrossesTheBoundary(t *testing.T) {
	deadline := time.Date(2026, 8, 13, 9, 0, 0, 0, time.UTC)
	list := &fakeList{batches: [][]app.LapsedReservation{{row("aa11", "sub_1", deadline)}}}
	repo := newFakeRepo()
	repo.aggs["aa11"] = held(t, "aa11", "sub_1", deadline)

	if _, err := newSweep(t, list, repo).SweepOnce(context.Background(), deadline.Add(time.Hour), 10); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	meta := repo.appends[0].meta
	if len(meta.SubjectIDs) != 1 || meta.SubjectIDs[0] != "sub_1" {
		t.Errorf("subjects %v, want the pseudonym that held the claim", meta.SubjectIDs)
	}
	if meta.ActorID != "" {
		t.Errorf("actor %q: nobody performed this release, a deadline passed — naming a "+
			"person makes it look like an action they took", meta.ActorID)
	}
	if !meta.OccurredAt.Equal(meta.OccurredAt.UTC()) {
		t.Errorf("occurred at %s, which is not UTC", meta.OccurredAt)
	}
	// The workflow argument itself carries no per-reservation data at all.
	var in any = temporaladapter.SweepReservationsInput{Batch: 1, MaxPasses: 1}
	if _, ok := in.(interface{ Address() string }); ok {
		t.Error("the workflow input can carry an address")
	}
}

// A sweep constructed with a missing half would run to completion and free
// nothing, reporting success the whole way.
func TestTheSweepRefusesToBeBuiltHalfWired(t *testing.T) {
	if _, err := app.NewReservationSweep(nil, newFakeRepo(), nil); err == nil {
		t.Error("a sweep was built with no work list")
	}
	if _, err := app.NewReservationSweep(&fakeList{}, nil, nil); err == nil {
		t.Error("a sweep was built with no reservation repository")
	}
}

// A non-positive limit is refused rather than treated as "no bound". Passing it
// through would turn a configuration slip into a query with LIMIT 0, which
// returns nothing and looks exactly like an empty backlog.
func TestANonPositiveLimitIsRefused(t *testing.T) {
	s := newSweep(t, &fakeList{}, newFakeRepo())
	if _, err := s.SweepOnce(context.Background(), time.Now(), 0); err == nil {
		t.Error("a limit of zero was accepted")
	}
}

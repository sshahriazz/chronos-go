package temporal_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/testsuite"
)

// ---------------------------------------------------------------------------
// Fake
// ---------------------------------------------------------------------------

// fakeResealer hands out one scripted batch per (kind, call), so a test can say
// "the first pass fills its limit and the second does not" — the only thing that
// makes the workflow's per-kind loop observable.
type fakeResealer struct {
	kinds    []string
	batches  map[string][]temporaladapter.ResealBatch
	calls    map[string]int
	err      error
	kindsErr error

	// cursors records the After value each pass was given, which is what proves
	// the workflow carries the cursor forward rather than restarting the page.
	cursors []string
	limits  []int
}

func newFakeResealer(kinds ...string) *fakeResealer {
	return &fakeResealer{
		kinds:   kinds,
		batches: map[string][]temporaladapter.ResealBatch{},
		calls:   map[string]int{},
	}
}

func (f *fakeResealer) Kinds() []string {
	if f.kindsErr != nil {
		return nil
	}
	return f.kinds
}

func (f *fakeResealer) ResealOnce(
	_ context.Context, kind, after string, limit int,
) (temporaladapter.ResealBatch, error) {
	f.calls[kind]++
	f.cursors = append(f.cursors, after)
	f.limits = append(f.limits, limit)
	if f.err != nil {
		return temporaladapter.ResealBatch{}, f.err
	}
	scripted := f.batches[kind]
	if f.calls[kind] > len(scripted) {
		return temporaladapter.ResealBatch{Counted: true}, nil
	}
	return scripted[f.calls[kind]-1], nil
}

func runReseal(
	t *testing.T, r temporaladapter.CredentialResealer, in temporaladapter.ResealCredentialKeysInput,
) (temporaladapter.ResealCredentialKeysResult, error) {
	t.Helper()
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	activities, err := temporaladapter.NewResealActivities(r)
	if err != nil {
		t.Fatalf("activities: %v", err)
	}
	temporaladapter.RegisterResealForTest(env, activities)

	env.ExecuteWorkflow(temporaladapter.ResealCredentialKeys, in)
	if !env.IsWorkflowCompleted() {
		t.Fatal("the workflow did not complete")
	}
	var out temporaladapter.ResealCredentialKeysResult
	if err := env.GetWorkflowError(); err != nil {
		return out, err
	}
	if err := env.GetWorkflowResult(&out); err != nil {
		t.Fatalf("reading the result: %v", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// The workflow
// ---------------------------------------------------------------------------

// The workflow's whole job: do every bit of I/O in an ACTIVITY. The test
// environment fails the run if the workflow reads a clock, reaches the network
// or is otherwise non-deterministic, which is what makes this worth more than
// "it returned a number".
func TestReseal_RunsBothKindsThroughActivitiesAndReportsPerKind(t *testing.T) {
	f := newFakeResealer("password", "totp")
	f.batches["password"] = []temporaladapter.ResealBatch{
		{Version: 2, Scanned: 3, Resealed: 3, Cursor: "cred_c", Remaining: 0, Counted: true},
	}
	f.batches["totp"] = []temporaladapter.ResealBatch{
		{Version: 5, Scanned: 2, Resealed: 1, Skipped: 1, Cursor: "cred_z", Remaining: 0, Counted: true},
	}

	res, err := runReseal(t, f, temporaladapter.ResealCredentialKeysInput{Batch: 10, MaxPasses: 3})
	if err != nil {
		t.Fatalf("running: %v", err)
	}
	if len(res.Kinds) != 2 {
		t.Fatalf("%d kinds in the result; both key sets must be reported separately, "+
			"because their version sequences are unrelated", len(res.Kinds))
	}
	if res.Kinds[0].Kind != "password" || res.Kinds[0].Version != 2 {
		t.Errorf("first kind is %+v", res.Kinds[0])
	}
	if res.Kinds[1].Kind != "totp" || res.Kinds[1].Version != 5 {
		t.Errorf("second kind is %+v", res.Kinds[1])
	}
	if res.Resealed != 4 {
		t.Errorf("re-sealed %d, want 4 across both kinds", res.Resealed)
	}
	if !res.Complete {
		t.Error("both kinds report zero remaining, so the rotation IS complete and the " +
			"result must say so — it is the operator's only signal to destroy the old key")
	}
}

// The loop, and the cursor. A pass that fills its batch must be followed by one
// that resumes AFTER it — not one that re-reads the same page, which is what
// turns a single unfixable row into a job that never advances.
func TestReseal_LoopsWhileBatchesFillAndCarriesTheCursorForward(t *testing.T) {
	f := newFakeResealer("totp")
	f.batches["totp"] = []temporaladapter.ResealBatch{
		{Scanned: 2, Resealed: 2, Cursor: "cred_b", More: true, Remaining: 2, Counted: true},
		{Scanned: 2, Resealed: 2, Cursor: "cred_d", More: false, Remaining: 0, Counted: true},
	}

	res, err := runReseal(t, f, temporaladapter.ResealCredentialKeysInput{Batch: 2, MaxPasses: 5})
	if err != nil {
		t.Fatalf("running: %v", err)
	}
	if f.calls["totp"] != 2 {
		t.Fatalf("%d passes; the first batch filled, so a second was required", f.calls["totp"])
	}
	if want := []string{"", "cred_b"}; !slices.Equal(f.cursors, want) {
		t.Errorf("the passes resumed at %v, want %v; a workflow that restarts the page "+
			"cannot get past a row it could not re-seal", f.cursors, want)
	}
	if res.Kinds[0].Passes != 2 || res.Kinds[0].Resealed != 4 {
		t.Errorf("kind result %+v", res.Kinds[0])
	}
	if res.Kinds[0].Truncated {
		t.Error("the run finished inside its pass limit and must not report truncation")
	}
	if !res.Complete {
		t.Error("nothing is left, so the run is complete")
	}
}

// Truncation is REPORTED, never reported as completion. A run that quietly
// stopped at its limit reads as "everything is re-sealed" — and that reading is
// what gets a key destroyed while rows still need it.
func TestReseal_TruncationIsReportedAndIsNotCompletion(t *testing.T) {
	f := newFakeResealer("totp")
	f.batches["totp"] = []temporaladapter.ResealBatch{
		{Scanned: 2, Resealed: 2, Cursor: "cred_b", More: true, Remaining: 40, Counted: true},
		{Scanned: 2, Resealed: 2, Cursor: "cred_d", More: true, Remaining: 38, Counted: true},
	}

	res, err := runReseal(t, f, temporaladapter.ResealCredentialKeysInput{Batch: 2, MaxPasses: 2})
	if err != nil {
		t.Fatalf("running: %v", err)
	}
	if f.calls["totp"] != 2 {
		t.Fatalf("%d passes, want exactly the pass limit", f.calls["totp"])
	}
	if !res.Truncated || !res.Kinds[0].Truncated {
		t.Error("the run stopped at its pass limit with a full batch and did not say so")
	}
	if res.Complete {
		t.Fatal("a truncated run reported the rotation complete; this is the answer that " +
			"destroys a key rows still depend on")
	}
	if res.Kinds[0].Remaining != 38 {
		t.Errorf("remaining %d; the last pass's count is the answer", res.Kinds[0].Remaining)
	}
}

// An empty page is not completion. The COUNT is what decides, and a pass that
// scanned nothing while rows remain is a STALLED rotation, not a finished one.
func TestReseal_AnEmptyPageWithRowsRemainingIsNotComplete(t *testing.T) {
	f := newFakeResealer("totp")
	f.batches["totp"] = []temporaladapter.ResealBatch{
		{Scanned: 0, Cursor: "cred_z", More: false, Remaining: 7, Counted: true},
	}

	res, err := runReseal(t, f, temporaladapter.ResealCredentialKeysInput{Batch: 10, MaxPasses: 3})
	if err != nil {
		t.Fatalf("running: %v", err)
	}
	if res.Complete {
		t.Fatal("an empty page was reported as a completed rotation; the whole reason the " +
			"done check is a separate COUNT is that a page can be empty because everything " +
			"left is behind the cursor")
	}
	if res.Kinds[0].Remaining != 7 {
		t.Errorf("remaining %d, want 7", res.Kinds[0].Remaining)
	}
}

// A done check that never RAN must not read as zero.
func TestReseal_AnUncountedPassIsNeverComplete(t *testing.T) {
	f := newFakeResealer("totp")
	f.batches["totp"] = []temporaladapter.ResealBatch{
		{Scanned: 1, Resealed: 1, Cursor: "cred_a", Remaining: 0, Counted: false},
	}

	res, err := runReseal(t, f, temporaladapter.ResealCredentialKeysInput{Batch: 10, MaxPasses: 3})
	if err != nil {
		t.Fatalf("running: %v", err)
	}
	if res.Complete {
		t.Fatal("a run whose done check never ran reported the rotation complete; zero and " +
			"'not measured' are the same number and must not be the same answer")
	}
}

// Unopenable rows are summed and surfaced at the top level, because they are the
// one outcome that means an account is about to lose an authentication method.
func TestReseal_UnopenableRowsSurfaceInTheResult(t *testing.T) {
	f := newFakeResealer("password", "totp")
	f.batches["password"] = []temporaladapter.ResealBatch{
		{Scanned: 4, Resealed: 3, Unopenable: 1, Cursor: "cred_d", Remaining: 1, Counted: true},
	}
	f.batches["totp"] = []temporaladapter.ResealBatch{
		{Scanned: 1, Resealed: 1, Cursor: "cred_x", Remaining: 0, Counted: true},
	}

	res, err := runReseal(t, f, temporaladapter.ResealCredentialKeysInput{Batch: 10, MaxPasses: 2})
	if err != nil {
		t.Fatalf("running: %v", err)
	}
	if res.Unopenable != 1 {
		t.Errorf("unopenable %d, want 1", res.Unopenable)
	}
	if res.Complete {
		t.Error("a kind with a row nobody can open is not a completed rotation")
	}
}

// A failing activity fails the RUN. "The re-sealing job is broken" and "there
// was nothing left to re-seal" must never look alike, because one of them is the
// operator's signal to destroy a key.
func TestReseal_AFailingPassFailsTheRun(t *testing.T) {
	f := newFakeResealer("totp")
	f.err = errors.New("connection reset")

	res, err := runReseal(t, f, temporaladapter.ResealCredentialKeysInput{Batch: 2, MaxPasses: 1})
	if err == nil {
		t.Fatal("a run whose pass could not be attempted reported success")
	}
	if res.Complete {
		t.Error("a failed run must never carry Complete: true")
	}
}

// A deployment with no resealers wired must FAIL rather than report an empty,
// completed rotation.
func TestReseal_ADeploymentWithNoKindsWiredFailsTheRun(t *testing.T) {
	f := newFakeResealer()

	if _, err := runReseal(t, f, temporaladapter.ResealCredentialKeysInput{}); err == nil {
		t.Fatal("a run with no credential kind wired reported success; it would appear in " +
			"the UI as a completed rotation over rows nothing touched")
	}
}

// Defaults are applied inside the workflow, so a schedule that names neither
// bound still runs bounded work.
func TestReseal_DefaultsAreAppliedToAnEmptyInput(t *testing.T) {
	f := newFakeResealer("totp")
	f.batches["totp"] = []temporaladapter.ResealBatch{{Counted: true}}

	if _, err := runReseal(t, f, temporaladapter.ResealCredentialKeysInput{}); err != nil {
		t.Fatalf("running: %v", err)
	}
	if len(f.limits) == 0 || f.limits[0] <= 0 {
		t.Fatalf("the pass ran with limit %v; an unset batch must become a real bound, "+
			"not zero", f.limits)
	}
}

// ---------------------------------------------------------------------------
// The activity's own refusals
// ---------------------------------------------------------------------------

func TestResealActivities_RefuseInputsThatCouldNeverWork(t *testing.T) {
	t.Parallel()

	a, err := temporaladapter.NewResealActivities(newFakeResealer("totp"))
	if err != nil {
		t.Fatalf("activities: %v", err)
	}
	tests := []struct {
		name string
		in   temporaladapter.ResealBatchInput
	}{
		{"no kind selects no work list", temporaladapter.ResealBatchInput{Limit: 10}},
		{"a zero limit moves no rows", temporaladapter.ResealBatchInput{Kind: "totp"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := a.Reseal(t.Context(), tt.in); err == nil {
				t.Fatal("the activity accepted an input that can never move a row")
			}
		})
	}
}

func TestNewResealActivities_RefusesANilResealer(t *testing.T) {
	t.Parallel()
	if _, err := temporaladapter.NewResealActivities(nil); err == nil {
		t.Fatal("an activity set was built around nothing; every run would report a " +
			"completed rotation while re-sealing nothing")
	}
}

// ---------------------------------------------------------------------------
// The schedule
// ---------------------------------------------------------------------------

// The schedule's ACTION is the thing worth asserting without a server: a
// schedule naming a workflow no worker registers, or a queue no worker polls,
// creates runs that are queued where nothing is listening while every signal
// stays green.
func TestResealSchedule_NamesTheWorkflowTheWorkerRegisters(t *testing.T) {
	t.Parallel()

	opts := temporaladapter.ResealScheduleOptionsForTest(
		"chronos-queue", temporaladapter.ResealCredentialKeysInput{}, 0)

	if opts.ID != temporaladapter.ResealCredentialKeysScheduleID {
		t.Errorf("schedule id %q", opts.ID)
	}
	action, ok := opts.Action.(*client.ScheduleWorkflowAction)
	if !ok {
		t.Fatalf("the schedule's action is %T, not a workflow start", opts.Action)
	}
	if action.Workflow != temporaladapter.ResealCredentialKeysWorkflow {
		t.Errorf("the schedule starts %q, which is not the name the worker registers",
			action.Workflow)
	}
	if action.TaskQueue != "chronos-queue" {
		t.Errorf("the schedule targets queue %q", action.TaskQueue)
	}
	if opts.Overlap != enumspb.SCHEDULE_OVERLAP_POLICY_SKIP {
		t.Errorf("overlap policy %v; a buffered queue of identical passes is a pile-up "+
			"against the one identity table that is not rebuildable", opts.Overlap)
	}
	if opts.PauseOnFailure {
		t.Error("PauseOnFailure would leave a rotation half-finished with nothing saying so")
	}
	if opts.CatchupWindow != time.Hour {
		t.Errorf("catchup window %v; the work list is the current set of rows below the "+
			"current version, not a per-interval delta", opts.CatchupWindow)
	}
}

// The scheduled ARGUMENTS must already carry real bounds. A schedule is
// server-side state that EnsureResealSchedule deliberately never updates, so a
// zero left in there is a zero forever.
func TestResealSchedule_CarriesRealBoundsIntoTheAction(t *testing.T) {
	t.Parallel()

	opts := temporaladapter.ResealScheduleOptionsForTest(
		"q", temporaladapter.ResealCredentialKeysInput{}, 0)
	action := opts.Action.(*client.ScheduleWorkflowAction)
	if len(action.Args) != 1 {
		t.Fatalf("%d arguments", len(action.Args))
	}
	in, ok := action.Args[0].(temporaladapter.ResealCredentialKeysInput)
	if !ok {
		t.Fatalf("the argument is %T", action.Args[0])
	}
	if in.Batch <= 0 || in.MaxPasses <= 0 {
		t.Errorf("the schedule would start runs with batch %d and %d passes",
			in.Batch, in.MaxPasses)
	}
}

// The interval is a DECISION: this job is neither the sweep's fifteen minutes
// nor retention's day. It exists to make one operator question answerable, and
// hourly is what keeps a rotation completable inside a working day without
// putting an unindexed COUNT on the database every minute.
func TestResealSchedule_IntervalSitsBetweenTheSweepAndRetention(t *testing.T) {
	t.Parallel()

	if temporaladapter.DefaultResealInterval != time.Hour {
		t.Errorf("interval %v, want one hour", temporaladapter.DefaultResealInterval)
	}
	if temporaladapter.DefaultResealInterval <= temporaladapter.DefaultSweepInterval {
		t.Error("re-sealing runs at least as often as the reservation sweep; nobody is " +
			"blocked on a per-minute basis and each idle run still costs a COUNT per kind")
	}
	if temporaladapter.DefaultResealInterval >= temporaladapter.DefaultRetentionInterval {
		t.Error("re-sealing runs no more often than retention, which stretches a routine " +
			"rotation across days — and a key nobody can retire in reasonable time is a " +
			"key somebody destroys without waiting")
	}
}

// A nil client is a refusal, not a silent no-op: without a schedule the rotation
// never completes and nothing else reports it.
func TestEnsureResealSchedule_RefusesWithNoClient(t *testing.T) {
	t.Parallel()
	if _, err := temporaladapter.EnsureResealSchedule(
		t.Context(), nil, temporaladapter.ResealCredentialKeysInput{}, time.Hour,
	); err == nil {
		t.Fatal("scheduling reported success with no Temporal client")
	}
}

// The probe reports a MISSING schedule as unhealthy, including the
// TEMPORAL_ENABLED=false case — which is exactly the deployment where nothing
// recurring runs at all.
func TestResealProbe_ReportsAnUnscheduledJob(t *testing.T) {
	t.Parallel()

	p := temporaladapter.ResealCredentialKeysProbe(nil)
	if p.ID != temporaladapter.ResealCredentialKeysScheduleID {
		t.Errorf("the probe watches %q, not the schedule this job creates", p.ID)
	}
	if p.Impact() == "" {
		t.Error("the probe has no consequence, so whoever is paged learns nothing")
	}
	if err := p.Check(t.Context()); err == nil {
		t.Fatal("a probe with no client reported a healthy schedule")
	}
}

package temporal_test

import (
	"context"
	"errors"
	"testing"
	"time"

	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/client"
	sdktemporal "go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
)

// fakeRetainer stands in for the identity use case, recording what instant the
// activity was given.
type fakeRetainer struct {
	res  temporaladapter.PurgeRetentionResult
	err  error
	nows []time.Time
	runs int
}

func (f *fakeRetainer) PurgeOnce(
	_ context.Context, now time.Time,
) (temporaladapter.PurgeRetentionResult, error) {
	f.runs++
	f.nows = append(f.nows, now)
	return f.res, f.err
}

func retentionActivities(t *testing.T, r temporaladapter.IdentityRetainer) *temporaladapter.RetentionActivities {
	t.Helper()
	a, err := temporaladapter.NewRetentionActivities(r)
	if err != nil {
		t.Fatalf("building retention activities: %v", err)
	}
	return a
}

// okResult is a clean pass over all five statements.
func okResult() temporaladapter.PurgeRetentionResult {
	return temporaladapter.PurgeRetentionResult{
		Statements: []temporaladapter.StatementResult{
			{Statement: "totp_replay", Deleted: 5},
			{Statement: "identity_token", Deleted: 2},
			{Statement: "session_token", Deleted: 1},
			{Statement: "session_view", Deleted: 0},
			{Statement: "email_reservation_view", Deleted: 3},
		},
		Deleted: 11,
	}
}

// The whole run, through the SDK's test environment and through the SAME
// registration function the production worker uses.
func TestRetentionWorkflowRunsThePassAndReportsIt(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	retainer := &fakeRetainer{res: okResult()}
	temporaladapter.RegisterRetentionForTest(env, retentionActivities(t, retainer))

	env.ExecuteWorkflow(temporaladapter.PurgeIdentityRetentionWorkflow,
		temporaladapter.PurgeRetentionInput{})

	if !env.IsWorkflowCompleted() {
		t.Fatal("the workflow did not complete")
	}
	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("a clean pass failed the run: %v", err)
	}

	var got temporaladapter.PurgeRetentionResult
	if err := env.GetWorkflowResult(&got); err != nil {
		t.Fatalf("reading the result: %v", err)
	}
	if retainer.runs != 1 {
		t.Errorf("the use case ran %d times, want 1", retainer.runs)
	}
	if len(got.Statements) != 5 {
		t.Errorf("the result carries %d statements, want 5: a run that swept fewer tables "+
			"than it should must not be indistinguishable from one that swept them all",
			len(got.Statements))
	}
	if got.Deleted != 11 {
		t.Errorf("Deleted = %d, want 11", got.Deleted)
	}
}

// The activity is given the workflow's clock, not its own. A retried attempt and
// the original must agree about the horizon.
func TestRetentionWorkflowPassesTheWorkflowClockToTheActivity(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	start := time.Date(2026, 8, 13, 3, 0, 0, 0, time.UTC)
	env.SetStartTime(start)

	retainer := &fakeRetainer{res: okResult()}
	temporaladapter.RegisterRetentionForTest(env, retentionActivities(t, retainer))

	env.ExecuteWorkflow(temporaladapter.PurgeIdentityRetentionWorkflow,
		temporaladapter.PurgeRetentionInput{})

	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if len(retainer.nows) != 1 {
		t.Fatalf("the use case ran %d times, want 1", len(retainer.nows))
	}
	if retainer.nows[0].IsZero() {
		t.Fatal("the activity was given a zero instant, so every cutoff would be year 1 " +
			"and the horizon-bearing statements would delete nothing")
	}
	if !retainer.nows[0].Equal(start) {
		t.Errorf("the activity was given %s, want the workflow's own clock %s — an activity "+
			"that reads the clock itself makes a retry disagree with the original about the "+
			"horizon", retainer.nows[0], start)
	}
}

// Some statements failing is NOT a failed run: the others were still swept, and
// the failures are in the result where they can be seen.
func TestRetentionWorkflowSucceedsWhenSomeStatementsFail(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	res := okResult()
	res.Statements[0] = temporaladapter.StatementResult{
		Statement: "totp_replay", Error: "relation does not exist",
	}
	res.Failed = 1
	temporaladapter.RegisterRetentionForTest(env,
		retentionActivities(t, &fakeRetainer{res: res}))

	env.ExecuteWorkflow(temporaladapter.PurgeIdentityRetentionWorkflow,
		temporaladapter.PurgeRetentionInput{})

	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("one failing statement failed the whole run, so the four tables that were "+
			"swept are reported as if nothing happened: %v", err)
	}

	var got temporaladapter.PurgeRetentionResult
	if err := env.GetWorkflowResult(&got); err != nil {
		t.Fatalf("reading the result: %v", err)
	}
	if got.Failed != 1 {
		t.Errorf("Failed = %d, want 1", got.Failed)
	}
	if got.Statements[0].Error == "" {
		t.Error("the failure is absent from the result, so the run reports a clean pass over " +
			"a table that was never swept")
	}
}

// Every statement failing is a different fact: the database was unreachable or
// the grants are gone, and nothing was deleted at all. That must be a FAILED run,
// because a green run there is a retention job that has silently stopped.
func TestRetentionWorkflowFailsWhenEveryStatementFails(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	res := okResult()
	for i := range res.Statements {
		res.Statements[i] = temporaladapter.StatementResult{
			Statement: res.Statements[i].Statement, Error: "permission denied",
		}
	}
	res.Deleted, res.Failed = 0, len(res.Statements)
	temporaladapter.RegisterRetentionForTest(env,
		retentionActivities(t, &fakeRetainer{res: res}))

	env.ExecuteWorkflow(temporaladapter.PurgeIdentityRetentionWorkflow,
		temporaladapter.PurgeRetentionInput{})

	if env.GetWorkflowError() == nil {
		t.Fatal("a run in which every statement failed reported success; retention is off " +
			"and every signal is green")
	}
}

// A pass that could not be attempted must fail the run rather than report an
// empty success — "retention is broken" and "there was nothing to delete" look
// identical otherwise.
func TestRetentionWorkflowFailsWhenThePassCannotBeAttempted(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	temporaladapter.RegisterRetentionForTest(env,
		retentionActivities(t, &fakeRetainer{err: errors.New("pool exhausted")}))

	env.ExecuteWorkflow(temporaladapter.PurgeIdentityRetentionWorkflow,
		temporaladapter.PurgeRetentionInput{})

	if env.GetWorkflowError() == nil {
		t.Fatal("an unattemptable pass reported success")
	}
}

// The activity refuses a zero instant PERMANENTLY rather than retrying it: no
// number of attempts turns a missing clock reading into a horizon, and a
// retryable refusal would spend the run's whole retry budget on an input that
// cannot become valid.
func TestRetentionActivityRefusesAZeroInstant(t *testing.T) {
	retainer := &fakeRetainer{res: okResult()}

	_, err := retentionActivities(t, retainer).Purge(context.Background(),
		temporaladapter.PurgeRetentionActivityInput{})
	if err == nil {
		t.Fatal("a zero instant was accepted; every cutoff would be year 1 and the " +
			"horizon-bearing statements would delete nothing while reporting success")
	}
	if retainer.runs != 0 {
		t.Errorf("the use case ran %d times on an input the activity should have refused",
			retainer.runs)
	}

	var appErr *sdktemporal.ApplicationError
	if !errors.As(err, &appErr) {
		t.Fatalf("the refusal is %T, not an application error, so Temporal will retry it", err)
	}
	if !appErr.NonRetryable() {
		t.Error("the refusal is retryable, so an input that can never become valid consumes " +
			"the run's whole retry budget")
	}
}

// An activity set with no retainer would panic on the first task rather than fail
// to be built, so the refusal has to happen at construction.
func TestRetentionActivitiesRefuseANilRetainer(t *testing.T) {
	if _, err := temporaladapter.NewRetentionActivities(nil); err == nil {
		t.Fatal("an activity set was built with no retainer; every run would report success " +
			"while deleting nothing")
	}
}

// The schedule must name the workflow the worker registers and the queue it
// polls. A mismatch queues runs where nothing is listening: the run is created,
// the schedule looks healthy, and nothing is ever deleted.
func TestTheRetentionScheduleNamesWhatTheWorkerAnswersTo(t *testing.T) {
	opts := temporaladapter.RetentionScheduleOptionsForTest("chronos-queue",
		temporaladapter.PurgeRetentionInput{}, temporaladapter.DefaultRetentionInterval)

	if opts.ID != temporaladapter.PurgeRetentionScheduleID {
		t.Errorf("schedule id = %q, want %q", opts.ID, temporaladapter.PurgeRetentionScheduleID)
	}
	action, ok := opts.Action.(*client.ScheduleWorkflowAction)
	if !ok {
		t.Fatalf("the schedule action is %T, not a workflow action", opts.Action)
	}
	if action.Workflow != temporaladapter.PurgeIdentityRetentionWorkflow {
		t.Errorf("the schedule starts %q but the worker answers to %q, so every run is "+
			"queued where nothing is listening",
			action.Workflow, temporaladapter.PurgeIdentityRetentionWorkflow)
	}
	if action.TaskQueue != "chronos-queue" {
		t.Errorf("task queue = %q, want the client's own queue", action.TaskQueue)
	}
	if len(opts.Spec.Intervals) != 1 || opts.Spec.Intervals[0].Every != 24*time.Hour {
		t.Errorf("interval = %v, want a daily one: retention is housekeeping, and running "+
			"five unbounded DELETEs more often buys nothing", opts.Spec.Intervals)
	}
	if opts.Overlap != enumspb.SCHEDULE_OVERLAP_POLICY_SKIP {
		t.Errorf("overlap policy = %v, want SKIP. Buffering identical retention passes turns "+
			"one slow run after an outage into a pile-up of work the first pass already did",
			opts.Overlap)
	}
	if opts.CatchupWindow != time.Hour {
		t.Errorf("catchup window = %v, want one hour. Retention is defined by a CUTOFF and "+
			"not by a per-interval delta, so replaying a month of missed daily runs achieves "+
			"exactly what tomorrow's single run achieves", opts.CatchupWindow)
	}
	if opts.PauseOnFailure {
		t.Error("PauseOnFailure would turn one transient database failure into retention " +
			"that is switched off until somebody notices — and nobody notices, because an " +
			"unswept table looks exactly like one with nothing to sweep")
	}
}

// The retention schedule must be a SECOND schedule, not a rename of the sweep's.
// One id serving both would leave whichever was created second silently absent.
func TestTheRetentionAndSweepSchedulesAreDistinct(t *testing.T) {
	if temporaladapter.PurgeRetentionScheduleID == temporaladapter.SweepReservationsScheduleID {
		t.Fatal("retention and the reservation sweep share a schedule id, so only one of " +
			"them is ever created and the other never runs")
	}
	if temporaladapter.PurgeIdentityRetentionWorkflow == temporaladapter.SweepReservationsWorkflow {
		t.Fatal("retention and the reservation sweep share a workflow name")
	}
	// Retention is housekeeping and the sweep is a security control; if these ever
	// converge, one of the two has had its cadence reasoned about wrongly.
	if temporaladapter.DefaultRetentionInterval <= temporaladapter.DefaultSweepInterval {
		t.Errorf("retention runs every %v and the reservation sweep every %v; the sweep is a "+
			"security control whose interval is a user-visible window, and retention is not",
			temporaladapter.DefaultRetentionInterval, temporaladapter.DefaultSweepInterval)
	}
}

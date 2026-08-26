package temporal_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	complianceapp "github.com/chronos/chronos-go/internal/modules/compliance/app"
	"go.temporal.io/sdk/testsuite"

	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
)

const erasureSubject = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV"

// fakeErasure is the state the workflow reads and the erasure it performs.
//
// The snapshot is a FUNCTION of the read count, so a test can make the state
// change between wakes — which is the whole behaviour under test: a request
// cancelled while the workflow sleeps must stop it.
type fakeErasure struct {
	snapshots []temporaladapter.ErasureSnapshot
	stateErr  error

	reads    int
	erased   int
	eraseErr error

	// holdFor makes the first N attempts report a legal hold, after which the
	// matter closes. holdForever never lifts.
	//
	// They model compliance's ErrHeld rather than a generic failure, because
	// the distinction is the entire subject of the tests that use them: the
	// activity must translate a hold into a NON-RETRYABLE application error so
	// the workflow waits, instead of letting the retry policy grind.
	holdFor     int
	holdForever bool
	attempts    int
}

func (f *fakeErasure) ErasureState(
	_ context.Context, _ string,
) (temporaladapter.ErasureSnapshot, error) {
	if f.stateErr != nil {
		return temporaladapter.ErasureSnapshot{}, f.stateErr
	}
	i := f.reads
	f.reads++
	if i >= len(f.snapshots) {
		i = len(f.snapshots) - 1
	}
	return f.snapshots[i], nil
}

func (f *fakeErasure) Execute(_ context.Context, subjectID string) error {
	f.attempts++
	if f.eraseErr != nil {
		return f.eraseErr
	}
	if f.holdForever || f.attempts <= f.holdFor {
		return fmt.Errorf("%w: matter %q", complianceapp.ErrHeld, "litigation 2026-4711")
	}
	f.erased++
	return nil
}

func runErasure(
	t *testing.T, env *testsuite.TestWorkflowEnvironment, f *fakeErasure,
) (temporaladapter.ErasureResult, error) {
	t.Helper()

	state, err := temporaladapter.NewErasureState(f)
	if err != nil {
		t.Fatal(err)
	}
	execute, err := temporaladapter.NewExecuteErasure(f)
	if err != nil {
		t.Fatal(err)
	}
	temporaladapter.RegisterErasureForTest(env, state, execute)

	env.ExecuteWorkflow(temporaladapter.ErasureWorkflow,
		temporaladapter.ErasureInput{SubjectID: erasureSubject})
	if !env.IsWorkflowCompleted() {
		t.Fatal("the workflow did not complete")
	}

	var result temporaladapter.ErasureResult
	if err := env.GetWorkflowError(); err != nil {
		return result, err
	}
	if err := env.GetWorkflowResult(&result); err != nil {
		t.Fatalf("decoding the result: %v", err)
	}
	return result, nil
}

// A REQUEST NOBODY WITHDRAWS IS ERASED WHEN ITS DEADLINE ARRIVES.
//
// The whole point of the workflow. Without it a person asks to be forgotten, is
// told a date, and is still in the database after it — with nothing anywhere
// reporting a failure.
func TestAnUntouchedRequestIsErasedAtItsDeadline(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	f := &fakeErasure{snapshots: []temporaladapter.ErasureSnapshot{{
		Exists: true, Requested: true,
		ScheduledFor: env.Now().Add(30 * 24 * time.Hour).UTC(),
	}}}

	result, err := runErasure(t, env, f)
	if err != nil {
		t.Fatalf("the erasure failed: %v", err)
	}
	if f.erased != 1 {
		t.Fatalf("erased %d times, want 1; the request was recorded and never executed",
			f.erased)
	}
	if result.Outcome != "erased" {
		t.Errorf("outcome %q, want erased", result.Outcome)
	}
}

// A CANCELLATION DURING THE GRACE PERIOD STOPS IT.
//
// The grace period exists to be USED, and this is the assertion that makes it
// real. A workflow that slept to its deadline and then erased would destroy the
// account of somebody who changed their mind an hour after asking — and they
// would have no way to discover it until it was gone.
//
// The snapshot CHANGES between the first read and the second, which is exactly
// what a cancellation looks like from inside the run.
func TestACancellationDuringTheGracePeriodStopsTheErasure(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	deadline := env.Now().Add(30 * 24 * time.Hour).UTC()

	f := &fakeErasure{snapshots: []temporaladapter.ErasureSnapshot{
		{Exists: true, Requested: true, ScheduledFor: deadline},
		// Woken at the deadline, and by then withdrawn.
		{Exists: true, Requested: false, ScheduledFor: deadline},
	}}

	result, err := runErasure(t, env, f)
	if err != nil {
		t.Fatalf("the workflow failed: %v", err)
	}
	if f.erased != 0 {
		t.Fatal("an account was erased after its request was withdrawn; the grace period " +
			"is decoration and the cancel button is a lie the person cannot discover " +
			"until their account is gone")
	}
	if result.Outcome != "cancelled" {
		t.Errorf("outcome %q, want cancelled", result.Outcome)
	}
}

// A DEADLINE THAT MOVES IS FOLLOWED, NOT PRE-EMPTED.
//
// A cancel-then-request cycle produces a later date while this run may still be
// sleeping. A workflow that acted on the deadline it was started with would
// erase early — before the window the person was told about had run out.
func TestALaterDeadlineIsWaitedOut(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	first := env.Now().Add(30 * 24 * time.Hour).UTC()
	later := first.Add(30 * 24 * time.Hour)

	f := &fakeErasure{snapshots: []temporaladapter.ErasureSnapshot{
		{Exists: true, Requested: true, ScheduledFor: first},
		// Woken at the first deadline; the request now names a later one.
		{Exists: true, Requested: true, ScheduledFor: later},
		{Exists: true, Requested: true, ScheduledFor: later},
	}}

	result, err := runErasure(t, env, f)
	if err != nil {
		t.Fatalf("the workflow failed: %v", err)
	}
	if f.erased != 1 {
		t.Fatalf("erased %d times, want 1", f.erased)
	}
	if f.reads < 3 {
		t.Errorf("read the state %d times; a run that acted on its first read would erase "+
			"before the window the person was told about had run out", f.reads)
	}
	if result.Outcome != "erased" {
		t.Errorf("outcome %q, want erased", result.Outcome)
	}
}

// AN ALREADY-ERASED SUBJECT ENDS THE RUN WITHOUT ERASING AGAIN.
//
// Reachable when a redelivery starts a second run for an account the first
// already finished.
func TestAnAlreadyErasedSubjectEndsTheRun(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	f := &fakeErasure{snapshots: []temporaladapter.ErasureSnapshot{{
		Exists: true, Requested: true, Erased: true,
		ScheduledFor: env.Now().Add(-time.Hour).UTC(),
	}}}

	result, err := runErasure(t, env, f)
	if err != nil {
		t.Fatalf("the workflow failed: %v", err)
	}
	if f.erased != 0 {
		t.Error("an already-erased account was erased again")
	}
	if result.Outcome != "erased" {
		t.Errorf("outcome %q, want erased", result.Outcome)
	}
}

// A SUBJECT WITH NO ACCOUNT ENDS THE RUN.
func TestASubjectWithNoAccountEndsTheRun(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	f := &fakeErasure{snapshots: []temporaladapter.ErasureSnapshot{{Exists: false}}}

	result, err := runErasure(t, env, f)
	if err != nil {
		t.Fatalf("the workflow failed: %v", err)
	}
	if f.erased != 0 {
		t.Error("a subject with no account was erased")
	}
	if result.Outcome != "gone" {
		t.Errorf("outcome %q, want gone", result.Outcome)
	}
}

// A DEADLINE ALREADY PAST ERASES ON THE FIRST WAKE.
//
// The backlog case: a request whose deadline passed while nothing was running.
func TestAPastDeadlineErasesImmediately(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	f := &fakeErasure{snapshots: []temporaladapter.ErasureSnapshot{{
		Exists: true, Requested: true,
		ScheduledFor: env.Now().Add(-24 * time.Hour).UTC(),
	}}}

	if _, err := runErasure(t, env, f); err != nil {
		t.Fatalf("the workflow failed: %v", err)
	}
	if f.erased != 1 {
		t.Fatalf("erased %d times, want 1; an overdue request was never executed", f.erased)
	}
}

// A FAILING ERASURE DOES NOT REPORT SUCCESS.
//
// Unlimited retries mean the workflow keeps trying; what must never happen is a
// run that ends "erased" having erased nothing, because the only record of the
// obligation is then a workflow that says it was met.
func TestAFailingErasureDoesNotReportSuccess(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	f := &fakeErasure{
		snapshots: []temporaladapter.ErasureSnapshot{{
			Exists: true, Requested: true,
			ScheduledFor: env.Now().Add(-time.Hour).UTC(),
		}},
		eraseErr: errors.New("openbao: connection refused"),
	}

	result, err := runErasure(t, env, f)
	if err == nil {
		t.Fatal("a failing erasure completed successfully; the only record of an unmet " +
			"legal obligation is a workflow saying it was met")
	}
	if result.Outcome == "erased" {
		t.Error("the result claims erased")
	}
}

// AN EMPTY SUBJECT IS REFUSED PERMANENTLY.
func TestAnErasureWithNoSubjectIsRefused(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	f := &fakeErasure{snapshots: []temporaladapter.ErasureSnapshot{{Exists: true}}}
	state, err := temporaladapter.NewErasureState(f)
	if err != nil {
		t.Fatal(err)
	}
	execute, err := temporaladapter.NewExecuteErasure(f)
	if err != nil {
		t.Fatal(err)
	}
	temporaladapter.RegisterErasureForTest(env, state, execute)

	env.ExecuteWorkflow(temporaladapter.ErasureWorkflow, temporaladapter.ErasureInput{})
	if !env.IsWorkflowCompleted() {
		t.Fatal("the workflow did not complete")
	}
	if env.GetWorkflowError() == nil {
		t.Fatal("an erasure with no subject was accepted")
	}
}

// THE ACTIVITIES REFUSE AN INCOMPLETE WIRING.
func TestTheErasureActivitiesRefuseAnIncompleteWiring(t *testing.T) {
	if _, err := temporaladapter.NewErasureState(nil); err == nil {
		t.Error("a state activity with no reader was accepted")
	}
	if _, err := temporaladapter.NewExecuteErasure(nil); err == nil {
		t.Error("an execute activity with no eraser was accepted")
	}
}

// A LEGAL HOLD MAKES THE WORKFLOW WAIT, NOT FAIL AND NOT STORM.
//
// # The three wrong answers this asserts against
//
// A hold is not a failure — the request is DEFERRED and executes automatically
// when the hold lifts (compliance.md §7) — so all three obvious behaviours are
// wrong in a different way:
//
//   - FAIL the run: ends a request that is still live. The person asked to be
//     forgotten, was told it would happen, and the workflow that would have
//     done it is gone.
//   - RETRY the activity: the policy here has NO attempt limit and a one-minute
//     maximum backoff, so a hold that runs for a month is a query per minute
//     for a month, to learn something that changes once.
//   - COMPLETE as erased: destroys nothing and reports success, which is the
//     worst of the three because it is the one nobody investigates.
//
// The right answer is to sleep and re-check on a cadence chosen for how often
// the answer actually changes.
func TestALegalHoldMakesTheWorkflowWaitRatherThanRetry(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	f := &fakeErasure{
		snapshots: []temporaladapter.ErasureSnapshot{
			{Exists: true, Requested: true, ScheduledFor: time.Now().Add(-time.Hour)},
		},
		// Held for the first two attempts, then the matter closes.
		holdFor: 2,
	}

	result, err := runErasure(t, env, f)
	if err != nil {
		t.Fatalf("a deferred erasure failed the run: %v\n\n"+
			"A hold is not a failure — the request is deferred and executes "+
			"automatically when the hold lifts. Failing ends a request that is "+
			"still live.", err)
	}
	if result.Outcome != "erased" {
		t.Fatalf("outcome = %q, want erased once the hold lifted", result.Outcome)
	}

	// THREE calls: two refused by the hold, one that ran. If the activity had
	// been left retryable the count would be far higher — the retry policy has
	// no attempt limit — and the workflow would never have reached its own
	// sleep.
	if f.attempts != 3 {
		t.Errorf("the erasure was attempted %d times, want 3 (two held, one erased).\n\n"+
			"A much higher count means the activity is RETRYING the hold rather than "+
			"failing fast and letting the workflow wait — which is a query per minute "+
			"for the length of a legal matter.", f.attempts)
	}
	if f.erased != 1 {
		t.Errorf("the subject was erased %d times", f.erased)
	}
}

// A HOLD THAT NEVER LIFTS LEAVES THE WORKFLOW WAITING, NOT FINISHED.
//
// The complement of the test above, and the one that catches the most dangerous
// wrong answer: a deferral that completes the run as "erased" would report
// success while the data is still there, and nothing downstream would look
// again.
func TestAHoldThatNeverLiftsLeavesTheRequestOpen(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	f := &fakeErasure{
		snapshots: []temporaladapter.ErasureSnapshot{
			{Exists: true, Requested: true, ScheduledFor: time.Now().Add(-time.Hour)},
		},
		holdForever: true,
	}

	state, err := temporaladapter.NewErasureState(f)
	if err != nil {
		t.Fatal(err)
	}
	execute, err := temporaladapter.NewExecuteErasure(f)
	if err != nil {
		t.Fatal(err)
	}
	temporaladapter.RegisterErasureForTest(env, state, execute)

	// The test environment runs a workflow's timers instantly, so a run that
	// sleeps forever would loop forever. Cutting it off after a bounded number
	// of attempts is what makes "still waiting" observable at all.
	env.RegisterDelayedCallback(func() { env.CancelWorkflow() }, 30*24*time.Hour)

	env.ExecuteWorkflow(temporaladapter.ErasureWorkflow,
		temporaladapter.ErasureInput{SubjectID: erasureSubject})

	if !env.IsWorkflowCompleted() {
		t.Fatal("the workflow did not complete")
	}

	// It must NOT have erased, and it must NOT have reported success.
	if f.erased != 0 {
		t.Errorf("a permanently held subject was erased %d times", f.erased)
	}

	var result temporaladapter.ErasureResult
	if err := env.GetWorkflowError(); err == nil {
		_ = env.GetWorkflowResult(&result)
		if result.Outcome == "erased" {
			t.Fatal("a permanently held erasure reported itself as ERASED. Nothing " +
				"downstream looks again, so the data stays and the request is closed.")
		}
	}

	// And it kept asking, rather than giving up after the first refusal.
	if f.attempts < 2 {
		t.Errorf("the erasure was attempted %d times over thirty days; a deferred "+
			"request must keep re-checking, because the hold lifting is the only "+
			"thing that completes it", f.attempts)
	}
}

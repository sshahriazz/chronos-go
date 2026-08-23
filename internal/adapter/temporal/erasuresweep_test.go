package temporal_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/testsuite"

	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
)

type fakeErasureSweeper struct {
	passes []temporaladapter.ErasureSweepPass
	err    error

	calls int
	nows  []time.Time
	limit int
}

func (f *fakeErasureSweeper) SweepOnce(
	_ context.Context, now time.Time, limit int,
) (temporaladapter.ErasureSweepPass, error) {
	f.nows = append(f.nows, now)
	f.limit = limit
	if f.err != nil {
		return temporaladapter.ErasureSweepPass{}, f.err
	}
	i := f.calls
	f.calls++
	if i >= len(f.passes) {
		i = len(f.passes) - 1
	}
	return f.passes[i], nil
}

func runErasureSweep(
	t *testing.T, s *fakeErasureSweeper, in temporaladapter.SweepErasuresInput,
) (temporaladapter.SweepErasuresResult, error) {
	t.Helper()
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	a, err := temporaladapter.NewErasureSweepActivities(s)
	if err != nil {
		t.Fatal(err)
	}
	temporaladapter.RegisterErasureSweepForTest(env, a)

	env.ExecuteWorkflow(temporaladapter.SweepErasuresWorkflow, in)
	if !env.IsWorkflowCompleted() {
		t.Fatal("the workflow did not complete")
	}
	var result temporaladapter.SweepErasuresResult
	if err := env.GetWorkflowError(); err != nil {
		return result, err
	}
	if err := env.GetWorkflowResult(&result); err != nil {
		t.Fatalf("decoding the result: %v", err)
	}
	return result, nil
}

// ONE PASS ENDS THE RUN WHEN THE BATCH IS SHORT.
func TestASingleShortPassEndsTheSweep(t *testing.T) {
	s := &fakeErasureSweeper{passes: []temporaladapter.ErasureSweepPass{
		{Scanned: 3, Started: 1},
	}}

	res, err := runErasureSweep(t, s, temporaladapter.SweepErasuresInput{})
	if err != nil {
		t.Fatal(err)
	}
	if s.calls != 1 {
		t.Fatalf("ran %d passes, want 1", s.calls)
	}
	if res.Started != 1 || res.Scanned != 3 {
		t.Errorf("got started=%d scanned=%d", res.Started, res.Scanned)
	}
}

// A FULL BATCH PAGES.
//
// Without it a backlog drains one batch per SCHEDULED RUN — six hours each —
// and the requests at the back sit past their deadline for days.
func TestAFullBatchPagesWithinOneRun(t *testing.T) {
	s := &fakeErasureSweeper{passes: []temporaladapter.ErasureSweepPass{
		{Scanned: 2, Started: 2, More: true},
		{Scanned: 2, Started: 1, More: true},
		{Scanned: 1, Started: 0},
	}}

	res, err := runErasureSweep(t, s, temporaladapter.SweepErasuresInput{Batch: 2})
	if err != nil {
		t.Fatal(err)
	}
	if s.calls != 3 {
		t.Fatalf("ran %d passes, want 3; the backlog drains one batch per scheduled run",
			s.calls)
	}
	if res.Started != 3 || res.Passes != 3 {
		t.Errorf("got started=%d passes=%d", res.Started, res.Passes)
	}
	if res.Truncated {
		t.Error("a run that finished reported truncation")
	}
}

// THE PASS LIMIT BOUNDS THE RUN AND SAYS SO.
//
// Truncation has to be visible: a run that stopped early with work left looks
// identical in every metric to one that finished.
func TestThePassLimitTruncatesVisibly(t *testing.T) {
	s := &fakeErasureSweeper{passes: []temporaladapter.ErasureSweepPass{
		{Scanned: 1, Started: 1, More: true},
	}}

	res, err := runErasureSweep(t, s,
		temporaladapter.SweepErasuresInput{Batch: 1, MaxPasses: 2})
	if err != nil {
		t.Fatal(err)
	}
	if s.calls != 2 {
		t.Fatalf("ran %d passes, want 2", s.calls)
	}
	if !res.Truncated {
		t.Fatal("a run that stopped at its pass limit with work remaining did not report " +
			"truncation; it is indistinguishable from one that finished")
	}
}

// ONE CLOCK READING FOR THE WHOLE RUN.
//
// Two passes disagreeing about which requests were overdue would make a retried
// attempt and the original act on different sets.
func TestTheSweepReadsTheClockOnce(t *testing.T) {
	s := &fakeErasureSweeper{passes: []temporaladapter.ErasureSweepPass{
		{Scanned: 1, More: true},
		{Scanned: 1},
	}}

	if _, err := runErasureSweep(t, s,
		temporaladapter.SweepErasuresInput{Batch: 1}); err != nil {
		t.Fatal(err)
	}
	if len(s.nows) < 2 {
		t.Fatalf("only %d passes ran", len(s.nows))
	}
	if !s.nows[0].Equal(s.nows[1]) {
		t.Errorf("pass 1 saw %v and pass 2 saw %v; a retried attempt and the original "+
			"would act on different sets", s.nows[0], s.nows[1])
	}
}

// A FAILING PASS FAILS THE RUN.
//
// "The backstop is broken" and "there was nothing overdue" look identical
// otherwise — and this is the safety net for a statutory obligation.
func TestAFailingPassFailsTheSweep(t *testing.T) {
	s := &fakeErasureSweeper{err: errors.New("postgres: down")}

	if _, err := runErasureSweep(t, s, temporaladapter.SweepErasuresInput{}); err == nil {
		t.Fatal("a failing sweep completed successfully; a broken backstop reports exactly " +
			"what a working one reports")
	}
}

// THE DEFAULTS ARE APPLIED.
func TestTheSweepDefaultsItsBounds(t *testing.T) {
	s := &fakeErasureSweeper{passes: []temporaladapter.ErasureSweepPass{{}}}

	if _, err := runErasureSweep(t, s, temporaladapter.SweepErasuresInput{}); err != nil {
		t.Fatal(err)
	}
	if s.limit <= 0 {
		t.Fatalf("the activity was called with limit %d; an unbounded query is not what "+
			"a zero input should mean", s.limit)
	}
}

// THE ACTIVITIES REFUSE AN INCOMPLETE WIRING.
func TestTheErasureSweepActivitiesRefuseAnIncompleteWiring(t *testing.T) {
	if _, err := temporaladapter.NewErasureSweepActivities(nil); err == nil {
		t.Error("activities with no sweeper were accepted; every run reports a clean pass " +
			"having scanned nothing")
	}
}

// THE SCHEDULE NAMES THE WORKFLOW A WORKER REGISTERS, ON THE QUEUE IT POLLS.
//
// A schedule naming neither queues runs where nothing is listening, and every
// observable signal stays green while overdue requests keep no clock.
func TestTheErasureSweepScheduleNamesTheRightAction(t *testing.T) {
	opts := temporaladapter.ErasureSweepScheduleOptionsForTest(
		"chronos", temporaladapter.SweepErasuresInput{}, time.Hour)

	action, ok := opts.Action.(*client.ScheduleWorkflowAction)
	if !ok {
		t.Fatalf("the schedule's action is %T", opts.Action)
	}
	if action.Workflow != temporaladapter.SweepErasuresWorkflow {
		t.Errorf("the schedule starts %v, want %s", action.Workflow,
			temporaladapter.SweepErasuresWorkflow)
	}
	if action.TaskQueue != "chronos" {
		t.Errorf("the schedule queues on %q", action.TaskQueue)
	}
	if opts.PauseOnFailure {
		t.Error("the schedule pauses on failure; a transient error would switch off the " +
			"safety net for a statutory obligation until somebody noticed")
	}
}

package temporal_test

import (
	"context"
	"testing"
	"time"

	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/notify"
	"github.com/chronos/chronos-go/internal/platform/workflow"
	"go.temporal.io/sdk/testsuite"
)

// spyDispatcher records what the activity was asked to deliver.
type spyDispatcher struct {
	got   []notify.Notification
	trace eventsourcing.Trace
	err   error
}

func (s *spyDispatcher) Dispatch(ctx context.Context, n notify.Notification) error {
	s.got = append(s.got, n)
	s.trace = eventsourcing.TraceFrom(ctx)
	return s.err
}

func input() temporaladapter.SendNotificationInput {
	return temporaladapter.SendNotificationInput{
		Template:       "identity.password_changed",
		Class:          notify.Security,
		SubjectID:      "sub_01J8Z9",
		OrgID:          "org_01J8Z9",
		Data:           map[string]any{"ip_country": "SE"},
		OccurredAt:     time.Date(2026, 8, 12, 9, 0, 0, 0, time.UTC),
		IdempotencyKey: "evt_01J8Z9",
	}
}

// The workflow's whole job: run the delivery as an ACTIVITY, never inline
// (ADR-017). The test environment fails the run if the workflow does I/O,
// reads the clock, or is otherwise non-deterministic.
func TestSendNotificationDeliversThroughAnActivity(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	spy := &spyDispatcher{}
	activities, err := temporaladapter.NewNotificationActivities(spy)
	if err != nil {
		t.Fatalf("activities: %v", err)
	}
	temporaladapter.RegisterForTest(env, activities)

	env.ExecuteWorkflow(temporaladapter.SendNotification, input())

	if !env.IsWorkflowCompleted() {
		t.Fatal("the workflow did not complete")
	}
	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("workflow: %v", err)
	}
	if len(spy.got) != 1 {
		t.Fatalf("dispatched %d notifications, want 1", len(spy.got))
	}
	if got := spy.got[0].Template; got != "identity.password_changed" {
		t.Errorf("template %q", got)
	}
	// The recipient crossing the boundary is a PSEUDONYM. Workflow input is
	// written to history — durable, replicated, long-lived — so a resolved
	// address there would be personal data crypto-shredding cannot reach
	// (ADR-002). The vault resolves it inside the dispatcher instead.
	if spy.got[0].Recipient.Address != "" {
		t.Error("a resolved address reached workflow history")
	}
	if spy.got[0].Recipient.SubjectID != "sub_01J8Z9" {
		t.Errorf("subject %q", spy.got[0].Recipient.SubjectID)
	}
}

// An erased subject is not a failure: there is nothing to deliver to, and the
// correct outcome is to stop rather than retry for the full hour.
func TestAnErasedSubjectEndsTheWorkflowQuietly(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	spy := &spyDispatcher{err: notify.ErrSubjectErased}
	activities, err := temporaladapter.NewNotificationActivities(spy)
	if err != nil {
		t.Fatalf("activities: %v", err)
	}
	temporaladapter.RegisterForTest(env, activities)

	env.ExecuteWorkflow(temporaladapter.SendNotification, input())

	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("an erased subject must end the run cleanly, got %v", err)
	}
}

// A structurally invalid notification fails identically forever. Retrying it
// burns the whole retry budget to reach the same answer, so it is marked
// non-retryable and the run ends at once.
func TestAnInvalidNotificationIsNotRetried(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	spy := &spyDispatcher{}
	activities, err := temporaladapter.NewNotificationActivities(spy)
	if err != nil {
		t.Fatalf("activities: %v", err)
	}
	temporaladapter.RegisterForTest(env, activities)

	in := input()
	in.Template = "" // never valid

	env.ExecuteWorkflow(temporaladapter.SendNotification, in)

	if env.GetWorkflowError() == nil {
		t.Fatal("an invalid notification must fail the run")
	}
	if len(spy.got) != 0 {
		t.Errorf("an invalid notification reached the dispatcher %d times", len(spy.got))
	}
}

// The causation chain must cross the workflow boundary. Without it a workflow's
// effects appear in the log with no visible cause — and the log is append-only,
// so it could never be repaired afterwards.
func TestTheCausationChainReachesTheActivity(t *testing.T) {
	spy := &spyDispatcher{}
	activities, err := temporaladapter.NewNotificationActivities(spy)
	if err != nil {
		t.Fatalf("activities: %v", err)
	}

	// Seeded on the SUITE, before the environment is built: the header is what a
	// real start carries, and the propagator is the production one.
	var suite testsuite.WorkflowTestSuite
	temporaladapter.PropagateForTest(&suite, eventsourcing.Trace{
		CorrelationID: "corr_1", CausationID: "evt_01J8Z9",
	})
	env := suite.NewTestWorkflowEnvironment()
	temporaladapter.RegisterForTest(env, activities)

	env.ExecuteWorkflow(temporaladapter.SendNotification, input())

	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("workflow: %v", err)
	}
	if spy.trace.CorrelationID != "corr_1" {
		t.Errorf("correlation %q reached the activity, want corr_1", spy.trace.CorrelationID)
	}
	if spy.trace.CausationID != "evt_01J8Z9" {
		t.Errorf("causation %q reached the activity, want evt_01J8Z9", spy.trace.CausationID)
	}
}

// A start with no derived id is refused. A random id would turn every
// redelivered event into a second run — for mail, a second email.
func TestStartRequiresADerivedID(t *testing.T) {
	if err := (workflow.Start{Name: "x"}).Validate(); err == nil {
		t.Error("a start with no id was accepted")
	}
	if err := (workflow.Start{ID: "evt_1"}).Validate(); err == nil {
		t.Error("a start with no workflow name was accepted")
	}
	if err := (workflow.Start{ID: "evt_1", Name: "x"}).Validate(); err != nil {
		t.Errorf("a valid start was refused: %v", err)
	}
}

// A worker that registers nothing polls a queue it cannot serve: it looks
// healthy, tasks arrive, and every one of them fails to find a handler.
func TestAWorkerWithNothingRegisteredIsRefused(t *testing.T) {
	_, err := temporaladapter.NewWorker(temporaladapter.WorkerDeps{})
	if err == nil {
		t.Fatal("a worker with no client was built")
	}
}

// The activity set refuses to exist without a dispatcher. Built without one,
// every run would fail — after burning a full hour of retries first.
func TestActivitiesRequireADispatcher(t *testing.T) {
	if _, err := temporaladapter.NewNotificationActivities(nil); err == nil {
		t.Fatal("activities were built with no dispatcher")
	}
}

// Names are written into workflow history and are permanent. This test exists
// so changing one is a deliberate act with a visible failure, rather than a
// rename that strands every in-flight execution.
func TestWorkflowNamesArePermanent(t *testing.T) {
	if temporaladapter.SendNotificationWorkflow != "chronos.notification.Send.v1" {
		t.Errorf("the workflow name changed to %q; every in-flight execution now names a "+
			"workflow no worker answers to", temporaladapter.SendNotificationWorkflow)
	}
}

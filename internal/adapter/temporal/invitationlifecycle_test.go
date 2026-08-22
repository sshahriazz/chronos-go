package temporal_test

import (
	"context"
	"errors"
	"testing"
	"time"

	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
	"go.temporal.io/sdk/testsuite"
)

// fakeLifecycle scripts an invitation's state over time.
//
// The clock is the test environment's, not this fake's: the workflow reads
// workflow.Now, and the environment advances it when the workflow sleeps. So the
// fake answers from whatever the environment has reached, which is what makes a
// seven-day wait a millisecond test.
type fakeLifecycle struct {
	// expiresAt is the invitation's deadline. Mutable, so a test can model a
	// RESEND landing while the workflow sleeps.
	expiresAt time.Time

	// settledAfter, when non-zero, makes the invitation stop being pending once
	// the environment's clock passes it.
	settledAfter time.Time

	exists bool

	// extendTo and extendOnRead model a RESEND landing while the workflow
	// sleeps: on the Nth State read the deadline moves.
	extendTo     time.Time
	extendOnRead int

	// expiredAt records when Expire was finally called, by the ENVIRONMENT's
	// clock — the only thing that can show the run outlasted the original
	// deadline.
	expiredAt time.Time

	now func() time.Time

	states   int
	reminded int
	expired  int

	remindDid bool
	expireDid bool

	stateErr  error
	remindErr error
	expireErr error
}

func (f *fakeLifecycle) State(
	context.Context, string,
) (temporaladapter.InvitationSnapshot, error) {
	f.states++
	if f.stateErr != nil {
		return temporaladapter.InvitationSnapshot{}, f.stateErr
	}
	if f.extendOnRead > 0 && f.states == f.extendOnRead {
		f.expiresAt = f.extendTo
	}
	pending := f.exists
	if !f.settledAfter.IsZero() && !f.now().Before(f.settledAfter) {
		pending = false
	}
	return temporaladapter.InvitationSnapshot{
		Exists: f.exists, Pending: pending, ExpiresAt: f.expiresAt,
	}, nil
}

func (f *fakeLifecycle) Remind(context.Context, string, string) (bool, error) {
	f.reminded++
	return f.remindDid, f.remindErr
}

func (f *fakeLifecycle) Expire(context.Context, string) (bool, error) {
	f.expired++
	f.expiredAt = f.now()
	return f.expireDid, f.expireErr
}

const (
	lifecycleInvitation = "inv_01H8XG5N2QK7VB3C9WPYZR4TFN"
	lifecycleOrg        = "org_01H8XG5N2QK7VB3C9WPYZR4TFM"
)

// runLifecycle drives the workflow in the test environment.
func runLifecycle(
	t *testing.T, ops *fakeLifecycle,
) (temporaladapter.InvitationLifecycleResult, error) {
	t.Helper()

	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	ops.now = env.Now

	activities, err := temporaladapter.NewInvitationLifecycleActivities(ops)
	if err != nil {
		t.Fatal(err)
	}
	temporaladapter.RegisterInvitationLifecycleForTest(env, activities)

	env.ExecuteWorkflow(temporaladapter.InvitationLifecycleWorkflow,
		temporaladapter.InvitationLifecycleInput{
			InvitationID: lifecycleInvitation, OrgID: lifecycleOrg,
		})
	if !env.IsWorkflowCompleted() {
		t.Fatal("the workflow did not complete")
	}

	var result temporaladapter.InvitationLifecycleResult
	if err := env.GetWorkflowError(); err != nil {
		return result, err
	}
	if err := env.GetWorkflowResult(&result); err != nil {
		t.Fatalf("decoding the result: %v", err)
	}
	return result, nil
}

// AN UNTOUCHED INVITATION IS REMINDED ONCE AND THEN EXPIRED.
//
// The whole point of the workflow. Without it the seat comes back only when the
// hourly sweep happens to notice, and the person invited is never nudged at all.
func TestTheLifecycleRemindsThenExpires(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	ops := &fakeLifecycle{
		exists: true, expiresAt: env.Now().Add(7 * 24 * time.Hour),
		remindDid: true, expireDid: true,
	}
	result, err := runLifecycle(t, ops)
	if err != nil {
		t.Fatalf("the lifecycle failed: %v", err)
	}

	if ops.reminded != 1 {
		t.Errorf("reminded %d times, want exactly 1; repeating turns a useful mail into "+
			"one people filter, and never sending it wastes the whole mechanism",
			ops.reminded)
	}
	if ops.expired != 1 {
		t.Errorf("expired %d times, want 1", ops.expired)
	}
	if result.Outcome != "expired" {
		t.Errorf("outcome %q, want expired", result.Outcome)
	}
	if !result.Reminded {
		t.Error("the result does not record that a reminder went out")
	}
}

// A RESEND MOVES THE DEADLINE, and the workflow follows it.
//
// This is why the input carries no deadline and every wake re-reads. A workflow
// sleeping to the deadline it was started with would wake early, find the
// invitation still pending, and EXPIRE it — killing a link that is live in
// somebody's inbox and taking back a seat that is still needed.
func TestAResendPostponesTheExpiry(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	start := env.Now()

	original := start.Add(7 * 24 * time.Hour)
	extended := start.Add(21 * 24 * time.Hour)

	ops := &fakeLifecycle{
		exists: true, expiresAt: original,
		// The resend lands while the workflow sleeps toward the reminder, so the
		// SECOND read reports the longer window.
		extendTo: extended, extendOnRead: 2,
		remindDid: true, expireDid: true,
	}
	result, err := runLifecycle(t, ops)
	if err != nil {
		t.Fatalf("the lifecycle failed: %v", err)
	}
	if result.Outcome != "expired" {
		t.Fatalf("outcome %q, want expired", result.Outcome)
	}

	if ops.expiredAt.Before(extended) {
		t.Fatalf("expired at %s, which is before the EXTENDED deadline %s (the original "+
			"was %s). A workflow that trusted the deadline it was started with would kill "+
			"a link that is live in somebody's inbox and take back a seat that is still "+
			"needed", ops.expiredAt, extended, original)
	}
}

// A RESEND AFTER THE REMINDER ALSO POSTPONES THE EXPIRY.
//
// The case above has the resend land BEFORE the reminder, and it passes even for
// a workflow that reads once and then trusts what it read — because the read it
// trusts already has the new deadline. This one lands AFTER, which is the only
// arrangement that separates "re-reads every wake" from "re-read once".
//
// A one-hour window so the reminder fires immediately, and the extension on the
// read that follows it.
func TestAResendAfterTheReminderAlsoPostponesTheExpiry(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	start := env.Now()

	short := start.Add(time.Hour)
	extended := start.Add(21 * 24 * time.Hour)

	ops := &fakeLifecycle{
		exists: true, expiresAt: short,
		extendTo: extended, extendOnRead: 2,
		remindDid: true, expireDid: true,
	}
	result, err := runLifecycle(t, ops)
	if err != nil {
		t.Fatalf("the lifecycle failed: %v", err)
	}
	if result.Outcome != "expired" {
		t.Fatalf("outcome %q, want expired", result.Outcome)
	}
	if ops.expiredAt.Before(extended) {
		t.Fatalf("expired at %s, before the deadline the resend set (%s). The workflow "+
			"slept to a window it had already read rather than re-reading, so a resend "+
			"landing after the reminder kills a link that is live", ops.expiredAt, extended)
	}
}

// A SETTLED INVITATION ENDS THE RUN without expiring anything.
//
// Accepted, revoked, declined and undeliverable all settle it elsewhere. This
// run exists for the case where nobody acts, and finishing quietly when somebody
// did is the common outcome rather than an error.
func TestASettledInvitationEndsTheLifecycle(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	ops := &fakeLifecycle{
		exists: true, expiresAt: env.Now().Add(7 * 24 * time.Hour),
		// Accepted a day in, before the reminder is due.
		settledAfter: env.Now().Add(24 * time.Hour),
		remindDid:    true, expireDid: true,
	}
	result, err := runLifecycle(t, ops)
	if err != nil {
		t.Fatalf("the lifecycle failed: %v", err)
	}
	if result.Outcome != "settled" {
		t.Errorf("outcome %q, want settled", result.Outcome)
	}
	if ops.expired != 0 {
		t.Fatal("an invitation that was already settled was expired, which releases the " +
			"seat its new member is sitting in")
	}
	if ops.reminded != 0 {
		t.Error("somebody who already accepted was reminded to accept")
	}
}

// AN INVITATION THAT DOES NOT EXIST ENDS THE RUN.
func TestAMissingInvitationEndsTheLifecycle(t *testing.T) {
	ops := &fakeLifecycle{exists: false, expiresAt: time.Now().Add(time.Hour)}
	result, err := runLifecycle(t, ops)
	if err != nil {
		t.Fatalf("the lifecycle failed: %v", err)
	}
	if result.Outcome != "gone" {
		t.Errorf("outcome %q, want gone", result.Outcome)
	}
	if ops.expired != 0 || ops.reminded != 0 {
		t.Error("an invitation with no stream was acted on")
	}
}

// A SHORT WINDOW STILL GETS ITS REMINDER.
//
// An invitation issued with less than the lead time left is already inside the
// reminder window when the workflow starts. Skipping would silently drop the
// reminder for every one of them.
func TestAShortWindowIsRemindedImmediately(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	ops := &fakeLifecycle{
		exists: true, expiresAt: env.Now().Add(time.Hour),
		remindDid: true, expireDid: true,
	}
	if _, err := runLifecycle(t, ops); err != nil {
		t.Fatalf("the lifecycle failed: %v", err)
	}
	if ops.reminded != 1 {
		t.Fatalf("reminded %d times for a one-hour window; an invitation issued inside the "+
			"reminder lead would never be nudged at all", ops.reminded)
	}
}

// AN EXPIRY THE AGGREGATE REFUSED ENDS THE RUN AS SETTLED.
//
// Did=false means it moved between the read and the write. Looping would risk
// spinning on a fast enough resend, and the reconciliation sweep picks up
// anything this run leaves behind.
func TestARefusedExpiryEndsTheRun(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	ops := &fakeLifecycle{
		exists: true, expiresAt: env.Now().Add(7 * 24 * time.Hour),
		remindDid: true, expireDid: false,
	}
	result, err := runLifecycle(t, ops)
	if err != nil {
		t.Fatalf("the lifecycle failed: %v", err)
	}
	if result.Outcome != "settled" {
		t.Errorf("outcome %q, want settled for a refused expiry", result.Outcome)
	}
	if ops.expired != 1 {
		t.Errorf("attempted %d expiries, want 1", ops.expired)
	}
}

// AN INPUT NAMING NOTHING IS REFUSED PERMANENTLY.
func TestAnEmptyInputIsRefused(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	activities, err := temporaladapter.NewInvitationLifecycleActivities(&fakeLifecycle{})
	if err != nil {
		t.Fatal(err)
	}
	temporaladapter.RegisterInvitationLifecycleForTest(env, activities)

	env.ExecuteWorkflow(temporaladapter.InvitationLifecycleWorkflow,
		temporaladapter.InvitationLifecycleInput{})
	if !env.IsWorkflowCompleted() {
		t.Fatal("the workflow did not complete")
	}
	if env.GetWorkflowError() == nil {
		t.Fatal("a lifecycle naming no invitation ran anyway")
	}
}

// THE ACTIVITY SET IS REQUIRED.
func TestTheLifecycleRefusesNoOperations(t *testing.T) {
	if _, err := temporaladapter.NewInvitationLifecycleActivities(nil); err == nil {
		t.Fatal("constructed with no operations; every run would read nothing, remind " +
			"nobody and expire nothing while reporting success")
	}
}

// A READ FAILURE FAILS THE RUN rather than expiring on a guess.
func TestAFailedReadFailsTheRun(t *testing.T) {
	ops := &fakeLifecycle{exists: true, stateErr: errors.New("kurrentdb: unreachable")}
	if _, err := runLifecycle(t, ops); err == nil {
		t.Fatal("a run that could not read the invitation completed successfully; the next " +
			"thing it would have done is expire it")
	}
}

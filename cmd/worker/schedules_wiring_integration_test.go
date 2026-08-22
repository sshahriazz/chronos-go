//go:build integration

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"testing"
	"time"

	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/client"
)

// The three recurring jobs this binary is responsible for creating, and what
// each of them must point at once created.
//
// Kept as one table rather than three tests because the failure being closed is
// identical for all three and was found three separate times by three separate
// mutation passes: deleting the d.scheduleX(log) call from startTemporal leaves
// every existing test green. The workflow is still registered, the worker is
// still healthy, the queue is still empty, and no signal anywhere moves. What
// actually stops is different in each case — lapsed email claims are never
// released, identity's TTL-less tables grow forever, and a key rotation can
// never be completed — so each row carries its own consequence rather than a
// shared one.
type scheduledJob struct {
	// name is the subtest name.
	name string

	// id is the server-side schedule id the worker must have created.
	id string

	// workflow is the workflow type the schedule's action must name. Asserting
	// it is not pedantry: a schedule pointing at a workflow nobody registered,
	// or at a task queue nobody polls, still creates runs, and the caller is
	// told the run started while the work never happens.
	workflow string

	// consequence completes "…, so <consequence>" in the failure message.
	consequence string
}

func scheduledJobs() []scheduledJob {
	return []scheduledJob{
		{
			name:     "lapsed_email_reservation_sweep",
			id:       temporaladapter.SweepReservationsScheduleID,
			workflow: temporaladapter.SweepReservationsWorkflow,
			consequence: "an address claimed by someone who never proved they own it stays " +
				"claimed indefinitely and its real owner cannot register",
		},
		{
			name:     "identity_retention",
			id:       temporaladapter.PurgeRetentionScheduleID,
			workflow: temporaladapter.PurgeIdentityRetentionWorkflow,
			consequence: "spent TOTP steps, expired token digests and dead session secrets " +
				"accumulate without bound in tables PostgreSQL gives no TTL",
		},
		{
			name:     "invitation_sweep",
			id:       temporaladapter.SweepInvitationsScheduleID,
			workflow: temporaladapter.SweepInvitationsWorkflow,
			consequence: "an invitation that ran out is never expired, so the seat it holds " +
				"stays held and the organization keeps paying for somebody who never arrived",
		},
		{
			name:     "credential_key_reseal",
			id:       temporaladapter.ResealCredentialKeysScheduleID,
			workflow: temporaladapter.ResealCredentialKeysWorkflow,
			consequence: "a sealing-key rotation can never complete: the count of rows at the " +
				"old version never falls and the retired key must be kept alive forever",
		},
	}
}

// TestEnablingDurableWorkCreatesEverySchedule asserts that a worker built the
// production way — newDependencies, which calls startTemporal, which calls the
// three scheduleX helpers — leaves all three schedules on the running Temporal,
// each pointing at a workflow this same worker registered, on the queue this
// same worker polls.
//
// # Why this cannot be a unit test
//
// A schedule is server-side state and nothing else. The Go side of it is
// asserted without a server in internal/adapter/temporal/*schedule.go's own
// tests — those cover what the options SAY. Nothing short of a live Temporal can
// say whether the call that submits them was ever made, and that call is exactly
// what three mutation passes were able to delete without turning a single test
// red.
//
// # The leftover-schedule trap, and how it is solved here
//
// EnsureXSchedule deliberately LEAVES AN EXISTING SCHEDULE ALONE — an operator
// who paused a job during an incident must not have that undone by the next
// deployment. That policy is correct and it is also what would make this test
// worthless: the dev Temporal is long-lived and shared, so a schedule created by
// an earlier passing run, or by a developer's worker, would still be there and
// the assertion would pass with the creation call deleted.
//
// The schedule ids are compile-time constants with no override — deliberately,
// because a schedule id is a wire-level identifier and a changed one creates a
// SECOND schedule instead of moving the first — so a unique-id-per-run solution
// would need a production change and is not available. Instead the test DELETES
// all three first, through a client of its own, and waits until the server
// confirms each one is gone before newDependencies is allowed to run. Every
// schedule found afterwards was therefore created by this run.
//
// Cleanup deletes them again so the shared dev Temporal is not left holding
// state this test put there; the next worker start recreates all three, which is
// the whole point of the code under test.
func TestEnablingDurableWorkCreatesEverySchedule(t *testing.T) {
	t.Setenv("TEMPORAL_ENABLED", "true")
	cfg := testConfig(t)
	jobs := scheduledJobs()

	// A SEPARATE client from the one under test. The dependencies' client is
	// closed by its own cleanup at the end of the test, and the pre-delete has to
	// happen before that client exists at all.
	admin, err := temporaladapter.Dial(temporaladapter.Config{
		HostPort:  cfg.Temporal.HostPort,
		Namespace: cfg.Temporal.Namespace,
		Queue:     cfg.Temporal.Queue,
	})
	if err != nil {
		t.Fatalf("no Temporal client for the test's own bookkeeping: %v", err)
	}
	// Registered FIRST so it runs LAST: t.Cleanup is LIFO, and the delete below
	// needs the connection still open.
	t.Cleanup(admin.Close)
	t.Cleanup(func() {
		for _, j := range jobs {
			deleteSchedule(context.Background(), admin, j.id)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	for _, j := range jobs {
		requireScheduleAbsent(ctx, t, admin, j.id)
	}

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	if d.temporal == nil {
		t.Fatal("TEMPORAL_ENABLED=true built no client, so nothing could have been scheduled")
	}
	if d.temporalWorker == nil {
		t.Fatal("a client was built with no worker: durable work would be accepted and " +
			"never run, and the caller would be told it started")
	}

	for _, j := range jobs {
		t.Run(j.name, func(t *testing.T) {
			desc, err := d.temporal.Raw().ScheduleClient().GetHandle(ctx, j.id).Describe(ctx)
			if err != nil {
				t.Fatalf("schedule %s does not exist after a full production startup, so %s. "+
					"The %s workflow is registered and will simply never be started: %v",
					j.id, j.consequence, j.workflow, err)
			}

			action, ok := desc.Schedule.Action.(*client.ScheduleWorkflowAction)
			if !ok {
				t.Fatalf("schedule %s does not start a workflow at all (%T), so %s",
					j.id, desc.Schedule.Action, j.consequence)
			}

			// The workflow type the action names, and whether THIS worker answers
			// to it. A schedule naming a workflow nobody registered creates runs
			// that sit on the queue until they time out, hours later, with the
			// caller long since told the run started.
			if got := fmt.Sprint(action.Workflow); got != j.workflow {
				t.Errorf("schedule %s starts %q, not %q; the registered workflow is never "+
					"run, so %s", j.id, got, j.workflow, j.consequence)
			}
			if !slices.Contains(d.temporalWorkflows, j.workflow) {
				t.Errorf("schedule %s starts %q, which this worker did NOT register "+
					"(registered: %v); its runs are queued where nothing is listening",
					j.id, j.workflow, d.temporalWorkflows)
			}

			// And the queue. Same failure by a different route: the right
			// workflow name on a queue this worker does not poll is still work
			// that never happens.
			if action.TaskQueue != d.temporalWorker.Queue() {
				t.Errorf("schedule %s queues on %q but the worker polls %q, so its runs are "+
					"queued where nothing is listening and %s",
					j.id, action.TaskQueue, d.temporalWorker.Queue(), j.consequence)
			}
			if action.TaskQueue != cfg.Temporal.Queue {
				t.Errorf("schedule %s queues on %q, not the configured TEMPORAL_QUEUE %q",
					j.id, action.TaskQueue, cfg.Temporal.Queue)
			}

			// A schedule that exists but is paused runs exactly as often as one
			// that does not exist. Since this run created it, paused here would
			// mean the creation options carry it, not an operator's decision.
			if desc.Schedule.State != nil && desc.Schedule.State.Paused {
				t.Errorf("schedule %s was just created PAUSED, so it never fires and %s: %s",
					j.id, j.consequence, desc.Schedule.State.Note)
			}
		})
	}
}

// requireScheduleAbsent deletes a schedule and blocks until the server agrees it
// is gone.
//
// The wait is what makes the test's central claim true. A delete that the server
// has accepted but not yet applied would let the subsequent create fail as
// already-running, and the schedule the assertions then find would be the OLD
// one — precisely the leftover this whole approach exists to rule out.
func requireScheduleAbsent(ctx context.Context, t *testing.T, c *temporaladapter.Client, id string) {
	t.Helper()

	deleteSchedule(ctx, c, id)

	deadline := time.Now().Add(15 * time.Second)
	for {
		_, err := c.Raw().ScheduleClient().GetHandle(ctx, id).Describe(ctx)
		if isNotFound(err) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("schedule %s still exists 15s after being deleted; the test cannot "+
				"tell a schedule this run created from one left over by an earlier run, "+
				"and would pass even with the creation call removed (describe: %v)", id, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// deleteSchedule removes a schedule, treating "there was none" as success.
//
// Used both for the pre-delete and for cleanup, and in the cleanup case there is
// nothing useful to do with a failure: the test has already finished, and the
// next worker start recreates all three regardless.
func deleteSchedule(ctx context.Context, c *temporaladapter.Client, id string) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_ = c.Raw().ScheduleClient().GetHandle(ctx, id).Delete(ctx)
}

// isNotFound distinguishes "the schedule is gone" from "the server could not
// say". Treating any error as absence would make the pre-delete wait succeed
// against an unreachable Temporal, and the test would then blame the worker for
// a schedule the server was never asked about.
func isNotFound(err error) bool {
	var nf *serviceerror.NotFound
	return errors.As(err, &nf)
}

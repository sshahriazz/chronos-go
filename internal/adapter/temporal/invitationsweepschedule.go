package temporal

import (
	"context"
	"errors"
	"fmt"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/client"
	sdktemporal "go.temporal.io/sdk/temporal"
)

// SweepInvitationsScheduleID names the recurring run.
//
// Permanent for the reason the sweep's workflow name is: the id is what the
// server stores, what a probe watches, and what a restart looks for before
// deciding whether to create one. Renaming it creates a SECOND schedule beside
// the first, and the old one keeps running under a name nothing reports on.
const SweepInvitationsScheduleID = "chronos.workspace.invitation-sweep"

// DefaultInvitationSweepInterval is how often the reconciliation runs.
//
// An hour, and deliberately coarser than the reservation sweep's fifteen
// minutes. What is at stake is different: a lapsed reservation holds an ADDRESS
// its real owner cannot register, which is a person locked out, while a lapsed
// invitation holds a SEAT, which is money. An hour of over-billing is a rounding
// error against a seven-day window; an hour of being unable to register is not.
//
// It is also not the primary mechanism. The per-invitation workflow expires on
// time; this catches the ones whose workflow never started, and that is a rare
// case whose cost grows slowly.
const DefaultInvitationSweepInterval = time.Hour

// EnsureInvitationSweepSchedule creates the recurring sweep if it is absent.
//
// Idempotent: every restart after the first finds it already running and says
// so. That matters because the alternative — delete and recreate — would lose
// the schedule's own state, and a worker restarting during an incident is
// exactly when that state is worth keeping.
func EnsureInvitationSweepSchedule(
	ctx context.Context, c *Client, in SweepInvitationsInput, every time.Duration,
) (created bool, err error) {
	if c == nil || c.c == nil {
		return false, errors.New("temporal: no client, so the invitation sweep cannot be " +
			"scheduled and a seat held by a lapsed invitation is held forever")
	}
	if every <= 0 {
		every = DefaultInvitationSweepInterval
	}

	_, err = c.c.ScheduleClient().Create(ctx, invitationSweepScheduleOptions(c.queue, in, every))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, sdktemporal.ErrScheduleAlreadyRunning):
		// The normal case on every restart after the first.
		return false, nil
	default:
		return false, fmt.Errorf("temporal: creating the %s schedule: %w",
			SweepInvitationsScheduleID, err)
	}
}

// invitationSweepScheduleOptions is what the schedule is created with.
//
// Split out from the call so it can be asserted without a server. The thing
// worth asserting is the ACTION: a schedule naming a workflow no worker
// registers, or a task queue no worker polls, creates a run that is queued where
// nothing is listening — and every observable signal stays green while seats are
// never given back.
func invitationSweepScheduleOptions(
	queue string, in SweepInvitationsInput, every time.Duration,
) client.ScheduleOptions {
	return client.ScheduleOptions{
		ID:   SweepInvitationsScheduleID,
		Spec: client.ScheduleSpec{Intervals: []client.ScheduleIntervalSpec{{Every: every}}},
		Action: &client.ScheduleWorkflowAction{
			ID:        SweepInvitationsScheduleID,
			Workflow:  SweepInvitationsWorkflow,
			Args:      []any{in.withDefaults()},
			TaskQueue: queue,
		},
		// SKIP, not BUFFER: two sweeps at once is harmless — the expiry is
		// decided against the aggregate and the loser's append is refused by the
		// expected-revision check — but it is also pointless, and a buffered
		// queue turns one slow run into a pile-up.
		Overlap: enumspb.SCHEDULE_OVERLAP_POLICY_SKIP,
		// One hour rather than the server's one-year default. Replaying a year
		// of missed sweeps achieves exactly what the next single run achieves:
		// the work list is the CURRENT set of overdue invitations, not a
		// per-interval delta.
		CatchupWindow: time.Hour,
		// A failing sweep must keep being retried. Pausing would leave seats
		// held indefinitely with nothing on the application side to say why.
		PauseOnFailure: false,
	}
}

// SweepInvitationsProbe reports whether the schedule exists.
//
// Built here rather than in the composition root so the consequence is written
// once, next to the schedule it describes, by whoever knows what the sweep is
// for. A wiring-site string is one nobody updates when the job's purpose changes.
func SweepInvitationsProbe(c *Client) ScheduleProbe {
	return ScheduleProbe{
		Client:    c,
		ID:        SweepInvitationsScheduleID,
		ProbeName: "invitation_sweep",
		Consequence: "Invitations that ran out are never expired, so every seat one of them " +
			"holds stays held and the organization keeps paying for people who never " +
			"arrived. The per-invitation workflow still expires the ones it started, so " +
			"the loss is silent and grows slowly. Nothing else reports this.",
	}
}

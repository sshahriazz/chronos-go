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

// SweepReservationsScheduleID identifies the recurring sweep.
//
// Stable and permanent: a schedule is server-side state, so a changed id creates
// a SECOND schedule rather than moving the first, and both then run. The old one
// keeps its old interval and its old arguments, and nothing reports that two
// exist.
const SweepReservationsScheduleID = "chronos.identity.email-reservation-sweep"

// DefaultSweepInterval is how often lapsed reservations are released.
//
// The interval is the WINDOW during which an address whose lease has expired is
// still unavailable to its rightful owner, so it is chosen against a human
// retrying a registration rather than against database load: fifteen minutes is
// short enough that "try again shortly" is honest advice, and long enough that
// the query — which has a partial index built for exactly its predicate — is
// nowhere near a cost worth tuning.
const DefaultSweepInterval = 15 * time.Minute

// EnsureSweepSchedule creates the recurring sweep if it is not already there.
//
// A schedule rather than a ticker, a cron table or a time.AfterFunc, for the
// reason ADR-017 gives: none of those outlives the process that created them,
// and this one has to run whether or not any particular worker is up.
//
// Existing schedules are LEFT ALONE. An operator who paused the sweep, or
// widened its interval during an incident, must not have that undone by the next
// deployment restarting a worker — a silent revert of a deliberate operational
// change is worse than a stale interval, because nobody is told.
func EnsureSweepSchedule(
	ctx context.Context, c *Client, in SweepReservationsInput, every time.Duration,
) (created bool, err error) {
	if c == nil || c.c == nil {
		return false, errors.New("temporal: no client, so the lapsed-reservation sweep " +
			"cannot be scheduled and lapsed claims are never released")
	}
	if every <= 0 {
		every = DefaultSweepInterval
	}

	_, err = c.c.ScheduleClient().Create(ctx, sweepScheduleOptions(c.queue, in, every))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, sdktemporal.ErrScheduleAlreadyRunning):
		// The normal case on every restart after the first.
		return false, nil
	default:
		return false, fmt.Errorf("temporal: creating the %s schedule: %w",
			SweepReservationsScheduleID, err)
	}
}

// sweepScheduleOptions is what the schedule is created with.
//
// Split out from the call so it can be asserted without a server. The thing
// worth asserting is the ACTION: a schedule naming a workflow no worker
// registers, or a task queue no worker polls, creates a run that is queued where
// nothing is listening — and every observable signal stays green while lapsed
// reservations are never released.
func sweepScheduleOptions(
	queue string, in SweepReservationsInput, every time.Duration,
) client.ScheduleOptions {
	return client.ScheduleOptions{
		ID:   SweepReservationsScheduleID,
		Spec: client.ScheduleSpec{Intervals: []client.ScheduleIntervalSpec{{Every: every}}},
		Action: &client.ScheduleWorkflowAction{
			ID:        SweepReservationsScheduleID,
			Workflow:  SweepReservationsWorkflow,
			Args:      []any{in.withDefaults()},
			TaskQueue: queue,
		},
		// SKIP, not BUFFER: two sweeps running at once is harmless — the
		// releases are idempotent by construction and the loser's append is
		// refused by the expected-revision check — but it is also pointless, and
		// a buffered queue of sweeps turns one slow run into a pile-up.
		Overlap: enumspb.SCHEDULE_OVERLAP_POLICY_SKIP,
		// One hour rather than the server's one-year default. After an outage,
		// replaying a year of missed sweeps would achieve exactly what the next
		// single run achieves — the work list is the CURRENT set of lapsed
		// claims, not a per-interval delta.
		CatchupWindow: time.Hour,
		// A failing sweep must keep being retried. Pausing would turn a
		// transient failure into a security control that is switched off until
		// somebody notices — and nothing about a paused schedule is visible from
		// the application side.
		PauseOnFailure: false,
	}
}

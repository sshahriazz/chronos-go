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

// SweepErasuresScheduleID identifies the recurring backstop.
//
// PERMANENT, like every other schedule id here: renaming it leaves the old
// schedule running under the old name and creates a second, so both fire.
const SweepErasuresScheduleID = "chronos.compliance.erasure-sweep"

// EnsureErasureSweepSchedule makes the backstop recur.
//
// Idempotent: already-running is the normal answer on every restart after the
// first, and is not an error.
func EnsureErasureSweepSchedule(
	ctx context.Context, c *Client, in SweepErasuresInput, every time.Duration,
) (created bool, err error) {
	if c == nil || c.c == nil {
		return false, errors.New("temporal: no client, so the erasure backstop cannot be " +
			"scheduled and a deletion request the reactor missed is never picked up")
	}
	if every <= 0 {
		every = DefaultErasureSweepInterval
	}

	_, err = c.c.ScheduleClient().Create(ctx, erasureSweepScheduleOptions(c.queue, in, every))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, sdktemporal.ErrScheduleAlreadyRunning):
		return false, nil
	default:
		return false, fmt.Errorf("temporal: creating the %s schedule: %w",
			SweepErasuresScheduleID, err)
	}
}

// erasureSweepScheduleOptions is what the schedule is created with.
//
// Split out so the ACTION can be asserted without a server: a schedule naming a
// workflow no worker registers, or a task queue no worker polls, queues runs
// where nothing is listening — and every observable signal stays green while
// deletion requests sit past their deadline with no clock.
func erasureSweepScheduleOptions(
	queue string, in SweepErasuresInput, every time.Duration,
) client.ScheduleOptions {
	return client.ScheduleOptions{
		ID:   SweepErasuresScheduleID,
		Spec: client.ScheduleSpec{Intervals: []client.ScheduleIntervalSpec{{Every: every}}},
		Action: &client.ScheduleWorkflowAction{
			ID:        SweepErasuresScheduleID,
			Workflow:  SweepErasuresWorkflow,
			Args:      []any{in.withDefaults()},
			TaskQueue: queue,
		},
		// SKIP: two sweeps at once is harmless — starting a clock that exists
		// collapses on the workflow id — and pointless.
		Overlap: enumspb.SCHEDULE_OVERLAP_POLICY_SKIP,
		// One hour. The work list is the CURRENT set of overdue requests, not a
		// per-interval delta, so replaying a backlog of missed runs achieves
		// exactly what the next single run achieves.
		CatchupWindow: time.Hour,
		// A failing backstop must keep being retried. Pausing would switch off
		// the safety net for a statutory obligation until somebody noticed, and
		// nothing about a paused schedule is visible from the application side.
		PauseOnFailure: false,
	}
}

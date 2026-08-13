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

// PurgeRetentionScheduleID identifies the recurring retention job.
//
// Stable and permanent: a schedule is server-side state, so a changed id creates
// a SECOND schedule rather than moving the first, and both then run. For a
// retention job two schedules is not harmful — the statements are idempotent by
// construction, the second finds nothing left — but the old one keeps its old
// interval and nothing reports that two exist.
const PurgeRetentionScheduleID = "chronos.identity.retention-purge"

// DefaultRetentionInterval is how often identity's retention statements run.
//
// DAILY, and the contrast with DefaultSweepInterval's fifteen minutes is the
// whole reasoning. The reservation sweep is a security control: its interval is
// the window during which a real owner cannot register with their own address, so
// it is chosen against a human retrying. Nothing here is waiting on this job.
// Every row it deletes is already unusable — a spent step cannot be replayed, an
// expired digest cannot be redeemed, a revoked session's secret cannot be
// presented — so the interval is chosen against how large these tables get
// between runs, and a day of TOTP steps and expired tokens is a trivial amount of
// data to delete in one pass.
//
// Running it more often would buy nothing and would put five unbounded DELETEs on
// a live database more frequently than any question about them is ever asked.
const DefaultRetentionInterval = 24 * time.Hour

// EnsureRetentionSchedule creates the recurring retention job if it is not
// already there.
//
// A schedule rather than a ticker, a cron table or a time.AfterFunc, for the
// reason ADR-017 gives: none of those outlives the process that created them, and
// this one has to run whether or not any particular worker is up.
//
// Existing schedules are LEFT ALONE, exactly as EnsureSweepSchedule leaves the
// sweep's. An operator who paused retention during an incident — the obvious
// reason being an investigation that needs the rows kept — must not have that
// undone by the next deployment restarting a worker. A silent revert of that
// particular decision destroys the evidence somebody deliberately preserved.
func EnsureRetentionSchedule(
	ctx context.Context, c *Client, in PurgeRetentionInput, every time.Duration,
) (created bool, err error) {
	if c == nil || c.c == nil {
		return false, errors.New("temporal: no client, so identity retention cannot be " +
			"scheduled and its tables with no TTL grow for the lifetime of the deployment")
	}
	if every <= 0 {
		every = DefaultRetentionInterval
	}

	_, err = c.c.ScheduleClient().Create(ctx, retentionScheduleOptions(c.queue, in, every))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, sdktemporal.ErrScheduleAlreadyRunning):
		// The normal case on every restart after the first.
		return false, nil
	default:
		return false, fmt.Errorf("temporal: creating the %s schedule: %w",
			PurgeRetentionScheduleID, err)
	}
}

// retentionScheduleOptions is what the schedule is created with.
//
// Split out from the call so it can be asserted without a server. The thing worth
// asserting is the ACTION: a schedule naming a workflow no worker registers, or a
// task queue no worker polls, creates a run that is queued where nothing is
// listening — and every observable signal stays green while nothing is ever
// deleted.
func retentionScheduleOptions(
	queue string, in PurgeRetentionInput, every time.Duration,
) client.ScheduleOptions {
	return client.ScheduleOptions{
		ID:   PurgeRetentionScheduleID,
		Spec: client.ScheduleSpec{Intervals: []client.ScheduleIntervalSpec{{Every: every}}},
		Action: &client.ScheduleWorkflowAction{
			ID:        PurgeRetentionScheduleID,
			Workflow:  PurgeIdentityRetentionWorkflow,
			Args:      []any{in},
			TaskQueue: queue,
		},
		// SKIP, not BUFFER. Two retention passes at once would be harmless — the
		// statements are DELETEs whose predicates the first pass already
		// satisfied, so the second finds nothing — but they would contend for the
		// same rows for no benefit, and a buffered queue turns one slow pass after
		// a long outage into a pile-up of identical work.
		Overlap: enumspb.SCHEDULE_OVERLAP_POLICY_SKIP,
		// One hour rather than the server's one-year default, and the reasoning is
		// stronger here than for the sweep: retention is defined by a CUTOFF, not
		// by a per-interval delta, so replaying a month of missed daily runs would
		// achieve exactly what tomorrow's single run achieves.
		CatchupWindow: time.Hour,
		// A failing retention job must keep being retried. Pausing would turn a
		// transient database failure into retention that is switched off until
		// somebody notices — and nobody notices, because a table that is not being
		// swept looks identical to a table with nothing to sweep.
		PauseOnFailure: false,
	}
}

package temporal

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.temporal.io/sdk/activity"
	sdktemporal "go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// InvitationLifecycleWorkflow is one invitation's timer.
//
// The name is PERSISTED in workflow history, so it is permanent: renaming it
// strands every in-flight execution against a worker that no longer answers to
// the name history records — and here that means every outstanding invitation
// loses its reminder and its expiry at once, silently.
const InvitationLifecycleWorkflow = "chronos.workspace.InvitationLifecycle.v1"

const (
	// invitationStateActivity reads the CURRENT state from the aggregate.
	invitationStateActivity = "chronos.workspace.InvitationState.v1"

	// remindInvitationActivity mints a fresh link and mails it.
	remindInvitationActivity = "chronos.workspace.RemindInvitation.v1"

	// expireInvitationActivity closes one invitation and returns its seat.
	expireInvitationActivity = "chronos.workspace.ExpireInvitation.v1"
)

// ReminderLead is how long before the deadline the reminder fires.
//
// Two days into a seven-day window, so the nudge arrives with time to act on it.
// One reminder, not several: the message is "this is about to lapse", and
// repeating it turns a useful mail into one people filter.
const ReminderLead = 48 * time.Hour

// InvitationLifecycleInput names the invitation this run is about.
//
// Ids and nothing else. Workflow input is written to history, which is durable
// and replicated, so what crosses this boundary is subject to ADR-002 exactly as
// the event log is — and every field here is a pseudonym or a public id.
type InvitationLifecycleInput struct {
	InvitationID string
	OrgID        string
}

// InvitationLifecycleResult is how the run ended, and it is the run's OUTPUT
// rather than a log line: workflow results survive in the UI and in visibility
// queries long after logs rotate, and "why did this seat come back" is a
// question asked weeks later.
type InvitationLifecycleResult struct {
	// Outcome is one of "expired", "settled", "gone".
	Outcome string

	// Reminded reports whether a reminder went out before the end.
	Reminded bool
}

// InvitationLifecycle waits out one invitation, reminding once and expiring at
// the end.
//
// # Why it re-reads instead of sleeping to a deadline it was given
//
// A RESEND moves the window. A workflow that slept to the deadline it was
// started with would wake early, find the invitation still pending, and expire
// it — killing a link that is live in somebody's inbox and taking back a seat
// that is still needed. So every wake re-reads the aggregate and re-decides, and
// the input carries no deadline at all.
//
// # Why it is a loop rather than two timers
//
// The same reason. Each iteration sleeps to the NEXT thing that could happen and
// then re-reads, so a resend during the sleep simply produces a longer wait, and
// a settlement during the sleep ends the run.
//
// # Why it can end without doing anything
//
// Accepted, revoked, declined and undeliverable all settle the invitation
// elsewhere. This run exists to handle the case where nobody acts, and finishing
// quietly when somebody did is the common outcome, not an error.
func InvitationLifecycle(
	ctx workflow.Context, in InvitationLifecycleInput,
) (InvitationLifecycleResult, error) {
	if in.InvitationID == "" || in.OrgID == "" {
		return InvitationLifecycleResult{}, sdktemporal.NewNonRetryableApplicationError(
			"an invitation lifecycle needs an invitation and an organization",
			errTypePermanent, nil)
	}

	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: time.Minute,
		RetryPolicy: &sdktemporal.RetryPolicy{
			InitialInterval:        5 * time.Second,
			BackoffCoefficient:     2,
			MaximumInterval:        time.Minute,
			MaximumAttempts:        0,
			NonRetryableErrorTypes: []string{errTypePermanent},
		},
		ScheduleToCloseTimeout: 15 * time.Minute,
	})

	var result InvitationLifecycleResult
	for {
		var state InvitationSnapshot
		if err := workflow.ExecuteActivity(ctx, invitationStateActivity, in).
			Get(ctx, &state); err != nil {
			return result, fmt.Errorf("reading invitation %s: %w", in.InvitationID, err)
		}

		switch {
		case !state.Exists:
			// The stream is empty. Reachable if this run was started for an
			// invitation whose append then failed — the reactor's ordering makes
			// that unlikely and not impossible. Nothing to wait for.
			result.Outcome = "gone"
			return result, nil
		case !state.Pending:
			result.Outcome = "settled"
			return result, nil
		}

		now := workflow.Now(ctx).UTC()
		if !now.Before(state.ExpiresAt) {
			var expired InvitationActionResult
			if err := workflow.ExecuteActivity(ctx, expireInvitationActivity, in).
				Get(ctx, &expired); err != nil {
				return result, fmt.Errorf("expiring invitation %s: %w", in.InvitationID, err)
			}
			// "did" is false when the aggregate refused — settled or resent
			// between the read and the write. Both end this run: a resend that
			// lands in that window is picked up by the reconciliation sweep, and
			// the alternative is a loop that could spin on a fast enough resend.
			result.Outcome = "expired"
			if !expired.Did {
				result.Outcome = "settled"
			}
			return result, nil
		}

		// The next thing that could happen: the reminder if it is still ahead,
		// otherwise the deadline.
		wake := state.ExpiresAt
		remindNow := false
		if remindAt := state.ExpiresAt.Add(-ReminderLead); !result.Reminded {
			switch {
			case now.Before(remindAt):
				wake = remindAt
			default:
				// Already inside the reminder window — either because the
				// invitation was issued with less than the lead time left, or
				// because this run started late. Remind immediately rather than
				// skipping: a late nudge is still a nudge, and skipping would
				// silently drop the reminder for every short-window invitation.
				remindNow = true
			}
		}

		if remindNow {
			var reminded InvitationActionResult
			if err := workflow.ExecuteActivity(ctx, remindInvitationActivity, in).
				Get(ctx, &reminded); err != nil {
				return result, fmt.Errorf("reminding about invitation %s: %w",
					in.InvitationID, err)
			}
			// Marked whether or not it sent. A reminder that found the
			// invitation settled did not need sending, and retrying it on the
			// next wake would mail somebody about an invitation they already
			// accepted.
			result.Reminded = true
			continue
		}

		if err := workflow.Sleep(ctx, wake.Sub(now)); err != nil {
			// Cancellation, normally a worker shutting down. Returned so the
			// run is not recorded as a completed lifecycle that expired nothing.
			return result, err
		}
	}
}

// InvitationSnapshot is the aggregate's current state, crossing the activity
// boundary.
//
// It mirrors the use case's type rather than sharing it, which keeps this
// adapter free of the workspace module — the same reason InvitationSweeper
// declares its own pass type.
type InvitationSnapshot struct {
	Exists    bool
	Pending   bool
	ExpiresAt time.Time
}

// InvitationActionResult reports whether an action changed anything.
//
// Did=false is a normal answer and never an error: the aggregate is re-read
// inside the activity and may have moved since the workflow looked.
type InvitationActionResult struct{ Did bool }

// InvitationLifecycleOps is the activity set's dependency.
//
// Declared as an interface so this package neither depends on the workspace
// module nor can re-implement the decisions. Each of the three is taken against
// the aggregate, which is the only thing that can say whether an invitation may
// still be reminded about or expired.
type InvitationLifecycleOps interface {
	State(ctx context.Context, invitationID string) (InvitationSnapshot, error)
	Remind(ctx context.Context, invitationID, orgID string) (bool, error)
	Expire(ctx context.Context, invitationID string) (bool, error)
}

// InvitationLifecycleActivities holds the I/O half.
type InvitationLifecycleActivities struct{ ops InvitationLifecycleOps }

// NewInvitationLifecycleActivities builds the activity set.
func NewInvitationLifecycleActivities(
	ops InvitationLifecycleOps,
) (*InvitationLifecycleActivities, error) {
	if ops == nil {
		return nil, errors.New("temporal: the invitation lifecycle needs its operations; " +
			"without them every run would read nothing, remind nobody and expire nothing " +
			"while reporting success")
	}
	return &InvitationLifecycleActivities{ops: ops}, nil
}

// State reads the aggregate.
func (a *InvitationLifecycleActivities) State(
	ctx context.Context, in InvitationLifecycleInput,
) (InvitationSnapshot, error) {
	if in.InvitationID == "" {
		return InvitationSnapshot{}, sdktemporal.NewNonRetryableApplicationError(
			"no invitation was named", errTypePermanent, nil)
	}
	return a.ops.State(ctx, in.InvitationID)
}

// Remind mints a fresh link and mails it.
func (a *InvitationLifecycleActivities) Remind(
	ctx context.Context, in InvitationLifecycleInput,
) (InvitationActionResult, error) {
	if in.InvitationID == "" || in.OrgID == "" {
		return InvitationActionResult{}, sdktemporal.NewNonRetryableApplicationError(
			"a reminder needs an invitation and an organization", errTypePermanent, nil)
	}
	did, err := a.ops.Remind(ctx, in.InvitationID, in.OrgID)
	if err != nil {
		return InvitationActionResult{}, err
	}
	activity.GetLogger(ctx).Info("invitation reminder",
		"invitation", in.InvitationID, "sent", did)
	return InvitationActionResult{Did: did}, nil
}

// Expire closes the invitation and returns its seat.
func (a *InvitationLifecycleActivities) Expire(
	ctx context.Context, in InvitationLifecycleInput,
) (InvitationActionResult, error) {
	if in.InvitationID == "" {
		return InvitationActionResult{}, sdktemporal.NewNonRetryableApplicationError(
			"no invitation was named", errTypePermanent, nil)
	}
	did, err := a.ops.Expire(ctx, in.InvitationID)
	if err != nil {
		return InvitationActionResult{}, err
	}
	activity.GetLogger(ctx).Info("invitation expiry",
		"invitation", in.InvitationID, "expired", did)
	return InvitationActionResult{Did: did}, nil
}

// RegisterInvitationLifecycle adds the workflow to a worker, returning the names
// it now answers to.
func (w *Worker) RegisterInvitationLifecycle(
	a *InvitationLifecycleActivities,
) ([]string, error) {
	if w == nil || w.w == nil {
		return nil, errors.New("temporal: cannot register the invitation lifecycle on a nil worker")
	}
	if a == nil {
		return nil, errors.New("temporal: refusing to register the invitation lifecycle with " +
			"no activity set; every started run would fail on its first task")
	}
	registerInvitationLifecycle(w.w, a)
	return []string{InvitationLifecycleWorkflow}, nil
}

// registerInvitationLifecycle binds the workflow and its activities by NAME.
func registerInvitationLifecycle(r registry, a *InvitationLifecycleActivities) {
	r.RegisterWorkflowWithOptions(InvitationLifecycle,
		workflow.RegisterOptions{Name: InvitationLifecycleWorkflow})
	r.RegisterActivityWithOptions(a.State,
		activity.RegisterOptions{Name: invitationStateActivity})
	r.RegisterActivityWithOptions(a.Remind,
		activity.RegisterOptions{Name: remindInvitationActivity})
	r.RegisterActivityWithOptions(a.Expire,
		activity.RegisterOptions{Name: expireInvitationActivity})
}

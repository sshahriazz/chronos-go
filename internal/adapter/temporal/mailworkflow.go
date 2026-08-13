package temporal

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/platform/notify"
	sdktemporal "go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// SendNotificationWorkflow delivers one notification through the dispatcher.
//
// Names are PERSISTED in workflow history, so they are permanent: renaming one
// strands every in-flight execution against a worker that no longer answers to
// the name history records.
//
// The name lives in platform/notify, not here: the reactor that STARTS the
// workflow and the worker that REGISTERS it must agree, and two constants that
// must match are one constant with an extra chance to drift.
const SendNotificationWorkflow = notify.SendNotificationWorkflow

// deliverActivity is the single I/O step. All the I/O lives here because
// workflow code must be deterministic (no network, no clock, no randomness).
const deliverActivity = "chronos.notification.Deliver.v1"

// SendNotificationInput is the workflow argument, defined in platform/notify so
// the kernel can build one without importing this adapter (ADR-001).
type SendNotificationInput = notify.SendNotificationInput

// SendNotification is the reference workflow: mail is sent from an ACTIVITY,
// never inline in a handler (ADR-017).
//
// It contains no I/O, no clock and no randomness — every one of those would make
// replay produce a different history, which is the one thing a workflow may not
// do. What it does own is the RETRY POLICY, and owning it here is the point:
// a reactor's retries are the subscription's and stop when the event is parked,
// whereas an SMTP server that is down for an hour needs an hour of retries that
// survive this process being restarted.
func SendNotification(ctx workflow.Context, in notify.SendNotificationInput) error {
	opts := workflow.ActivityOptions{
		// One delivery attempt. Longer than any SMTP conversation should take,
		// short enough that a hung transport is retried rather than waited on.
		StartToCloseTimeout: 2 * time.Minute,
		RetryPolicy: &sdktemporal.RetryPolicy{
			InitialInterval:    5 * time.Second,
			BackoffCoefficient: 2,
			MaximumInterval:    10 * time.Minute,
			// Bounded by TIME rather than by attempts: what matters is "we kept
			// trying for an hour", not how many attempts fitted into it.
			MaximumAttempts: 0,
			// A notification that is structurally invalid, or addressed to a
			// subject that has been erased, will fail identically forever.
			// Retrying it burns an hour to reach the same answer.
			NonRetryableErrorTypes: []string{errTypePermanent},
		},
		ScheduleToCloseTimeout: time.Hour,
	}
	return workflow.ExecuteActivity(workflow.WithActivityOptions(ctx, opts),
		deliverActivity, in).Get(ctx, nil)
}

// errTypePermanent names failures no retry can fix.
const errTypePermanent = "chronos.permanent"

// Dispatcher is the activity's dependency: the notification dispatcher, which
// owns class policy, preferences, read arbitration and vault resolution.
//
// Declared as an interface so this package does not depend on the concrete
// dispatcher and a test can drive the activity without a vault.
type Dispatcher interface {
	Dispatch(ctx context.Context, n notify.Notification) error
}

// NotificationActivities holds the I/O half of the workflow.
type NotificationActivities struct{ dispatcher Dispatcher }

// NewNotificationActivities builds the activity set.
func NewNotificationActivities(d Dispatcher) (*NotificationActivities, error) {
	if d == nil {
		return nil, errors.New("temporal: the notification activity needs a dispatcher; " +
			"without one every workflow run would fail after a full hour of retries")
	}
	return &NotificationActivities{dispatcher: d}, nil
}

// Deliver performs the send.
//
// The context here carries the causation chain — the propagator put it there —
// so anything this activity does that appends an event is already attributed to
// whatever started the workflow, with no argument threaded through.
//
// Validation failures and erased subjects are marked NON-RETRYABLE. They are
// permanent by construction, and retrying one for an hour delays the failure
// without changing it.
func (a *NotificationActivities) Deliver(ctx context.Context, in notify.SendNotificationInput) error {
	n := in.Notification()
	if err := n.Validate(); err != nil {
		return sdktemporal.NewNonRetryableApplicationError(
			"the notification is not valid and never will be", errTypePermanent, err)
	}

	if err := a.dispatcher.Dispatch(ctx, n); err != nil {
		if errors.Is(err, notify.ErrSubjectErased) {
			// Not a failure: there is nothing to deliver to, and the correct
			// outcome is to stop rather than retry for an hour (ADR-002).
			return nil
		}
		return fmt.Errorf("delivering %s: %w", in.Template, err)
	}
	return nil
}

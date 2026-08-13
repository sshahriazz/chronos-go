package temporal

import (
	"errors"
	"fmt"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/worker"
	sdkworkflow "go.temporal.io/sdk/workflow"
)

// Worker runs registered workflows and activities from one task queue.
//
// It is a thin wrapper on purpose: what is worth owning here is the
// REGISTRATION, because a workflow that no worker registers is queued where
// nothing is listening — the run is created, the caller sees success, and the
// work simply never happens. That failure is invisible from the caller's side,
// which is why NewWorker refuses to build one with nothing registered.
type Worker struct {
	w     worker.Worker
	queue string
}

// WorkerDeps is what the worker needs to register the full set.
type WorkerDeps struct {
	// Client is the connection the worker polls on. Required.
	Client *Client

	// Notifications registers the mail/push/in-app workflow. Optional only in
	// the sense that a deployment may not have a dispatcher yet; without it that
	// workflow is NOT registered, and starting one would hang rather than fail.
	Notifications *NotificationActivities
}

// NewWorker builds and registers, without starting.
//
// Registration is name-based and the names are permanent (see the constants in
// mailworkflow.go): a worker registers the same string the history records, and
// changing either side strands in-flight executions.
func NewWorker(d WorkerDeps) (*Worker, error) {
	if d.Client == nil || d.Client.Raw() == nil {
		return nil, errors.New("temporal: a worker needs a client")
	}

	w := worker.New(d.Client.Raw(), d.Client.Queue(), worker.Options{})

	registered := 0
	if d.Notifications != nil {
		// Registered by NAME rather than by Go function name: the Go name is a
		// refactor away from changing, and the string is written into history
		// forever.
		w.RegisterWorkflowWithOptions(SendNotification,
			sdkworkflow.RegisterOptions{Name: SendNotificationWorkflow})
		w.RegisterActivityWithOptions(d.Notifications.Deliver,
			activity.RegisterOptions{Name: deliverActivity})
		registered++
	}

	if registered == 0 {
		// A worker that polls a queue and can run nothing on it is worse than no
		// worker: it looks healthy, the queue drains into it, and every task
		// fails to find a handler.
		return nil, errors.New("temporal: a worker with nothing registered would accept " +
			"tasks it cannot run; wire at least one workflow or do not start it")
	}
	return &Worker{w: w, queue: d.Client.Queue()}, nil
}

// Queue is the task queue this worker polls.
func (w *Worker) Queue() string { return w.queue }

// Registered reports the workflow names this worker answers to.
//
// Exposed so a composition-root test can assert the binary actually registered
// them. Three adapters in this repository were once fully built, fully tested
// and constructed by no binary; a component test cannot see that, and neither
// can this package.
func (w *Worker) Registered() []string { return []string{SendNotificationWorkflow} }

// Start begins polling in the background.
func (w *Worker) Start() error {
	if err := w.w.Start(); err != nil {
		return fmt.Errorf("temporal: starting the worker on %s: %w", w.queue, err)
	}
	return nil
}

// Stop drains in-flight tasks and stops polling.
func (w *Worker) Stop() { w.w.Stop() }

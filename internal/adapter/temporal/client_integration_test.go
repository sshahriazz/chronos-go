//go:build integration

package temporal_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/notify"
	"github.com/chronos/chronos-go/internal/platform/workflow"
)

func hostPort() string {
	if v := os.Getenv("TEMPORAL_HOSTPORT"); v != "" {
		return v
	}
	return "localhost:7233"
}

// dial builds a client and a worker against the running server, on a queue
// unique to this test binary so a stray worker elsewhere cannot serve its tasks.
func dial(t *testing.T, queue string, d temporaladapter.Dispatcher) *temporaladapter.Client {
	t.Helper()

	client, err := temporaladapter.Dial(temporaladapter.Config{
		HostPort: hostPort(), Namespace: "default", Queue: queue,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(client.Close)

	activities, err := temporaladapter.NewNotificationActivities(d)
	if err != nil {
		t.Fatalf("activities: %v", err)
	}
	w, err := temporaladapter.NewWorker(temporaladapter.WorkerDeps{
		Client: client, Notifications: activities,
	})
	if err != nil {
		t.Fatalf("worker: %v", err)
	}
	if err := w.Start(); err != nil {
		t.Fatalf("worker start: %v", err)
	}
	t.Cleanup(w.Stop)
	return client
}

// recording dispatcher, safe for the worker's goroutine.
type recorder struct {
	done  chan struct{}
	got   notify.Notification
	trace eventsourcing.Trace
}

func newRecorder() *recorder { return &recorder{done: make(chan struct{}, 4)} }

func (r *recorder) Dispatch(ctx context.Context, n notify.Notification) error {
	r.got = n
	r.trace = eventsourcing.TraceFrom(ctx)
	r.done <- struct{}{}
	return nil
}

// The whole path against the real server: start, poll, run the activity, and
// carry the causation chain across the process boundary.
func TestWorkflowRunsAgainstTheRunningServer(t *testing.T) {
	rec := newRecorder()
	queue := "chronos-it-" + time.Now().Format("150405.000000")
	client := dial(t, queue, rec)

	ctx := eventsourcing.WithTrace(context.Background(), eventsourcing.Trace{
		CorrelationID: "corr_it_1", CausationID: "evt_it_1",
	})
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	run, err := client.Start(ctx, workflow.Start{
		ID:   "chronos-it-" + queue,
		Name: temporaladapter.SendNotificationWorkflow,
		Input: temporaladapter.SendNotificationInput{
			Template:       "identity.password_changed",
			Class:          notify.Security,
			SubjectID:      "sub_it_1",
			OrgID:          "org_it_1",
			IdempotencyKey: "evt_it_1",
			OccurredAt:     time.Now().UTC(),
		},
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if run.RunID == "" {
		t.Error("the server reported no run id")
	}

	select {
	case <-rec.done:
	case <-ctx.Done():
		t.Fatal("the activity never ran: the workflow was started on a queue no worker served, " +
			"or the worker registered a different name than history recorded")
	}

	if rec.got.Recipient.SubjectID != "sub_it_1" {
		t.Errorf("subject %q reached the activity", rec.got.Recipient.SubjectID)
	}
	// The chain crossed a real gRPC boundary and a real workflow history.
	if rec.trace.CorrelationID != "corr_it_1" || rec.trace.CausationID != "evt_it_1" {
		t.Errorf("the causation chain did not survive the server: %+v", rec.trace)
	}
}

// The workflow id is derived from the event, so a redelivery starts the same id
// twice — and the second attempt must be REFUSED. That refusal is the
// idempotency guarantee: without it a redelivered event is a second email.
func TestASecondStartWithTheSameIDIsRefused(t *testing.T) {
	rec := newRecorder()
	queue := "chronos-it-dup-" + time.Now().Format("150405.000000")
	client := dial(t, queue, rec)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := workflow.Start{
		ID:   "chronos-it-dup-" + queue,
		Name: temporaladapter.SendNotificationWorkflow,
		Input: temporaladapter.SendNotificationInput{
			Template: "identity.password_changed", Class: notify.Security,
			SubjectID: "sub_it_2", OrgID: "org_it_2", IdempotencyKey: "evt_it_2",
			OccurredAt: time.Now().UTC(),
		},
	}

	if _, err := client.Start(ctx, start); err != nil {
		t.Fatalf("first start: %v", err)
	}
	_, err := client.Start(ctx, start)
	if !errors.Is(err, workflow.ErrAlreadyStarted) {
		t.Fatalf("the second start returned %v, want ErrAlreadyStarted — a redelivered "+
			"event would run the effect twice", err)
	}
}

// A probe that does not make a round trip reports healthy against a dead
// server: the client object exists whether or not anything is listening.
func TestProbeReachesTheServer(t *testing.T) {
	client := dial(t, "chronos-it-probe-"+time.Now().Format("150405.000000"), newRecorder())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := (temporaladapter.Probe{Client: client}).Check(ctx); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if err := (temporaladapter.Probe{}).Check(ctx); err == nil {
		t.Error("a probe with no client reported healthy")
	}
}

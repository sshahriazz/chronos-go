//go:build integration

package main

import (
	"context"
	"log/slog"
	"testing"
	"time"

	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
)

// Registering the sweep is only half of it: a workflow nothing ever STARTS is
// indistinguishable from a working one. The worker is healthy, the queue is
// empty, every metric is green, and email addresses stay held by people who
// never proved they own them.
//
// Integration-tagged because a schedule is server-side state — the assertion is
// that the running Temporal actually has it, which is the only place that fact
// exists. The unit half (that the schedule names the workflow the worker
// registers, on the queue it polls) is in
// internal/adapter/temporal/sweepworkflow_test.go and needs nothing running.
func TestEnablingDurableWorkSchedulesTheSweep(t *testing.T) {
	t.Setenv("TEMPORAL_ENABLED", "true")
	cfg := testConfig(t)

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	if d.temporal == nil {
		t.Fatal("TEMPORAL_ENABLED=true built no client")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	handle := d.temporal.Raw().ScheduleClient().
		GetHandle(ctx, temporaladapter.SweepReservationsScheduleID)
	desc, err := handle.Describe(ctx)
	if err != nil {
		t.Fatalf("the lapsed email-reservation sweep is not scheduled, so lapsed claims "+
			"are never released and nothing else reports it: %v", err)
	}

	// What the schedule STARTS is asserted without a server in the adapter's own
	// tests; what only a running server can say is that it exists and is live.
	if desc.Schedule.State != nil && desc.Schedule.State.Paused {
		t.Errorf("the sweep schedule exists but is PAUSED, so nothing releases lapsed "+
			"reservations: %s", desc.Schedule.State.Note)
	}
}

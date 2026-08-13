//go:build integration

package main

import (
	"context"
	"log/slog"
	"testing"
	"time"

	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
)

// Registering the retention workflow is only half of it: a workflow nothing ever
// STARTS is indistinguishable from a working one, and for retention it is
// indistinguishable from EVERYTHING. The worker is healthy, the queue is empty,
// every metric is green, no user is affected, and totp_replay — which PostgreSQL
// gives no TTL — grows for the lifetime of the deployment.
//
// Integration-tagged because a schedule is server-side state: the assertion is
// that the running Temporal actually has it, which is the only place that fact
// exists. The unit half — that the schedule names the workflow the worker
// registers, on the queue it polls — is in
// internal/adapter/temporal/retentionworkflow_test.go and needs nothing running.
func TestEnablingDurableWorkSchedulesRetention(t *testing.T) {
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
		GetHandle(ctx, temporaladapter.PurgeRetentionScheduleID)
	desc, err := handle.Describe(ctx)
	if err != nil {
		t.Fatalf("identity retention is not scheduled, so nothing is ever deleted and "+
			"nothing else reports it: %v", err)
	}

	if desc.Schedule.State != nil && desc.Schedule.State.Paused {
		t.Errorf("the retention schedule exists but is PAUSED, so identity's tables with no "+
			"TTL keep growing: %s", desc.Schedule.State.Note)
	}
}

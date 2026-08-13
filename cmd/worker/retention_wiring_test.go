package main

import (
	"log/slog"
	"slices"
	"testing"

	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
)

// Identity's retention job is the case a component test is structurally unable
// to see.
//
// Every other gap in this system eventually produces a symptom somebody reports.
// This one produces none. If the workflow is never registered, the schedule
// queues runs where nothing is listening: the run is created, the caller is told
// it started, the worker is healthy, the queue is empty and every metric is
// green. Nothing errors, nothing degrades, and no user is ever affected — while
// totp_replay, which PostgreSQL gives no TTL and which gains a row for every TOTP
// code anyone presents, grows for the lifetime of the deployment (ADR-049).
//
// Only a test of the COMPOSITION ROOT can catch that. Three adapters in this
// repository were once fully built, fully tested and constructed by no binary.
func TestIdentityRetentionIsBuiltAndRegistered(t *testing.T) {
	// A dead address, deliberately. The Temporal client is lazy and neither
	// building a worker nor registering on one performs any I/O, so this test
	// needs no infrastructure — and pointing it at a port nothing listens on is
	// what proves that rather than assuming it. Only Start dials, and Start is the
	// one step this test does not take.
	t.Setenv("TEMPORAL_HOSTPORT", "127.0.0.1:1")
	cfg := testConfig(t)

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	if d.retention == nil {
		t.Fatal("identity retention was not constructed: spent TOTP steps, expired token " +
			"digests and the secret half of dead sessions are retained for the lifetime of " +
			"the deployment, and nothing reports it")
	}

	client, err := temporaladapter.Dial(temporaladapter.Config{
		HostPort:  cfg.Temporal.HostPort,
		Namespace: cfg.Temporal.Namespace,
		Queue:     cfg.Temporal.Queue,
	})
	if err != nil {
		t.Fatalf("dialling lazily: %v", err)
	}
	defer client.Close()

	// The production path, exactly — startTemporal calls this and then Start.
	w, names, err := d.newTemporalWorker(client)
	if err != nil {
		t.Fatalf("the worker this binary would build could not be built: %v", err)
	}
	if w == nil {
		t.Fatal("no worker was built")
	}

	if !slices.Contains(names, temporaladapter.PurgeIdentityRetentionWorkflow) {
		t.Errorf("the worker does not answer to %s, so the schedule that starts it queues "+
			"work where nothing is listening: the run is created, the caller is told it "+
			"started, and not one row is ever deleted. Registered: %v",
			temporaladapter.PurgeIdentityRetentionWorkflow, names)
	}
	// Registered BESIDE the others, not instead of them: a registration that
	// replaced another would pass a containment check while silently stranding
	// every notification workflow in flight, or switching off the reservation
	// sweep — which IS a security control.
	for _, other := range []string{
		temporaladapter.SendNotificationWorkflow,
		temporaladapter.SweepReservationsWorkflow,
	} {
		if !slices.Contains(names, other) {
			t.Errorf("registering identity retention displaced %s. Registered: %v", other, names)
		}
	}
}

// Retention is built whether or not durable work is enabled, so that a deployment
// without Temporal reports "retention could not be constructed" rather than
// reporting nothing at all.
func TestRetentionIsConstructedEvenWithDurableWorkDisabled(t *testing.T) {
	cfg := testConfig(t) // TEMPORAL_ENABLED defaults to false
	if cfg.Temporal.Enabled {
		t.Fatal("this test is meaningless with durable work enabled")
	}

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	if d.retention == nil {
		t.Fatal("no retention job was constructed")
	}
}

// The worker must refuse to be built rather than register a retention activity
// wrapping nothing.
//
// A retentionAdapter around a nil use case is a NON-nil interface, so
// NewRetentionActivities' own nil check passes and the failure moves to a panic
// on the first scheduled run — daily, forever, in a job nobody is watching. The
// composition root checks the use case itself for exactly that reason, and this
// asserts the check is there.
func TestTheWorkerRefusesToRegisterRetentionThatWasNotBuilt(t *testing.T) {
	t.Setenv("TEMPORAL_HOSTPORT", "127.0.0.1:1")
	cfg := testConfig(t)

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	client, err := temporaladapter.Dial(temporaladapter.Config{
		HostPort:  cfg.Temporal.HostPort,
		Namespace: cfg.Temporal.Namespace,
		Queue:     cfg.Temporal.Queue,
	})
	if err != nil {
		t.Fatalf("dialling lazily: %v", err)
	}
	defer client.Close()

	d.retention = nil
	if _, _, err := d.newTemporalWorker(client); err == nil {
		t.Fatal("a worker was built with no retention use case; its schedule would start " +
			"runs that panic on every task")
	}
}

package main

import (
	"log/slog"
	"slices"
	"testing"

	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
)

// The invitation sweep must be REGISTERED, or the schedule that starts it queues
// work where nothing is listening.
//
// The failure has a particular shape here. The run is created, the schedule
// reports it started, and every observable signal stays green — while seats held
// by invitations that ran out weeks ago are never given back. Nothing else in
// the system reports it, because the per-invitation workflow still expires the
// ones it did start, so the loss is partial and grows slowly.
func TestTheInvitationSweepIsRegistered(t *testing.T) {
	// A lazy client against a port nothing listens on: registration performs no
	// I/O, and pointing it somewhere dead is what proves that rather than
	// assuming it. Only Start dials, and Start is the step this test omits.
	t.Setenv("TEMPORAL_HOSTPORT", "127.0.0.1:1")
	cfg := testConfig(t)

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	if d.invitationSweep == nil {
		t.Fatal("the invitation sweep was not constructed: an invitation whose " +
			"per-invitation workflow never started holds its seat forever, and no other " +
			"part of this system reports it")
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
	_, names, err := d.newTemporalWorker(client)
	if err != nil {
		t.Fatalf("the worker this binary would build could not be built: %v", err)
	}

	if !slices.Contains(names, temporaladapter.SweepInvitationsWorkflow) {
		t.Errorf("the worker does not answer to %s, so the schedule that starts it queues "+
			"work where nothing is listening: the run is created, the caller is told it "+
			"started, and no seat is ever given back. Registered: %v",
			temporaladapter.SweepInvitationsWorkflow, names)
	}

	// The per-invitation timer, registered beside the sweep. It is what makes
	// expiry timely and reminders possible at all; without it every invitation
	// waits for the hourly reconciliation and nobody is ever nudged.
	if !slices.Contains(names, temporaladapter.InvitationLifecycleWorkflow) {
		t.Errorf("the worker does not answer to %s, so every timer the reactor starts is "+
			"queued where nothing is listening: no reminder is ever sent and expiry falls "+
			"back to the hourly sweep. Registered: %v",
			temporaladapter.InvitationLifecycleWorkflow, names)
	}

	// BESIDE the others, not instead of them. A registration that displaced
	// another would pass a containment check while stranding every workflow of
	// the displaced kind that is in flight.
	for _, other := range []string{
		temporaladapter.SendNotificationWorkflow,
		temporaladapter.SweepReservationsWorkflow,
	} {
		if !slices.Contains(names, other) {
			t.Errorf("registering the invitation sweep displaced %s. Registered: %v",
				other, names)
		}
	}
}

// The sweep is built whether or not durable work is enabled, so a deployment
// without Temporal reports "the sweep could not be constructed" rather than
// reporting nothing at all.
func TestTheInvitationSweepIsConstructedEvenWithDurableWorkDisabled(t *testing.T) {
	cfg := testConfig(t) // TEMPORAL_ENABLED defaults to false
	if cfg.Temporal.Enabled {
		t.Fatal("this test is meaningless with durable work enabled")
	}

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	if d.invitationSweep == nil {
		t.Fatal("with durable work disabled the sweep was not constructed at all, so the " +
			"log says nothing about why seats are not coming back")
	}
}

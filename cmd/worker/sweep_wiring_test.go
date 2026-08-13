package main

import (
	"log/slog"
	"slices"
	"testing"

	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
)

// The lapsed email-reservation sweep is a SECURITY CONTROL, and one whose
// absence is invisible from every other signal this binary emits: the worker is
// healthy, the queue is empty, every metric is green, and email addresses stay
// held by people who never proved they own them. Nothing degrades, nothing
// errors, and the first report is a user saying they cannot register with their
// own address.
//
// Component tests cannot see that gap — the workflow, the activity and the use
// case all pass on their own. Only a test of the COMPOSITION ROOT can, which is
// what this is. Three adapters in this repository were once fully built, fully
// tested and constructed by no binary.
func TestTheLapsedReservationSweepIsBuiltAndRegistered(t *testing.T) {
	// A dead address, deliberately. The Temporal client is lazy and neither
	// building a worker nor registering on one performs any I/O, so this test
	// needs no infrastructure — and pointing it at a port nothing listens on is
	// what proves that rather than assuming it. Only Start dials, and Start is
	// the one step this test does not take.
	t.Setenv("TEMPORAL_HOSTPORT", "127.0.0.1:1")
	cfg := testConfig(t)

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	if d.reservations == nil {
		t.Fatal("the lapsed email-reservation sweep was not constructed: an abandoned " +
			"registration holds its address permanently, and its owner can never register")
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

	if !slices.Contains(names, temporaladapter.SweepReservationsWorkflow) {
		t.Errorf("the worker does not answer to %s, so the schedule that starts it queues "+
			"work where nothing is listening: the run is created, the caller is told it "+
			"started, and no reservation is ever released. Registered: %v",
			temporaladapter.SweepReservationsWorkflow, names)
	}
	// The sweep must be registered BESIDE the notification workflow, not instead
	// of it: a registration that replaced another would pass a containment check
	// while silently stranding every notification workflow in flight.
	if !slices.Contains(names, temporaladapter.SendNotificationWorkflow) {
		t.Errorf("registering the sweep displaced %s. Registered: %v",
			temporaladapter.SendNotificationWorkflow, names)
	}
}

// The sweep is built whether or not durable work is enabled, so that a
// deployment without Temporal reports "the sweep could not be constructed"
// rather than reporting nothing at all.
func TestTheSweepIsConstructedEvenWithDurableWorkDisabled(t *testing.T) {
	cfg := testConfig(t) // TEMPORAL_ENABLED defaults to false
	if cfg.Temporal.Enabled {
		t.Fatal("this test is meaningless with durable work enabled")
	}

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	if d.reservations == nil {
		t.Fatal("no sweep was constructed")
	}
}

// The repository the sweep appends through must be able to decode the whole
// reservation stream. A codec missing one of the three types loads the aggregate
// into a wrong state — or fails — on exactly the streams that need releasing.
func TestTheReservationCodecDecodesTheWholeStream(t *testing.T) {
	codec, upcasters := newReservationCodec()
	if upcasters == nil {
		t.Fatal("no upcaster registry: a stored event at any schema version but the " +
			"current one would fail to load")
	}
	for _, want := range []string{
		"identity.EmailReserved.v1",
		"identity.EmailReservationConfirmed.v1",
		"identity.EmailReleased.v1",
	} {
		if !slices.Contains(codec.Types(), want) {
			t.Errorf("the reservation repository's codec cannot decode %s, which is on "+
				"every reservation stream it loads", want)
		}
	}
}

package main

import (
	"log/slog"
	"testing"

	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
)

// The sweep's probe must be registered EVEN WHEN durable work is disabled.
//
// That is the case worth testing, and it is the one a reasonable implementation
// gets wrong: `startTemporal` returns early when TEMPORAL_ENABLED=false, so a
// probe registered further down never exists in exactly the deployment where the
// sweep never runs. Every other probe would be green, the worker would be
// healthy, and lapsed email reservations would be held forever with nothing
// reporting it.
//
// Infra-free: with durable work disabled nothing dials, so this holds whether or
// not Temporal is running. The variant that needs a live server is in
// sweep_wiring_integration_test.go.
func TestScheduleProbesAreRegisteredEvenWithDurableWorkDisabled(t *testing.T) {
	cfg := testConfig(t) // TEMPORAL_ENABLED defaults to false
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	registered := make(map[string]bool, len(d.probes))
	for _, p := range d.probes {
		registered[p.Name()] = true

		// Registered is not enough — a probe has to REPORT the problem. One that
		// returned nil here would be worse than no probe: it would put a green row
		// on the status page next to work that never runs.
		if p.Name() == temporaladapter.SweepReservationsProbe(nil).Name() ||
			p.Name() == temporaladapter.PurgeRetentionProbe(nil).Name() {
			if err := p.Check(t.Context()); err == nil {
				t.Errorf("with durable work disabled, %q reports healthy, so a deployment "+
					"in which that job never runs looks fine", p.Name())
			}
		}
	}

	// Both schedules, not just the sweep. Every recurring job added from here on
	// belongs in this list — the failure they share is that nothing else in the
	// system reports a schedule that was never created.
	for _, want := range []struct{ probe, consequence string }{
		{
			temporaladapter.SweepReservationsProbe(nil).Name(),
			"lapsed email reservations are never released, so an address claimed by " +
				"someone who never proved they own it is held forever",
		},
		{
			temporaladapter.PurgeRetentionProbe(nil).Name(),
			"identity's retention statements never run, so totp_replay and the token " +
				"and session-secret tables grow without bound",
		},
	} {
		if !registered[want.probe] {
			t.Errorf("no probe watches %q with durable work disabled: %s, and nothing "+
				"reports it", want.probe, want.consequence)
		}
	}
}

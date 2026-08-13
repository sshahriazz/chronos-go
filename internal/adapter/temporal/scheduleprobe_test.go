package temporal_test

import (
	"context"
	"strings"
	"testing"

	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
	"github.com/chronos/chronos-go/internal/server/health"
)

// A probe with no client reports NOT SCHEDULED rather than healthy.
//
// This is the TEMPORAL_ENABLED=false deployment and the whole reason the probe
// exists: with durable work off, nothing recurring runs, and every other probe
// in the process is green because every other dependency really is fine. A probe
// that treated "no client" as "nothing to check" would confirm the silence
// instead of breaking it.
//
// Infra-free by construction — a nil client never dials.
func TestAScheduleProbeWithNoClientReportsItIsNotScheduled(t *testing.T) {
	t.Parallel()

	err := temporaladapter.SweepReservationsProbe(nil).Check(context.Background())
	if err == nil {
		t.Fatal("a probe with no Temporal client reported the sweep as scheduled; a deployment " +
			"with durable work disabled would look healthy while lapsed claims are never released")
	}
	if !strings.Contains(err.Error(), "not scheduled") {
		t.Errorf("the failure reads %q, which does not tell an operator the job is unscheduled",
			err.Error())
	}
}

// The probe must not be Critical.
//
// Asserted rather than assumed, because the consequence of getting it wrong is
// the opposite of what the probe is for: Critical fails readiness, so an
// unscheduled background job would pull every worker out of the load balancer and
// turn late work into an outage (ADR-010).
func TestAScheduleProbeIsDegradableNotCritical(t *testing.T) {
	t.Parallel()

	if got := temporaladapter.SweepReservationsProbe(nil).Criticality(); got != health.Degradable {
		t.Errorf("the sweep probe is %v; Critical would fail readiness and take the binary "+
			"out of rotation because background work is late", got)
	}
}

// Name and Impact are what an operator actually reads.
func TestAScheduleProbeDescribesItself(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		probe temporaladapter.ScheduleProbe
		want  func(t *testing.T, p temporaladapter.ScheduleProbe)
	}{
		{
			name:  "the sweep probe names the schedule it watches",
			probe: temporaladapter.SweepReservationsProbe(nil),
			want: func(t *testing.T, p temporaladapter.ScheduleProbe) {
				t.Helper()
				// Pinned to the constant, not to a copy of the string: the id is a
				// wire-level identifier, and a probe watching a schedule nobody
				// creates is exactly as silent as no probe at all.
				if p.ID != temporaladapter.SweepReservationsScheduleID {
					t.Errorf("the probe watches %q, not the schedule the worker creates (%q)",
						p.ID, temporaladapter.SweepReservationsScheduleID)
				}
				if p.Name() == "" || p.Name() == "schedule" {
					t.Errorf("the probe is called %q, which does not identify it on a status "+
						"page listing several schedules", p.Name())
				}
				// The impact line is read by whoever is paged. A generic one tells
				// them a job is late; this one has to tell them what it costs.
				if !strings.Contains(strings.ToLower(p.Impact()), "address") {
					t.Errorf("the impact line %q does not say what is actually lost when "+
						"lapsed reservations are never released", p.Impact())
				}
			},
		},
		{
			name:  "a bare probe still answers, rather than reporting an empty name",
			probe: temporaladapter.ScheduleProbe{},
			want: func(t *testing.T, p temporaladapter.ScheduleProbe) {
				t.Helper()
				// A probe with an empty Name would render as a blank row on the
				// status surface, which is worse than a generic label.
				if p.Name() == "" {
					t.Error("an unconfigured probe has no name, so it renders as a blank row")
				}
				if p.Impact() == "" {
					t.Error("an unconfigured probe describes no impact")
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.want(t, tc.probe)
		})
	}
}

// A probe naming no schedule fails rather than passing vacuously.
//
// Without this, a wiring mistake that left ID empty would produce a probe that
// reports healthy forever while watching nothing — the failure mode this whole
// type exists to eliminate, reintroduced one level up.
func TestAScheduleProbeWithNoScheduleIDRefusesToReportHealthy(t *testing.T) {
	t.Parallel()

	p := temporaladapter.ScheduleProbe{ProbeName: "unnamed"}
	if err := p.Check(context.Background()); err == nil {
		t.Fatal("a probe naming no schedule reported healthy")
	}
}

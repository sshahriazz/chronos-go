package temporal

import (
	"context"
	"errors"
	"fmt"

	"github.com/chronos/chronos-go/internal/server/health"
)

// ScheduleProbe reports whether a recurring job is actually scheduled.
//
// # Why a schedule needs its own probe
//
// Every other probe in this system answers "is the dependency reachable?" This
// one answers a question nothing else asks: "is the recurring work ever going to
// run?" Those come apart completely. Temporal can be up, the worker polling, the
// queue empty, every existing probe green — and a schedule that was never created
// simply never fires. There is no error, no failed workflow, no retry, no metric
// that moves. The absence of work looks exactly like the absence of work to do.
//
// That failure mode is why the reservation sweep needed this. The sweep releases
// email claims whose lease has lapsed, and a claim that is never released holds an
// address forever against someone who may be its real owner. A missing schedule
// turns a security control into nothing at all, silently and indefinitely.
//
// # Why it is DEGRADABLE rather than Critical
//
// Following seaweedfs and the Temporal client probe: an unscheduled sweep does
// not stop anyone signing in, reading, or writing. Marking it Critical would take
// the binary out of the load balancer over work that is late rather than wrong,
// which converts a background problem into an outage. The point of the probe is
// to make the state VISIBLE on the status surface and in alerting, not to fail
// the process — ADR-010 exactly.
//
// # Deliberately not a liveness check on the runs
//
// It asserts that the schedule EXISTS, not that its last run succeeded. A failed
// run is Temporal's to retry and is visible in its own UI and metrics; a missing
// schedule is invisible everywhere else, and that is the gap this fills. Checking
// run outcomes here would duplicate Temporal's own reporting and make the probe
// flap on a single transient failure.
type ScheduleProbe struct {
	Client *Client

	// ID is the schedule to look for.
	ID string

	// ProbeName is what the status surface calls this. It is a parameter rather
	// than derived from ID because operators read it, and a schedule id is a
	// wire-level identifier that must never change.
	ProbeName string

	// Consequence completes the sentence "while this is not scheduled, …". It is
	// required, and it is written for whoever is paged: what stops happening, and
	// what it costs.
	Consequence string
}

var _ health.Probe = ScheduleProbe{}

func (p ScheduleProbe) Name() string {
	if p.ProbeName == "" {
		return "schedule"
	}
	return p.ProbeName
}

func (ScheduleProbe) Criticality() health.Criticality { return health.Degradable }

func (p ScheduleProbe) Impact() string {
	if p.Consequence == "" {
		return "A recurring job is not scheduled and will never run."
	}
	return p.Consequence
}

// Check describes the schedule.
//
// A real round trip, like every other probe here: a handle exists whether or not
// the schedule does, so anything short of a Describe reports healthy against a
// schedule that was never created — which is the one state this probe exists to
// catch.
//
// A nil client is reported as NOT scheduled rather than skipped. That is the
// TEMPORAL_ENABLED=false deployment, and it is precisely the case worth
// surfacing: durable work is off, so nothing recurring runs at all, and a probe
// that quietly passed would confirm the silence instead of breaking it.
func (p ScheduleProbe) Check(ctx context.Context) error {
	if p.Client == nil || p.Client.c == nil {
		return errors.New("durable work is not enabled, so this job is not scheduled and " +
			"will never run")
	}
	if p.ID == "" {
		return errors.New("the probe names no schedule, so it cannot report whether one exists")
	}

	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	if _, err := p.Client.c.ScheduleClient().GetHandle(ctx, p.ID).Describe(ctx); err != nil {
		return fmt.Errorf("schedule %s: %w", p.ID, err)
	}
	return nil
}

// PurgeRetentionProbe watches identity's daily retention schedule.
//
// Retention is the quieter of the two schedules and the easier one to lose: it
// deletes rows nobody looks at, so nothing downstream fails when it stops. The
// tables simply grow — `totp_replay` gains rows on every second-factor
// verification, forever, and PostgreSQL has no TTL to bound them (ADR-049).
//
// The mutation pass on the retention job found exactly this gap: removing the
// call that creates the schedule leaves the workflow registered and never
// started, and no test without a live Temporal can see it. This probe is what
// makes that state visible at runtime instead.
func PurgeRetentionProbe(c *Client) ScheduleProbe {
	return ScheduleProbe{
		Client:    c,
		ID:        PurgeRetentionScheduleID,
		ProbeName: "identity_retention",
		Consequence: "Identity's retention statements never run, so spent TOTP steps, expired " +
			"token digests and dead session secrets accumulate without bound. Nothing fails; " +
			"the tables just grow, and no other signal reports it.",
	}
}

// SweepReservationsProbe is the reservation sweep's probe, pre-worded.
//
// Built here rather than in the composition root so the consequence is written
// once, next to the schedule it describes, by whoever knows what the sweep is
// for. A wiring-site string is one nobody updates when the job's purpose changes.
func SweepReservationsProbe(c *Client) ScheduleProbe {
	return ScheduleProbe{
		Client:    c,
		ID:        SweepReservationsScheduleID,
		ProbeName: "email_reservation_sweep",
		Consequence: "Lapsed email reservations are never released, so an address claimed by " +
			"someone who never proved they own it stays claimed indefinitely and its real " +
			"owner cannot register. Nothing else is affected, and nothing else reports this.",
	}
}

package health_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/obs"
	"github.com/chronos/chronos-go/internal/server/health"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

var at = time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)

func newRegistry(timeout time.Duration) *health.Registry {
	return health.New(clock.NewFixed(at), timeout)
}

func probe(name string, c health.Criticality, err error) health.Probe {
	return health.ProbeFunc{
		NameValue:        name,
		CriticalityValue: c,
		ImpactValue:      "impact of " + name,
		CheckFunc:        func(context.Context) error { return err },
	}
}

func find(t *testing.T, rep health.Report, name string) health.Result {
	t.Helper()
	for _, d := range rep.Dependencies {
		if d.Name == name {
			return d
		}
	}
	t.Fatalf("dependency %q absent from report", name)
	return health.Result{}
}

func TestAllUp(t *testing.T) {
	r := newRegistry(time.Second)
	r.Register(probe("postgres", health.Critical, nil))
	r.Register(probe("valkey", health.Degradable, nil))

	rep := r.Check(t.Context())
	if !rep.Ready || !rep.FullyOperational {
		t.Fatalf("ready=%v fullyOperational=%v, want both true", rep.Ready, rep.FullyOperational)
	}
}

func TestCriticalDown_FailsReadiness(t *testing.T) {
	r := newRegistry(time.Second)
	r.Register(probe("postgres", health.Critical, errors.New("connection refused")))

	rep := r.Check(t.Context())
	if rep.Ready {
		t.Fatal("a critical dependency being down must fail readiness")
	}
	if got := find(t, rep, "postgres"); got.Health != health.Down {
		t.Fatalf("health: got %v want down", got.Health)
	}
}

// Losing a cache must not take the service out of the load balancer.
func TestDegradableDown_StaysReady(t *testing.T) {
	r := newRegistry(time.Second)
	r.Register(probe("postgres", health.Critical, nil))
	r.Register(probe("valkey", health.Degradable, errors.New("unreachable")))

	rep := r.Check(t.Context())
	if !rep.Ready {
		t.Fatal("a degradable dependency must not fail readiness")
	}
	if rep.FullyOperational {
		t.Fatal("but the system is not fully operational")
	}
	if got := find(t, rep, "valkey"); got.Health != health.Degraded {
		t.Fatalf("a degradable failure reports DEGRADED, got %v", got.Health)
	}
}

// The subtle one: OpenFGA down means every request denies (ADR-010). Readiness
// must still pass, or every instance leaves the load balancer simultaneously and
// clients get a connection error instead of a clear cause.
func TestFailClosedDown_StaysReadyButNotOperational(t *testing.T) {
	r := newRegistry(time.Second)
	r.Register(probe("postgres", health.Critical, nil))
	r.Register(probe("openfga", health.FailClosed, errors.New("unreachable")))

	rep := r.Check(t.Context())
	if !rep.Ready {
		t.Fatal("fail-closed down must not remove the instance from the load balancer")
	}
	if rep.FullyOperational {
		t.Fatal("fully operational must be false")
	}
	if got := find(t, rep, "openfga"); got.Health != health.Down {
		t.Fatalf("fail-closed reports DOWN, not degraded; got %v", got.Health)
	}
}

// A dependency that hangs must not hang the endpoint someone is reading
// *because* it is hanging.
func TestHangingProbe_IsBoundedByTimeout(t *testing.T) {
	r := newRegistry(50 * time.Millisecond)
	r.Register(health.ProbeFunc{
		NameValue:        "slow",
		CriticalityValue: health.Critical,
		CheckFunc: func(ctx context.Context) error {
			<-ctx.Done() // never returns on its own
			return ctx.Err()
		},
	})

	start := time.Now()
	rep := r.Check(t.Context())
	elapsed := time.Since(start)

	if elapsed > time.Second {
		t.Fatalf("probe was not bounded: took %v", elapsed)
	}
	if got := find(t, rep, "slow"); got.Health != health.Down {
		t.Fatalf("a timed-out probe is down, got %v", got.Health)
	}
	if rep.Ready {
		t.Fatal("timed-out critical dependency must fail readiness")
	}
}

// A badly written adapter must not be able to take down the health endpoint.
func TestPanickingProbe_IsContained(t *testing.T) {
	r := newRegistry(time.Second)
	r.Register(probe("postgres", health.Critical, nil))
	r.Register(health.ProbeFunc{
		NameValue:        "buggy",
		CriticalityValue: health.Degradable,
		CheckFunc:        func(context.Context) error { panic("nil map write") },
	})

	rep := r.Check(t.Context()) // must not panic
	got := find(t, rep, "buggy")
	if got.Health != health.Down {
		t.Fatalf("a panicking probe is down, got %v", got.Health)
	}
	if got.Detail == "" {
		t.Fatal("the panic should be reported to operators")
	}
	if !rep.Ready {
		t.Fatal("one buggy degradable probe must not fail readiness")
	}
}

func TestProbesRunConcurrently(t *testing.T) {
	r := newRegistry(2 * time.Second)
	const n = 8
	for i := range n {
		r.Register(health.ProbeFunc{
			NameValue:        string(rune('a' + i)),
			CriticalityValue: health.Degradable,
			CheckFunc: func(context.Context) error {
				time.Sleep(80 * time.Millisecond)
				return nil
			},
		})
	}
	start := time.Now()
	r.Check(t.Context())
	if elapsed := time.Since(start); elapsed > 400*time.Millisecond {
		t.Fatalf("probes appear serial: %d probes took %v", n, elapsed)
	}
}

func TestEmptyRegistry_IsReady(t *testing.T) {
	rep := newRegistry(time.Second).Check(t.Context())
	if !rep.Ready || !rep.FullyOperational {
		t.Fatal("a server with no dependencies is ready")
	}
}

func TestReport_CarriesImpactAndTiming(t *testing.T) {
	r := newRegistry(time.Second)
	r.Register(probe("seaweedfs", health.Degradable, errors.New("no route to host")))

	got := find(t, r.Check(t.Context()), "seaweedfs")
	if got.Impact == "" {
		t.Error("impact must be reported so a client can degrade deliberately")
	}
	if got.Detail == "" {
		t.Error("detail must reach operators")
	}
	if !got.CheckedAt.Equal(at) {
		t.Errorf("checked-at should come from the injected clock, got %v", got.CheckedAt)
	}
}

// ---------------------------------------------------------------------------
// Metrics export
//
// These are the tests for the reason this hook exists: the two Temporal
// schedule probes are the only signal that a recurring job will ever run, and a
// schedule that was never created produces no error and no failed workflow. If
// the probe result does not reach Prometheus, the only way to learn about it is
// for someone to open the status endpoint and read.
// ---------------------------------------------------------------------------

// observation is one call to Observed, flattened so a test can compare whole
// tuples rather than asserting field by field and missing the field that broke.
type observation struct {
	dependency  string
	criticality string
	state       string
	seconds     float64
}

type recordingObserver struct {
	mu           sync.Mutex
	registered   []observation // criticality carried; state and seconds unset
	observations []observation
}

func (o *recordingObserver) Registered(dependency, criticality string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.registered = append(o.registered, observation{dependency: dependency, criticality: criticality})
}

func (o *recordingObserver) Observed(dependency, criticality, state string, seconds float64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.observations = append(o.observations,
		observation{dependency, criticality, state, seconds})
}

func (o *recordingObserver) find(t *testing.T, dependency string) observation {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, obv := range o.observations {
		if obv.dependency == dependency {
			return obv
		}
	}
	t.Fatalf("no observation recorded for %q; recorded %+v", dependency, o.observations)
	return observation{}
}

func TestObserver_RecordsStateAndCriticalityPerProbe(t *testing.T) {
	o := &recordingObserver{}
	r := health.New(clock.NewFixed(at), time.Second, health.WithObserver(o))
	r.Register(probe("postgres", health.Critical, nil))
	r.Register(probe("valkey", health.Degradable, errors.New("unreachable")))
	r.Register(probe("openfga", health.FailClosed, errors.New("unreachable")))

	r.Check(t.Context())

	want := map[string]observation{
		"postgres": {"postgres", "critical", "up", 0},
		"valkey":   {"valkey", "degradable", "degraded", 0},
		"openfga":  {"openfga", "fail_closed", "down", 0},
	}
	for name, w := range want {
		got := o.find(t, name)
		if got.criticality != w.criticality || got.state != w.state {
			t.Errorf("%s: got criticality=%q state=%q, want %q/%q",
				name, got.criticality, got.state, w.criticality, w.state)
		}
		if got.seconds <= 0 {
			t.Errorf("%s: latency %v must be a real measurement", name, got.seconds)
		}
	}
}

// The whole point: a failing probe must MOVE the metric. A test that only
// asserted the observer was called for a healthy probe would pass with the
// failure path deleted.
func TestObserver_FailureMovesTheStateFromUpToDown(t *testing.T) {
	failing := errors.New("connection refused")
	var fail bool

	o := &recordingObserver{}
	r := health.New(clock.NewFixed(at), time.Second, health.WithObserver(o))
	r.Register(health.ProbeFunc{
		NameValue:        "postgres",
		CriticalityValue: health.Critical,
		CheckFunc: func(context.Context) error {
			if fail {
				return failing
			}
			return nil
		},
	})

	r.Check(t.Context())
	if got := o.find(t, "postgres").state; got != "up" {
		t.Fatalf("healthy probe recorded as %q", got)
	}

	fail = true
	o.observations = nil
	r.Check(t.Context())
	if got := o.find(t, "postgres").state; got != "down" {
		t.Fatalf("a failing probe must be recorded as down, got %q", got)
	}
}

// A probe's error text is unbounded and routinely contains a host, a port or an
// id. One such label value turns three series into an unbounded number and
// takes Prometheus down with the dependency it was meant to report on.
func TestObserver_NeverReceivesTheErrorText(t *testing.T) {
	const detail = "dial tcp 10.4.19.7:5432: connection refused"

	o := &recordingObserver{}
	r := health.New(clock.NewFixed(at), time.Second, health.WithObserver(o))
	r.Register(probe("postgres", health.Critical, errors.New(detail)))

	rep := r.Check(t.Context())
	if !strings.Contains(find(t, rep, "postgres").Detail, detail) {
		t.Fatal("precondition: the detail should still reach the status endpoint")
	}
	for _, obv := range o.observations {
		for _, label := range []string{obv.dependency, obv.criticality, obv.state} {
			if strings.Contains(label, detail) || strings.Contains(label, "10.4.19.7") {
				t.Fatalf("error text reached a metric label: %q", label)
			}
		}
	}
}

// Registration seeds the series. Without it a dependency that is never checked
// — because nothing polls readiness — is ABSENT rather than reported, and an
// absent series reads as healthy in every dashboard and every alert rule.
func TestObserver_SeedsSeriesAtRegistrationBeforeAnyCheck(t *testing.T) {
	o := &recordingObserver{}
	r := health.New(clock.NewFixed(at), time.Second, health.WithObserver(o))
	r.Register(probe("email_reservation_sweep", health.Degradable, nil))

	if len(o.registered) != 1 {
		t.Fatalf("want one registration, got %+v", o.registered)
	}
	if got := o.registered[0]; got.dependency != "email_reservation_sweep" ||
		got.criticality != "degradable" {
		t.Fatalf("registration carried %+v", got)
	}
	if len(o.observations) != 0 {
		t.Fatalf("registration must not fabricate an observation: %+v", o.observations)
	}
}

// The recover() defer rewrites the result after the probe has already returned
// (violently). The recording defer is registered first precisely so it runs
// last and sees that rewrite; get the LIFO order wrong and a panicking probe is
// silently exported as up.
func TestObserver_PanickingProbeIsRecordedAsDown(t *testing.T) {
	o := &recordingObserver{}
	r := health.New(clock.NewFixed(at), time.Second, health.WithObserver(o))
	r.Register(health.ProbeFunc{
		NameValue:        "buggy",
		CriticalityValue: health.Degradable,
		CheckFunc:        func(context.Context) error { panic("nil map write") },
	})

	r.Check(t.Context())

	got := o.find(t, "buggy")
	if got.state != "down" {
		t.Fatalf("a panicking probe must be recorded as down, got %q", got.state)
	}
	if got.seconds <= 0 {
		t.Errorf("a panicking probe still took time; got %v", got.seconds)
	}
}

func TestObserver_TimedOutProbeIsRecordedAsDown(t *testing.T) {
	o := &recordingObserver{}
	r := health.New(clock.NewFixed(at), 50*time.Millisecond, health.WithObserver(o))
	r.Register(health.ProbeFunc{
		NameValue:        "slow",
		CriticalityValue: health.Critical,
		CheckFunc:        func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() },
	})

	r.Check(t.Context())

	got := o.find(t, "slow")
	if got.state != "down" {
		t.Fatalf("a timed-out probe is down, got %q", got.state)
	}
	if got.seconds < 0.04 {
		t.Errorf("latency should reflect the wait, got %v", got.seconds)
	}
}

// A registry built without an observer must keep working: the health endpoints
// are what answer while the system is already unwell, and a nil-metrics panic
// there would take out the one surface that explains the outage.
func TestObserver_AbsentByDefault(t *testing.T) {
	r := health.New(clock.NewFixed(at), time.Second)
	r.Register(probe("postgres", health.Critical, errors.New("boom")))

	if rep := r.Check(t.Context()); rep.Ready {
		t.Fatal("the report must still be computed without an observer")
	}
}

// End to end against the real Prometheus instruments, because the observer
// contract being satisfied says nothing about which series actually move.
func TestPrometheusMetrics_MoveWithProbeState(t *testing.T) {
	m := obs.New()
	var fail bool
	r := health.New(clock.NewFixed(at), time.Second, health.WithObserver(m.Health()))
	r.Register(health.ProbeFunc{
		NameValue:        "identity_retention",
		CriticalityValue: health.Degradable,
		CheckFunc: func(context.Context) error {
			if fail {
				return errors.New("schedule not found")
			}
			return nil
		},
	})

	state := func(s string) float64 {
		t.Helper()
		return testutil.ToFloat64(
			m.DependencyHealth.WithLabelValues("identity_retention", "degradable", s))
	}

	// Seeded but not yet checked: nothing is claimed, least of all health.
	for _, s := range []string{"up", "degraded", "down"} {
		if got := state(s); got != 0 {
			t.Fatalf("before any check, %s = %v, want 0", s, got)
		}
	}

	r.Check(t.Context())
	if state("up") != 1 || state("degraded") != 0 {
		t.Fatalf("healthy: up=%v degraded=%v", state("up"), state("degraded"))
	}

	fail = true
	r.Check(t.Context())
	if state("degraded") != 1 {
		t.Fatalf("a degradable probe that fails must report degraded=1, got %v", state("degraded"))
	}
	// The state set is only useful if the stale state is cleared: a series left
	// at 1 pages someone about an incident that ended.
	if state("up") != 0 {
		t.Fatalf("up must fall to 0 when the dependency is no longer up, got %v", state("up"))
	}

	fail = false
	r.Check(t.Context())
	if state("up") != 1 || state("degraded") != 0 {
		t.Fatalf("recovery: up=%v degraded=%v", state("up"), state("degraded"))
	}

	if got := testutil.ToFloat64(
		m.DependencyChecks.WithLabelValues("identity_retention", "up")); got != 2 {
		t.Errorf("checks_total{state=up} = %v, want 2", got)
	}
	// Sample COUNT, not series count: the series exists from registration, so
	// counting series would pass with the Observe call deleted.
	if got := histogramSamples(t, m, "chronos_dependency_check_seconds", "identity_retention"); got != 3 {
		t.Errorf("latency histogram recorded %d samples, want 3 (one per check)", got)
	}
}

// histogramSamples reads one dependency's observation count straight out of the
// gathered exposition — the same bytes Prometheus scrapes.
func histogramSamples(t *testing.T, m *obs.Metrics, name, dependency string) uint64 {
	t.Helper()
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "dependency" && label.GetValue() == dependency {
					return metric.GetHistogram().GetSampleCount()
				}
			}
		}
	}
	t.Fatalf("no %s series for dependency %q", name, dependency)
	return 0
}

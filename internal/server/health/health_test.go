package health_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/server/health"
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

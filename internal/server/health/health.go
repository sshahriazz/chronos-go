// Package health is the dependency registry behind the probe endpoints
// (ADR-010).
//
// The process never exits because a dependency is unreachable. Instead every
// adapter registers a probe, and the registry answers three different questions
// that are easy to conflate:
//
//	/healthz   is the process alive?          — never gated on dependencies
//	/readyz    can it serve at all?           — gated on CRITICAL dependencies
//	GetStatus  what exactly is degraded?      — the whole picture, for clients
package health

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/chronos/chronos-go/internal/platform/clock"
)

type Health int

const (
	Unknown Health = iota
	Up
	Degraded
	Down
)

func (h Health) String() string {
	switch h {
	case Up:
		return "up"
	case Degraded:
		return "degraded"
	case Down:
		return "down"
	default:
		return "unknown"
	}
}

// Criticality is fixed per dependency at wiring time — never decided during an
// incident, which is when judgement is worst.
type Criticality int

const (
	// Critical: readiness fails. We cannot serve anything useful.
	Critical Criticality = iota

	// Degradable: some capability is lost, the rest of the product continues.
	Degradable

	// FailClosed: down means DENY. Reserved for authorization — an attacker who
	// can take out the authorization service must not thereby gain access.
	FailClosed
)

func (c Criticality) String() string {
	switch c {
	case Critical:
		return "critical"
	case Degradable:
		return "degradable"
	case FailClosed:
		return "fail_closed"
	default:
		return "unknown"
	}
}

// Probe is implemented by every adapter. Check returns nil when the dependency
// is healthy; the error text is surfaced to operators, never to end users.
type Probe interface {
	Name() string
	Criticality() Criticality
	// Impact describes, in product terms, what a client loses while this
	// dependency is not up.
	Impact() string
	Check(context.Context) error
}

// Result is one dependency's most recent observation.
type Result struct {
	Name        string
	Health      Health
	Criticality Criticality
	Impact      string
	Detail      string
	CheckedAt   time.Time
	Latency     time.Duration
}

// Report is a point-in-time view of every dependency.
type Report struct {
	Ready            bool
	FullyOperational bool
	Dependencies     []Result
	At               time.Time
}

// Registry holds the probes and evaluates them.
type Registry struct {
	clk     clock.Clock
	timeout time.Duration

	mu     sync.RWMutex
	probes []Probe
}

// New builds a registry. timeout bounds each individual probe: a dependency
// that hangs must not hang the status endpoint, which is precisely the endpoint
// someone is reading while it hangs.
func New(clk clock.Clock, timeout time.Duration) *Registry {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &Registry{clk: clk, timeout: timeout}
}

func (r *Registry) Register(p Probe) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.probes = append(r.probes, p)
}

func (r *Registry) snapshotProbes() []Probe {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]Probe(nil), r.probes...)
}

// Check evaluates every probe concurrently and returns the report.
func (r *Registry) Check(ctx context.Context) Report {
	probes := r.snapshotProbes()
	results := make([]Result, len(probes))

	var wg sync.WaitGroup
	for i, p := range probes {
		wg.Add(1)
		go func(i int, p Probe) {
			defer wg.Done()
			results[i] = r.run(ctx, p)
		}(i, p)
	}
	wg.Wait()

	rep := Report{Ready: true, FullyOperational: true, Dependencies: results, At: r.clk.Now()}
	for _, res := range results {
		if res.Health != Up {
			rep.FullyOperational = false
			// Only CRITICAL affects readiness. A FAIL_CLOSED dependency that is
			// down would otherwise take every instance out of the load
			// balancer at once — turning a clear "authorization unavailable"
			// into a connection error that hides the cause.
			if res.Criticality == Critical {
				rep.Ready = false
			}
		}
	}
	return rep
}

// Ready reports whether every CRITICAL dependency is up.
func (r *Registry) Ready(ctx context.Context) bool { return r.Check(ctx).Ready }

func (r *Registry) run(ctx context.Context, p Probe) (res Result) {
	res = Result{
		Name:        p.Name(),
		Criticality: p.Criticality(),
		Impact:      p.Impact(),
		CheckedAt:   r.clk.Now(),
	}

	// A misbehaving adapter must not be able to take down the health endpoint.
	defer func() {
		if v := recover(); v != nil {
			res.Health = Down
			res.Detail = fmt.Sprintf("probe panicked: %v", v)
		}
	}()

	pctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	start := time.Now()
	err := p.Check(pctx)
	res.Latency = time.Since(start)

	switch {
	case err == nil:
		res.Health = Up
	case p.Criticality() == Degradable:
		// A degradable dependency being unreachable is a known, absorbed state
		// rather than a failure of the system as a whole.
		res.Health = Degraded
		res.Detail = err.Error()
	default:
		res.Health = Down
		res.Detail = err.Error()
	}
	return res
}

// ProbeFunc adapts a function into a Probe.
type ProbeFunc struct {
	NameValue        string
	CriticalityValue Criticality
	ImpactValue      string
	CheckFunc        func(context.Context) error
}

func (p ProbeFunc) Name() string             { return p.NameValue }
func (p ProbeFunc) Criticality() Criticality { return p.CriticalityValue }
func (p ProbeFunc) Impact() string           { return p.ImpactValue }
func (p ProbeFunc) Check(ctx context.Context) error {
	if p.CheckFunc == nil {
		return nil
	}
	return p.CheckFunc(ctx)
}

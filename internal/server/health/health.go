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

// Observer is the metrics port, declared here by the consumer rather than in
// the metrics package (ADR-001, CONVENTIONS §2). It carries strings and a
// float, not this package's types, so the implementation satisfies it
// structurally and neither package imports the other.
//
// Every argument is drawn from a closed set — the registered probe names, the
// three criticalities, the three health states — because these become label
// values. A probe's error text must never be passed here: it is unbounded, it
// often contains a host, a port or an id, and one such label turns a handful of
// series into an unbounded number. The text belongs on the status endpoint,
// where an operator reads it once, not in a time series that is kept forever.
type Observer interface {
	// Registered announces a dependency before it has ever been checked, so its
	// series exist from the first scrape. Without it a dependency is ABSENT
	// rather than reported, and absent reads as healthy in both a dashboard and
	// an alert rule.
	Registered(dependency, criticality string)

	// Observed records one probe's outcome and how long it took.
	Observed(dependency, criticality, state string, seconds float64)
}

// nopObserver is the default, so the recording calls need no nil check on a
// path that runs while the system is already unwell.
type nopObserver struct{}

func (nopObserver) Registered(string, string)                {}
func (nopObserver) Observed(string, string, string, float64) {}

// Option configures a registry. Variadic so a composition root that does not
// export metrics — a test, a one-shot tool — stays a two-argument call.
type Option func(*Registry)

// WithObserver exports every probe result as metrics.
//
// This is the difference between a dependency an operator can see and one they
// must remember to look at. Two probes here report whether a recurring Temporal
// SCHEDULE exists, and a schedule that was never created produces no error, no
// failed workflow and no other metric that moves; the only evidence is this
// gauge.
func WithObserver(o Observer) Option {
	return func(r *Registry) {
		if o != nil {
			r.obs = o
		}
	}
}

// Registry holds the probes and evaluates them.
type Registry struct {
	clk     clock.Clock
	timeout time.Duration
	obs     Observer

	mu     sync.RWMutex
	probes []Probe
}

// New builds a registry. timeout bounds each individual probe: a dependency
// that hangs must not hang the status endpoint, which is precisely the endpoint
// someone is reading while it hangs.
func New(clk clock.Clock, timeout time.Duration, opts ...Option) *Registry {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	r := &Registry{clk: clk, timeout: timeout, obs: nopObserver{}}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Exports reports whether probe results reach a real observer.
//
// Exposed so the composition root can be ASSERTED rather than assumed, in the
// same spirit as piivault.Vault.HasKeyCache. The default observer is a nop, which
// is the right default — the health endpoints must work in a test and in a binary
// that has no metrics — and it is also indistinguishable at runtime from a
// registry somebody forgot to wire. The consequence of forgetting is silent and
// expensive: every probe still answers correctly on the status endpoint, and no
// dashboard or alert ever sees a dependency go down.
//
// This is not hypothetical. The observer landed wired into nothing, and all three
// binaries compiled and passed their tests while exporting no dependency health
// at all.
func (r *Registry) Exports() bool {
	_, nop := r.obs.(nopObserver)
	return !nop
}

func (r *Registry) Register(p Probe) {
	r.mu.Lock()
	r.probes = append(r.probes, p)
	r.mu.Unlock()

	// Seeded at registration rather than at the first Check: a process whose
	// status endpoint is never polled would otherwise export nothing at all,
	// and "no series" is the one state a threshold alert cannot fire on.
	r.obs.Registered(p.Name(), p.Criticality().String())
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

	start := time.Now()

	// Registered FIRST so it runs LAST: defers are LIFO, and this one must see
	// the result the recover below writes. A probe that panics is a probe that
	// is down, and it is the one an operator most needs the metric for.
	defer func() {
		if res.Latency == 0 {
			res.Latency = time.Since(start)
		}
		r.obs.Observed(
			res.Name, res.Criticality.String(), res.Health.String(), res.Latency.Seconds())
	}()

	// A misbehaving adapter must not be able to take down the health endpoint.
	defer func() {
		if v := recover(); v != nil {
			res.Health = Down
			res.Detail = fmt.Sprintf("probe panicked: %v", v)
		}
	}()

	pctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

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

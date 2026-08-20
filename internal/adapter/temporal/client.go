// Package temporal implements the durable-work ports against Temporal (ADR-017),
// using the official SDK over gRPC (ADR-037).
//
// Nothing in the kernel imports this package: it is constructed in a binary and
// handed to the kernel as a workflow.Starter.
package temporal

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/platform/workflow"
	"github.com/chronos/chronos-go/internal/server/health"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/contrib/opentelemetry"
	"go.temporal.io/sdk/interceptor"
)

// Client wraps the SDK client and implements workflow.Starter.
type Client struct {
	c     client.Client
	queue string
}

// Config is what a client needs.
type Config struct {
	// HostPort is the frontend address, e.g. "localhost:7233".
	HostPort string

	// Namespace isolates one deployment's workflows from another's.
	Namespace string

	// Queue is the default task queue for starts that do not name one.
	Queue string
}

// Dial builds a client.
//
// It is lazy in the same way the other adapters are: the SDK connects in the
// background and reconnects on its own, so a process may start before Temporal
// is up and report DOWN through its probe instead of refusing to boot
// (ADR-010).
//
// The propagator is installed HERE rather than per call, because a propagator
// registered on some clients and not others produces workflows whose causation
// chain depends on which binary started them.
func Dial(cfg Config) (*Client, error) {
	if cfg.HostPort == "" {
		return nil, errors.New("temporal: no host:port configured")
	}
	if cfg.Queue == "" {
		return nil, errors.New("temporal: no task queue configured; workers and starters " +
			"must agree on one or the work is queued where nothing is listening")
	}

	// Tracing rides alongside the causation propagator, and they are not the
	// same thing. The tracer links a workflow's spans to the request that
	// started it, for a human reading Tempo; the propagator carries the ids that
	// are WRITTEN INTO THE EVENT LOG, which must not depend on whether tracing
	// happens to be enabled.
	tracer, err := opentelemetry.NewTracingInterceptor(opentelemetry.TracerOptions{})
	if err != nil {
		return nil, fmt.Errorf("temporal: building the tracing interceptor: %w", err)
	}

	c, err := client.NewLazyClient(client.Options{
		HostPort:           cfg.HostPort,
		Namespace:          cfg.Namespace,
		ContextPropagators: propagators(),
		Interceptors:       []interceptor.ClientInterceptor{tracer},
	})
	if err != nil {
		return nil, fmt.Errorf("temporal: dialling %s: %w", cfg.HostPort, err)
	}
	return &Client{c: c, queue: cfg.Queue}, nil
}

// New wraps an existing SDK client, for tests and for callers that own one.
func New(c client.Client, queue string) *Client { return &Client{c: c, queue: queue} }

// Raw exposes the SDK client so a worker can be built on the same connection.
func (c *Client) Raw() client.Client { return c.c }

// Queue is the default task queue.
func (c *Client) Queue() string { return c.queue }

// Close releases the connection.
func (c *Client) Close() {
	if c.c != nil {
		c.c.Close()
	}
}

var _ workflow.Starter = (*Client)(nil)

// Start begins one execution, idempotently.
//
// WorkflowIDReusePolicy is deliberately RejectDuplicate: the id is derived from
// the event that caused the work, so a second start with the same id is a
// REDELIVERY, and the correct response is to refuse it rather than run the
// effect again. The caller treats ErrAlreadyStarted as success — the work is
// already in progress or finished, which is what it wanted.
func (c *Client) Start(ctx context.Context, s workflow.Start) (workflow.Run, error) {
	if err := s.Validate(); err != nil {
		return workflow.Run{}, err
	}
	if c.c == nil {
		return workflow.Run{}, fmt.Errorf("%w: no client", workflow.ErrUnavailable)
	}

	queue := s.Queue
	if queue == "" {
		queue = c.queue
	}

	run, err := c.c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID:                    s.ID,
		TaskQueue:             queue,
		WorkflowIDReusePolicy: enumsRejectDuplicate,
		// Without this the SDK SWALLOWS the duplicate: verified against the
		// running server, a second start with the same id returned the first
		// run's id and a nil error, whether that run was still going or had
		// already closed. Silent success is the wrong answer for a caller whose
		// next line acknowledges an event — "started" and "already ran" have to
		// be distinguishable, even though both mean the effect happens once.
		WorkflowExecutionErrorWhenAlreadyStarted: true,
	}, s.Name, s.Input)
	if err != nil {
		if _, ok := errors.AsType[*serviceerror.WorkflowExecutionAlreadyStarted](err); ok {
			return workflow.Run{ID: s.ID}, fmt.Errorf("%w: %s", workflow.ErrAlreadyStarted, s.ID)
		}
		// Everything else means the work did NOT start. Wrapping it as
		// unavailable is what tells a reactor to ask for redelivery rather than
		// ack an effect that never happened.
		return workflow.Run{}, fmt.Errorf("%w: starting %s (%s): %w",
			workflow.ErrUnavailable, s.Name, s.ID, err)
	}
	return workflow.Run{ID: run.GetID(), RunID: run.GetRunID()}, nil
}

// Probe reports whether Temporal is reachable.
type Probe struct{ Client *Client }

func (Probe) Name() string { return "temporal" }

// Criticality is Degradable, not Critical.
//
// A worker that cannot reach Temporal still runs every reactor and still fills
// every read model; what stops is durable work, and a start that fails returns
// ErrUnavailable so the event is redelivered rather than acked. Marking it
// Critical would take a whole binary out of the load balancer over a subsystem
// whose failures are already retried by the transport that called it.
func (Probe) Criticality() health.Criticality { return health.Degradable }

// Impact is written in product terms, because it is read by whoever is paged.
func (Probe) Impact() string {
	return "Durable work stops: notification workflows do not run, so scheduled and " +
		"retried sends are delayed. Nothing is lost — the events that trigger them are " +
		"redelivered — and reactors, projections and the API are unaffected."
}

// Check asks the service to describe the namespace. It is a real round trip:
// a client object exists whether or not anything is listening, so anything less
// reports healthy against a dead server.
func (p Probe) Check(ctx context.Context) error {
	if p.Client == nil || p.Client.c == nil {
		return errors.New("temporal: client was not constructed; no durable work can be started")
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	if _, err := p.Client.c.CheckHealth(ctx, &client.CheckHealthRequest{}); err != nil {
		return fmt.Errorf("temporal: %w", err)
	}
	return nil
}

const probeTimeout = 2 * time.Second

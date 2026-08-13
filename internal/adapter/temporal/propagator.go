package temporal

import (
	"context"

	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	sdkenums "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/workflow"
)

// enumsRejectDuplicate is the reuse policy every start uses. Named here so the
// enum import stays in one file.
const enumsRejectDuplicate = sdkenums.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE

// Header keys for the causation chain. They are written into workflow history,
// so they are permanent: renaming one makes every in-flight execution lose its
// chain mid-run.
const (
	correlationHeader = "chronos-correlation-id"
	causationHeader   = "chronos-causation-id"
)

// tracePropagator carries eventsourcing.Trace across the workflow boundary.
//
// Without it the chain stops at the process edge. A reactor knows the event it
// is handling, starts a workflow, and three activities later something appends
// an event — and that event's causation would be whatever the activity's own
// context happened to hold, which is nothing. The log would show an effect with
// no visible cause, and the log is append-only, so it could never be repaired.
//
// It is a PROPAGATOR rather than an ordinary workflow argument on purpose. An
// argument has to be threaded through every workflow and activity signature,
// and one that forgets is a hole nothing detects. Headers travel whether or not
// the workflow author knows they exist.
//
// The two values are pseudonymous identifiers — a client-generated idempotency
// key or an event id — so putting them in durable history breaks no rule
// (ADR-002).
type tracePropagator struct{}

// propagators is what both the client and its workers install. One function, so
// a worker cannot be built with a different set from the client that starts its
// work — which would produce workflows whose chain depends on who started them.
func propagators() []workflow.ContextPropagator {
	return []workflow.ContextPropagator{tracePropagator{}}
}

func (p tracePropagator) Inject(ctx context.Context, w workflow.HeaderWriter) error {
	return write(eventsourcing.TraceFrom(ctx), w)
}

func (p tracePropagator) InjectFromWorkflow(ctx workflow.Context, w workflow.HeaderWriter) error {
	t, _ := ctx.Value(traceKey{}).(eventsourcing.Trace)
	return write(t, w)
}

func (p tracePropagator) Extract(ctx context.Context, r workflow.HeaderReader) (context.Context, error) {
	t := read(r)
	if t.IsZero() {
		return ctx, nil
	}
	return eventsourcing.WithTrace(ctx, t), nil
}

func (p tracePropagator) ExtractToWorkflow(
	ctx workflow.Context, r workflow.HeaderReader,
) (workflow.Context, error) {
	t := read(r)
	if t.IsZero() {
		return ctx, nil
	}
	return workflow.WithValue(ctx, traceKey{}, t), nil
}

// traceKey is the workflow-context key. A private type, so nothing outside this
// package can plant a chain a workflow would then propagate as its own.
type traceKey struct{}

// TraceFromWorkflow reads the chain inside workflow code.
//
// Workflow code cannot use a context.Context, so it cannot call
// eventsourcing.TraceFrom. An activity CAN — the propagator puts the chain into
// its ordinary context, which is where anything that appends an event will look
// for it.
func TraceFromWorkflow(ctx workflow.Context) eventsourcing.Trace {
	t, _ := ctx.Value(traceKey{}).(eventsourcing.Trace)
	return t
}

func write(t eventsourcing.Trace, w workflow.HeaderWriter) error {
	if t.IsZero() {
		return nil
	}
	corr, err := converter.GetDefaultDataConverter().ToPayload(t.CorrelationID)
	if err != nil {
		return err
	}
	cause, err := converter.GetDefaultDataConverter().ToPayload(t.CausationID)
	if err != nil {
		return err
	}
	w.Set(correlationHeader, corr)
	w.Set(causationHeader, cause)
	return nil
}

// read never fails: a header that cannot be decoded means the chain is lost,
// and losing a chain must not fail the work that carries it. An effect that
// happened without a traceable cause is bad; an effect that never happened
// because its trace would not decode is worse.
func read(r workflow.HeaderReader) eventsourcing.Trace {
	return eventsourcing.Trace{
		CorrelationID: readString(r, correlationHeader),
		CausationID:   readString(r, causationHeader),
	}
}

func readString(r workflow.HeaderReader, key string) string {
	payload, ok := r.Get(key)
	if !ok {
		return ""
	}
	var out string
	if err := converter.GetDefaultDataConverter().FromPayload(payload, &out); err != nil {
		return ""
	}
	return out
}

package interceptor

import (
	"context"

	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/obs"
)

// withCausation attaches the causation chain every event written under this
// request will carry (EVENT-SOURCING §8).
//
// It is attached HERE, at the edge, because the log is append-only: a
// correlation id that was not written at append time can never be added, and a
// rule of the form "every command handler remembers to set it" is forgotten
// exactly once and then permanently.
//
// # What the two ids are
//
// The CAUSATION id is the idempotency key. It names the COMMAND that produced a
// root event, which is what causation means for a write with no event above it:
// client-generated, required on every mutation, and stable across retries, so a
// retried command reports the same cause rather than opening a second chain.
//
// The CORRELATION id is the TRACE id when the request carries one. That is the
// join between two systems that otherwise cannot be correlated — a span in Tempo
// and an event in the log line up with no join table — and it groups everything
// one request caused, including work in several aggregates that would otherwise
// root separate chains.
//
// It falls back to the idempotency key when there is no span: tracing may be off
// (OTEL_ENABLED=false), or a caller may not propagate a trace context. A
// locally-unique id is worth far more than an empty one, and the log is
// append-only, so "we will fill it in later" is not available.
//
// Neither value is personal data: a trace id is random, and an idempotency key
// is client-generated opaque text documented as such.
func withCausation(ctx context.Context, idempotencyKey string) context.Context {
	correlation := obs.TraceIDFrom(ctx)
	if correlation == "" {
		correlation = idempotencyKey
	}
	return eventsourcing.WithTrace(ctx, eventsourcing.Trace{
		CorrelationID: correlation,
		CausationID:   idempotencyKey,
	})
}

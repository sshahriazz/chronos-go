package eventsourcing

import "context"

// Trace is the causation chain a write inherits from whatever caused it: the
// originating request, or the event a reactor is handling.
//
// It rides in the context rather than in every command signature because the
// alternative is a parameter that every handler must remember to thread through
// — and one that is forgotten is not a compile error, it is a permanently
// untraceable event. The log is append-only, so a correlation id that was not
// written at append time cannot be added later.
type Trace struct {
	// CorrelationID groups everything caused by one originating request. It is
	// constant for the whole chain.
	CorrelationID string

	// CausationID is the immediate cause of the next write: the command that
	// was invoked, or the event being reacted to. It changes at every hop.
	CausationID string
}

// IsZero reports whether nothing about the chain is known — the case a root
// write fills in for itself.
func (t Trace) IsZero() bool { return t.CorrelationID == "" && t.CausationID == "" }

type traceKey struct{}

// WithTrace attaches a causation chain to the context. Call it once at the edge
// (an interceptor, a reactor, a workflow activity); everything downstream picks
// it up without knowing it exists.
func WithTrace(ctx context.Context, t Trace) context.Context {
	return context.WithValue(ctx, traceKey{}, t)
}

// TraceFrom reports the chain in the context, or the zero Trace when there is
// none. It never fails: an absent trace is a root write, not an error.
func TraceFrom(ctx context.Context) Trace {
	t, _ := ctx.Value(traceKey{}).(Trace)
	return t
}

// CausedBy is the chain that anything written while handling env must carry.
//
// The correlation id is INHERITED so a whole chain — request, event, reaction,
// the event that reaction produces — shares one id and can be pulled out of the
// log as a unit. The causation id is REPLACED by this event's own id, which is
// what makes the chain a tree rather than a flat list: it answers "what directly
// produced this?", and only the immediate parent answers that.
//
// An event with no correlation id of its own (written before this existed, or by
// something outside the system) becomes the root of its chain: it correlates to
// itself, which is strictly better than propagating an empty string that groups
// every such event together.
func CausedBy(env Envelope) Trace {
	correlation := env.Meta.CorrelationID
	if correlation == "" {
		correlation = env.ID.String()
	}
	return Trace{CorrelationID: correlation, CausationID: env.ID.String()}
}

// applyTrace fills a metadata's causation fields from the context, and falls
// back to making the write the root of its own chain.
//
// An explicitly-set value always wins: a caller that knows better than the
// ambient context — replaying, backfilling from an external system — must not
// have it overwritten by whatever context it happens to be running under.
//
// The root fallback uses the FIRST event's derived id as the correlation id and
// the command's idempotency key as the causation id. Both are deterministic, so
// a retried command produces the same chain rather than a second one, and the
// causation of a root event names the command that produced it — which is what
// the field means (EVENT-SOURCING §8).
func applyTrace(m Metadata, t Trace, rootCorrelation, idempotencyKey string) Metadata {
	if m.CorrelationID == "" {
		m.CorrelationID = t.CorrelationID
	}
	if m.CausationID == "" {
		m.CausationID = t.CausationID
	}
	if m.CorrelationID == "" {
		m.CorrelationID = rootCorrelation
	}
	if m.CausationID == "" {
		m.CausationID = idempotencyKey
	}
	return m
}

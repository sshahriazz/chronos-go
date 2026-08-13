package obs

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/trace"
)

// TraceHandler stamps every context-aware log record with the trace it belongs
// to.
//
// Logs and traces answer different questions — "what did it say" and "how long
// did it take, and what called what" — and correlating them by timestamp is
// guesswork the moment two requests overlap. A trace id in the log line turns
// that into a lookup: paste it into Tempo and get the whole call tree, or filter
// the logs by a span you are already staring at.
//
// It only applies to the *Context log methods (InfoContext, ErrorContext, …).
// A plain slog.Info has no context and therefore no trace to attach, which is
// not a defect to work around: a log line with no request behind it genuinely
// belongs to no trace, and inventing one would be worse than omitting it.
type TraceHandler struct{ slog.Handler }

// NewTraceHandler wraps a handler.
func NewTraceHandler(h slog.Handler) *TraceHandler { return &TraceHandler{Handler: h} }

// Handle adds trace_id and span_id when the record carries a span context.
//
// The names are the ones Grafana's trace-to-logs integration looks for by
// default, so the link works with no per-datasource configuration.
func (h *TraceHandler) Handle(ctx context.Context, r slog.Record) error {
	sc := trace.SpanContextFromContext(ctx)
	if sc.HasTraceID() {
		r = r.Clone()
		r.AddAttrs(
			slog.String("trace_id", sc.TraceID().String()),
			slog.String("span_id", sc.SpanID().String()),
		)
	}
	return h.Handler.Handle(ctx, r)
}

// WithAttrs rewraps, so a logger derived with .With() keeps stamping. Embedding
// alone would return the INNER handler and silently drop the correlation for
// every logger built from a base one — which is most of them, since each runner
// logs through log.With("projection", name).
func (h *TraceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &TraceHandler{Handler: h.Handler.WithAttrs(attrs)}
}

// WithGroup rewraps too, but the ids then land INSIDE the group — slog offers a
// wrapper no way to add an attribute above a group opened beneath it.
//
// That would break the correlation, because Grafana's trace-to-logs link reads
// `trace_id` at the top level. Nothing in this repository calls WithGroup, and
// the fix if something ever does is to group the message's own fields rather
// than the logger, so this is left as the honest behaviour rather than papered
// over with a nested duplicate.
func (h *TraceHandler) WithGroup(name string) slog.Handler {
	return &TraceHandler{Handler: h.Handler.WithGroup(name)}
}

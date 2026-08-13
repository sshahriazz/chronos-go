package obs_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/obs"
	"go.opentelemetry.io/otel/trace"
)

func spanContext(t *testing.T) context.Context {
	t.Helper()
	traceID, err := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	if err != nil {
		t.Fatalf("trace id: %v", err)
	}
	spanID, err := trace.SpanIDFromHex("00f067aa0ba902b7")
	if err != nil {
		t.Fatalf("span id: %v", err)
	}
	return trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: spanID, TraceFlags: trace.FlagsSampled,
	}))
}

func logged(t *testing.T, fn func(*slog.Logger)) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	log := slog.New(obs.NewTraceHandler(slog.NewJSONHandler(&buf, nil)))
	fn(log)

	line := strings.TrimSpace(buf.String())
	if line == "" {
		return nil
	}
	// Through the codec, like everything else that decodes JSON here (ADR-047).
	// Tolerant, because a log line legitimately carries whatever the caller
	// attached.
	out, err := codec.Tolerant[map[string]any]([]byte(line))
	if err != nil {
		t.Fatalf("log line is not JSON: %v (%s)", err, line)
	}
	return out
}

// The whole point: a log line and a span become one lookup instead of a
// timestamp comparison that stops working the moment two requests overlap.
func TestAContextualLogCarriesItsTrace(t *testing.T) {
	ctx := spanContext(t)
	rec := logged(t, func(l *slog.Logger) { l.InfoContext(ctx, "hello") })

	if rec["trace_id"] != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("trace_id = %v, want the span's trace id", rec["trace_id"])
	}
	if rec["span_id"] != "00f067aa0ba902b7" {
		t.Errorf("span_id = %v", rec["span_id"])
	}
}

// A logger built with .With() is the common case — every runner does it — and a
// handler that dropped the correlation there would leave almost every line
// uncorrelated while the test above still passed.
//
// WithGroup is deliberately not asserted: a wrapper cannot add an attribute
// above a group opened beneath it, so the ids would nest. Nothing here calls it.
func TestADerivedLoggerStillCarriesItsTrace(t *testing.T) {
	ctx := spanContext(t)
	rec := logged(t, func(l *slog.Logger) {
		l.With("projection", "user_view").InfoContext(ctx, "hello")
	})

	if rec["trace_id"] == nil {
		t.Fatal("a derived logger dropped the trace; almost every line in the system " +
			"comes from one of these")
	}
}

// No span, no ids. A line with no request behind it belongs to no trace, and
// inventing one would be worse than omitting it.
func TestALineWithNoSpanCarriesNoTrace(t *testing.T) {
	rec := logged(t, func(l *slog.Logger) { l.InfoContext(context.Background(), "hello") })

	if _, ok := rec["trace_id"]; ok {
		t.Error("a log line with no span was given a trace id")
	}
}

// The wrapper must not swallow anything the base handler would have written.
func TestTheBaseHandlerStillSeesEverything(t *testing.T) {
	ctx := spanContext(t)
	rec := logged(t, func(l *slog.Logger) { l.InfoContext(ctx, "hello", "count", 3) })

	if rec["msg"] != "hello" || rec["count"] != float64(3) {
		t.Errorf("the record lost attributes: %v", rec)
	}
}

//go:build integration

package obs_test

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/obs"
	"go.opentelemetry.io/otel"
)

func endpoint() string {
	if v := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); v != "" {
		return v
	}
	return "http://localhost:4317"
}

// Spans must reach the COLLECTOR, not Tempo directly: sampling and attribute
// scrubbing live there, and a service exporting straight to the backend would
// bypass both (ADR-002).
//
// It asserts the export SUCCEEDS — a provider that silently drops every span is
// indistinguishable from a working one until someone goes looking in Tempo.
func TestSpansReachTheCollector(t *testing.T) {
	ctx := context.Background()
	stop, err := obs.StartTracing(ctx, obs.TracingConfig{
		Endpoint: endpoint(), Service: "chronos-it", Version: "test",
		Environment: "local", Enabled: true,
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	tracer := otel.Tracer("chronos-it")
	spanCtx, span := tracer.Start(ctx, "integration-probe")
	if id := obs.TraceIDFrom(spanCtx); id == "" {
		t.Fatal("a started span produced no trace id, so no event could ever be correlated with it")
	}
	span.End()

	// Shutdown flushes. If the collector refused the batch it is reported here,
	// which is the only place a dropped export is visible at all.
	done := make(chan struct{})
	go func() { stop(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the exporter did not flush; spans are being queued and dropped")
	}
}

// With tracing off the propagator is STILL installed: an incoming trace id has
// to reach the code that writes it into an event's correlation id, and turning
// tracing off must not change what lands in a permanent log.
func TestPropagatorIsInstalledEvenWhenDisabled(t *testing.T) {
	stop, err := obs.StartTracing(context.Background(), obs.TracingConfig{Enabled: false},
		slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer stop(context.Background())

	if fields := otel.GetTextMapPropagator().Fields(); len(fields) == 0 {
		t.Fatal("no propagator was installed; an incoming trace id would be dropped at the edge")
	}
}

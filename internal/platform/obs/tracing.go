package obs

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// TracingConfig is what a binary needs to export traces.
type TracingConfig struct {
	// Endpoint is the OTLP COLLECTOR, never Tempo directly. Sampling and
	// attribute scrubbing are the collector's job, so a service that exported
	// straight to the backend would bypass both — and the scrubbing is what keeps
	// personal data out of spans (ADR-002).
	Endpoint string

	// Service names the binary in every span. It is the label operators filter
	// by, so it is stable: "chronos-api", "chronos-worker", "chronos-projector".
	Service string

	// Version and Environment tag the deployment.
	Version     string
	Environment string

	// Enabled turns exporting on. Off means a no-op tracer: spans are still
	// created by instrumented libraries and cost almost nothing, and no
	// connection is opened to a collector that may not exist.
	Enabled bool
}

// StartTracing installs the global tracer provider and returns its shutdown.
//
// Two decisions worth stating.
//
// It samples EVERYTHING here. Sampling belongs in the collector
// (infra/otel-collector/config.yaml), and a service that samples first makes the
// collector's policy unenforceable: a span dropped in-process cannot be
// recovered by a rule downstream.
//
// It never fails a boot. The exporter connects lazily and retries, so a
// collector that is down means traces are queued and eventually dropped —
// which is the correct trade for telemetry (ADR-010). A process that refused to
// start because it could not export traces would turn an observability outage
// into a service outage.
func StartTracing(ctx context.Context, cfg TracingConfig, log *slog.Logger) (func(context.Context), error) {
	// The propagator is installed WHETHER OR NOT exporting is enabled. It is how
	// an incoming trace id reaches this process, and the causation chain written
	// into the event log uses that id — so turning tracing off must not silently
	// change what is written to a permanent log.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))

	if !cfg.Enabled {
		log.Info("tracing is disabled; spans are not exported", "reason", "OTEL_ENABLED=false")
		return func(context.Context) {}, nil
	}
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("obs: tracing is enabled but no collector endpoint is set")
	}

	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpointURL(cfg.Endpoint),
		// Lazy: the process starts before the collector is reachable and
		// reconnects on its own.
		otlptracegrpc.WithRetry(otlptracegrpc.RetryConfig{
			Enabled:         true,
			InitialInterval: time.Second,
			MaxInterval:     30 * time.Second,
			MaxElapsedTime:  time.Minute,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("obs: building the OTLP exporter: %w", err)
	}

	// SCHEMALESS deliberately. resource.Default() carries whichever semantic
	// convention version the SDK was built against, and Merge refuses to combine
	// two different schema URLs — pinning one here makes every SDK upgrade a
	// startup failure in a package whose whole job is to be optional.
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		attribute.String("service.name", cfg.Service),
		attribute.String("service.version", cfg.Version),
		attribute.String("deployment.environment", cfg.Environment),
	))
	if err != nil {
		return nil, fmt.Errorf("obs: building the trace resource: %w", err)
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		// Everything. See above: the collector owns sampling.
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(provider)

	log.Info("tracing enabled", "collector", cfg.Endpoint, "service", cfg.Service)

	return func(ctx context.Context) {
		// Bounded, because shutdown flushes over the network to a collector that
		// may be the reason we are shutting down.
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := provider.Shutdown(ctx); err != nil {
			log.Warn("tracer shutdown incomplete; the last spans may be lost", "error", err)
		}
	}, nil
}

// TraceIDFrom reports the current trace id, or "" when the context carries no
// sampled span.
//
// It is the join between two systems that otherwise cannot be correlated: this
// id goes into an event's metadata as the correlation id (EVENT-SOURCING §8), so
// a span in Tempo and an event in the log can be lined up with no join table.
func TraceIDFrom(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.HasTraceID() {
		return ""
	}
	return sc.TraceID().String()
}

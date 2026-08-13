// Command api is the tenant-facing server: gRPC, gRPC-Web and HTTP/JSON on a
// single port (ADR-007).
//
// It never links the operator plane (ADR-024), and it never exits because a
// dependency is unreachable — connections are lazy and supervised, and the
// probe surface reports what is degraded (ADR-010).
package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"connectrpc.com/grpcreflect"
	"github.com/chronos/chronos-go/gen/proto/chronos/system/v1/systemv1connect"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/config"
	"github.com/chronos/chronos-go/internal/platform/obs"
	"github.com/chronos/chronos-go/internal/server/connect"
	"github.com/chronos/chronos-go/internal/server/health"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// version is set at build time: -ldflags "-X main.version=$(git rev-parse --short HEAD)"
var version = "dev"

func main() {
	addr := flag.String("addr", ":"+envOr("API_PORT", "8090"), "listen address")
	flag.Parse()

	// Wrapped so every context-aware line carries the trace it belongs to.
	// Correlating logs and traces by timestamp stops working the moment two
	// requests overlap; an id turns it into a lookup.
	log := slog.New(obs.NewTraceHandler(
		slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	slog.SetDefault(log)

	if err := run(*addr, log); err != nil {
		log.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(addr string, log *slog.Logger) error {
	// Configuration is validated once, here. An invalid environment is a startup
	// failure with a precise message, never a zero value found at request time.
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log.Info("configuration loaded",
		"env", cfg.Env, "timezone", cfg.Timezone, "version", version)

	// Tracing first, so every span this process creates — including the ones
	// libraries open during wiring — belongs to a provider that can export them.
	// It never fails a boot: an observability outage must not become a service
	// outage (ADR-010).
	stopTracing, err := obs.StartTracing(context.Background(), obs.TracingConfig{
		Endpoint:    cfg.Tracing.Endpoint,
		Service:     "chronos-api",
		Version:     version,
		Environment: string(cfg.Env),
		Enabled:     cfg.Tracing.Enabled,
	}, log)
	if err != nil {
		log.Error("tracing unavailable; continuing without it", "error", err)
		stopTracing = func(context.Context) {}
	}
	defer stopTracing(context.Background())

	clk := clock.System{}
	startedAt := clk.Now()

	// The composition root. Hand-written while the graph is small: it is
	// ordinary Go, so the compiler checks it, which is the property ADR-009
	// actually requires. Generated wiring earns its keep once this grows past
	// a screen — the shape here is already what a provider set would produce.
	deps, closeDeps := newDependencies(cfg, log)
	defer closeDeps()

	registry := health.New(clk, 2*time.Second)
	for _, p := range deps.probes {
		registry.Register(p)
	}

	mux := http.NewServeMux()

	// Prometheus scrapes this. It is plain HTTP rather than an RPC because
	// scrapers speak HTTP and nothing else.
	mux.Handle("GET /metrics", deps.metrics.Handler())

	// Liveness is never gated on dependencies: the process is alive or it is not.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Readiness reflects only CRITICAL dependencies (health.Registry.Check).
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if registry.Ready(r.Context()) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ready"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ready"))
	})

	// One handler, three protocols.
	systemSvc := health.NewService(registry, version, cfg.Timezone, startedAt)
	// JSONOptions makes protobuf-JSON emit default values, so `false` and `0`
	// never vanish from a response (see internal/server/connect/codec.go).
	mux.Handle(systemv1connect.NewSystemServiceHandler(systemSvc, connect.JSONOptions()...))

	// Reflection lets grpcurl and Postman explore a running server. The docs
	// binary also ships a descriptor set, so tooling works when reflection is
	// disabled in production.
	reflector := grpcreflect.NewStaticReflector(systemv1connect.SystemServiceName)
	mux.Handle(grpcreflect.NewHandlerV1(reflector))
	mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))

	// otelhttp EXTRACTS the incoming W3C trace context and opens the server
	// span. It is what makes a caller's trace id available to the idempotency
	// gate, which writes it into every event this request produces as the
	// correlation id — so a span in Tempo and an event in the log line up with
	// no join table.
	//
	// It wraps the mux rather than each handler: a route added later is
	// instrumented by construction, and an uninstrumented route is invisible in
	// exactly the way tracing exists to prevent.
	handler := otelhttp.NewHandler(mux, "chronos-api",
		// The span name is the Connect procedure, not the raw path. Paths here
		// are procedures already, but this keeps one span name per RPC when a
		// route gains parameters.
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method + " " + r.URL.Path
		}),
		// The health endpoints are polled every few seconds by Kubernetes and by
		// the local stack. Tracing them buries every real request under probe
		// spans and tells nobody anything.
		otelhttp.WithFilter(func(r *http.Request) bool {
			return r.URL.Path != "/healthz" && r.URL.Path != "/readyz" && r.URL.Path != "/metrics"
		}),
	)

	srv := connect.New(connect.DefaultConfig(addr), handler, log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	for _, task := range backgroundTasks(deps) {
		go task.run(ctx, deps, log.With("task", task.name))
	}

	// Report what we can reach at boot — informational only. Nothing here can
	// prevent startup (ADR-010).
	logInitialHealth(ctx, registry, log)

	return srv.Run(ctx)
}

// backgroundTask is a duty this binary owns beyond serving requests.
type backgroundTask struct {
	name string
	run  func(context.Context, *dependencies, *slog.Logger)
}

// backgroundTasks is the list main starts, and the list a test can assert.
//
// A list rather than a `go` statement inline, for the reason cmd/worker learned
// the hard way: a duty nobody starts is invisible. Dedup.Forget was written,
// documented and indexed for, and called by no binary at all — while its unit
// test passed. A test that calls the function directly reproduces exactly that
// blind spot, so the composition root has to expose WHAT IT STARTS.
func backgroundTasks(*dependencies) []backgroundTask {
	return []backgroundTask{
		{name: "idempotency-retention", run: sweepIdempotency},
	}
}

// sweepIdempotency deletes expired idempotency records.
//
// idempotency_key gains a row per mutating request and the read path already
// refuses to replay an expired one — so nothing here is about correctness. It is
// about RETENTION: a stored response is a serialized reply and can contain
// personal data, which makes an unswept table a compliance problem rather than a
// full disk (ADR-002).
func sweepIdempotency(ctx context.Context, d *dependencies, log *slog.Logger) {
	if d.idempotency == nil {
		log.Warn("idempotency retention is not running: expired records, and the personal " +
			"data in their stored responses, will never be deleted")
		return
	}
	t := time.NewTicker(d.sweepEvery)
	defer t.Stop()
	for {
		removed, err := d.idempotency.Sweep(ctx)
		switch {
		case err != nil && ctx.Err() == nil:
			// Degradable: a failed sweep costs disk and retention, never
			// correctness. Requests keep being gated with a larger table.
			log.Error("idempotency retention sweep failed", "error", err)
		case removed > 0:
			log.Info("idempotency retention swept", "rows", removed)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func logInitialHealth(ctx context.Context, r *health.Registry, log *slog.Logger) {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	rep := r.Check(probeCtx)
	for _, d := range rep.Dependencies {
		log.Info("dependency",
			"name", d.Name,
			"health", d.Health.String(),
			"criticality", d.Criticality.String(),
			"latency_ms", d.Latency.Milliseconds(),
			"detail", d.Detail)
	}
	log.Info("startup health",
		"ready", rep.Ready, "fully_operational", rep.FullyOperational)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

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
	"github.com/chronos/chronos-go/internal/server/connect"
	"github.com/chronos/chronos-go/internal/server/health"
)

// version is set at build time: -ldflags "-X main.version=$(git rev-parse --short HEAD)"
var version = "dev"

func main() {
	addr := flag.String("addr", ":"+envOr("API_PORT", "8090"), "listen address")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
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

	srv := connect.New(connect.DefaultConfig(addr), mux, log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Report what we can reach at boot — informational only. Nothing here can
	// prevent startup (ADR-010).
	logInitialHealth(ctx, registry, log)

	return srv.Run(ctx)
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

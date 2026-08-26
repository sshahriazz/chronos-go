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

	connectrpc "connectrpc.com/connect"
	"connectrpc.com/grpcreflect"
	"connectrpc.com/validate"
	"github.com/chronos/chronos-go/gen/proto/chronos/billing/v1/billingv1connect"
	"github.com/chronos/chronos-go/gen/proto/chronos/compliance/v1/compliancev1connect"
	"github.com/chronos/chronos-go/gen/proto/chronos/identity/v1/identityv1connect"
	"github.com/chronos/chronos-go/gen/proto/chronos/notification/v1/notificationv1connect"
	"github.com/chronos/chronos-go/gen/proto/chronos/organization/v1/organizationv1connect"
	"github.com/chronos/chronos-go/gen/proto/chronos/profile/v1/profilev1connect"
	"github.com/chronos/chronos-go/gen/proto/chronos/system/v1/systemv1connect"
	"github.com/chronos/chronos-go/gen/proto/chronos/workspace/v1/workspacev1connect"
	billingapi "github.com/chronos/chronos-go/internal/modules/billing/api"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/config"
	"github.com/chronos/chronos-go/internal/platform/obs"
	"github.com/chronos/chronos-go/internal/server/connect"
	"github.com/chronos/chronos-go/internal/server/health"
	"github.com/chronos/chronos-go/internal/server/interceptor"
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

	// Secrets in custody override the environment, before anything reads them.
	// It runs HERE — before tracing, before any dependency — because a value
	// resolved after something has already read the environment copy is a value
	// two things disagree about.
	if err := resolveSecrets(context.Background(), cfg, log); err != nil {
		return err
	}

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

	// The composition root. Hand-written while the graph is small: it is
	// ordinary Go, so the compiler checks it, which is the property ADR-009
	// actually requires. Generated wiring earns its keep once this grows past
	// a screen — the shape here is already what a provider set would produce.
	deps, closeDeps := newDependencies(cfg, log)
	defer closeDeps()

	// The one dependency failure that stops the process. See dependencies.fatal
	// and verifyKEK: a key store that is briefly unreachable is survivable and a
	// key that cannot decrypt this installation's data is not.
	if deps.fatal != nil {
		return deps.fatal
	}

	startedAt := deps.clock.Now()

	// The movable clock (ADR-054). Disabled everywhere but local, and config
	// validation has already refused the boot if that is not where we are — this
	// is the second of the two checks, and it is here so that deleting either
	// one still leaves a server that refuses.
	//
	// A failure here FAILS THE BOOT, unlike every other optional surface. See
	// startClockControl: a harness that asked for a movable clock and silently
	// got a fixed one does not fail, it passes while advancing nothing.
	clockCtl, err := startClockControl(
		context.Background(), cfg.Env, cfg.ClockControl, deps.movableClock, log)
	if err != nil {
		return err
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := clockCtl.Shutdown(shutdownCtx); err != nil {
			log.Warn("clock control listener did not drain", "error", err)
		}
	}()

	registry := newHealthRegistry(deps.clock, deps)

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
	served := registerServices(mux, deps, cfg, systemSvc, log)

	// Reflection lets grpcurl and Postman explore a running server. It advertises
	// exactly what was REGISTERED, not what this build could serve: a reflector
	// naming a service the mux does not route sends every tool that trusts it to a
	// 404, which reads as a broken server rather than as a service this process
	// could not construct.
	reflector := grpcreflect.NewStaticReflector(served...)
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

// handlerOptions is the option set EVERY Connect handler in this binary is
// built with.
//
// It is a function rather than an inline argument so that exactly one list
// exists. A service registered with its own hand-rolled options is a service
// with different guarantees from every other one, and the difference is
// invisible at the call site — which is how a validation interceptor comes to be
// applied to eight endpoints out of nine.
//
// It is also what makes the wiring TESTABLE. `TestValidationIsWired` builds a
// real handler from this list and pushes a request that violates a declared rule
// through it, so "protovalidate is wired" is an assertion about the composition
// root rather than about a package that happens to be imported.
// It takes the enforcement pipeline as an optional argument rather than reading
// it from a package-level variable, so that the list stays a pure function of
// its inputs and a test can build the same handler with and without gates. The
// variadic form is what lets `handlerOptions()` keep meaning "everything except
// the gates" for the validation test, which needs a handler it can reach without
// authenticating.
func handlerOptions(gates ...connectrpc.Interceptor) []connectrpc.HandlerOption {
	// ORDER MATTERS, and it is the ADR-021 order: connect applies the first
	// interceptor outermost for handlers, so the gates run BEFORE protovalidate.
	//
	// That direction is deliberate. Validation ahead of authentication would
	// answer an unauthenticated caller with a field-level description of a
	// request they were never entitled to make — ADR-036 puts the disclosure
	// boundary at the authz gate, and "your email field is malformed" is above it.
	// Running gates first also means a refused request never pays for validating
	// a message it will not serve.
	interceptors := make([]connectrpc.Interceptor, 0, len(gates)+1)
	for _, g := range gates {
		if g != nil {
			interceptors = append(interceptors, g)
		}
	}
	// Constraints are declared in the .proto and enforced HERE, before any
	// handler runs (ADR-007, CONVENTIONS §7). Without this line every rule in
	// identity.proto is a comment: the schema documents a constraint, the
	// generated OpenAPI publishes it, and nothing refuses input that breaks
	// it. Handlers do not re-check.
	// OUTSIDE the validation interceptor, so it sees the error on the way out.
	//
	// connectrpc.com/validate builds its own connect.Error and never passes
	// through errs, so a schema refusal used to arrive with buf.validate
	// violations and NO reason — leaving a client unable to tell a broken field
	// rule from a missing Idempotency-Key. This re-raises it as VALIDATION_FAILED
	// and carries the violations across.
	interceptors = append(interceptors, interceptor.NewValidationReason())
	interceptors = append(interceptors, validate.NewInterceptor())

	opts := []connectrpc.HandlerOption{connectrpc.WithInterceptors(interceptors...)}
	// JSONOptions makes protobuf-JSON emit default values, so `false` and `0`
	// never vanish from a response (see internal/server/connect/codec.go).
	return append(opts, connect.JSONOptions()...)
}

// registerServices mounts every Connect handler this binary serves and returns
// the fully-qualified names it registered.
//
// Returning the names is what makes the wiring ASSERTABLE. A service that was
// built and mounted leaves no artefact otherwise — mux registration is a side
// effect on an http.ServeMux — and this repository has shipped six seams that
// were fully built, fully tested, and constructed by no binary. The reflector is
// also driven from this list, so what tooling is told matches what is served.
//
// Nothing here is registered over a nil collaborator. The two failure modes are
// deliberately different: a service that could not be CONSTRUCTED is left off
// (callers get `unimplemented`), and a pipeline that could not be BUILT takes
// every service off with it, because serving a method whose gates are unknown is
// worse than not serving it (ADR-021).
func registerServices(
	mux *http.ServeMux,
	d *dependencies,
	cfg *config.Config,
	systemSvc systemv1connect.SystemServiceHandler,
	log *slog.Logger,
) []string {
	if d.gates == nil {
		log.Error("NO CONNECT SERVICE IS REGISTERED: the enforcement pipeline could not be " +
			"built, so every RPC this binary could serve is unreachable. /healthz, /readyz " +
			"and /metrics still answer, which is what makes this state findable")
		return nil
	}
	// The error gate goes FIRST, which makes it outermost: it has to see the
	// failures the gates themselves produce, not only the ones handlers return.
	// Without it, an error that reached the wire unclassified was reported to
	// nobody — `internal: internal error` to the caller and silence in the log.
	opts := handlerOptions(interceptor.NewErrorLog(log, d.metrics.RPC()), d.gates)

	var served []string

	mux.Handle(systemv1connect.NewSystemServiceHandler(systemSvc, opts...))
	served = append(served, systemv1connect.SystemServiceName)

	if d.identity == nil {
		// Already logged in full by startIdentity. Repeated here at the moment of
		// non-registration because this is the line that answers "why does my
		// login return unimplemented" from a log search for the service name.
		log.Error("IdentityService is NOT registered; every identity RPC answers " +
			"'unimplemented'")
	} else {
		mux.Handle(identityv1connect.NewIdentityServiceHandler(d.identity, opts...))
		served = append(served, identityv1connect.IdentityServiceName)
	}

	if d.notification == nil {
		// Already logged in full by buildNotification. Repeated at the moment of
		// non-registration because this is the line a log search for the service
		// name lands on when somebody asks why their inbox is empty.
		log.Error("NotificationService is NOT registered; the feed, push registration " +
			"and every channel preference answer 'unimplemented'")
	} else {
		mux.Handle(notificationv1connect.NewNotificationServiceHandler(d.notification, opts...))
		served = append(served, notificationv1connect.NotificationServiceName)
	}

	if d.profile == nil {
		log.Error("ProfileService is NOT registered; the display name, locale, timezone " +
			"and avatar all answer 'unimplemented'")
	} else {
		mux.Handle(profilev1connect.NewProfileServiceHandler(d.profile, opts...))
		served = append(served, profilev1connect.ProfileServiceName)
	}

	// The Stripe webhook is plain HTTP, not a Connect procedure: Stripe posts a
	// signed body to a URL and knows nothing of Connect's envelope. It is also
	// deliberately OUTSIDE the interceptor chain — there is no session, no
	// principal and no Idempotency-Key header, and its authentication is the
	// signature over the raw body.
	if hook, err := d.buildStripeWebhook(cfg, log); err != nil {
		log.Error("the Stripe webhook endpoint is NOT served; a cardless trial will end in "+
			"Stripe and never end here, so the tenant keeps working for free and nothing "+
			"says so", "error", err)
	} else {
		mux.Handle(billingapi.Path, hook)
		log.Info("stripe webhook registered", "path", billingapi.Path)
	}

	if d.organization == nil {
		log.Error("OrganizationService is NOT registered; no tenant can be created and every " +
			"organization RPC answers 'unimplemented'")
	} else {
		mux.Handle(organizationv1connect.NewOrganizationServiceHandler(d.organization, opts...))
		served = append(served, organizationv1connect.OrganizationServiceName)
	}

	if d.compliance == nil {
		log.Error("ComplianceService is NOT registered; a person cannot halt processing of " +
			"their own data and every Article 18 method answers 'unimplemented'")
	} else {
		mux.Handle(compliancev1connect.NewComplianceServiceHandler(d.compliance, opts...))
		served = append(served, compliancev1connect.ComplianceServiceName)
	}

	if d.billing == nil {
		log.Error("BillingService is NOT registered; the Customer Portal is the only way a " +
			"card is ever added, so no trial can convert and no suspended tenant can pay")
	} else {
		mux.Handle(billingv1connect.NewBillingServiceHandler(d.billing, opts...))
		served = append(served, billingv1connect.BillingServiceName)
	}

	if d.workspace == nil {
		log.Error("WorkspaceService is NOT registered; no workspace can be created and every " +
			"workspace RPC answers 'unimplemented'")
	} else {
		mux.Handle(workspacev1connect.NewWorkspaceServiceHandler(d.workspace, opts...))
		served = append(served, workspacev1connect.WorkspaceServiceName)
	}

	log.Info("connect services registered", "services", served)
	return served
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

// newHealthRegistry builds the probe registry, WITH the observer that publishes
// results to Prometheus.
//
// Extracted from main so a composition-root test can assert the observer is
// attached. Without it the registry answers /readyz and GetStatus exactly as it
// does now and exports nothing, so every dashboard silently falls back to
// `up{job=...}` — which reports whether Prometheus can scrape this process, not
// whether its dependencies work. The two differ precisely when it matters: a
// Postgres that accepts connections and rejects our credentials is up=1 and
// probe-DOWN, and a sealed OpenBao is up=1 and probe-DOWN.
func newHealthRegistry(clk clock.Clock, deps *dependencies) *health.Registry {
	registry := health.New(clk, 2*time.Second, health.WithObserver(deps.metrics.Health()))
	for _, p := range deps.probes {
		registry.Register(p)
	}
	return registry
}

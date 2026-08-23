// Command projector builds the read models.
//
// It consumes the event log and writes PostgreSQL rows, and does nothing else.
// It serves no tenant traffic, sends no email, and calls no other Chronos
// binary: the log is the bus (ARCHITECTURE §3.1). Everything it does is
// replayable, which is what makes `-rebuild` a routine operation rather than an
// incident.
//
// Exactly one instance of each projection runs at a time, enforced by a
// Postgres advisory lock. Running several copies of this binary is safe and is
// how failover works — the extras stand by (ADR-019).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/modules/billing"
	billingprojection "github.com/chronos/chronos-go/internal/modules/billing/projection"
	"github.com/chronos/chronos-go/internal/modules/identity"
	identityprojection "github.com/chronos/chronos-go/internal/modules/identity/projection"
	"github.com/chronos/chronos-go/internal/modules/notification"
	notificationprojection "github.com/chronos/chronos-go/internal/modules/notification/projection"
	"github.com/chronos/chronos-go/internal/modules/organization"
	organizationprojection "github.com/chronos/chronos-go/internal/modules/organization/projection"
	"github.com/chronos/chronos-go/internal/modules/profile"
	profileprojection "github.com/chronos/chronos-go/internal/modules/profile/projection"
	"github.com/chronos/chronos-go/internal/modules/workspace"
	workspaceprojection "github.com/chronos/chronos-go/internal/modules/workspace/projection"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/config"
	"github.com/chronos/chronos-go/internal/platform/obs"
	"github.com/chronos/chronos-go/internal/platform/projection"
	"github.com/chronos/chronos-go/internal/server/health"
)

// version is set at build time: -ldflags "-X main.version=$(git rev-parse --short HEAD)"
var version = "dev"

func main() {
	addr := flag.String("addr", ":"+envOr("PROJECTOR_PORT", "8093"), "health listen address")
	rebuild := flag.String("rebuild", "", "rebuild one projection from the beginning of the log, then exit")
	list := flag.Bool("list", false, "list registered projections and exit")
	flag.Parse()

	// Wrapped so every context-aware line carries the trace it belongs to.
	// Correlating logs and traces by timestamp stops working the moment two
	// requests overlap; an id turns it into a lookup.
	log := slog.New(obs.NewTraceHandler(
		slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	slog.SetDefault(log)

	if err := run(*addr, *rebuild, *list, log); err != nil {
		log.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(addr, rebuild string, list bool, log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	if list {
		// A real codec, not nil: a projection builds its dispatch table in its
		// constructor, so a nil codec would panic the moment the first one is
		// registered here.
		for _, p := range projections(newCodec()) {
			fmt.Println(p.Name())
		}
		return nil
	}

	log.Info("configuration loaded", "env", cfg.Env, "version", version)

	// The registry is built BEFORE the dependencies because the lease pool is
	// sized from it: every running projection pins one connection for its
	// lifetime, so a shared pool would deadlock at scale (see newDependencies).
	// Tracing is installed before anything else builds a client, so spans opened
	// during wiring belong to a provider that can export them. It never fails a
	// boot: an observability outage must not become a service outage (ADR-010).
	stopTracing, err := obs.StartTracing(context.Background(), obs.TracingConfig{
		Endpoint:    cfg.Tracing.Endpoint,
		Service:     "chronos-projector",
		Version:     version,
		Environment: string(cfg.Env),
		Enabled:     cfg.Tracing.Enabled,
	}, log)
	if err != nil {
		log.Error("tracing unavailable; continuing without it", "error", err)
		stopTracing = func(context.Context) {}
	}
	defer stopTracing(context.Background())

	codec := newCodec()
	views := projections(codec)

	d, closeAll := newDependencies(cfg, log, codec, len(views))
	defer closeAll()

	// Publish every projection's series at zero before any of them runs. A
	// Prometheus vector exports nothing for a label it has never seen, so a
	// projection that has applied no events would be ABSENT — and absent and
	// broken look identical on a dashboard, while `rate(...) == 0` never fires
	// for a series that does not exist.
	for _, v := range views {
		d.metrics.InitProjection(v.Name())
	}

	if len(views) == 0 {
		// Not an error. Until the first module ships a read model there is
		// genuinely nothing to project, and a binary that refused to start
		// would just be one more thing to work around.
		log.Warn("no projections are registered; the projector is idle")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if rebuild != "" {
		return rebuildOne(ctx, views, d, rebuild, log)
	}

	go serveHealth(ctx, addr, d, log)
	supervise(ctx, views, d, log)

	// supervise returns when every runner has stopped — including immediately,
	// when none are registered. Exiting here would look like a crash loop to a
	// supervisor, and would take down the health endpoint that reports WHY
	// nothing is running. Stay up until actually told to stop.
	<-ctx.Done()
	return nil
}

// rebuildOne empties one projection and replays the whole log into it.
//
// Deliberately a flag on this binary rather than an RPC: a rebuild is an
// operator action with a real cost, and it must not be reachable from tenant
// traffic (ADR-024).
func rebuildOne(ctx context.Context, views []projection.Projection, d *dependencies, name string, log *slog.Logger) error {
	for _, v := range views {
		if v.Name() != name {
			continue
		}
		log.Info("rebuilding projection", "projection", name)
		start := time.Now()
		err := projection.NewRunner(v, d.deps(log)).Rebuild(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("rebuilding %s: %w", name, err)
		}
		log.Info("rebuild finished", "projection", name, "elapsed", time.Since(start).String())
		return nil
	}
	return fmt.Errorf("no projection named %q — run with -list to see the registered ones", name)
}

// supervise runs every projection until the process is told to stop.
//
// A projection that fails stays down and stays loud. It is NOT restarted in a
// loop: a failing Apply is a bug in the projection, and retrying it forever
// produces a log full of the same error while the read model silently falls
// further behind. Everything else keeps running, so one broken projection does
// not take down the rest.
func supervise(ctx context.Context, views []projection.Projection, d *dependencies, log *slog.Logger) {
	var wg sync.WaitGroup
	for _, v := range views {
		wg.Add(1)
		go func(v projection.Projection) {
			defer wg.Done()
			runner := projection.NewRunner(v, d.deps(log))
			d.status.track(v.Name(), runner)
			if err := runner.Run(ctx); err != nil {
				log.Error("PROJECTION STOPPED — it will not restart on its own",
					"projection", v.Name(), "error", err)
				d.status.fail(v.Name(), err)
				return
			}
			log.Info("projection stopped", "projection", v.Name())
		}(v)
	}
	wg.Wait()
}

func serveHealth(ctx context.Context, addr string, d *dependencies, log *slog.Logger) {
	registry := newHealthRegistry(d)

	mux := http.NewServeMux()
	mux.Handle("GET /metrics", d.metrics.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	// A projector with a stopped projection is NOT ready: its read model is
	// frozen, and routing traffic to a replica that reads it would serve stale
	// data indefinitely.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if failed := d.status.failures(); len(failed) > 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintf(w, "projections stopped: %v", failed)
			return
		}
		// Still replaying is not ready. Without this a projector that is a day
		// behind reports healthy, because "no recent errors" and "up to date"
		// look identical from the outside.
		if behind := d.status.behind(); len(behind) > 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintf(w, "projections still catching up: %v", behind)
			return
		}
		if !registry.Ready(r.Context()) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		// WithoutCancel, not Background: this context is already cancelled —
		// draining it is the point — but the values on it still belong here.
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	log.Info("health endpoint listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("health endpoint failed", "error", err)
	}
}

// projections is the registry.
//
// Every read model in the system is listed here, and nowhere else. A projection
// that is not in this list does not run — which is the intended way to retire
// one, and the reason the list is worth reading before a deploy.
func projections(codec *eventcodec.JSON) []projection.Projection {
	return []projection.Projection{
		// One projection per table. Two writers to one table makes rebuild
		// order undefined (CONVENTIONS §8).
		notificationprojection.NewFeed(codec),
		notificationprojection.NewPushSubscriptions(codec),
		notificationprojection.NewPreferences(codec),

		profileprojection.NewProfile(codec),

		organizationprojection.NewStatus(codec),

		// Billing's invoice mirror. Its own projection because it is its own
		// table, and its own STREAM CATEGORY because an invoice is Stripe's
		// object rather than part of the organization's lifecycle.
		billingprojection.NewInvoices(codec),

		// Both membership projections belong to WORKSPACE, including the one
		// that builds `org_member_index`: belonging to an organization comes
		// from organization events AND from workspace joins, one table has one
		// writer, and `workspace -> organization` is the only direction the
		// dependency may run (ADR-020).
		workspaceprojection.NewOrgMembers(codec),
		workspaceprojection.NewMembers(codec),
		workspaceprojection.NewInvitations(codec),
		workspaceprojection.NewTeams(codec),

		identityprojection.NewUser(codec),
		identityprojection.NewSession(codec),
		identityprojection.NewReservation(codec),
	}
}

// registerEvents binds every stored event type to its Go type.
//
// A type missing here is a hard read error rather than a silent skip, by design
// (see adapter/eventcodec): skipping would let a projector quietly ignore facts
// it does not understand and build a read model that is wrong in a way nothing
// detects.
func registerEvents(codec *eventcodec.JSON) {
	// A type missing here is a hard read error rather than a silent skip:
	// skipping would let a projector quietly ignore facts it does not
	// understand and build a read model that is wrong in a way nothing detects.
	//
	// Registered from the module's own composition surface rather than listed
	// here, for the reason identity already is: three binaries register these,
	// and a type registered in two of them is a projector that stops on an event
	// the API can happily write.
	billing.RegisterEvents(codec)
	notification.RegisterEvents(codec)
	profile.RegisterEvents(codec)
	organization.RegisterEvents(codec)
	workspace.RegisterEvents(codec)

	// Identity registers its own types, from the module's composition surface.
	// Listing them here as well would be a second place to forget one, and the
	// module test that guards the schema registry checks that list, not this file.
	identity.RegisterEvents(codec)
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
// Extracted from serveHealth so a composition-root test can assert the observer
// is attached. A registry without one answers /readyz and GetStatus exactly as
// this does and exports nothing, which is indistinguishable at runtime from a
// healthy system: the dashboards fall back to `up{job=...}`, which reports
// whether Prometheus can scrape this process rather than whether its
// dependencies work.
func newHealthRegistry(d *dependencies) *health.Registry {
	registry := health.New(clock.System{}, 2*time.Second,
		health.WithObserver(d.metrics.Health()))
	for _, p := range d.probes {
		registry.Register(p)
	}
	return registry
}

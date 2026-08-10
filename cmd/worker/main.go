// Command worker runs the reactors: the side effects of the event log.
//
// Email, push, webhooks and workflow starts happen here and nowhere else. It is
// deliberately a separate binary from the projector, because the two have
// opposite failure rules and opposite replay semantics (ADR-019):
//
//   - A projector may be rebuilt at any time. This binary has NO rebuild and no
//     way to rewind a subscription group. Replaying it re-sends every email in
//     history.
//   - A projector stops loudly on a bad event, because a wrong read model is
//     invisible. A reactor keeps running and lets the server park what fails,
//     because one broken notification must not stop every other one.
//
// Scaling is the opposite too: run as many instances as you like. A persistent
// subscription group is a competing-consumer queue, so the server hands each
// event to exactly one of them, and that is also how failover works. The
// projector, by contrast, admits exactly one writer per projection.
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
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/config"
	"github.com/chronos/chronos-go/internal/platform/notify"
	"github.com/chronos/chronos-go/internal/platform/reactor"
	"github.com/chronos/chronos-go/internal/server/health"
)

// version is set at build time: -ldflags "-X main.version=$(git rev-parse --short HEAD)"
var version = "dev"

func main() {
	addr := flag.String("addr", ":"+envOr("WORKER_PORT", "8094"), "health listen address")
	list := flag.Bool("list", false, "list registered reactors and exit")
	replay := flag.String("replay-parked", "", "return a reactor's parked events to the live queue, then exit")
	stats := flag.Bool("stats", false, "print each reactor's queue depth and parked count, then exit")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	if err := run(*addr, *list, *replay, *stats, log); err != nil {
		log.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(addr string, list bool, replay string, stats bool, log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	codec := newCodec()

	if list {
		// The catalogue alone answers this; no infrastructure required.
		for _, e := range notifications().Events() {
			spec, _ := notifications().For(e)
			fmt.Printf("%-40s -> %-28s class=%-13s audience=%s\n",
				e, spec.Template, spec.Class, spec.Audience)
		}
		return nil
	}

	d, closeAll := newDependencies(cfg, log, codec)
	defer closeAll()

	rs := reactors(codec, d)
	log.Info("configuration loaded", "env", cfg.Env, "version", version, "reactors", len(rs))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if stats {
		return printStats(ctx, rs, d)
	}
	if replay != "" {
		return replayParked(ctx, rs, d, replay, log)
	}

	if len(rs) == 0 {
		log.Warn("no reactors are registered; the worker is idle")
	}

	go serveHealth(ctx, addr, d, log)
	for _, task := range backgroundTasks(rs, d) {
		go task.run(ctx, d, log)
	}
	supervise(ctx, rs, d, log)

	// supervise returns when every runner has stopped — including immediately,
	// when none are registered. Exiting here would look like a crash loop to a
	// supervisor, and would take down the health endpoint that reports WHY
	// nothing is running. Stay up until actually told to stop.
	<-ctx.Done()
	return nil
}

// backgroundTask is one long-running duty this binary owns besides its
// reactors.
type backgroundTask struct {
	name string
	run  func(context.Context, *dependencies, *slog.Logger)
}

// backgroundTasks is the list main starts, and the list a test can assert.
//
// A list rather than four `go` statements, because a duty that nobody starts is
// invisible: Dedup.Forget was written, documented and indexed for, and called by
// no binary at all — while its unit test passed. A test that calls the function
// directly reproduces exactly that blind spot, so the composition root has to
// expose WHAT IT STARTS, not just what it built.
func backgroundTasks(rs []reactor.Reactor, d *dependencies) []backgroundTask {
	return []backgroundTask{
		{
			// The parked count lives in KurrentDB, not here, and a reactor that
			// has stopped entirely still has a backlog worth reporting — so it is
			// polled rather than incremented in the handler path.
			name: "parked-poll",
			run:  func(ctx context.Context, d *dependencies, log *slog.Logger) { pollParked(ctx, rs, d, log) },
		},
		{
			name: "dedup-retention",
			run:  pruneDedup,
		},
		{
			// Applies erasures published by other replicas, and zeroes expired
			// subject keys. Without it a destroyed key can outlive its own
			// destruction in this process (ADR-041).
			name: "pii-key-cache",
			// Returns immediately: the duties it starts are goroutines of their
			// own, and it is listed here so it cannot be silently dropped.
			run: func(ctx context.Context, d *dependencies, log *slog.Logger) {
				d.startKeyCache(ctx, log)
			},
		},
	}
}

// supervise runs every reactor until the process is told to stop.
//
// Unlike the projector's supervisor, a reactor that returns is restarted by its
// own Runner loop rather than left down: its failures are transport-level, and
// the server already parks the events that genuinely cannot be handled.
func supervise(ctx context.Context, rs []reactor.Reactor, d *dependencies, log *slog.Logger) {
	var wg sync.WaitGroup
	for _, r := range rs {
		wg.Add(1)
		go func(r reactor.Reactor) {
			defer wg.Done()
			if err := reactor.NewRunner(r, d.deps(log)).Run(ctx); err != nil {
				log.Error("reactor stopped", "reactor", r.Name(), "error", err)
				d.status.fail(r.Name(), err)
			}
		}(r)
	}
	wg.Wait()
}

// replayParked returns a reactor's parked events to the live queue.
//
// An operator action, and deliberately not automatic: parked events already
// failed every retry, so replaying them before fixing the cause simply repeats
// the outage.
func replayParked(ctx context.Context, rs []reactor.Reactor, d *dependencies, name string, log *slog.Logger) error {
	for _, r := range rs {
		if r.Name() != name {
			continue
		}
		before, err := d.store.GroupStats(ctx, name)
		if err != nil {
			return err
		}
		if before.Parked == 0 {
			log.Info("nothing parked", "reactor", name)
			return nil
		}
		log.Info("replaying parked events", "reactor", name, "parked", before.Parked)
		if err := d.store.ReplayParked(ctx, name, 0); err != nil {
			return err
		}
		log.Info("replay requested; the events return to the live queue", "reactor", name)
		return nil
	}
	return fmt.Errorf("no reactor named %q — run with -list to see the registered ones", name)
}

func printStats(ctx context.Context, rs []reactor.Reactor, d *dependencies) error {
	for _, r := range rs {
		s, err := d.store.GroupStats(ctx, r.Name())
		if err != nil {
			fmt.Printf("%-28s unavailable: %v\n", r.Name(), err)
			continue
		}
		fmt.Printf("%-28s in_flight=%d unacked=%d parked=%d\n",
			s.Group, s.InFlight, s.Unacked, s.Parked)
	}
	return nil
}

// pollParked keeps chronos_reactor_parked current. Parked events are mail
// nobody received; the number must be visible even when nothing is running.
func pollParked(ctx context.Context, rs []reactor.Reactor, d *dependencies, log *slog.Logger) {
	if d.store == nil || len(rs) == 0 {
		return
	}
	const every = 30 * time.Second
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		for _, r := range rs {
			stats, err := d.store.GroupStats(ctx, r.Name())
			if err != nil {
				log.Debug("parked count unavailable", "reactor", r.Name(), "error", err)
				continue
			}
			d.metrics.SetParked(r.Name(), stats.Parked)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// pruneDedup deletes dedup rows older than the retention window.
//
// reactor_processed gains one row per event per reactor and nothing ever removed
// them: Dedup.Forget existed, was documented, had an index built for it, and was
// called by no binary at all. The table grew for the lifetime of the deployment,
// and the index over it grew with it — so the lookup on the hot path got slower
// every day, which is the shape of problem nobody attributes to a missing cron.
//
// The retention window must comfortably exceed the longest redelivery gap: a
// parked event replayed weeks later must still be recognised as already handled,
// or the reactor performs its effect a second time.
func pruneDedup(ctx context.Context, d *dependencies, log *slog.Logger) {
	if d.dedup == nil {
		log.Warn("dedup retention is not running: reactor_processed will grow without bound")
		return
	}
	t := time.NewTicker(d.dedupEvery)
	defer t.Stop()
	for {
		removed, err := d.dedup.Forget(ctx, d.dedupDays)
		switch {
		case err != nil && ctx.Err() == nil:
			// Degradable: a failed prune costs disk, never correctness. The
			// reactor keeps working with a larger table.
			log.Error("dedup retention sweep failed", "error", err)
		case removed > 0:
			log.Info("dedup retention swept", "rows", removed, "older_than_days", d.dedupDays)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func serveHealth(ctx context.Context, addr string, d *dependencies, log *slog.Logger) {
	registry := health.New(clock.System{}, 2*time.Second)
	for _, p := range d.probes {
		registry.Register(p)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /metrics", d.metrics.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	// Readiness deliberately does NOT consider parked events. Parked events are
	// a backlog for a human, not a reason to pull an instance out of service —
	// taking the worker down would stop the notifications that still work.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if failed := d.status.failures(); len(failed) > 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintf(w, "reactors stopped: %v", failed)
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
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	log.Info("health endpoint listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("health endpoint failed", "error", err)
	}
}

// reactors is the registry.
//
// There is exactly ONE notification reactor, driven by the catalogue in
// events.go, rather than one reactor per notification. Per-notification
// handlers are where a mapping drifts: two disagree about a class, a third
// forgets an audience, and nothing compares them.
func reactors(codec *eventcodec.JSON, d *dependencies) []reactor.Reactor {
	return []reactor.Reactor{
		notify.NewEventReactor(
			notificationReactorName,
			notifications(),
			codec,
			audiences(d.operator),
			d.Notify(),
		),
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

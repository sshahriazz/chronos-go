package main

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"time"

	centrifugoadapter "github.com/chronos/chronos-go/internal/adapter/centrifugo"
	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	kurrentadapter "github.com/chronos/chronos-go/internal/adapter/kurrentdb"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	valkeyadapter "github.com/chronos/chronos-go/internal/adapter/valkey"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/config"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/obs"
	"github.com/chronos/chronos-go/internal/platform/projection"
	"github.com/chronos/chronos-go/internal/platform/realtime"
	"github.com/chronos/chronos-go/internal/server/health"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valkey-io/valkey-go"
)

// newCodec builds the event codec with every stored type registered. It is the
// single place that knows how to read what is in the log, so `-list` and the
// running projector cannot disagree about it.
func newCodec() *eventcodec.JSON {
	codec := eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry())
	registerEvents(codec)
	return codec
}

// dependencies is the composition root.
//
// As in cmd/api, nothing here fails because a dependency is unreachable
// (ADR-010): a pool that cannot connect yet is still a valid pool, and the
// probe reporting DOWN is the designed outcome.
type dependencies struct {
	pool     *pgxpool.Pool
	leases   *pgxpool.Pool
	tx       *pgadapter.DB
	store    *kurrentadapter.Store
	codec    *eventcodec.JSON
	realtime *centrifugoadapter.Publisher
	probes   []health.Probe
	status   *statuses
	holder   string
	metrics  *obs.Metrics

	// The authorization graph is written by cmd/worker, not here.
	//
	// This binary used to build a ConfirmingWriter that nothing read — assigned
	// and never used, which is the same "built and wired into nothing" shape
	// that left three notification adapters dead. It was removed when the access
	// projector was actually written, and the writer moved to the binary that
	// consumes it.
	//
	// It belongs there rather than here for a structural reason: every
	// projection this binary runs writes its rows and its checkpoint in ONE
	// transaction, which is what makes it exactly-once. No transaction spans
	// PostgreSQL and OpenFGA, so tuple writing is at-least-once work and lives
	// with the other at-least-once work.

	// rebuildShards is the parallelism a rebuild applies events through. One is
	// sequential. Config validates it against POSTGRES_MAX_CONNS, because each
	// shard holds a pooled connection for the whole rebuild.
	rebuildShards int

	// catchUpBatch is how many events share one transaction while a projector is
	// behind; rebuildRate paces a rebuild (0 is unthrottled); announceBuf bounds
	// the realtime queue that sits between the projector and Centrifugo. All
	// three are validated in config.
	catchUpBatch int
	rebuildRate  int
	announceBuf  int

	closes []func()
}

func newDependencies(
	cfg *config.Config, log *slog.Logger, codec *eventcodec.JSON, projectionCount int,
) (*dependencies, func()) {
	d := &dependencies{
		status: newStatuses(), holder: holderName(), codec: codec, metrics: obs.New(),
		rebuildShards: cfg.Projector.RebuildShards,
		catchUpBatch:  cfg.Projector.CatchUpBatch,
		rebuildRate:   cfg.Projector.RebuildEventsPerSecond,
		announceBuf:   cfg.Projector.AnnounceBuffer,
	}

	if pool, err := pgadapter.NewPool(context.Background(), cfg.Postgres.AppDSN(), cfg.Postgres.MaxConns); err != nil {
		log.Error("postgres pool unavailable", "error", err)
		d.probes = append(d.probes, pgadapter.Probe{})
	} else {
		// A privileged role ignores row-level security entirely, which would
		// silently disable tenant isolation on every row this binary writes.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := pgadapter.VerifyNotPrivileged(ctx, pool); err != nil {
				log.Error("DATABASE PRIVILEGE CHECK FAILED", "error", err)
			} else {
				log.Info("postgres role verified", "rls_enforced", true)
			}
		}()
		d.pool = pool
		d.tx = pgadapter.New(pool)
		d.probes = append(d.probes, pgadapter.Probe{Pool: pool})
		d.closes = append(d.closes, pool.Close)
	}

	// A SEPARATE pool for leases. A Postgres advisory lock is bound to its
	// connection, so a held lease pins one for as long as the projection runs.
	// Taking those from the work pool means N projections consume N of its
	// connections, and at N = MaxConns the projector deadlocks: every
	// connection is pinned by a lease and not one query can run. Verified — a
	// 3-connection pool with 3 leases could not execute `SELECT 1`.
	if d.pool != nil {
		if leases, err := pgadapter.NewPool(context.Background(), cfg.Postgres.AppDSN(),
			leasePoolSize(projectionCount)); err != nil {
			log.Error("lease pool unavailable", "error", err)
		} else {
			d.leases = leases
			d.closes = append(d.closes, leases.Close)
		}
	}

	if kc, err := kurrentadapter.Dial(cfg.KurrentDB.ConnectionString); err != nil {
		log.Error("kurrentdb client unavailable", "error", err)
		d.probes = append(d.probes, kurrentadapter.Probe{})
	} else {
		d.store = kurrentadapter.NewStore(kc, d.codec)
		d.probes = append(d.probes, kurrentadapter.Probe{Client: kc})
		d.closes = append(d.closes, func() { _ = kc.Close() })
	}

	// Realtime: projections announce their changes to connected browsers.
	// Optional — a projector with no realtime service still fills every read
	// model, and browsers see the change on their next read (ADR-010).
	if conn, err := centrifugoadapter.Dial(cfg.Realtime.GRPCEndpoint); err != nil {
		log.Error("centrifugo client unavailable; live updates will not be sent", "error", err)
	} else {
		d.realtime = centrifugoadapter.New(conn, cfg.Realtime.APIKey.Expose(), nil)
		d.probes = append(d.probes, centrifugoadapter.Probe{Publisher: d.realtime})
		d.closes = append(d.closes, func() { _ = conn.Close() })
	}

	// ---- Valkey, for the health probe -------------------------------------
	//
	// This binary no longer writes tuples — cmd/worker does — so it needs no
	// revocation store. The client stays for the probe: a projector publishes
	// realtime invalidation through Valkey, and an operator wants that reported
	// alongside everything else this process depends on.
	if vk, err := valkey.NewClient(valkey.ClientOption{
		InitAddress:  cfg.Valkey.Addr,
		Password:     cfg.Valkey.Password.Expose(),
		DisableCache: true,
	}); err != nil {
		log.Error("valkey client unavailable", "error", err)
		d.probes = append(d.probes, valkeyadapter.Probe{})
	} else {
		d.probes = append(d.probes, valkeyadapter.Probe{Client: vk})
		d.closes = append(d.closes, vk.Close)
	}

	return d, func() {
		for _, c := range d.closes {
			c()
		}
	}
}

// deps builds the Runner dependency set. Every projection gets the same one;
// what differs between them is the projection itself.
func (d *dependencies) deps(log *slog.Logger) projection.Deps {
	return projection.Deps{
		Subscriber:             d.store,
		Codec:                  d.codec,
		Categories:             d.store,
		Types:                  d.store,
		RebuildShards:          d.rebuildShards,
		CatchUpBatch:           d.catchUpBatch,
		RebuildEventsPerSecond: d.rebuildRate,
		AnnounceBuffer:         d.announceBuf,
		Batch:                  d.tx,
		TX:                     d.tx,
		Realtime:               d.realtimePublisher(),
		Checkpoints:            pgadapter.Checkpoints{},
		Lease:                  pgadapter.NewLease(d.leases),
		Clock:                  clock.System{},
		Log:                    log,
		Metrics:                d.metrics.Projections(),
		Holder:                 d.holder,
	}
}

// leasePoolSize gives every projection its own connection plus headroom for a
// rebuild running alongside the steady-state set.
func leasePoolSize(projections int) int32 {
	const headroom = 4
	n := int32(projections) + headroom //nolint:gosec // a registry this large is not reachable
	if n < headroom {
		return headroom
	}
	return n
}

// realtimePublisher returns the publisher, or nil when Centrifugo could not be
// reached. Typed nil is a real hazard here: a nil *Publisher inside a non-nil
// interface passes the runner's nil check and panics on first use.
func (d *dependencies) realtimePublisher() realtime.Publisher {
	if d.realtime == nil {
		return nil
	}
	return d.realtime
}

// statuses records projections that have stopped, so readiness can report a
// frozen read model instead of claiming everything is fine.
type statuses struct {
	mu      sync.RWMutex
	failed  map[string]string
	runners map[string]*projection.Runner
}

func newStatuses() *statuses {
	return &statuses{
		failed:  make(map[string]string),
		runners: make(map[string]*projection.Runner),
	}
}

func (s *statuses) track(name string, r *projection.Runner) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runners[name] = r
}

// behind lists projections that have not caught up to the head of the log.
func (s *statuses) behind() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for name, r := range s.runners {
		if !r.Live() {
			out = append(out, name)
		}
	}
	return out
}

func (s *statuses) fail(name string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failed[name] = err.Error()
}

func (s *statuses) failures() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.failed))
	for name := range s.failed {
		out = append(out, name)
	}
	return out
}

// holderName is written to the checkpoint row so an operator can see which
// process holds a projection. It is informational: mutual exclusion is the
// advisory lock, never this string.
func holderName() string {
	host, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return host
}

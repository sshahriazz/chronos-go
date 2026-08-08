package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/kurrentdb"
	"github.com/chronos/chronos-go/internal/adapter/openbao"
	fgaadapter "github.com/chronos/chronos-go/internal/adapter/openfga"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	valkeyadapter "github.com/chronos/chronos-go/internal/adapter/valkey"
	"github.com/chronos/chronos-go/internal/platform/config"
	"github.com/chronos/chronos-go/internal/server/health"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valkey-io/valkey-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// dependencies holds everything the server talks to.
//
// Construction NEVER fails on an unreachable dependency (ADR-010): a pool that
// cannot connect yet is still a valid pool, and a probe reporting DOWN is the
// designed outcome. Only genuinely malformed configuration stops startup, and
// that is caught by config.Load before we get here.
type dependencies struct {
	probes []health.Probe
	closes []func()
}

func newDependencies(cfg *config.Config, log *slog.Logger) (*dependencies, func()) {
	d := &dependencies{}

	// ---- PostgreSQL: lazy pool, no connection attempted here -------------
	if pool, err := newPGPool(cfg); err != nil {
		// A malformed DSN is a configuration error, but it must not stop the
		// process — the probe will report it, loudly and continuously.
		log.Error("postgres pool unavailable", "error", err)
		d.probes = append(d.probes, pgadapter.Probe{})
	} else {
		// Verify the connected role cannot bypass RLS. Done lazily so an
		// unreachable database still does not prevent startup (ADR-010), but
		// reported at ERROR because a privileged role means tenant isolation is
		// silently off at the database layer.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := pgadapter.VerifyNotPrivileged(ctx, pool); err != nil {
				log.Error("DATABASE PRIVILEGE CHECK FAILED", "error", err)
			} else {
				log.Info("postgres role verified", "rls_enforced", true)
			}
		}()
		d.probes = append(d.probes, pgadapter.Probe{Pool: pool})
		d.closes = append(d.closes, pool.Close)
	}

	// ---- OpenFGA over gRPC (ADR-037) ------------------------------------
	// NewClient does not dial; the connection is established lazily and
	// re-established automatically, which is exactly the behaviour ADR-010 wants.
	if conn, err := grpc.NewClient(
		cfg.OpenFGA.Endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	); err != nil {
		log.Error("openfga client unavailable", "error", err)
		d.probes = append(d.probes, fgaadapter.Probe{})
	} else {
		d.probes = append(d.probes, fgaadapter.Probe{Conn: conn})
		d.closes = append(d.closes, func() { _ = conn.Close() })
	}

	// ---- KurrentDB: official gRPC client (ADR-037) -----------------------
	// Dial parses the connection string but does not connect; the client
	// reconnects on its own, which is what ADR-010 requires.
	if kc, err := kurrentdb.Dial(cfg.KurrentDB.ConnectionString); err != nil {
		log.Error("kurrentdb client unavailable", "error", err)
		d.probes = append(d.probes, kurrentdb.Probe{})
	} else {
		d.probes = append(d.probes, kurrentdb.Probe{Client: kc})
		d.closes = append(d.closes, func() { _ = kc.Close() })
	}

	// ---- Valkey ----------------------------------------------------------
	if vk, err := valkey.NewClient(valkey.ClientOption{
		InitAddress:  []string{envOr("VALKEY_ADDR", "localhost:6379")},
		DisableCache: true,
	}); err != nil {
		log.Warn("valkey client unavailable", "error", err)
		d.probes = append(d.probes, valkeyadapter.Probe{})
	} else {
		d.probes = append(d.probes, valkeyadapter.Probe{Client: vk})
		d.closes = append(d.closes, vk.Close)
	}

	// ---- OpenBao: official SDK -------------------------------------------
	if bc, err := openbao.Dial(cfg.OpenBao.Address, cfg.OpenBao.Token.Expose()); err != nil {
		log.Error("openbao client unavailable", "error", err)
		d.probes = append(d.probes, openbao.Probe{})
	} else {
		d.probes = append(d.probes, openbao.Probe{Client: bc})
	}

	return d, func() {
		for _, c := range d.closes {
			c()
		}
	}
}

func newPGPool(cfg *config.Config) (*pgxpool.Pool, error) {
	pc, err := pgxpool.ParseConfig(pgDSN(cfg))
	if err != nil {
		return nil, err
	}
	pc.MaxConns = cfg.Postgres.MaxConns
	pc.MaxConnLifetime = time.Hour
	pc.HealthCheckPeriod = 30 * time.Second

	// NewWithConfig does not connect: the first acquisition does. That is what
	// lets the process start while PostgreSQL is still coming up.
	return pgxpool.NewWithConfig(context.Background(), pc)
}

// pgDSN builds the APPLICATION connection string. It deliberately uses the
// non-privileged role: the owner credentials exist only for migrations.
func pgDSN(cfg *config.Config) string {
	return "postgres://" + cfg.Postgres.AppUser + ":" + cfg.Postgres.AppPassword.Expose() +
		"@" + cfg.Postgres.Host + ":" + itoa(cfg.Postgres.Port) +
		"/" + cfg.Postgres.Database + "?sslmode=disable"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}

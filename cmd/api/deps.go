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
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/config"
	"github.com/chronos/chronos-go/internal/platform/obs"
	"github.com/chronos/chronos-go/internal/server/health"
	"github.com/valkey-io/valkey-go"
)

// dependencies holds everything the server talks to.
//
// Construction NEVER fails on an unreachable dependency (ADR-010): a pool that
// cannot connect yet is still a valid pool, and a probe reporting DOWN is the
// designed outcome. Only genuinely malformed configuration stops startup, and
// that is caught by config.Load before we get here.
type dependencies struct {
	probes  []health.Probe
	closes  []func()
	metrics *obs.Metrics

	// authz is the ONLY authorization surface handlers get. It is never nil: if
	// OpenFGA is unreachable it is a Guard over DenyAll, so an outage denies
	// rather than panicking or — far worse — being skipped.
	authz *authz.Guard

	// authzCache is held so the access projector can CONFIRM a revocation once
	// it has removed the tuple. Clearing a tombstone on a timer instead would
	// race the projector, and losing that race restores access to a revoked
	// principal.
	authzCache *valkeyadapter.Authz
}

// tombstonesOrNil and decisionsOrNil avoid the typed-nil trap.
func tombstonesOrNil(a *valkeyadapter.Authz) authz.Tombstones {
	if a == nil {
		return nil
	}
	return a
}

func decisionsOrNil(a *valkeyadapter.Authz) authz.Decisions {
	if a == nil {
		return nil
	}
	return a
}

func newDependencies(cfg *config.Config, log *slog.Logger) (*dependencies, func()) {
	d := &dependencies{metrics: obs.New()}

	// ---- PostgreSQL: lazy pool, no connection attempted here -------------
	if pool, err := pgadapter.NewPool(context.Background(), cfg.Postgres.AppDSN(), cfg.Postgres.MaxConns); err != nil {
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

	// ---- Valkey ----------------------------------------------------------
	//
	// Dialled BEFORE authorization, because the Guard takes its revocation
	// tombstones and decision cache from here. Losing Valkey costs latency and a
	// longer revocation window; it never costs a wrong answer, because every
	// failure in those ports is reported as an error and the Guard denies on any
	// error.
	var authzCache *valkeyadapter.Authz
	if vk, err := valkey.NewClient(valkey.ClientOption{
		InitAddress:  cfg.Valkey.Addr,
		Password:     cfg.Valkey.Password.Expose(),
		DisableCache: true,
	}); err != nil {
		log.Warn("valkey client unavailable; revocations will not take effect until the "+
			"access projector removes the tuple", "error", err)
		d.probes = append(d.probes, valkeyadapter.Probe{})
	} else {
		authzCache = valkeyadapter.NewAuthz(vk)
		d.authzCache = authzCache
		d.probes = append(d.probes, valkeyadapter.Probe{Client: vk})
		d.closes = append(d.closes, vk.Close)
	}

	// ---- OpenFGA over gRPC (ADR-037) ------------------------------------
	//
	// The official Go SDK is OpenAPI-generated and speaks HTTP only, so the
	// client here is generated from the server's protos. Dial does not connect:
	// the connection is established lazily and re-established automatically,
	// which is what ADR-010 wants — authorization being down must not stop the
	// process, it must make every check DENY.
	//
	// The Guard is built either way. When authorization is unreachable it is
	// built over DenyAll, so the failure is an explicit object that refuses
	// rather than a nil that panics on the first request.
	checker := authz.Checker(authz.DenyAll{Reason: "authorization is not configured"})
	if conn, err := fgaadapter.Dial(cfg.OpenFGA.Endpoint, cfg.OpenFGA.PresharedKey.Expose()); err != nil {
		log.Error("openfga client unavailable; EVERY permission check will be denied",
			"error", err)
		d.probes = append(d.probes, fgaadapter.Probe{})
	} else {
		d.probes = append(d.probes, fgaadapter.Probe{Conn: conn})
		d.closes = append(d.closes, func() { _ = conn.Close() })

		built, buildErr := fgaadapter.New(conn, fgaadapter.Config{
			StoreID: cfg.OpenFGA.StoreID,
			ModelID: cfg.OpenFGA.ModelID,
		})
		if buildErr != nil {
			// Missing store id, almost always. Deliberately not fatal, and
			// deliberately not silent: the server runs and denies everything.
			log.Error("openfga checker not constructed; EVERY permission check will be denied",
				"error", buildErr)
		} else {
			checker = built
		}
	}

	guard, err := authz.NewGuard(authz.GuardDeps{
		Checker: checker,
		// Typed nil is a real hazard: a nil *Authz inside a non-nil interface
		// passes the Guard's nil check and then fails every call — which denies,
		// but for a reason that reads as an outage rather than as missing wiring.
		Tombstones: tombstonesOrNil(authzCache),
		Decisions:  decisionsOrNil(authzCache),
		Log:        log,
		Observer:   d.metrics.Authz(),
	})
	if err != nil {
		// NewGuard refuses only misconfiguration we control — a nil checker or a
		// decision TTL above the cap. Either is a wiring bug, not an outage.
		log.Error("authorization guard could not be built; denying everything", "error", err)
		guard, _ = authz.NewGuard(authz.GuardDeps{
			Checker: authz.DenyAll{Reason: "guard misconfigured"}, Log: log,
		})
	}
	d.authz = guard

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

// Command operator serves the back office — where WE see our customers
// (ADR-024, operator.md).
//
// # It is a separate binary, and that is the whole security design
//
// A cross-tenant capability living in the same process as the tenant API is one
// routing mistake, one middleware-ordering bug, or one forgotten annotation
// away from total data disclosure. Separation makes that class of bug
// impossible rather than unlikely: the operator endpoints are not reachable
// from the public surface because they are not in the running binary.
//
// Four things make that claim true rather than aspirational, and each is
// enforced somewhere a test can see it:
//
//   - The code lives at internal/operator, which depguard's
//     `api-excludes-operator` rule denies to cmd/api, internal/server and every
//     module.
//   - The schema lives in its own buf module, proto-operator/, which the
//     OpenAPI generator is never handed — so no operator method can appear in
//     the published REST reference.
//   - This process connects as chronos_operator, which is granted the six
//     operator tables and REVOKED from every tenant table (migration 00037).
//   - Every method declares a capability and an audit action, and the policy
//     loader refuses to serve one that does not.
//
// # What it runs
//
// The RPC server, and its own catch-up projectors. The projectors are here
// rather than in cmd/projector because cmd/projector connects as chronos_app,
// and chronos_app must not hold write access to operator tables — otherwise the
// grant that keeps the tenant plane out is a grant the tenant plane has.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"connectrpc.com/connect"

	"github.com/chronos/chronos-go/gen/proto/chronos/operator/v1/operatorv1connect"
	"github.com/chronos/chronos-go/internal/operator/api"
	"github.com/chronos/chronos-go/internal/operator/app"
	"github.com/chronos/chronos-go/internal/operator/policy"
	operatorprojection "github.com/chronos/chronos-go/internal/operator/projection"
	"github.com/chronos/chronos-go/internal/platform/config"
	"github.com/chronos/chronos-go/internal/platform/obs"
	"github.com/chronos/chronos-go/internal/platform/projection"
	connectserver "github.com/chronos/chronos-go/internal/server/connect"
)

func main() {
	if err := run(); err != nil {
		slog.Error("the operator plane stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	log := slog.New(obs.NewTraceHandler(
		slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	// # This binary REFUSES to start misconfigured, unlike every other one
	//
	// ADR-010's rule is that the server stays resilient: a dependency that is
	// unreachable produces a probe that reports DOWN, not a process that will
	// not boot. That rule is right for the tenant API, where refusing to start
	// turns one broken dependency into a total outage.
	//
	// It is wrong here, and the reason is what a degraded operator plane WOULD
	// still do. An operator binary that came up without an IdP would serve
	// nothing — every method needs a session and there would be no way to get
	// one — so "resilient" buys nothing. An operator binary that came up
	// without its network restriction, or as the wrong database role, would
	// serve the cross-tenant surface with a guard missing. There is no partial
	// state here worth having.
	if err := validate(cfg); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	deps, closeDeps, err := newDependencies(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer closeDeps()

	// The policy catalogue is loaded from the SERVICE DESCRIPTOR this binary
	// registers, before a listener exists. A method with no declared capability
	// or audit action stops the process here rather than serving unguarded.
	catalogue, err := policy.LoadByName("chronos.operator.v1.OperatorService")
	if err != nil {
		return fmt.Errorf("the operator service will not be served: %w", err)
	}
	log.Info("operator policy loaded", "methods", len(catalogue))

	guard, err := api.NewGuard(api.GuardConfig{
		Catalogue: catalogue,
		Sessions:  deps.store,
		Clock:     deps.clock,
		Resolver:  deps.resolver,
		Allowed:   deps.allowed,
		Log:       log,
	})
	if err != nil {
		return err
	}

	service, err := api.NewService(deps.signIn, deps.customers)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	path, handler := operatorv1connect.NewOperatorServiceHandler(service,
		connect.WithInterceptors(guard))
	mux.Handle(path, handler)

	var wg sync.WaitGroup
	runProjectors(ctx, &wg, deps, log)
	runSweeps(ctx, &wg, deps, log)

	srv := connectserver.New(connectserver.DefaultConfig(cfg.Operator.Addr), mux, log)

	log.Info("the operator plane is listening",
		"addr", cfg.Operator.Addr,
		"networks", len(deps.allowed),
		"issuer", cfg.Operator.OIDCIssuer,
		"rp_id", cfg.Operator.WebauthnRPID)

	err = srv.Run(ctx)
	wg.Wait()
	return err
}

// validate refuses every configuration that would produce a back office with a
// guard missing.
func validate(cfg *config.Config) error {
	var problems []string

	if cfg.Postgres.OperatorPassword.IsZero() {
		problems = append(problems,
			"POSTGRES_OPERATOR_PASSWORD is unset; this binary must connect as "+
				cfg.Postgres.OperatorUser+" and must never fall back to the tenant role, "+
				"which is granted every tenant table")
	}
	if !cfg.Operator.Configured() {
		problems = append(problems,
			"the operator IdP or relying party is unset (OPERATOR_OIDC_* and "+
				"OPERATOR_WEBAUTHN_*); sign-in is SSO-then-WebAuthn only (operator.md §3), "+
				"so without both there is no way in and nothing to serve")
	}
	if len(cfg.Operator.AllowedNetworks) == 0 && !cfg.Operator.AllowAnyIP {
		problems = append(problems,
			"OPERATOR_ALLOWED_NETWORKS is empty and OPERATOR_ALLOW_ANY_IP is not set; "+
				"operator access is IP-restricted to internal ranges (operator.md §3), and "+
				"serving the cross-tenant plane to every network must be asked for rather "+
				"than reached by forgetting to configure it")
	}
	if len(problems) > 0 {
		return fmt.Errorf("the operator plane will not start:\n  - %s",
			strings.Join(problems, "\n  - "))
	}
	return nil
}

// parseNetworks turns the configured CIDRs into prefixes, refusing any it
// cannot read.
//
// A malformed CIDR is a startup failure rather than a skipped entry. Skipping
// would narrow the permitted set silently — or, if it were the only entry,
// widen it to everything.
func parseNetworks(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("OPERATOR_ALLOWED_NETWORKS entry %q is not a CIDR: %w", raw, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// runProjectors starts the plane's own catch-up subscriptions.
func runProjectors(ctx context.Context, wg *sync.WaitGroup, d *dependencies, log *slog.Logger) {
	views := []projection.Projection{
		operatorprojection.NewAccounts(d.codec),
		operatorprojection.NewAuditLog(d.codec),
		operatorprojection.NewCustomers(d.codec),
	}
	for _, v := range views {
		wg.Add(1)
		go func(v projection.Projection) {
			defer wg.Done()
			runner := projection.NewRunner(v, d.projectionDeps(log))
			if err := runner.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				log.Error("an operator projection stopped", "projection", v.Name(), "error", err)
			}
		}(v)
	}
}

// runSweeps removes expired sessions and ceremonies.
//
// Both tables are authoritative and short-lived, so nothing else prunes them.
// The interval is generous because neither row is dangerous once expired — the
// queries that read them compare the deadline in SQL, so an unswept row is
// already unusable. This bounds table SIZE, not exposure.
func runSweeps(ctx context.Context, wg *sync.WaitGroup, d *dependencies, log *slog.Logger) {
	const every = 10 * time.Minute

	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				now := d.clock.Now()
				if n, err := d.store.SweepSessions(ctx, now); err != nil {
					log.Error("the operator session sweep failed", "error", err)
				} else if n > 0 {
					log.Info("swept expired operator sessions", "removed", n)
				}
				if n, err := d.store.SweepCeremonies(ctx, now); err != nil {
					log.Error("the operator ceremony sweep failed", "error", err)
				} else if n > 0 {
					log.Info("swept expired operator ceremonies", "removed", n)
				}
			}
		}
	}()
}

var _ = app.StageLive // keeps the app import honest for readers of this file

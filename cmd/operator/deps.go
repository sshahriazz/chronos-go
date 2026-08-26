package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	kurrentadapter "github.com/chronos/chronos-go/internal/adapter/kurrentdb"
	oidcadapter "github.com/chronos/chronos-go/internal/adapter/oidc"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	waadapter "github.com/chronos/chronos-go/internal/adapter/webauthn"
	"github.com/chronos/chronos-go/internal/operator"
	alertadapter "github.com/chronos/chronos-go/internal/operator/adapter/alert"
	operatorceremony "github.com/chronos/chronos-go/internal/operator/adapter/ceremony"
	operatorevents "github.com/chronos/chronos-go/internal/operator/adapter/kurrentdb"
	operatorpg "github.com/chronos/chronos-go/internal/operator/adapter/postgres"
	"github.com/chronos/chronos-go/internal/operator/app"
	"github.com/chronos/chronos-go/internal/platform/clientip"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/config"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/obs"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// dependencies is the composition root.
//
// Unlike cmd/api's, every constructor here is REQUIRED to succeed — see run()'s
// comment on why this binary refuses to start rather than degrading. A
// dependency that is merely unreachable is still fine: a pool that cannot
// connect yet is a valid pool.
type dependencies struct {
	pool   *pgxpool.Pool
	leases *pgxpool.Pool
	tx     *pgadapter.DB

	store     *operatorpg.Store
	directory *operatorpg.DirectoryStore

	eventStore *kurrentadapter.Store
	codec      *eventcodec.JSON

	signIn    *app.SignIn
	customers *app.Customers
	elevation *app.Elevation

	clock    app.Clock
	resolver clientip.Resolver
	allowed  []netip.Prefix
	metrics  *obs.Metrics
	holder   string

	closes []func()
}

func newDependencies(
	ctx context.Context, cfg *config.Config, log *slog.Logger,
) (*dependencies, func(), error) {
	d := &dependencies{
		clock:   clock.System{},
		metrics: obs.New(),
		holder:  holderName(),
	}
	closeAll := func() {
		for i := len(d.closes) - 1; i >= 0; i-- {
			d.closes[i]()
		}
	}
	fail := func(err error) (*dependencies, func(), error) {
		closeAll()
		return nil, func() {}, err
	}

	allowed, err := parseNetworks(cfg.Operator.AllowedNetworks)
	if err != nil {
		return fail(err)
	}
	d.allowed = allowed

	resolver, err := clientip.NewResolver(cfg.API.TrustedProxyHops)
	if err != nil {
		return fail(fmt.Errorf("building the client-address resolver: %w", err))
	}
	d.resolver = resolver

	// # The DSN is the operator role's, and the check below is the point
	//
	// Connecting as chronos_app here would compile, connect, and hand this
	// process every tenant table — the exact grants the separation exists to
	// withhold. The DSN comes from config.OperatorDSN so no binary assembles
	// one by hand, and the assertion after connecting proves the role that
	// actually arrived is the one intended.
	pool, err := pgadapter.NewPool(ctx, cfg.Postgres.OperatorDSN(), cfg.Postgres.MaxConns)
	if err != nil {
		return fail(fmt.Errorf("connecting as %s: %w", cfg.Postgres.OperatorUser, err))
	}
	d.pool = pool
	d.closes = append(d.closes, pool.Close)
	d.tx = pgadapter.New(pool)

	if err := verifyRole(ctx, pool, cfg.Postgres.OperatorUser); err != nil {
		return fail(err)
	}
	log.Info("operator database role verified", "role", cfg.Postgres.OperatorUser)

	// A SEPARATE pool for leases, for the reason cmd/projector documents: a
	// Postgres advisory lock is bound to its connection, so a held lease pins
	// one for as long as the projection runs. Three projections taking theirs
	// from the work pool means three fewer connections for queries.
	leasePool, err := pgadapter.NewPool(ctx, cfg.Postgres.OperatorDSN(), leasePoolSize())
	if err != nil {
		return fail(fmt.Errorf("connecting the operator lease pool: %w", err))
	}
	d.leases = leasePool
	d.closes = append(d.closes, leasePool.Close)

	store, err := operatorpg.New(d.tx)
	if err != nil {
		return fail(err)
	}
	d.store = store

	directory, err := operatorpg.NewDirectory(d.tx)
	if err != nil {
		return fail(err)
	}
	d.directory = directory

	// The codec registers the OPERATOR events plus the tenant events the
	// customer projection reads. A codec missing either half produces a
	// projection that silently skips what it cannot decode.
	upcasters := eventsourcing.NewUpcasterRegistry()
	codec := eventcodec.NewJSON(upcasters)
	registerEvents(codec, upcasters)
	d.codec = codec

	kc, err := kurrentadapter.Dial(cfg.KurrentDB.ConnectionString)
	if err != nil {
		return fail(fmt.Errorf("connecting to the event log: %w", err))
	}
	d.eventStore = kurrentadapter.NewStore(kc, codec)
	d.closes = append(d.closes, func() { _ = kc.Close() })
	eventStore := d.eventStore

	appender, err := operatorevents.New(eventStore, codec, upcasters, d.clock.Now)
	if err != nil {
		return fail(err)
	}
	auditor := app.NewAuditor(appender, d.clock)

	provider, err := oidcadapter.New(ctx, oidcadapter.Config{
		Issuer:       cfg.Operator.OIDCIssuer,
		ClientID:     cfg.Operator.OIDCClientID,
		ClientSecret: cfg.Operator.OIDCClientSecret.Expose(),
		RedirectURL:  cfg.Operator.OIDCRedirectURL,
		Scopes:       []string{"openid", "email", "profile"},
	})
	if err != nil {
		return fail(fmt.Errorf("reaching the operator identity provider: %w", err))
	}
	idp, err := operatorceremony.NewIdP(provider, cfg.Operator.HostedDomain)
	if err != nil {
		return fail(err)
	}

	ceremony, err := waadapter.New(waadapter.Config{
		RPID:          cfg.Operator.WebauthnRPID,
		RPDisplayName: cfg.Operator.WebauthnRPName,
		Origins:       cfg.Operator.WebauthnOrigins,
	})
	if err != nil {
		return fail(fmt.Errorf("building the operator relying party: %w", err))
	}
	authenticator, err := operatorceremony.NewAuthenticator(ceremony)
	if err != nil {
		return fail(err)
	}

	signIn, err := app.NewSignIn(app.SignInDeps{
		IdP:           idp,
		Authenticator: authenticator,
		Accounts:      store,
		Credentials:   store,
		Sessions:      store,
		Ceremonies:    store,
		Events:        appender,
		Auditor:       auditor,
		Clock:         d.clock,
		Log:           log,
	})
	if err != nil {
		return fail(err)
	}
	d.signIn = signIn

	vault, err := newVault(d.tx, cfg, log)
	if err != nil {
		return fail(err)
	}

	customers, err := app.NewCustomers(directory, vault, auditor, log)
	if err != nil {
		return fail(err)
	}
	d.customers = customers

	// The alerter is REQUIRED by NewElevation, not optional, so a build that
	// forgot to construct it does not start. operator.md §5 lists the alert
	// beside the justification and the time box as one of three controls, and a
	// break-glass that raises none is the dangerous half of the feature.
	elevation, err := app.NewElevation(store, auditor,
		alertadapter.NewElevations(d.metrics.Registry(), log), d.clock, log)
	if err != nil {
		return fail(err)
	}
	d.elevation = elevation

	return d, closeAll, nil
}

// projectionDeps is what the plane's own projectors run with.
func (d *dependencies) projectionDeps(log *slog.Logger) projection.Deps {
	return projection.Deps{
		Subscriber:  d.eventStore,
		Codec:       d.codec,
		Categories:  d.eventStore,
		Types:       d.eventStore,
		Batch:       d.tx,
		TX:          d.tx,
		Checkpoints: pgadapter.Checkpoints{},
		Lease:       pgadapter.NewLease(d.leases),
		Clock:       clock.System{},
		Log:         log,
		Metrics:     d.metrics.Projections(),
		Holder:      d.holder,

		// Realtime is deliberately ABSENT. The operator console is a
		// back-office tool with a handful of users and no live-update
		// requirement, and wiring it to Centrifugo would publish operator
		// activity onto the same bus tenants subscribe to.
	}
}

// leasePoolSize gives each of the three projections its own connection plus
// headroom.
func leasePoolSize() int32 { return 3 + 4 }

func holderName() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return fmt.Sprintf("operator-%d", os.Getpid())
	}
	return fmt.Sprintf("%s-%d", host, os.Getpid())
}

// verifyRole asserts the connection actually arrived as the operator role.
//
// # Why this is checked rather than assumed
//
// cmd/api has the mirror of this check — VerifyNotPrivileged — because
// connecting as the owner silently disables row-level security while every test
// passes. The failure here is the same shape and the opposite direction:
// connecting as chronos_app would give this process the tenant plane's grants,
// and nothing about the behaviour would look wrong until somebody audited what
// the operator plane can read.
//
// A DSN is a string in an environment variable. Asserting on the role that
// arrived, rather than on the one we asked for, is what makes the grant table a
// guarantee instead of an intention.
func verifyRole(ctx context.Context, pool *pgxpool.Pool, want string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := pgadapter.VerifyRole(ctx, pool, want); err != nil {
		return fmt.Errorf(
			"%w — the operator plane must connect as %s, because any other role holds the "+
				"TENANT plane's grants and the isolation migration 00037 establishes would "+
				"not be in effect", err, want)
	}
	return nil
}

// registerEvents declares every type this binary can decode.
//
// BOTH halves, and the second is easy to miss: the operator plane's own events,
// and the tenant events the customer directory is projected from. A codec with
// only the first would build a directory that stays empty while every log line
// says the projection is running.
func registerEvents(codec *eventcodec.JSON, upcasters *eventsourcing.UpcasterRegistry) {
	operator.RegisterEvents(codec)
	operator.RegisterSchemas(upcasters)

	registerTenantEvents(codec, upcasters)
}

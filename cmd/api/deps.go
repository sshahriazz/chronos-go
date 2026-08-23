package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/adapter/kurrentdb"
	"github.com/chronos/chronos-go/internal/adapter/openbao"
	fgaadapter "github.com/chronos/chronos-go/internal/adapter/openfga"
	"github.com/chronos/chronos-go/internal/adapter/piivault"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	"github.com/chronos/chronos-go/internal/adapter/seaweedfs"
	valkeyadapter "github.com/chronos/chronos-go/internal/adapter/valkey"
	"github.com/chronos/chronos-go/internal/modules/billing"
	billingapi "github.com/chronos/chronos-go/internal/modules/billing/api"
	entitlementapp "github.com/chronos/chronos-go/internal/modules/entitlement/app"
	"github.com/chronos/chronos-go/internal/modules/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/argon2id"
	identityapi "github.com/chronos/chronos-go/internal/modules/identity/api"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/notification"
	notificationapi "github.com/chronos/chronos-go/internal/modules/notification/api"
	"github.com/chronos/chronos-go/internal/modules/organization"
	orgapi "github.com/chronos/chronos-go/internal/modules/organization/api"
	"github.com/chronos/chronos-go/internal/modules/profile"
	profileapi "github.com/chronos/chronos-go/internal/modules/profile/api"
	"github.com/chronos/chronos-go/internal/modules/workspace"
	workspaceapi "github.com/chronos/chronos-go/internal/modules/workspace/api"
	workspaceapp "github.com/chronos/chronos-go/internal/modules/workspace/app"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/blob"
	"github.com/chronos/chronos-go/internal/platform/clientip"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/config"
	"github.com/chronos/chronos-go/internal/platform/cqrs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/obs"
	"github.com/chronos/chronos-go/internal/platform/ratelimit"
	"github.com/chronos/chronos-go/internal/server/health"
	"github.com/chronos/chronos-go/internal/server/interceptor"
	"github.com/chronos/chronos-go/internal/server/policy"
	"github.com/jackc/pgx/v5/pgxpool"
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

	// clock is the ONE clock this binary has. Everything time-derived reads it:
	// session deadlines, token expiry, attempt ceilings, TOTP verification, the
	// health registry's uptime.
	//
	// One, because two is how a process comes to disagree with itself about
	// whether a token has expired. It is clock.System{} unless the local-only
	// movable clock was asked for (ADR-054), and in that case it is the SAME
	// object movableClock points at — a second offset clock would be a second
	// answer to "what time is it" that only some rules would follow.
	clock clock.Clock

	// movableClock is non-nil in exactly one case: CLOCK_CONTROL_ENABLED is true.
	//
	// It is the same object as clock, held again at its concrete type because
	// moving time is not part of the clock.Clock interface and must not become
	// part of it. Only the control listener receives this field, so no
	// collaborator in this binary is able to move time even by accident.
	movableClock *clock.Offset

	// profiling is the /debug/pprof listener (Go 1.27's goroutineleak profile
	// among them). Never nil: disabled is a working object whose Addr is "".
	//
	// It is built HERE rather than in main for the reason every other field on
	// this struct is: a composition-root test can then assert it, and this
	// particular seam has the worst possible failure signature. A profiler that
	// was never started is invisible — no error, no log line, and the only
	// symptom is a `go tool pprof` that cannot connect on the day somebody is
	// trying to explain a memory leak. A profiler started with the TOKEN
	// dropped from the mapping is worse than invisible: it works, and it serves
	// heap dumps to anyone who reaches the port.
	profiling *obs.Profiler

	// authz is the ONLY authorization surface handlers get. It is never nil: if
	// OpenFGA is unreachable it is a Guard over DenyAll, so an outage denies
	// rather than panicking or — far worse — being skipped.
	authz *authz.Guard

	// emailIndex and accounts are held for WORKSPACE, not for identity — identity
	// builds and keeps its own.
	//
	// Invitations need both, and neither may be reached from the workspace
	// module: `modules/A` may import `modules/B/contract` and nothing more
	// (CONVENTIONS §2). Workspace declares the two ports it needs and this
	// composition root satisfies them, which is the only place allowed to know
	// both sides. See cmd/api/invitationports.go.
	emailIndex workspaceapp.EmailIndexer
	accounts   workspaceapp.Directory

	// authzCache is held so the access projector can CONFIRM a revocation once
	// it has removed the tuple. Clearing a tombstone on a timer instead would
	// race the projector, and losing that race restores access to a revoked
	// principal.
	authzCache *valkeyadapter.Authz

	// once is the idempotency gate every mutating RPC passes through
	// (CONVENTIONS §6). Nil when Postgres is unreachable, and the interceptor
	// must REFUSE mutations rather than wave them through — a gate that is
	// skipped during an outage is skipped exactly when clients are retrying
	// hardest.
	once *cqrs.Once

	// idempotency is the same store, held so the retention sweep can run. A
	// stored response can carry personal data, so nothing deleting it is a
	// compliance problem rather than a full disk (ADR-002).
	idempotency *pgadapter.Idempotency

	// pool is held for readiness probing and for the sweep's lifetime.
	pool *pgxpool.Pool

	// sweepEvery is how often expired idempotency records are deleted. A field
	// rather than a constant so a test can observe the sweep without waiting an
	// hour for it.
	sweepEvery time.Duration

	// ---- identity (S1-27) ------------------------------------------------
	//
	// Everything below was built, tested, and constructed by no binary until this
	// wiring existed. Each field is held on the struct rather than kept in a
	// local for one reason: a composition-root test can assert it. Six seams in
	// this repository have shipped fully tested and wired into nothing, and every
	// one of them was invisible precisely because the wiring left no artefact.

	// store is the event store, as the MultiAppender every identity command
	// writes through. Nil when KurrentDB could not be dialled.
	store *kurrentdb.Store

	// codec and upcasters are the ONE event registry this binary has. One,
	// because a second is a second place to forget a type: the store encodes
	// through it on append and the aggregate repositories decode through it on
	// load, and a type registered in one and not the other is a command that
	// writes an event nothing can read back.
	codec     *eventcodec.JSON
	upcasters *eventsourcing.UpcasterRegistry

	// vault turns a pseudonym into somewhere an email address can legally live
	// (ADR-002). Nil when Postgres or OpenBao is unreachable, and identity cannot
	// be built without it: registration has nowhere to put the address.
	vault app.SubjectVault

	// piiVault is the SAME object as vault, held concretely because profile
	// READS from it and identity's port deliberately cannot.
	//
	// app.SubjectVault is write-only on purpose — ports.go says a port that could
	// read is a port through which an address reaches a log — and that constraint
	// is worth keeping for identity even though profile needs the other half.
	// Widening the shared port would remove the guarantee from the module that
	// asked for it, so the two views are separate and both point at one vault.
	piiVault *piivault.Vault

	// blobs is the object store. Avatar bytes never pass through this process:
	// the client is handed a signed POST target and uploads straight to it.
	blobs *seaweedfs.Store

	// profile is display name, locale, timezone and avatar — its own module,
	// because identity answers "who is this" and every attribute added there
	// widens the aggregate that guards authentication (ADR-020's reasoning).
	profile      *profileapi.Service
	organization *orgapi.Service
	workspace    *workspaceapi.Service

	// billing is the commercial self-service surface: one RPC, which mints a
	// signed link into Stripe's hosted Customer Portal. Everything a customer
	// can change about their subscription happens there and arrives back as a
	// webhook, which is why the webhook handler re-fetches rather than trusting
	// a payload.
	billing *billingapi.Service

	// reserver is entitlement's use case, held because TWO things need it: gate
	// 4 reserves through it, and the workspace handler COMMITS through it. A
	// second instance would be a second view of the same table, which is fine —
	// but a second CATALOGUE would not be, and this keeps one of each.
	reserver      *entitlementapp.Reserver
	entitlements  interceptor.Entitlements
	subscriptions interceptor.Subscriptions
	orgContext    interceptor.OrgResolver

	// counter backs the authentication attempt ceiling. Nil when Valkey is
	// unreachable — and identity is then refused outright, because a login path
	// with no ceiling permits unlimited guessing with nothing reporting it.
	counter ratelimit.Counter

	// identity is the Connect handler. Nil means the module could not be built,
	// and main leaves the service UNREGISTERED rather than registering something
	// that panics on first use.
	identity *identityapi.Service

	// notification is the client surface over the feed, the push subscriptions
	// and the per-person channel preferences. Held on the struct, not built in
	// main, so a composition-root test can assert it was constructed — the whole
	// module was written, tested and reachable by nobody for exactly as long as
	// nothing asserted this.
	notification *notificationapi.Service

	// revocations is the authentication service, held ONLY so a composition-root
	// test can assert that revoking a session also invalidates the authorization
	// decisions cached for that principal (ADR-045).
	//
	// Nothing at runtime can notice this wiring going missing: with no epochs the
	// service logs once at construction and every revocation then succeeds
	// locally while a cached permit keeps authorizing for up to
	// authz.MaxDecisionTTL. The assertion is the only detector.
	revocations *app.Authentication

	// hasher is held so a test can assert the concurrency bound is the resolved
	// CPU limit rather than GOMAXPROCS. Each concurrent hash holds 32 MiB, so
	// that bound IS the memory ceiling on password verification.
	hasher *argon2id.Hasher

	// cpuLimit is what this process may actually use (see resolveCPULimit), and
	// hashConcurrency is what the hasher was built with. Both recorded, because
	// the interesting assertion is the RELATIONSHIP between them.
	cpuLimit        int
	hashConcurrency int

	// limiter is the attempt ceiling. Held so a test can assert the rule set,
	// which is a policy decision that would otherwise exist only inside a
	// constructor's arguments.
	limiter *ratelimit.Limiter

	// mailAddressLimiter and mailCallerLimiter are the two axes of the
	// verification-mail ceiling. Held for the same reason as limiter, and with a
	// sharper edge: a resend that is not rate limited still works perfectly, so
	// nothing at runtime distinguishes "the ceiling is configured" from "the
	// ceiling was never wired" until somebody's mailbox is full. Only a
	// composition-root assertion can tell the difference.
	mailAddressLimiter *ratelimit.Limiter
	mailCallerLimiter  *ratelimit.Limiter

	// usernameCheckLimiter bounds the public username-availability endpoint.
	//
	// Its own limiter over its own key prefix, so a person picking a handle cannot
	// spend the budget that stops a stranger mail-bombing their mailbox. It is a
	// RESOURCE bound, not an information one: the endpoint is an enumeration
	// oracle by design (ADR-051).
	usernameCheckLimiter *ratelimit.Limiter

	// callerScope is the trust boundary the per-caller ceiling's bucket key is
	// derived through. Held for the sharpest version of the reason above: every
	// value of it produces a working server, and the difference between "trusts
	// one proxy" and "trusts the caller's own header" is invisible at runtime,
	// visible in no log line, and only ever discovered as an abuse incident.
	callerScope clientip.Resolver

	// totpEnroller and authObserver are the two collaborators the composition
	// root SYNTHESISES rather than receives: a func type over the TOTP adapter,
	// and the metrics observer for the two authentication outcomes that leave no
	// event behind. Both default to something harmless inside app, so their
	// absence is silent by construction — which is why they are asserted here.
	totpEnroller app.TotpEnroller
	authObserver app.AuthObserver

	// ---- the enforcement pipeline (ADR-021) -------------------------------

	// policies is every method this server will serve, with its declared gates.
	policies *policy.Set

	// authn resolves the bearer token. Nil means every authenticated RPC is
	// refused, which is the correct direction and must still be logged.
	authn *interceptor.SessionAuthenticator

	// idempotencyGate is gate 5, over the same cqrs.Once as `once`.
	idempotencyGate *interceptor.Idempotency

	// gates is the interceptor every Connect handler in this binary is built
	// with. Nil means no service is registered at all — serving a method whose
	// gates are unknown is worse than not serving it.
	gates *interceptor.Gates
}

// tombstonesOrNil and decisionsOrNil avoid the typed-nil trap.
func tombstonesOrNil(a *valkeyadapter.Authz) authz.Tombstones {
	if a == nil {
		return nil
	}
	return a
}

// revokerOrNil avoids the same trap on the tombstone WRITE side.
//
// A nil here is refused by NewMembers rather than tolerated, and that is the
// point of separating it out: without a revoker, removing somebody from a
// workspace leaves every permission working until a projector catches up, and
// being late to revoke is a security failure rather than a delay
// (access.md §6.1).
func revokerOrNil(a *valkeyadapter.Authz) authz.Revoker {
	if a == nil {
		return nil
	}
	return a
}

// epochsOrNil avoids the same typed-nil trap for the revocation epochs.
//
// A nil *Authz inside a non-nil interface passes NewAuthentication's nil check,
// so revocation would look wired, log nothing, and panic on the first sign-out —
// which is the worst possible moment to discover it.
func epochsOrNil(a *valkeyadapter.Authz) app.RevocationEpochs {
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

	// The clock, FIRST. Everything below that carries a deadline reads it, and a
	// collaborator built before the clock it should have been given is how a
	// process ends up with two of them.
	d.clock, d.movableClock = newClock(cfg)

	// The event registry, built before anything that reads or writes an event.
	// Types come from each module's own composition surface rather than from a
	// list here: a list in this file is a second place to forget a type, and the
	// module test that guards the schema registry checks the module's list.
	//
	// EVERY module that this binary writes, not just identity. Registering only
	// identity made every notification and profile aggregate writable exactly
	// ONCE and then permanently broken: the first append succeeds because an
	// empty stream decodes zero events, and every later command fails to load
	// its own aggregate with `event type "profile.ProfileUpdated.v1" is not
	// registered`. The read side keeps answering — cmd/projector has its own
	// codec and registers all six — so the projections, the dashboards and every
	// GET stay green while writes are dead. Found by protocolit's
	// TestASecondWriteToAnAggregateIsRefused.
	d.upcasters = eventsourcing.NewUpcasterRegistry()
	billing.RegisterSchemas(d.upcasters)
	identity.RegisterSchemas(d.upcasters)
	notification.RegisterSchemas(d.upcasters)
	profile.RegisterSchemas(d.upcasters)
	organization.RegisterSchemas(d.upcasters)
	workspace.RegisterSchemas(d.upcasters)
	d.codec = eventcodec.NewJSON(d.upcasters)
	billing.RegisterEvents(d.codec)
	identity.RegisterEvents(d.codec)
	notification.RegisterEvents(d.codec)
	profile.RegisterEvents(d.codec)
	organization.RegisterEvents(d.codec)
	workspace.RegisterEvents(d.codec)

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
		d.pool = pool
		d.probes = append(d.probes, pgadapter.Probe{Pool: pool})
		d.closes = append(d.closes, pool.Close)

		// ---- The idempotency gate (CONVENTIONS §6) -----------------------
		//
		// Built here rather than beside the interceptors, because it is the
		// database that makes it work: the claim is atomic because
		// `INSERT … ON CONFLICT` is one statement, not because of anything in
		// Go. Without Postgres there is no gate, and the interceptor must
		// refuse mutations rather than let them through — a gate skipped
		// during an outage is skipped exactly when clients retry hardest.
		d.idempotency = pgadapter.NewIdempotency(pgadapter.New(pool))
		once, err := cqrs.NewOnce(cqrs.OnceDeps{
			Store: d.idempotency,
			TTL:   cfg.API.IdempotencyTTL,
			Wait:  cfg.API.IdempotencyWait,
		})
		if err != nil {
			// Config validation already bounds the TTL, so reaching this means
			// the two disagree — report it rather than shipping a nil gate
			// nobody notices.
			log.Error("idempotency gate not constructed; EVERY mutation will be refused",
				"error", err)
		} else {
			d.once = once
		}
	}
	d.sweepEvery = cfg.API.IdempotencySweepEvery

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
		// The same connection carries the authentication attempt ceiling. One
		// client rather than two: they are the same store, and a second connection
		// would double the failure surface for no isolation — losing Valkey costs
		// both regardless.
		d.counter = counterOrNil(valkeyadapter.NewCounter(vk))
		d.probes = append(d.probes, valkeyadapter.Probe{Client: vk})
		d.closes = append(d.closes, vk.Close)
	}
	// A nil counter is NOT silently optional: startIdentity substitutes a counter
	// that fails, which makes every attempt Degraded and counted, and says so at
	// ERROR. The decision and its reasoning live there, beside the limiter.

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
		log.Error("kurrentdb client unavailable; NO command can be accepted, because every "+
			"write in this system is an append", "error", err)
		d.probes = append(d.probes, kurrentdb.Probe{})
	} else {
		// The Store is built with identity's own codec inside startIdentity. This
		// one carries the codec the store needs to APPEND, which is the same
		// registry: a codec that cannot encode an event cannot write it, and a
		// type missing from it is a hard error rather than a silent skip.
		d.store = kurrentdb.NewStore(kc, d.codec)
		d.probes = append(d.probes, kurrentdb.Probe{Client: kc})
		d.closes = append(d.closes, func() { _ = kc.Close() })
	}

	// ---- OpenBao: official SDK -------------------------------------------
	//
	// The PII vault is the single point at which a pseudonym becomes a real
	// address, and identity cannot be built without it: an email has nowhere else
	// it is allowed to go (ADR-002).
	if bc, err := openbao.Dial(cfg.OpenBao.Address, cfg.OpenBao.Token.Expose()); err != nil {
		log.Error("openbao client unavailable; no address can be stored or resolved, so "+
			"registration cannot complete", "error", err)
		d.probes = append(d.probes, openbao.Probe{})
	} else {
		d.probes = append(d.probes, openbao.Probe{Client: bc})
		if d.pool == nil {
			log.Error("no PII vault: postgres is unreachable, so there is nowhere to store " +
				"the ciphertext an address becomes")
		} else {
			// No key cache here, deliberately. cmd/worker caches unwrapped subject
			// keys because it fans one notification out to many recipients; the API
			// resolves at most one subject per request, so a cache would buy nothing
			// and would widen the window in which an erased subject's key is still
			// usable in a replica that missed its invalidation (ADR-041).
			v := piivault.New(pgadapter.New(d.pool),
				openbao.NewKeyRing(bc, cfg.OpenBao.KEKName))
			d.vault = vaultOrNil(v)
			d.piiVault = v
		}
	}

	// ---- profiling: a SEPARATE listener, off unless asked for --------------
	//
	// Never the API port. See obs.StartProfiling for why an "authenticated"
	// pprof route on the tenant mux would in fact be an unauthenticated one.
	//
	// A bind failure is logged and survived, exactly like every other
	// unreachable dependency (ADR-010): an optional debug surface that cannot
	// take its port must not turn into a crash loop on the server that serves
	// customers.
	profiler, err := obs.StartProfiling(context.Background(), obs.ProfilingConfig{
		Enabled: cfg.Profiling.Enabled,
		Addr:    cfg.Profiling.Addr,
		Token:   cfg.Profiling.Token.Expose(),
	}, log)
	if err != nil {
		log.Error("profiling listener not started; /debug/pprof is unreachable and no "+
			"heap, CPU or goroutine-leak profile can be collected from this process",
			"addr", cfg.Profiling.Addr, "error", err)
	}
	d.profiling = profiler
	d.closes = append(d.closes, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := profiler.Shutdown(ctx); err != nil {
			log.Warn("profiling listener did not drain", "error", err)
		}
	})

	// Identity LAST: it needs the pool, the store, the vault and the counter, and
	// a thing constructed before what it depends on is how a composition root
	// grows a nil that nobody notices until a request arrives.
	// Gates 3 and 4 BEFORE startIdentity, because that is what assembles the
	// enforcement pipeline — a gate constructed after it is a gate the pipeline
	// never sees, and every method needing it is refused for the process's life.
	// That is not hypothetical: entitlement was built afterwards at first, and
	// the startup log correctly reported it as blocking while the object existed.
	if gate, err := d.buildOrgContext(log); err != nil {
		log.Error("the org-context gate is NOT constructed; every method that is not "+
			"self-scoped is refused for the lifetime of this process", "error", err)
	} else {
		d.orgContext = gate
	}
	if gate, err := d.buildSubscriptions(log); err != nil {
		log.Error("the subscription gate is NOT constructed; every organization-scoped "+
			"method is refused for the lifetime of this process", "error", err)
	} else {
		d.subscriptions = gate
	}
	if gate, err := d.buildEntitlements(log); err != nil {
		log.Error("the entitlement gate is NOT constructed; every RPC declaring an "+
			"entitlement is refused for the lifetime of this process", "error", err)
	} else {
		d.entitlements = gate
	}

	d.startIdentity(cfg, log)

	// The object store. Constructed here because it was constructed by NO binary
	// until now — the third adapter in this repository to be fully built, fully
	// tested and wired into nothing (CLAUDE.md names the pattern; codegraph found
	// the first two). An avatar is a reference to an object, so profile cannot be
	// built without it.
	if limits, err := (blob.Limits{
		MaxBytes:            cfg.Storage.MaxUploadBytes,
		MaxBatchCount:       cfg.Storage.MaxBatchCount,
		AllowedContentTypes: cfg.Storage.AllowedContentTypes,
		ResumableThreshold:  cfg.Storage.ResumableThresholdBytes,
		PartSize:            cfg.Storage.PartSizeBytes,
		MaxExpiry:           cfg.Storage.GrantExpiry,
	}).Defaults(); err != nil {
		log.Error("object store limits are inconsistent; no avatar can be uploaded",
			"error", err)
	} else {
		d.blobs = seaweedfs.New(seaweedfs.Config{
			Endpoint:       cfg.Storage.Endpoint,
			Region:         cfg.Storage.Region,
			Bucket:         cfg.Storage.Bucket,
			AccessKey:      cfg.Storage.AccessKey,
			SecretKey:      cfg.Storage.SecretKey.Expose(),
			PublicEndpoint: cfg.Storage.PublicEndpoint,
			Limits:         limits,
		}, d.clock)
	}

	// Notification after identity, for the same ordering reason: it needs the
	// pool, the store and the clock, and it is a client surface over projections
	// rather than something identity depends on.
	if svc, err := d.buildNotification(cfg, log); err != nil {
		log.Error("the notification service is NOT constructed; the feed, push "+
			"registration and every per-person channel preference answer "+
			"'unimplemented' for the lifetime of this process", "error", err)
	} else {
		d.notification = svc
	}

	// Profile last: it needs the pool, the store, the vault, the clock AND the
	// object store, so it is built after every one of them.
	if svc, err := d.buildProfile(cfg, log); err != nil {
		log.Error("the profile service is NOT constructed; the display name, locale, "+
			"timezone and avatar answer 'unimplemented' for the lifetime of this process",
			"error", err)
	} else {
		d.profile = svc
	}

	if svc, err := d.buildOrganization(log); err != nil {
		log.Error("the organization service is NOT constructed; no tenant can be created "+
			"for the lifetime of this process", "error", err)
	} else {
		d.organization = svc
	}

	if svc, err := d.buildBilling(cfg); err != nil {
		log.Error("the billing service is NOT constructed; the Customer Portal is the only "+
			"way a card is ever added, so every trial has exactly one outcome and no "+
			"suspended tenant can recover", "error", err)
	} else {
		d.billing = svc
	}

	if svc, err := d.buildWorkspace(log); err != nil {
		log.Error("the workspace service is NOT constructed; no workspace can be created "+
			"for the lifetime of this process", "error", err)
	} else {
		d.workspace = svc
	}

	return d, func() {
		for _, c := range d.closes {
			c()
		}
	}
}

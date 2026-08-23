package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/adapter/inapp"
	kurrentadapter "github.com/chronos/chronos-go/internal/adapter/kurrentdb"
	"github.com/chronos/chronos-go/internal/adapter/mailrender"
	"github.com/chronos/chronos-go/internal/adapter/openbao"
	"github.com/chronos/chronos-go/internal/adapter/piivault"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	smtpadapter "github.com/chronos/chronos-go/internal/adapter/smtp"
	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
	valkeyadapter "github.com/chronos/chronos-go/internal/adapter/valkey"
	"github.com/chronos/chronos-go/internal/adapter/webpush"
	complianceapp "github.com/chronos/chronos-go/internal/modules/compliance/app"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	notificationpg "github.com/chronos/chronos-go/internal/modules/notification/adapter/postgres"
	workspaceapp "github.com/chronos/chronos-go/internal/modules/workspace/app"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/config"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/mail"
	"github.com/chronos/chronos-go/internal/platform/notify"
	"github.com/chronos/chronos-go/internal/platform/obs"
	"github.com/chronos/chronos-go/internal/platform/reactor"
	"github.com/chronos/chronos-go/internal/server/health"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valkey-io/valkey-go"
)

// newCodec builds the event codec with every stored type this binary reads.
func newCodec() *eventcodec.JSON {
	upcasters := eventsourcing.NewUpcasterRegistry()
	codec := eventcodec.NewJSON(upcasters)
	registerEvents(codec)
	return codec
}

// dependencies is the composition root.
//
// As everywhere else, nothing here fails because a dependency is unreachable
// (ADR-010).
//
// Note what is ABSENT: there is no BatchTX and no projection machinery. A
// reactor does not write read models, and giving it the tools to would invite
// exactly the mixing ADR-019 exists to prevent.
type dependencies struct {
	// cfg is the resolved configuration, held so a reactor built later can read
	// the settings it needs without a second parse.
	cfg *config.Config

	pool    *pgxpool.Pool
	store   *kurrentadapter.Store
	codec   *eventcodec.JSON
	dedup   *pgadapter.Dedup
	probes  []health.Probe
	status  *statuses
	metrics *obs.Metrics

	// notify is the notification system. Mail is one channel under it; the
	// in-app feed, web push and realtime plug in the same way (ADR-026).
	notify *notify.Dispatcher
	vault  notify.Vault

	// piiVault is the concrete vault, kept beside the narrow `vault` above
	// because erasure destroys a subject key and the notify view cannot express
	// that — deliberately.
	piiVault *piivault.Vault
	renderer *mailrender.Renderer
	operator string

	// keyCache short-circuits the PII vault's key path. Held here, not just
	// handed to the vault, because it owns two background duties the composition
	// root has to start: listening for erasures published by other replicas, and
	// zeroing keys as they expire.
	keyCache   *piivault.KeyCache
	cacheTTL   time.Duration
	cacheEvery time.Duration
	// cacheRetry is how long to wait before re-subscribing after the
	// invalidation stream drops. A field rather than a constant so a test can
	// observe the retry without spending the real interval waiting for it.
	cacheRetry time.Duration

	// dedup retention. reactor_processed gains a row per event per reactor and
	// nothing removed them: Forget was written, documented, indexed for — and
	// called by no binary.
	dedupDays  int
	dedupEvery time.Duration

	// temporal is durable work (ADR-017): effects that span several steps, need
	// timers, or must survive this process dying halfway. Nil when
	// TEMPORAL_ENABLED is false — a binary that dials a service it never uses
	// reports a DOWN probe for a dependency nothing needs.
	//
	// worker is the half that RUNS workflows. Holding it here rather than in a
	// local is what lets a composition-root test assert the binary registered
	// them: a workflow nobody registered is queued where nothing listens, the
	// caller is told the run started, and the work never happens.
	temporal       *temporaladapter.Client
	temporalWorker *temporaladapter.Worker

	// temporalWorkflows is what the worker was actually registered with, in the
	// order it was registered. Recorded rather than recomputed so a
	// composition-root test can assert the set WITHOUT starting a worker or
	// reaching Temporal — a registration that exists only in a log line at
	// startup is a registration nothing can check.
	temporalWorkflows []string

	// reservations releases email reservations whose unverified lease has run
	// out. It is a security control, not a retention job: without it, anyone can
	// register with an address they do not control and hold it forever, and the
	// real owner can never register (ADR-044, IDENTITY-SLICE-1).
	//
	// Built whether or not Temporal is enabled, so that the gap is visible as
	// "the sweep could not be constructed" rather than as nothing at all.
	reservations *app.ReservationSweep

	// verification mints the emailed proof-of-control link. It is held here, and
	// built whether or not durable work is enabled, because its absence is
	// otherwise invisible: registration appends EmailVerificationRequested and
	// drops the plaintext, so a worker that cannot mint simply never sends the
	// mail — every account stays Pending, every address stays claimed, and
	// nothing anywhere reports it (ADR-002, identity.md §7).
	verification *app.VerificationIssuer

	// invitations mints the emailed invitation link, for the same reason and
	// with the same failure mode: issuing appends InvitationIssued and mints
	// nothing, so a worker that cannot mint spends a seat, leaves the invitation
	// Pending for seven days, and tells nobody it exists.
	invitations *workspaceapp.InvitationIssuer

	// invitationSweep is the RECONCILIATION half of invitation expiry. The
	// per-invitation workflow makes it timely; this makes it certain — a
	// workflow that was never started leaves a seat held forever, and nothing
	// else in the system would ever notice.
	invitationSweep *workspaceapp.InvitationSweep

	// retention deletes identity rows that can no longer affect a decision:
	// spent TOTP steps, expired token digests, the secret half of dead sessions,
	// and two projections past their horizon. Housekeeping rather than a security
	// control — nothing is waiting on it — which is why it runs daily where the
	// sweep above runs every fifteen minutes.
	//
	// Built whether or not Temporal is enabled, for the same reason: the gap must
	// be visible as "retention could not be constructed" rather than as nothing at
	// all. Nothing else in this system reports a table that stopped being swept.
	retention *app.Retention

	// reseal carries password verifiers and TOTP shared secrets from an old
	// sealing key version onto the current one, without ever needing the
	// plaintext. It is what makes a key rotation completable at all: nothing else
	// re-seals anything, so without it the count of rows at the old version never
	// falls and the only safe action is to keep every retired key alive forever
	// (identity.md §4, ADR-028).
	//
	// Built whether or not Temporal is enabled, like the two above, so the gap is
	// visible as "re-sealing could not be constructed" rather than as nothing at
	// all. Nothing else in this system reports a rotation that cannot finish.
	reseal *app.KeyReseal

	// accountErasure is identity's half: sessions, identifier reservations and
	// the account's own terminal event. erasure is compliance's orchestration
	// around it — confirm, destroy the key, then call the half above.
	//
	// Two fields rather than one because they belong to different modules and
	// the import contract keeps them apart: compliance may not load identity's
	// aggregates, so the composition root is where the two meet.
	accountErasure *app.Erasure
	erasure        *complianceapp.Erasure

	closes []func()
}

func newDependencies(cfg *config.Config, log *slog.Logger, codec *eventcodec.JSON) (*dependencies, func()) {
	d := &dependencies{
		cfg:    cfg,
		status: newStatuses(), codec: codec, metrics: obs.New(),
		dedupDays: cfg.Reactor.DedupRetentionDays, dedupEvery: cfg.Reactor.DedupSweepEvery,
	}

	if pool, err := pgadapter.NewPool(context.Background(), cfg.Postgres.AppDSN(), cfg.Postgres.MaxConns); err != nil {
		log.Error("postgres pool unavailable", "error", err)
		d.probes = append(d.probes, pgadapter.Probe{})
	} else {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := pgadapter.VerifyNotPrivileged(ctx, pool); err != nil {
				log.Error("DATABASE PRIVILEGE CHECK FAILED", "error", err)
			}
		}()
		d.pool = pool
		d.dedup = pgadapter.NewDedup(pgadapter.New(pool))
		d.probes = append(d.probes, pgadapter.Probe{Pool: pool})
		d.closes = append(d.closes, pool.Close)
	}

	if kc, err := kurrentadapter.Dial(cfg.KurrentDB.ConnectionString); err != nil {
		log.Error("kurrentdb client unavailable", "error", err)
		d.probes = append(d.probes, kurrentadapter.Probe{})
	} else {
		d.store = kurrentadapter.NewStore(kc, d.codec)
		d.probes = append(d.probes, kurrentadapter.Probe{Client: kc})
		d.closes = append(d.closes, func() { _ = kc.Close() })
	}

	// ---- notifications --------------------------------------------------
	//
	// Templates are parsed here, at startup. A template that will not compile
	// is a wiring bug, and finding it now beats finding it the first time
	// somebody resets a password.
	d.renderer = mailrender.New(mailrender.Embedded{}, mailrender.Config{
		From:           mail.Address{Name: cfg.Mail.FromName, Email: cfg.Mail.FromAddress},
		ReplyTo:        mail.Address{Email: cfg.Mail.ReplyTo},
		BaseURL:        cfg.Mail.BaseURL,
		FallbackLocale: cfg.Mail.DefaultLocale,
	})
	if err := d.renderer.Load(context.Background()); err != nil {
		// Deliberately fatal, unlike an unreachable dependency (ADR-010): this
		// is our own code failing to compile, not infrastructure being down.
		log.Error("email templates failed to load", "error", err)
	} else {
		log.Info("email templates loaded", "templates", len(d.renderer.Templates()))
	}

	mailer := smtpadapter.New(smtpadapter.Config{
		Host:     cfg.Mail.Host,
		Port:     cfg.Mail.Port,
		Username: cfg.Mail.Username,
		Password: cfg.Mail.Password.Expose(),
		StartTLS: cfg.Mail.StartTLS,
		Domain:   cfg.Mail.FromAddress,
	})
	d.operator = cfg.Mail.OperatorAddress

	// ---- Valkey: the invalidation bus, not a store for anything secret ----
	//
	// Degradable. Losing it costs the key cache, which costs latency. What it
	// must never cost is correctness, which is why the cache it enables holds no
	// personal data and no key material — only this connection carries the
	// SubjectIDs that say "forget that key" (see internal/adapter/piivault).
	var bus *valkeyadapter.Bus
	if vk, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: cfg.Valkey.Addr,
		Password:    cfg.Valkey.Password.Expose(),
		// Client-side caching is Valkey's own invalidation-tracked cache. Off
		// here: what this connection is for is publishing invalidations, and a
		// second caching layer with its own coherence rules underneath a
		// security-critical one is a source of surprises, not of speed.
		DisableCache: true,
	}); err != nil {
		log.Error("valkey client unavailable; subject key caching is disabled", "error", err)
		d.probes = append(d.probes, valkeyadapter.Probe{})
	} else {
		bus = valkeyadapter.NewBus(vk)
		d.probes = append(d.probes, valkeyadapter.Probe{Client: vk})
		d.closes = append(d.closes, vk.Close)
	}

	// The PII vault: the single point at which a pseudonym becomes a real
	// address. Everything upstream carries only a SubjectID (ADR-002).
	if d.pool != nil {
		if bao, err := openbao.Dial(cfg.OpenBao.Address, cfg.OpenBao.Token.Expose()); err != nil {
			log.Error("openbao client unavailable; tenant notifications cannot resolve addresses",
				"error", err)
		} else {
			var vaultOpts []piivault.Option
			// No bus, no cache. Deliberately not a fallback to a TTL-only cache:
			// that is silently wrong as soon as a second replica exists, and this
			// binary is designed to be run many times over (see the package
			// comment on competing consumers).
			if bus != nil {
				kc, err := piivault.NewKeyCache(piivault.KeyCacheOptions{
					TTL:      cfg.Valkey.KeyCacheTTL,
					Capacity: cfg.Valkey.KeyCacheCapacity,
					Bus:      bus,
					Observer: d.metrics.Caches(),
					Log:      log,
				})
				if err != nil {
					log.Error("subject key cache unavailable; every resolve will unwrap at OpenBao",
						"error", err)
				} else {
					d.keyCache = kc
					d.cacheTTL, d.cacheEvery = cfg.Valkey.KeyCacheTTL, cfg.Valkey.KeyCacheSweep
					vaultOpts = append(vaultOpts, piivault.WithKeyCache(kc))
				}
			}
			// Kept BOTH ways, like cmd/api does. `vault` is the narrow view the
			// notification path uses to resolve an address; `piiVault` is the
			// concrete one, and the erasure needs it because destroying a
			// subject key is not something the notify view can express — nor
			// should it be.
			v := piivault.New(pgadapter.New(d.pool),
				openbao.NewKeyRing(bao, cfg.OpenBao.KEKName), vaultOpts...)
			d.piiVault = v
			d.vault = piivault.NewNotifyVault(v, cfg.Mail.DefaultLocale, "UTC")
			d.probes = append(d.probes, openbao.Probe{Client: bao})
		}
	}

	// The notification read model: per-user channel toggles, in-app read state
	// for arbitration, and the live push endpoints.
	//
	// Without these the dispatcher silently permits everything — a nil Prefs
	// means no toggle is ever consulted, and a nil ReadState means an Activity
	// email is never suppressed by an in-app read.
	var reader *notificationpg.Reader
	if d.pool != nil && d.store != nil {
		reader = notificationpg.NewReader(
			pgadapter.New(d.pool),
			func(ctx context.Context, q db.Querier, orgID string) error {
				return pgadapter.SetTenantScope(ctx, q, db.Tenant{OrgID: orgID})
			},
			d.store, clock.System{})
	}

	transports := []notify.Transport{
		mail.NewTransport(d.renderer, mailer, clock.System{}, d.metrics.Mail()),
	}
	if d.store != nil {
		// In-app delivery APPENDS an event; the feed projection writes the row
		// and announces it to the browser (ADR-019).
		transports = append(transports, inapp.New(d.store, clock.System{}, nil))
	}
	if reader != nil {
		transports = append(transports, webpush.New(reader, pushTitles{}, webpush.Config{
			VAPID: webpush.VAPID{
				PublicKey:  cfg.Push.VAPIDPublicKey,
				PrivateKey: cfg.Push.VAPIDPrivateKey.Expose(),
				Subject:    cfg.Push.VAPIDSubject,
			},
			BaseURL: cfg.Mail.BaseURL,
		}))
	}

	d.notify = notify.NewDispatcher(notify.Deps{
		// Nil only when Postgres or OpenBao could not be reached at startup.
		// The dispatcher substitutes a stand-in that FAILS rather than panics,
		// so the gap is visible instead of crashing on the first notification.
		Vault:      d.vault,
		Transports: transports,
		// Nil until the read model is reachable. Nil is PERMISSIVE for both —
		// which is the safe direction (a security alert is never suppressed by
		// an unreadable preference) but means user toggles do nothing, so the
		// wiring is asserted by a test rather than trusted.
		Prefs:     prefsOrNil(reader),
		ReadState: readStateOrNil(reader),
		Log:       log,
		Observer:  d.metrics.Notifications(),
	})

	// The lapsed email-reservation sweep. Constructed before the worker, because
	// the worker registers it: a sweep that exists but is registered nowhere is
	// exactly the failure this repository has already shipped three times, and
	// for a security control it is invisible until somebody cannot register with
	// an address that is theirs.
	if sweep, err := newReservationSweep(d, log); err != nil {
		log.Error("the lapsed email-reservation sweep is NOT wired; an abandoned "+
			"registration holds its address permanently and its owner can never register",
			"error", err)
	} else {
		d.reservations = sweep
	}

	// The verification-mail issuer. Constructed here, before the reactors are
	// assembled, so that a worker which cannot mint says so once at startup
	// instead of running a reactor that consumes the event and acks it having
	// done nothing.
	if issuer, err := newVerificationIssuer(d); err != nil {
		log.Error("verification mail is NOT wired; every registration will claim its "+
			"address and mail nobody, so the account can never be verified and the "+
			"address can never be registered again", "error", err)
	} else {
		d.verification = issuer
	}

	// The invitation-link issuer, held for the reason above it: a worker that
	// cannot mint one must say so once at startup rather than run a reactor that
	// consumes InvitationIssued and acks it having done nothing.
	if issuer, err := newInvitationIssuer(d); err != nil {
		log.Error("invitation mail is NOT wired; every invitation will spend a seat and "+
			"mail nobody, so it sits pending until it expires and the person it was for "+
			"never learns it existed", "error", err)
	} else {
		d.invitations = issuer
	}

	// The invitation reconciliation. Constructed whether or not durable work is
	// enabled, so a deployment without Temporal logs why seats are not coming
	// back rather than logging nothing.
	if sweep, err := newInvitationSweep(d, log); err != nil {
		log.Error("the invitation sweep is NOT wired; an invitation whose per-invitation "+
			"workflow never started holds its seat forever, and no other part of this "+
			"system reports it", "error", err)
	} else {
		d.invitationSweep = sweep
	}

	// Identity retention. Constructed before the worker for the same reason the
	// sweep is — the worker registers it — and constructed whether or not durable
	// work is enabled, so that a deployment without Temporal logs why retention is
	// not running instead of logging nothing.
	if retention, err := newIdentityRetention(d, log); err != nil {
		log.Error("identity retention is NOT wired; spent TOTP steps, expired token digests "+
			"and the secret half of dead sessions are retained for the lifetime of the "+
			"deployment", "error", err)
	} else {
		d.retention = retention
	}

	// Erasure, in two halves that meet only here: identity's, which knows what an
	// account holds, and compliance's, which decides when and destroys the key.
	//
	// Loud rather than fatal like everything else in this binary (ADR-010), and
	// the wording is the strongest available because nothing else reports it: a
	// person asks to be forgotten, is told a date, and stays in the database
	// after it, while every metric stays green.
	if accounts, err := newAccountErasure(d); err != nil {
		log.Error("identity's erasure half is NOT wired; every deletion request is recorded "+
			"and never executed, and the account keeps working indefinitely", "error", err)
	} else {
		d.accountErasure = accounts
		if erasure, err := newErasure(d, log); err != nil {
			log.Error("the erasure orchestration is NOT wired; deletion requests are "+
				"recorded and never executed", "error", err)
		} else {
			d.erasure = erasure
		}
	}

	// Credential re-sealing. Constructed before the worker for the same reason as
	// the two above, and it is the one of the three whose absence produces no
	// symptom anywhere in the system: an operator simply reads a count that never
	// falls, and either keeps a key they meant to retire or destroys it anyway.
	if reseal, err := newCredentialReseal(d, cfg, log); err != nil {
		log.Error("credential re-sealing is NOT wired; a password pepper or TOTP sealing key "+
			"rotation can never be completed, and every retired key must be kept alive for "+
			"the lifetime of the deployment", "error", err)
	} else {
		d.reseal = reseal
	}

	// Durable work. Built LAST because its activities need the dispatcher above:
	// the reference workflow's whole job is to send a notification, and one wired
	// without a dispatcher would fail every run after a full hour of retries.
	d.startTemporal(cfg, log)

	return d, func() {
		for _, c := range d.closes {
			c()
		}
	}
}

// startTemporal builds the client, registers the workflows and starts polling.
//
// Every failure here is LOUD but not fatal, as elsewhere in this binary
// (ADR-010): a worker that cannot reach Temporal still runs every reactor, and
// the probe reports which half is down. What must never happen quietly is a
// STARTER without a worker — durable work would be accepted and never run — so
// the client is only published once its worker is polling.
func (d *dependencies) startTemporal(cfg *config.Config, log *slog.Logger) {
	if !cfg.Temporal.Enabled {
		log.Info("durable work is disabled; no workflows will run", "reason", "TEMPORAL_ENABLED=false")
		// Registered even here — especially here. With durable work off, the
		// lapsed-reservation sweep does not run at all, and mail is the only
		// workflow with an inline fallback. A probe carrying a nil client reports
		// exactly that, so the state appears on the status surface instead of
		// being a line in a startup log nobody reads again.
		//
		// The TEMPORAL PROBE ITSELF belongs in this list and was missing from it.
		// Without it, a deployment with TEMPORAL_ENABLED=false reported nothing
		// about Temporal at all — the three schedule probes below said their
		// schedules were absent, and the dependency they all depend on was not
		// on the surface. Erasure made that indefensible: it is a legal
		// obligation with a statutory clock and no inline fallback, so "durable
		// work is off" has to be visible to whoever is looking at status, not
		// only to whoever read the startup log.
		d.probes = append(d.probes,
			temporaladapter.Probe{},
			temporaladapter.SweepReservationsProbe(nil),
			temporaladapter.PurgeRetentionProbe(nil),
			temporaladapter.ResealCredentialKeysProbe(nil))
		return
	}

	client, err := temporaladapter.Dial(temporaladapter.Config{
		HostPort:  cfg.Temporal.HostPort,
		Namespace: cfg.Temporal.Namespace,
		Queue:     cfg.Temporal.Queue,
	})
	if err != nil {
		log.Error("temporal client unavailable; NO durable work can run", "error", err)
		d.probes = append(d.probes, temporaladapter.Probe{})
		return
	}

	w, names, err := d.newTemporalWorker(client)
	if err != nil {
		log.Error("temporal worker could not be built; durable work would be accepted "+
			"and never run", "error", err)
		client.Close()
		d.probes = append(d.probes, temporaladapter.Probe{})
		return
	}
	d.temporalWorkflows = names
	if err := w.Start(); err != nil {
		log.Error("temporal worker did not start", "error", err)
		client.Close()
		d.probes = append(d.probes, temporaladapter.Probe{})
		return
	}

	d.temporal, d.temporalWorker = client, w
	d.probes = append(d.probes, temporaladapter.Probe{Client: client})
	d.closes = append(d.closes, w.Stop, client.Close)
	log.Info("durable work enabled",
		"queue", cfg.Temporal.Queue, "namespace", cfg.Temporal.Namespace,
		"workflows", d.temporalWorkflows)

	d.scheduleSweep(log)
	d.scheduleRetention(log)
	d.scheduleReseal(log)
	d.scheduleInvitationSweep(log)

	// After scheduling, not before: a probe asks the server whether the schedule
	// exists, and asking before the attempt would report a state this process was
	// about to change. Registered whether or not the create succeeded — a failed
	// create is the case the probes are for.
	d.probes = append(d.probes,
		temporaladapter.SweepReservationsProbe(d.temporal),
		temporaladapter.PurgeRetentionProbe(d.temporal),
		temporaladapter.ResealCredentialKeysProbe(d.temporal),
		temporaladapter.SweepInvitationsProbe(d.temporal))
}

// newTemporalWorker builds the worker and registers EVERYTHING this binary can
// run, returning the workflow names it now answers to.
//
// Separated from startTemporal so a composition-root test can drive the exact
// production registration path without starting a worker or reaching Temporal.
// Registration itself performs no I/O; Start is what dials, and Start is what
// stays out of here.
//
// A failure to register any half is FATAL to the worker rather than degraded:
// a worker that polls the queue while answering to only some of its names looks
// healthy, and the tasks it cannot serve fail one at a time, forever.
func (d *dependencies) newTemporalWorker(
	client *temporaladapter.Client,
) (*temporaladapter.Worker, []string, error) {
	notifications, err := temporaladapter.NewNotificationActivities(d.notify)
	if err != nil {
		return nil, nil, fmt.Errorf("notification activities: %w", err)
	}

	w, err := temporaladapter.NewWorker(temporaladapter.WorkerDeps{
		Client: client, Notifications: notifications,
	})
	if err != nil {
		return nil, nil, err
	}
	names := w.Registered()

	// Checked here rather than left to the activity set's own nil check: a
	// sweepAdapter wrapping a nil use case is a NON-nil interface, so it would
	// pass that check and panic on the first run instead — the typed-nil trap
	// prefsOrNil exists for, one layer up.
	if d.reservations == nil {
		return nil, nil, errors.New("the lapsed email-reservation sweep was not constructed; " +
			"registering it would queue runs that panic")
	}
	sweep, err := temporaladapter.NewReservationActivities(sweepAdapter{sweep: d.reservations})
	if err != nil {
		return nil, nil, fmt.Errorf("reservation sweep activities: %w", err)
	}
	swept, err := w.RegisterReservationSweep(sweep)
	if err != nil {
		return nil, nil, fmt.Errorf("registering the reservation sweep: %w", err)
	}
	names = append(names, swept...)

	// Identity retention, checked the same way and for the same typed-nil reason.
	if d.retention == nil {
		return nil, nil, errors.New("identity retention was not constructed; registering it " +
			"would queue runs that panic")
	}
	retention, err := temporaladapter.NewRetentionActivities(retentionAdapter{retention: d.retention})
	if err != nil {
		return nil, nil, fmt.Errorf("identity retention activities: %w", err)
	}
	retained, err := w.RegisterIdentityRetention(retention)
	if err != nil {
		return nil, nil, fmt.Errorf("registering identity retention: %w", err)
	}
	names = append(names, retained...)

	// Credential re-sealing, checked the same way and for the same typed-nil
	// reason: a resealAdapter wrapping a nil use case is a NON-nil interface, so
	// NewResealActivities' own nil check would pass and the failure would move to
	// a panic on the first scheduled run — hourly, forever, in a job whose whole
	// output is the input to an irreversible decision about destroying a key.
	if d.reseal == nil {
		return nil, nil, errors.New("credential re-sealing was not constructed; registering " +
			"it would queue runs that panic")
	}
	reseal, err := temporaladapter.NewResealActivities(resealAdapter{reseal: d.reseal})
	if err != nil {
		return nil, nil, fmt.Errorf("credential re-sealing activities: %w", err)
	}
	resealed, err := w.RegisterCredentialReseal(reseal)
	if err != nil {
		return nil, nil, fmt.Errorf("registering credential re-sealing: %w", err)
	}
	names = append(names, resealed...)

	// The invitation sweep, checked the same way and for the same typed-nil
	// reason: an invitationSweepAdapter wrapping a nil use case is a NON-nil
	// interface, so NewInvitationActivities' own nil check would pass and the
	// failure would move to a panic on the first scheduled run.
	if d.invitationSweep == nil {
		return nil, nil, errors.New("the invitation sweep was not constructed; registering " +
			"it would queue runs that panic")
	}
	invitations, err := temporaladapter.NewInvitationActivities(
		invitationSweepAdapter{sweep: d.invitationSweep})
	if err != nil {
		return nil, nil, fmt.Errorf("invitation sweep activities: %w", err)
	}
	swept2, err := w.RegisterInvitationSweep(invitations)
	if err != nil {
		return nil, nil, fmt.Errorf("registering the invitation sweep: %w", err)
	}
	names = append(names, swept2...)

	// The per-invitation timer. It is what makes expiry TIMELY and reminders
	// possible at all; the sweep above is what makes expiry certain.
	ops, err := newInvitationLifecycleOps(d)
	if err != nil {
		return nil, nil, fmt.Errorf("invitation lifecycle: %w", err)
	}
	lifecycle, err := temporaladapter.NewInvitationLifecycleActivities(ops)
	if err != nil {
		return nil, nil, fmt.Errorf("invitation lifecycle activities: %w", err)
	}
	lifecycleNames, err := w.RegisterInvitationLifecycle(lifecycle)
	if err != nil {
		return nil, nil, fmt.Errorf("registering the invitation lifecycle: %w", err)
	}
	names = append(names, lifecycleNames...)

	// The erasure clock. Unlike everything above it, an unregistered workflow
	// here is not a delayed sweep or a missed reminder: it is a person who asked
	// to be forgotten, was told a date, and is still in the database after it.
	erasureNames, err := d.registerErasure(w)
	if err != nil {
		return nil, nil, err
	}
	return w, append(names, erasureNames...), nil
}

// registerErasure wires the grace-period workflow and its activities.
func (d *dependencies) registerErasure(w *temporaladapter.Worker) ([]string, error) {
	if d.erasure == nil {
		return nil, errors.New("the erasure executor was not constructed; registering the " +
			"workflow would queue runs that panic, and not registering it leaves every " +
			"deletion request unexecuted")
	}
	if d.accountErasure == nil {
		return nil, errors.New("identity's erasure half was not constructed")
	}

	state, err := temporaladapter.NewErasureState(erasureStateAdapter{accounts: d.accountErasure})
	if err != nil {
		return nil, fmt.Errorf("erasure state activity: %w", err)
	}
	execute, err := temporaladapter.NewExecuteErasure(d.erasure)
	if err != nil {
		return nil, fmt.Errorf("erasure activity: %w", err)
	}
	return w.RegisterErasure(state, execute)
}

// erasureStateAdapter narrows identity's use case to the activity's port.
//
// It also converts between two structurally identical snapshot types, which is
// the cost of the import contract: a module may not import an adapter, and an
// adapter may not import a module's internals, so the shape is declared twice
// and matched here — in one place, where a mismatch is a compile error.
type erasureStateAdapter struct{ accounts *app.Erasure }

func (a erasureStateAdapter) ErasureState(
	ctx context.Context, subjectID string,
) (temporaladapter.ErasureSnapshot, error) {
	s, err := a.accounts.State(ctx, subjectID)
	if err != nil {
		return temporaladapter.ErasureSnapshot{}, err
	}
	return temporaladapter.ErasureSnapshot{
		Exists:       s.Exists,
		Requested:    s.Requested,
		Erased:       s.Erased,
		ScheduledFor: s.ScheduledFor,
	}, nil
}

// scheduleSweep makes the lapsed-reservation sweep recur.
//
// Loud but not fatal, like every other dependency failure in this binary
// (ADR-010) — except that this one deserves the strongest wording available,
// because nothing else in the system reports it. A registered workflow that no
// schedule ever starts is indistinguishable from a working one: the worker is
// healthy, the queue is empty, every metric is green, and email addresses stay
// held by people who never proved they own them.
func (d *dependencies) scheduleSweep(log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), scheduleTimeout)
	defer cancel()

	created, err := temporaladapter.EnsureSweepSchedule(ctx, d.temporal,
		temporaladapter.SweepReservationsInput{}, temporaladapter.DefaultSweepInterval)
	switch {
	case err != nil:
		log.Error("the lapsed email-reservation sweep is NOT scheduled; lapsed claims "+
			"will never be released and nothing else will report it",
			"schedule", temporaladapter.SweepReservationsScheduleID, "error", err)
	case created:
		log.Info("lapsed email-reservation sweep scheduled",
			"schedule", temporaladapter.SweepReservationsScheduleID,
			"every", temporaladapter.DefaultSweepInterval)
	default:
		log.Info("lapsed email-reservation sweep already scheduled",
			"schedule", temporaladapter.SweepReservationsScheduleID)
	}
}

// scheduleInvitationSweep makes the invitation reconciliation recur.
//
// Loud but not fatal, like every other dependency failure here (ADR-010). A
// registered workflow that no schedule ever starts is indistinguishable from a
// working one: the worker is healthy, the queue is empty, every metric is green,
// and organizations keep paying for seats held by invitations that ran out weeks
// ago.
func (d *dependencies) scheduleInvitationSweep(log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), scheduleTimeout)
	defer cancel()

	created, err := temporaladapter.EnsureInvitationSweepSchedule(ctx, d.temporal,
		temporaladapter.SweepInvitationsInput{}, temporaladapter.DefaultInvitationSweepInterval)
	switch {
	case err != nil:
		log.Error("the invitation sweep is NOT scheduled; lapsed invitations will never be "+
			"expired and nothing else will report it",
			"schedule", temporaladapter.SweepInvitationsScheduleID, "error", err)
	case created:
		log.Info("invitation sweep scheduled",
			"schedule", temporaladapter.SweepInvitationsScheduleID,
			"every", temporaladapter.DefaultInvitationSweepInterval)
	default:
		log.Info("invitation sweep already scheduled",
			"schedule", temporaladapter.SweepInvitationsScheduleID)
	}
}

// scheduleTimeout bounds the one blocking call in startup. The client is lazy,
// so this is the only place a dead Temporal could stall the boot.
const scheduleTimeout = 10 * time.Second

// prefsOrNil and readStateOrNil avoid the typed-nil trap: a nil *Reader inside a
// non-nil interface passes the dispatcher's nil check and panics on first use.
func prefsOrNil(r *notificationpg.Reader) notify.Preferences {
	if r == nil {
		return nil
	}
	return r
}

func readStateOrNil(r *notificationpg.Reader) notify.ReadState {
	if r == nil {
		return nil
	}
	return r
}

// Notify exposes the dispatcher to reactors.
func (d *dependencies) Notify() *notify.Dispatcher { return d.notify }

// startKeyCache runs the two background duties a subject key cache cannot work
// without.
//
// Watch applies erasures published by other replicas, and returns when the
// subscription drops — having purged, because a subscriber that missed messages
// cannot know which. It is restarted with a delay rather than a tight loop: the
// reason it dropped is usually that Valkey is down, and hammering it changes
// nothing except the log volume.
//
// SweepEvery zeroes expired keys instead of waiting for someone to ask for that
// subject again. Without it, "expired" means invisible, not gone, and destroyed
// key material stays resident in the process indefinitely.
func (d *dependencies) startKeyCache(ctx context.Context, log *slog.Logger) {
	if d.keyCache == nil {
		log.Warn("subject key cache is not wired; every notification will unwrap its " +
			"subject key at OpenBao")
		return
	}
	retry := d.cacheRetry
	if retry <= 0 {
		retry = defaultCacheRetry
	}
	go d.keyCache.SweepEvery(ctx, d.cacheEvery)
	go func() {
		for ctx.Err() == nil {
			if err := d.keyCache.Watch(ctx); err != nil && ctx.Err() == nil {
				log.Error("key-invalidation subscription dropped; cached keys purged, retrying",
					"error", err, "retry_in", retry)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(retry):
			}
		}
	}()
	log.Info("subject key cache active", "ttl", d.cacheTTL, "sweep", d.cacheEvery)
}

func (d *dependencies) deps(log *slog.Logger) reactor.Deps {
	return reactor.Deps{
		Subscriber: d.store,
		Codec:      d.codec,
		Dedup:      d.dedup,
		Log:        log,
		Metrics:    d.metrics.Reactors(),
		Clock:      clock.System{},
	}
}

// defaultCacheRetry paces reconnection to the invalidation stream. The usual
// reason it dropped is that Valkey is down, and retrying faster changes nothing
// except the log volume.
const defaultCacheRetry = 5 * time.Second

// statuses records reactors that stopped, so readiness can report a worker that
// is running but doing nothing.
type statuses struct {
	mu     sync.RWMutex
	failed map[string]string
}

func newStatuses() *statuses { return &statuses{failed: make(map[string]string)} }

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

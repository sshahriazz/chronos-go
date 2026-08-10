package main

import (
	"context"
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
	valkeyadapter "github.com/chronos/chronos-go/internal/adapter/valkey"
	"github.com/chronos/chronos-go/internal/adapter/webpush"
	notificationpg "github.com/chronos/chronos-go/internal/modules/notification/adapter/postgres"
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
	codec := eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry())
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
	pool    *pgxpool.Pool
	store   *kurrentadapter.Store
	codec   *eventcodec.JSON
	dedup   *pgadapter.Dedup
	probes  []health.Probe
	status  *statuses
	metrics *obs.Metrics

	// notify is the notification system. Mail is one channel under it; the
	// in-app feed, web push and realtime plug in the same way (ADR-026).
	notify   *notify.Dispatcher
	vault    notify.Vault
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

	closes []func()
}

func newDependencies(cfg *config.Config, log *slog.Logger, codec *eventcodec.JSON) (*dependencies, func()) {
	d := &dependencies{
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
			d.vault = piivault.NewNotifyVault(
				piivault.New(pgadapter.New(d.pool),
					openbao.NewKeyRing(bao, cfg.OpenBao.KEKName), vaultOpts...),
				cfg.Mail.DefaultLocale, "UTC")
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

	return d, func() {
		for _, c := range d.closes {
			c()
		}
	}
}

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

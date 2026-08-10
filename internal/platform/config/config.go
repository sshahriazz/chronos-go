// Package config loads and validates configuration once, at startup (ADR-008).
//
// Three rules:
//
//   - Invalid configuration is a startup failure with a precise message, never a
//     zero value discovered at request time.
//   - Config is parsed once and injected. Nothing calls os.Getenv at runtime.
//   - Secrets never appear in String, Error or log output.
//
// APP_TIMEZONE exists for operator convenience only. Storage is always UTC —
// the Clock returns UTC and timestamps are timestamptz. That separation is
// deliberate: mixed timezones in a billing period boundary is a bug that only
// appears across a DST change, in production.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

// Environment is the deployment environment. Several safety rules key off it.
type Environment string

const (
	Local      Environment = "local"
	Staging    Environment = "staging"
	Production Environment = "production"
)

func (e Environment) IsLocal() bool { return e == Local }

// Secret wraps a sensitive value so it cannot be logged by accident.
// It renders as "[REDACTED]" through fmt, %v, %s and String.
type Secret string

func (Secret) String() string { return "[REDACTED]" }

// GoString covers %#v, which otherwise prints the underlying value.
func (Secret) GoString() string { return `"[REDACTED]"` }

// Expose returns the real value. The name is deliberately awkward: every call
// site should be visible in review.
func (s Secret) Expose() string { return string(s) }

func (s Secret) IsZero() bool { return s == "" }

type Config struct {
	Env      Environment `env:"APP_ENV"      envDefault:"local"`
	Timezone string      `env:"APP_TIMEZONE" envDefault:"UTC"`

	KurrentDB KurrentDBConfig
	Postgres  PostgresConfig
	OpenFGA   OpenFGAConfig
	OpenBao   OpenBaoConfig
	Mail      MailConfig
	Storage   StorageConfig
	Realtime  RealtimeConfig
	Push      PushConfig
	Valkey    ValkeyConfig
	Projector ProjectorConfig
	Reactor   ReactorConfig

	location *time.Location
}

type KurrentDBConfig struct {
	// ConnectionString is the kurrentdb:// URI. tls=false is refused outside
	// local (ADR-014) — code written against an unauthenticated store acquires
	// nowhere to put credentials, and "add auth later" becomes a rewrite.
	ConnectionString string `env:"KURRENTDB_CONNECTION_STRING" envDefault:"kurrentdb://localhost:2113?tls=false"`
}

type PostgresConfig struct {
	Host     string `env:"POSTGRES_HOST" envDefault:"localhost"`
	Port     int    `env:"POSTGRES_PORT" envDefault:"5432"`
	Database string `env:"POSTGRES_DB,required,notEmpty"`
	MaxConns int32  `env:"POSTGRES_MAX_CONNS" envDefault:"25"`

	// Owner credentials. Used ONLY by migrations. Typically a superuser, which
	// is exactly why the application must not use them.
	User     string `env:"POSTGRES_USER,required,notEmpty"`
	Password Secret `env:"POSTGRES_PASSWORD,required,notEmpty"`

	// Application credentials. A superuser BYPASSES row-level security
	// entirely — FORCE ROW LEVEL SECURITY removes the table-owner exemption but
	// not the superuser bypass — so connecting as the owner silently disables
	// layer 3 of ADR-015 while every test still passes.
	AppUser     string `env:"POSTGRES_APP_USER"     envDefault:"chronos_app"`
	AppPassword Secret `env:"POSTGRES_APP_PASSWORD,required,notEmpty"`
}

// AppDSN is the connection string every binary uses. It is built here, once, so
// no binary can accidentally assemble one from the OWNER credentials — a role
// that bypasses row-level security (see AppUser above).
func (p PostgresConfig) AppDSN() string {
	return p.dsn(p.AppUser, p.AppPassword.Expose())
}

// OwnerDSN is for migrations only: creating tables, policies and grants needs
// privileges the application must never hold (ADR-015).
func (p PostgresConfig) OwnerDSN() string {
	return p.dsn(p.User, p.Password.Expose())
}

func (p PostgresConfig) dsn(user, password string) string {
	return (&url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(user, password),
		Host:     net.JoinHostPort(p.Host, strconv.Itoa(p.Port)),
		Path:     "/" + p.Database,
		RawQuery: "sslmode=disable",
	}).String()
}

// MailConfig is the outbound mail transport and the identity messages are sent
// under.
type MailConfig struct {
	Host string `env:"SMTP_HOST" envDefault:"localhost"`
	Port int    `env:"SMTP_PORT" envDefault:"1025"`

	// Empty in development: Mailpit accepts unauthenticated mail. Requiring
	// credentials there would make the dev path differ from production in code
	// rather than in configuration.
	Username string `env:"SMTP_USERNAME"`
	Password Secret `env:"SMTP_PASSWORD"`

	// StartTLS is off for Mailpit and must be on everywhere real.
	StartTLS bool `env:"SMTP_STARTTLS" envDefault:"false"`

	FromName    string `env:"MAIL_FROM_NAME"    envDefault:"Chronos"`
	FromAddress string `env:"MAIL_FROM_ADDRESS" envDefault:"no-reply@chronos.local"`
	ReplyTo     string `env:"MAIL_REPLY_TO"`

	// BaseURL builds absolute links. Email clients do not resolve relative
	// URLs, so a wrong value here produces dead links in every message.
	BaseURL string `env:"MAIL_BASE_URL" envDefault:"http://localhost:3000"`

	// OperatorAddress receives Operator-class alerts: a stopped projection, a
	// parked backlog. It never receives tenant mail.
	OperatorAddress string `env:"MAIL_OPERATOR_ADDRESS"`

	// DefaultLocale is used when a recipient has none recorded.
	DefaultLocale string `env:"MAIL_DEFAULT_LOCALE" envDefault:"en"`
}

// StorageConfig is object storage. Every limit here is enforced BEFORE bytes
// are stored — the upload policy pins them and the storage service applies them
// — so these are not advisory hints, they are the boundary.
type StorageConfig struct {
	Endpoint  string `env:"S3_ENDPOINT"   envDefault:"http://localhost:8333"`
	Region    string `env:"S3_REGION"     envDefault:"us-east-1"`
	Bucket    string `env:"S3_BUCKET"     envDefault:"chronos"`
	AccessKey string `env:"S3_ACCESS_KEY"`
	SecretKey Secret `env:"S3_SECRET_KEY"`

	// PublicEndpoint is the address a BROWSER can reach, which differs from the
	// one this process uses whenever storage sits behind a container network or
	// a CDN. Wrong here means grants that work from the server and fail from
	// every browser.
	PublicEndpoint string `env:"S3_PUBLIC_ENDPOINT"`

	MaxUploadBytes int64 `env:"STORAGE_MAX_UPLOAD_BYTES" envDefault:"104857600"` // 100 MiB
	MaxBatchCount  int   `env:"STORAGE_MAX_BATCH_COUNT"  envDefault:"20"`

	// ResumableThresholdBytes is where a client switches to multipart. It must
	// be at least PartSizeBytes, or a resumable upload could be a single
	// undersized part that S3 rejects at completion.
	ResumableThresholdBytes int64 `env:"STORAGE_RESUMABLE_THRESHOLD_BYTES" envDefault:"8388608"` // 8 MiB
	PartSizeBytes           int64 `env:"STORAGE_PART_SIZE_BYTES"          envDefault:"8388608"`  // 8 MiB

	// GrantExpiry bounds how long an upload or download URL is usable. A grant
	// is a capability; a leaked one is a write into our bucket.
	GrantExpiry time.Duration `env:"STORAGE_GRANT_EXPIRY" envDefault:"15m"`

	// AllowedContentTypes is the allow-list a browser is told about and the
	// policy pins. Empty permits anything, which suits internal exports and
	// never suits user uploads.
	AllowedContentTypes []string `env:"STORAGE_ALLOWED_CONTENT_TYPES" envSeparator:","`
}

// RealtimeConfig is the live-delivery service.
//
// Two different secrets, and confusing them is the classic mistake: APIKey
// authenticates OUR server calls, TokenSecret signs the tokens BROWSERS present.
// Swapping them yields a server that cannot publish and browsers that cannot
// connect — two failures with one cause.
type RealtimeConfig struct {
	// GRPCEndpoint is the server API. gRPC rather than HTTP, chosen on
	// measurement (see internal/adapter/centrifugo).
	GRPCEndpoint string `env:"CENTRIFUGO_GRPC_ENDPOINT" envDefault:"localhost:10000"`

	// APIKey authenticates server-side publishes.
	APIKey Secret `env:"CENTRIFUGO_API_KEY"`

	// TokenSecret signs connection and subscription tokens. It is the
	// authorisation seam: no namespace grants clients the right to subscribe,
	// so a browser reaches a channel only via a token we minted.
	TokenSecret Secret `env:"CENTRIFUGO_TOKEN_HMAC_SECRET"`
}

// ValkeyConfig is the ephemeral store: caches, rate limits, sessions and the
// invalidation bus.
//
// Everything here is Degradable by construction — losing Valkey costs latency,
// never correctness — with one exception that is not a cache at all. The PII key
// cache's invalidation channel rides on the same connection, and a process that
// cannot hear invalidations purges the keys it holds rather than keep serving
// them (see internal/adapter/piivault).
type ValkeyConfig struct {
	// Addr is host:port. A list is accepted for a clustered deployment.
	Addr []string `env:"VALKEY_ADDR" envDefault:"localhost:6379" envSeparator:","`

	// Password is empty in development, where Valkey listens only on the compose
	// network.
	Password Secret `env:"VALKEY_PASSWORD"`

	// KeyCacheTTL bounds how long an unwrapped subject data key may live in a
	// process that never received its invalidation. It is a security window, not
	// a performance knob: raising it raises the time an erased subject's key can
	// still decrypt their data if the bus is down.
	KeyCacheTTL time.Duration `env:"PII_KEY_CACHE_TTL" envDefault:"1m"`

	// KeyCacheCapacity bounds how many subject keys one process holds.
	KeyCacheCapacity int `env:"PII_KEY_CACHE_CAPACITY" envDefault:"4096"`

	// KeyCacheSweep is how often expired keys are zeroed rather than merely
	// treated as absent. Lazy expiry alone leaves destroyed key material resident
	// until somebody happens to ask for that subject again.
	KeyCacheSweep time.Duration `env:"PII_KEY_CACHE_SWEEP" envDefault:"15s"`
}

// ReactorConfig tunes the side-effect binary.
type ReactorConfig struct {
	// DedupRetentionDays is how long a reactor remembers that it already handled
	// an event. It must comfortably exceed the longest redelivery gap: a parked
	// event replayed weeks later has to be recognised as already done, or the
	// effect happens twice — a second charge, a second email.
	DedupRetentionDays int `env:"REACTOR_DEDUP_RETENTION_DAYS" envDefault:"30"`

	// DedupSweepEvery is how often expired dedup rows are deleted. Hourly: the
	// table is append-only between sweeps and the delete is indexed, so there is
	// nothing to gain from running it more often.
	DedupSweepEvery time.Duration `env:"REACTOR_DEDUP_SWEEP_EVERY" envDefault:"1h"`
}

// MinDedupRetentionDays is the floor for REACTOR_DEDUP_RETENTION_DAYS. Seven
// days covers a weekend outage plus the time it takes somebody to notice and
// replay what parked.
const MinDedupRetentionDays = 7

// ProjectorConfig tunes the read-side.
type ProjectorConfig struct {
	// RebuildShards is how many workers a rebuild applies events through.
	//
	// One is sequential. Sharding partitions by STREAM, so every event of one
	// aggregate is applied in order by one worker; it trades away ordering across
	// aggregates, which a rebuild already gives up by reading a link stream.
	//
	// It is capped because each shard holds a pooled connection for the whole
	// rebuild, and a rebuild that drains the pool starves the live projectors
	// sharing it.
	RebuildShards int `env:"PROJECTOR_REBUILD_SHARDS" envDefault:"1"`
}

// MaxRebuildShards caps PROJECTOR_REBUILD_SHARDS. It matches the kernel's own
// cap; the value is repeated rather than imported because the config package
// sits beneath the kernel in the import contract (CONVENTIONS §2).
const MaxRebuildShards = 16

// MaxKeyCacheTTL caps PII_KEY_CACHE_TTL.
//
// Five minutes: comfortably longer than any legitimate tuning of a cache whose
// purpose is to collapse one notification fan-out, and short enough that the
// worst case — an erasure whose invalidation reached nobody — is a few minutes
// rather than an afternoon.
const MaxKeyCacheTTL = 5 * time.Minute

// PushConfig is web push. VAPID identifies this application server to the
// browser push services; without a keypair the push channel is inert, which is
// a correct state for a deployment that has not enabled it.
type PushConfig struct {
	VAPIDPublicKey  string `env:"VAPID_PUBLIC_KEY"`
	VAPIDPrivateKey Secret `env:"VAPID_PRIVATE_KEY"`

	// VAPIDSubject is a mailto: or https: URL push services use to reach the
	// operator about abuse. Required by the spec when a keypair is set.
	VAPIDSubject string `env:"VAPID_SUBJECT" envDefault:"mailto:ops@chronos.local"`
}

type OpenFGAConfig struct {
	Endpoint     string `env:"OPENFGA_ENDPOINT" envDefault:"localhost:8081"`
	PresharedKey Secret `env:"OPENFGA_PRESHARED_KEY,required,notEmpty"`
	StoreID      string `env:"OPENFGA_STORE_ID"`
	// ModelID is pinned per request; "use latest" makes deploys racy.
	ModelID string `env:"OPENFGA_MODEL_ID"`
}

type OpenBaoConfig struct {
	Address string `env:"OPENBAO_ADDR" envDefault:"http://localhost:8200"`
	Token   Secret `env:"OPENBAO_DEV_TOKEN"`
	KEKName string `env:"OPENBAO_KEK_NAME" envDefault:"chronos-kek"`
}

// Required values use `required,notEmpty`. `required` alone only checks that a
// variable is *set* — POSTGRES_PASSWORD= in a .env file would pass it, which is
// the most likely way this goes wrong in practice.
//
// Load parses the environment and validates it. The returned error names every
// problem at once, so a misconfigured deployment is fixed in one pass rather
// than one restart per mistake.
func Load() (*Config, error) {
	var c Config
	if err := env.Parse(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Location is the presentation timezone. Storage is UTC regardless.
func (c *Config) Location() *time.Location { return c.location }

func (c *Config) validate() error {
	var problems []string
	add := func(f string, a ...any) { problems = append(problems, fmt.Sprintf(f, a...)) }

	switch c.Env {
	case Local, Staging, Production:
	default:
		add("APP_ENV %q must be one of local, staging, production", c.Env)
	}

	loc, err := time.LoadLocation(c.Timezone)
	if err != nil {
		add("APP_TIMEZONE %q is not a valid IANA timezone", c.Timezone)
	} else {
		c.location = loc
	}

	// ADR-014: an unauthenticated event store outside local is a startup
	// failure, not a warning nobody reads.
	if !c.Env.IsLocal() && strings.Contains(strings.ToLower(c.KurrentDB.ConnectionString), "tls=false") {
		add("KURRENTDB_CONNECTION_STRING has tls=false, which is only permitted when APP_ENV=local (ADR-014)")
	}

	// ADR-028: a dev-mode OpenBao in production voids the erasure guarantee.
	if !c.Env.IsLocal() && strings.HasPrefix(c.OpenBao.Token.Expose(), "chronos_dev") {
		add("OPENBAO_DEV_TOKEN is a development token and must not be used when APP_ENV=%s (ADR-028)", c.Env)
	}

	if c.Postgres.Port < 1 || c.Postgres.Port > 65535 {
		add("POSTGRES_PORT %d is out of range", c.Postgres.Port)
	}
	if c.Env != Local && c.Realtime.TokenSecret.IsZero() {
		add("CENTRIFUGO_TOKEN_HMAC_SECRET must be set outside local: without it no " +
			"subscription token can be signed, and every browser silently fails to connect")
	}
	if c.Env != Local && !c.Mail.StartTLS {
		add("SMTP_STARTTLS must be enabled outside local: mail carries reset links " +
			"and sign-in alerts, and plaintext SMTP puts them on the wire")
	}
	if c.Postgres.MaxConns < 1 {
		add("POSTGRES_MAX_CONNS must be at least 1, got %d", c.Postgres.MaxConns)
	}

	// The PII key cache TTL is the window in which an erased subject's key can
	// still decrypt their data in a replica that missed the invalidation. It is
	// bounded here rather than left to whoever edits the environment, because
	// there is no error and no log line to reveal a value set too high — only a
	// guarantee quietly weakened (ADR-002, ADR-028).
	if c.Valkey.KeyCacheTTL <= 0 {
		add("PII_KEY_CACHE_TTL must be positive, got %s: a key cached without expiry "+
			"survives its own destruction", c.Valkey.KeyCacheTTL)
	}
	if c.Valkey.KeyCacheTTL > MaxKeyCacheTTL {
		add("PII_KEY_CACHE_TTL %s exceeds the %s ceiling: that is how long an erased "+
			"subject's key could still decrypt their data if the invalidation bus is down",
			c.Valkey.KeyCacheTTL, MaxKeyCacheTTL)
	}
	if c.Valkey.KeyCacheCapacity < 1 {
		add("PII_KEY_CACHE_CAPACITY must be at least 1, got %d", c.Valkey.KeyCacheCapacity)
	}
	if c.Valkey.KeyCacheSweep <= 0 || c.Valkey.KeyCacheSweep > c.Valkey.KeyCacheTTL {
		add("PII_KEY_CACHE_SWEEP %s must be positive and no larger than PII_KEY_CACHE_TTL %s: "+
			"sweeping less often than entries expire leaves destroyed keys resident in memory",
			c.Valkey.KeyCacheSweep, c.Valkey.KeyCacheTTL)
	}
	if len(c.Valkey.Addr) == 0 {
		add("VALKEY_ADDR must name at least one host:port")
	}

	// A rebuild shard holds a pooled connection for the whole rebuild. More
	// shards than the pool has connections deadlocks the rebuild against itself,
	// and a rebuild that drains the pool starves every live projector sharing it.
	if c.Projector.RebuildShards < 1 {
		add("PROJECTOR_REBUILD_SHARDS must be at least 1, got %d", c.Projector.RebuildShards)
	}
	if c.Projector.RebuildShards > MaxRebuildShards {
		add("PROJECTOR_REBUILD_SHARDS %d exceeds the %d cap", c.Projector.RebuildShards, MaxRebuildShards)
	}
	// Compared as int64 so the bound check itself cannot overflow: the value is
	// already capped above, but a check that can wrap is not a check.
	if int64(c.Projector.RebuildShards) >= int64(c.Postgres.MaxConns) {
		add("PROJECTOR_REBUILD_SHARDS %d needs POSTGRES_MAX_CONNS above it (currently %d): "+
			"each shard holds a connection for the whole rebuild",
			c.Projector.RebuildShards, c.Postgres.MaxConns)
	}

	// A dedup window shorter than the redelivery gap means a reactor forgets it
	// already sent an email before the server stops trying to redeliver it. The
	// floor is deliberately generous: parked events are replayed by hand, often
	// days after the outage that parked them.
	if c.Reactor.DedupRetentionDays < MinDedupRetentionDays {
		add("REACTOR_DEDUP_RETENTION_DAYS %d is below the %d-day floor: a reactor that "+
			"forgets an event still eligible for redelivery performs its effect twice",
			c.Reactor.DedupRetentionDays, MinDedupRetentionDays)
	}
	if c.Reactor.DedupSweepEvery <= 0 {
		add("REACTOR_DEDUP_SWEEP_EVERY must be positive, got %s: without a sweep, "+
			"reactor_processed grows for the lifetime of the deployment",
			c.Reactor.DedupSweepEvery)
	}

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(problems, "\n  - "))
}

// ErrMissing is returned when a required variable is absent.
var ErrMissing = errors.New("config: required environment variable is not set")

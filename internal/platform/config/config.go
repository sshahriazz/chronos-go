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
	"context"
	"encoding/hex"
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
	Stripe    StripeConfig
	Mail      MailConfig
	Storage   StorageConfig
	Realtime  RealtimeConfig
	Push      PushConfig
	Valkey    ValkeyConfig
	Projector ProjectorConfig
	Reactor   ReactorConfig
	Temporal  TemporalConfig
	Tracing   TracingConfig
	Profiling ProfilingConfig
	API       APIConfig
	Identity  IdentityConfig

	// ClockControl is the movable clock. Local only, and the validation below
	// is what makes that true rather than aspirational.
	ClockControl ClockControlConfig

	location *time.Location
}

// IdentityConfig is the key material and the two tuning knobs the identity
// module cannot be built without.
//
// Every key here is 32 bytes, hex-encoded — 64 characters. Hex rather than
// base64 because a mistyped base64 key is frequently still decodable at a
// different length, and the failure then surfaces as "this key is 31 bytes"
// somewhere deep in a constructor rather than as a refusal to boot.
//
// None of them is `required`. A deployment that has not yet provisioned identity
// keys must still start: the composition root reports at ERROR that the identity
// service could not be built and leaves it unregistered, which is ADR-010's rule
// applied to our own configuration rather than to an unreachable dependency.
// Outside local, validate() upgrades that to a refusal to boot — an API server
// in production with no login is not a degraded mode anybody wants discovered
// from a log line.
type IdentityConfig struct {
	// EmailIndexKey keys the blind index over email addresses. It is the one key
	// in this struct that can NEVER be rotated: the index names a KurrentDB
	// stream, stream names are immutable, and a new key orphans every reservation
	// ever written — after which uniqueness silently stops being enforced for
	// everything registered before the change (IDENTITY-SLICE-1).
	EmailIndexKey Secret `env:"IDENTITY_EMAIL_INDEX_KEY"`

	// PasswordPepperKey is the current pepper. The verifier is Argon2id sealed
	// under it, so a stolen database alone is not crackable offline (ADR-028).
	PasswordPepperKey Secret `env:"IDENTITY_PASSWORD_PEPPER_KEY"`

	// PasswordPepperVersion is the version the current key seals under, written
	// to the `pepper_version` column beside each verifier. It must be at least 1:
	// a row at 0 is invisible to the rotation job's `pepper_version < n` query, so
	// it is skipped silently and the account is locked out for good when the old
	// key is destroyed.
	PasswordPepperVersion int `env:"IDENTITY_PASSWORD_PEPPER_VERSION" envDefault:"1"`

	// PasswordPepperRetired carries the keys a PREVIOUS version sealed under, as
	// `version:hex` pairs separated by commas — e.g. `2:aabb…,1:ccdd…`.
	//
	// # Why this exists, and why rotation is broken without it
	//
	// A pepper rotation does not rewrite anything. Existing rows keep their old
	// `pepper_version` until the re-sealing job reaches them, and a verifier is
	// AEAD-sealed under the key of its own version — so a process holding only the
	// new key cannot open them at all.
	//
	// The consequence is not "the re-seal job stalls". It is that every user whose
	// verifier has not yet been re-sealed CANNOT LOG IN, immediately, from the
	// moment the new key is deployed. Verification reports the value as
	// unreadable, which is deliberately not the same as a wrong password — but the
	// user is locked out either way. A rotation without this field is an outage
	// with a delayed trigger.
	//
	// So the deployment order is: add the new key here as the current one, keep
	// every still-referenced version in this list, let the re-sealing job run to
	// zero rows (`CountCredentialsAtKeyVersion`), and only then remove the retired
	// entry and destroy the key in OpenBao. Nothing in code can enforce that
	// ordering, which is why the count query exists as the check.
	//
	// Empty is the normal steady state: one key, never rotated.
	PasswordPepperRetired Secret `env:"IDENTITY_PASSWORD_PEPPER_RETIRED"`

	// TotpSealKey seals shared TOTP secrets, and TotpSealKeyVersion is its
	// version, with exactly the same rotation-visibility rule as the pepper.
	TotpSealKey        Secret `env:"IDENTITY_TOTP_SEAL_KEY"`
	TotpSealKeyVersion int    `env:"IDENTITY_TOTP_SEAL_KEY_VERSION" envDefault:"1"`

	// TotpSealRetired is the same list for the TOTP sealing key, in the same
	// format and with the same deployment order.
	//
	// The failure it prevents is worse here than for passwords, because there is
	// no reset flow to fall back on: a TOTP secret that cannot be opened is a
	// second factor the user can never satisfy, and the account is locked behind a
	// factor nobody can produce. A password lockout ends with an email; this one
	// ends with support.
	TotpSealRetired Secret `env:"IDENTITY_TOTP_SEAL_RETIRED"`

	// TotpIssuer is the label a user sees above the account in their
	// authenticator app. An empty one produces an unlabelled entry, which is how
	// people delete the wrong credential.
	TotpIssuer string `env:"IDENTITY_TOTP_ISSUER" envDefault:"Chronos"`

	// PasswordHashConcurrency bounds simultaneous Argon2id hashes. Each one holds
	// 32 MiB for its whole duration, so this is the ceiling on how much memory
	// password verification can consume no matter what arrives.
	//
	// Zero means "resolve it from the CPU limit this process actually has", which
	// is what cmd/api does — see resolveCPULimit there for why GOMAXPROCS is the
	// wrong answer under a CFS quota. Set it explicitly only when a measurement on
	// the target hardware says otherwise; the measured saturation point is the
	// core count, and beyond it throughput DECLINES while memory grows linearly.
	PasswordHashConcurrency int `env:"IDENTITY_PASSWORD_HASH_CONCURRENCY" envDefault:"0"`
}

// IdentityKeySize is the length every identity key must decode to. It matches
// crypto.DEKSize and blindindex.KeySize; the value is repeated rather than
// imported because config sits beneath both in the import contract
// (CONVENTIONS §2).
const IdentityKeySize = 32

// Configured reports whether enough key material is present to build the
// identity module at all. Partial configuration is NOT configured — see
// validate, which names each missing key.
func (i IdentityConfig) Configured() bool {
	return !i.EmailIndexKey.IsZero() &&
		!i.PasswordPepperKey.IsZero() &&
		!i.TotpSealKey.IsZero()
}

// EmailIndexKeyBytes, PasswordPepperKeyBytes and TotpSealKeyBytes decode the hex
// forms. validate has already refused anything malformed, so a caller reaching
// an error here is looking at a Config nobody validated.
func (i IdentityConfig) EmailIndexKeyBytes() ([]byte, error) {
	return decodeIdentityKey("IDENTITY_EMAIL_INDEX_KEY", i.EmailIndexKey)
}

func (i IdentityConfig) PasswordPepperKeyBytes() ([]byte, error) {
	return decodeIdentityKey("IDENTITY_PASSWORD_PEPPER_KEY", i.PasswordPepperKey)
}

func (i IdentityConfig) TotpSealKeyBytes() ([]byte, error) {
	return decodeIdentityKey("IDENTITY_TOTP_SEAL_KEY", i.TotpSealKey)
}

// decodeIdentityKey turns a hex secret into bytes, refusing anything that is not
// exactly IdentityKeySize long.
//
// The error names the variable and the observed length, and deliberately never
// the value: an error string is the one place a key is most likely to reach a
// log aggregator.
func decodeIdentityKey(name string, s Secret) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(s.Expose()))
	if err != nil {
		return nil, fmt.Errorf("%s is not valid hex", name)
	}
	if len(raw) != IdentityKeySize {
		return nil, fmt.Errorf("%s decodes to %d bytes, want %d", name, len(raw), IdentityKeySize)
	}
	return raw, nil
}

// APIConfig tunes the request pipeline.
type APIConfig struct {
	// IdempotencyTTL is how long a mutation's response stays replayable
	// (CONVENTIONS §6). It is a RETENTION bound, not a cache hint: a stored
	// response can contain personal data (ADR-002).
	IdempotencyTTL time.Duration `env:"API_IDEMPOTENCY_TTL" envDefault:"24h"`

	// IdempotencySweepEvery is how often expired records are deleted. The
	// records are what make a retry safe, so the sweep is what keeps the table —
	// and the personal data in it — bounded.
	IdempotencySweepEvery time.Duration `env:"API_IDEMPOTENCY_SWEEP_EVERY" envDefault:"1h"`

	// IdempotencyWait is how long a duplicate arriving mid-flight waits for the
	// first request to finish before being refused. Zero does not wait, which
	// turns a double-click into an error the user sees rather than the answer
	// they were about to get.
	IdempotencyWait time.Duration `env:"API_IDEMPOTENCY_WAIT" envDefault:"5s"`

	// TrustedProxyHops is how many proxies in front of this server APPEND to
	// X-Forwarded-For. It is the trust boundary every per-source rate limit is
	// scoped by (internal/platform/clientip).
	//
	// # Zero is not "unset", it is a policy
	//
	// Zero means trust nothing: the header is not read at all and the
	// connection's peer address is the scope. That is the only value that is safe
	// without knowing the topology, so it is the default, and a deployment that
	// sets nothing behaves exactly as one that had no such setting.
	//
	// # The contract, and why it is asymmetric
	//
	// Set it to the number of proxies that append, AND NO MORE.
	//
	//   - Too LOW: every caller behind the proxy shares one bucket and the
	//     per-caller rule degrades into a global ceiling. Users are refused at
	//     random once traffic grows. Bad, never exploitable.
	//   - Too HIGH: the entry selected moves left, into the part of the header the
	//     CALLER wrote. An attacker then mints a fresh bucket per request to evade
	//     the ceiling, or borrows a victim's address to burn their budget. The
	//     control is not weakened, it is inverted into a weapon.
	//
	// There is no observable difference between the two at runtime, so the number
	// has to come from the topology diagram rather than from experiment. A load
	// balancer that terminates TLS and appends is one; an L4 balancer that
	// forwards the TCP connection untouched is ZERO, because it appends nothing.
	TrustedProxyHops int `env:"API_TRUSTED_PROXY_HOPS" envDefault:"0"`
}

// MaxIdempotencyTTL is the ceiling for API_IDEMPOTENCY_TTL. It mirrors
// cqrs.MaxTTL, which the kernel enforces again at construction — this one exists
// so the failure is a refusal to BOOT with a named environment variable, rather
// than an error from a constructor at some later point in wiring.
const MaxIdempotencyTTL = 7 * 24 * time.Hour

// MaxTrustedProxyHops caps API_TRUSTED_PROXY_HOPS. It mirrors
// clientip.MaxTrustedHops, which the kernel enforces again when the resolver is
// built — the value is repeated rather than imported because config sits beneath
// the kernel in the import contract (CONVENTIONS §2), exactly as
// MaxRebuildShards and IdentityKeySize are.
//
// This one exists so the failure is a refusal to BOOT naming the environment
// variable. The alternative is worse than for the other caps: a hop count set
// far too high does not fail at all, it quietly makes the client address
// attacker-chosen, and nothing at runtime reports the difference.
const MaxTrustedProxyHops = 8

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

// TracingConfig is distributed tracing (ADR-034).
//
// Services export to the COLLECTOR, never to Tempo directly: sampling and
// attribute scrubbing live in infra/otel-collector/config.yaml, and the
// scrubbing is what keeps personal data out of spans (ADR-002). A service that
// exported straight to the backend would bypass both.
type TracingConfig struct {
	// Endpoint is the OTLP gRPC collector.
	Endpoint string `env:"OTEL_EXPORTER_OTLP_ENDPOINT" envDefault:"http://localhost:4317"`

	// Enabled turns exporting on. Off still installs the W3C propagator, so an
	// incoming trace id still reaches the code that writes it into an event's
	// correlation id — turning tracing off must not change what lands in a
	// permanent log.
	Enabled bool `env:"OTEL_ENABLED" envDefault:"false"`
}

// ProfilingConfig is the Go runtime profiler served over HTTP (net/http/pprof).
//
// It is the fourth observability signal. Prometheus answers "how much", Tempo
// answers "where did the time go", the logs answer "what happened" — and none of
// them answers "which allocation is growing" or "which goroutine is stuck".
// Go 1.27 adds a fifth profile that matters here specifically: `goroutineleak`
// reports goroutines blocked on concurrency primitives nothing can reach again,
// which is the failure mode a projector, a reactor or a subscription loop
// actually dies of.
//
// # Everything in this struct is a security control
//
// A pprof surface is not a metrics endpoint with more detail. `heap` returns
// live heap contents. `goroutine?debug=2` returns every goroutine's stack WITH
// ARGUMENTS — which is where a bearer token, an email address and a decrypted
// data key are, in a system whose whole compliance story is that those three
// never leave the vault (ADR-002). `cmdline` returns argv. `symbol` and the
// binary's own function names disclose the source tree layout.
//
// So the exposure decision is made here rather than left to whoever writes the
// deployment manifest, and it is made in three independent layers:
//
//  1. OFF by default. A deployment that says nothing gets no profiler, and the
//     listener is never created. This is the only default that is safe without
//     knowing the network topology.
//  2. A SEPARATE listener, never the tenant API port. Anything mounted on the
//     API mux is reachable by every client that can reach the API, and no
//     interceptor protects it — the Connect gates run inside a Connect handler,
//     and /debug/pprof is not one. A second listener also means the port can be
//     left unpublished, so the app-level toggle and the network are two locks
//     rather than one.
//  3. A BEARER TOKEN, mandatory whenever the bind address is not loopback and
//     mandatory outside local regardless of address. A container's loopback is
//     shared by every process in the pod, so "127.0.0.1" is a weaker boundary in
//     production than it looks on a laptop.
//
// validate() refuses combinations that are unsafe rather than trusting an
// operator to notice, because none of them has a runtime symptom: a profiler
// bound to 0.0.0.0 with no token works perfectly, and the only report you get is
// somebody else's heap dump.
type ProfilingConfig struct {
	// Enabled creates the listener. Off means net.Listen is never called and
	// /debug/pprof exists nowhere in this process.
	//
	// Off is also the state `make check` runs in, which is deliberate: the test
	// that proves the endpoints ANSWER and the test that proves they are ABSENT
	// are both wiring assertions, and only one of them can be true at a time.
	Enabled bool `env:"PPROF_ENABLED" envDefault:"false"`

	// Addr is the debug listener's own host:port. It must never be the API's.
	//
	// The default binds loopback, so on a developer machine the profiler is
	// reachable by `go tool pprof http://localhost:6060/...` and by nothing on
	// the network. In a cluster the intended access path is the same one used for
	// any other debug surface — a port-forward into the pod — which needs no
	// published port and no ingress rule.
	Addr string `env:"PPROF_ADDR" envDefault:"127.0.0.1:6060"`

	// Token is the bearer credential every /debug/pprof request must present.
	//
	// Empty is permitted ONLY for a loopback bind inside local. Compared in
	// constant time, so the check cannot be turned into an oracle by timing it.
	Token Secret `env:"PPROF_TOKEN"`
}

// ClockControlConfig is the movable clock: a LOCAL-ONLY surface that lets a
// test push this process's clock forward instead of sleeping through a
// time-derived rule (ADR-054).
//
// # What it is for
//
// Almost everything identity enforces is derived from a clock — TOTP steps,
// session idle and absolute deadlines, verification and reset token expiry,
// attempt ceilings, lockouts. A test that needs to cross one of those
// boundaries has exactly two options: wait, or move the server's clock. The
// identity integration suite took the first option and spent most of four
// minutes asleep waiting for RFC 6238's thirty-second step to roll over.
//
// # What stops it in production — three independent locks
//
//  1. Enabled defaults to false, so the listener is never bound and the routes
//     exist on no mux. Nothing is reachable in a default build.
//  2. validate() REFUSES TO BOOT when Enabled is true and APP_ENV is anything
//     but local. Not a warning, not a degraded mode: config.Load returns an
//     error and cmd/api exits non-zero. A production deployment that sets the
//     variable gets a dead server, which is the loudest possible signal and the
//     only one nobody can miss.
//  3. Addr must be loopback, in every environment including local. A clock an
//     attacker can move is a clock that expires anybody's lockout on demand, so
//     it does not go on a routable interface even on a laptop.
//
// A fourth lock is in the type rather than the configuration: clock.Offset only
// moves FORWARD. See that type for why a rewind would be a hole rather than a
// feature.
//
// # Why not a build tag
//
// A build tag would remove the code from the production binary entirely, which
// is stronger — and it would do it by making the binary the tests exercise a
// DIFFERENT binary from the one that ships. internal/adapter/identityit exists
// precisely because this repository keeps finding code that was built, tested
// and wired into nothing; it compiles and runs cmd/api itself so that every
// interceptor, gate and adapter under test is the production one. A tag would
// reintroduce the gap that package was written to close, and it would make lock
// 2 — the refusal to boot, which is the property most worth testing — untestable
// because the refusing code would not be in the binary.
type ClockControlConfig struct {
	// Enabled binds the control listener. False means net.Listen is never
	// called, no route is registered, and this process's clock is
	// clock.System{} with nothing able to move it.
	Enabled bool `env:"CLOCK_CONTROL_ENABLED" envDefault:"false"`

	// Addr is the control listener's own host:port, and never the API's.
	//
	// Its own listener for the same reason /debug/pprof has one: the ADR-021
	// enforcement gates are Connect interceptors that run inside a Connect
	// handler, so a plain HTTP route on the tenant mux is an UNAUTHENTICATED
	// route no matter what it is called.
	//
	// Port 0 by default, so a harness that did not pick a port gets an
	// ephemeral one rather than colliding with a second server on the same
	// machine. The resolved address is logged at startup.
	Addr string `env:"CLOCK_CONTROL_ADDR" envDefault:"127.0.0.1:0"`
}

// MinProfilingTokenLength is the floor for PPROF_TOKEN.
//
// Thirty-two characters is 128 bits at four bits per hex character, which is the
// same floor the rest of this system uses for key material. A short token here
// is not a weak password on a low-value account: it is one guess away from a
// heap dump of a process that holds session tokens and decrypted addresses, and
// there is no lockout on a debug listener.
const MinProfilingTokenLength = 32

// TemporalConfig points at the durable-work service (ADR-017).
//
// Work that spans several effects, needs timers, or must survive the process
// dying halfway runs here. The banned alternatives — a cron table, a
// time.AfterFunc, an ad-hoc goroutine — all share one flaw: none of them
// outlives the process that created them.
type TemporalConfig struct {
	// HostPort is the frontend address.
	HostPort string `env:"TEMPORAL_HOSTPORT" envDefault:"localhost:7233"`

	// Namespace isolates one deployment's workflows from another's.
	Namespace string `env:"TEMPORAL_NAMESPACE" envDefault:"default"`

	// Queue is the task queue starters write to and workers poll.
	//
	// Both sides must agree: work queued where no worker listens is CREATED and
	// then never runs, and the caller sees a successful start. It is also the
	// versioning boundary — a workflow change that is not replay-safe moves to a
	// new queue rather than breaking in-flight executions.
	Queue string `env:"TEMPORAL_TASK_QUEUE" envDefault:"chronos"`

	// Enabled starts the worker and the client. Off by default while the
	// workflow set is small: a binary that dials a service it never uses reports
	// a DOWN probe for a dependency nothing needs.
	Enabled bool `env:"TEMPORAL_ENABLED" envDefault:"false"`
}

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

	// CatchUpBatch is how many events share ONE transaction while a projector is
	// behind the head of the log. 1 commits every event separately.
	//
	// The round trip dominates a catching-up projector, and it is paid per
	// transaction rather than per statement — measured at 364.8 µs/event
	// unbatched against 16.7 µs/event at 64. Atomicity is unchanged: the rows
	// and the checkpoint that describes them are still in the same transaction,
	// so a crash loses the batch as a unit and the projector reapplies it.
	//
	// It does not apply once a projector is LIVE: there an event commits on its
	// own, because latency to the read model is what matters.
	CatchUpBatch int `env:"PROJECTOR_CATCHUP_BATCH" envDefault:"64"`

	// RebuildEventsPerSecond paces a REBUILD. 0 is unthrottled.
	//
	// A rebuild writes through the same pool the API uses, so at full speed it
	// is a load test against production run at the worst moment. This makes it a
	// background job instead. It does not pace ordinary catch-up, where being
	// slow means every read stays stale for longer.
	RebuildEventsPerSecond int `env:"PROJECTOR_REBUILD_EVENTS_PER_SECOND" envDefault:"0"`

	// AnnounceBuffer is how many realtime announcements may queue behind a
	// projector before the oldest are dropped.
	//
	// Dropping is correct: the row is already committed and a browser recovers
	// by reading it, whereas blocking would put Centrifugo's latency back into
	// the loop that advances the read model. Drops are counted in
	// chronos_projection_announcements_dropped_total.
	AnnounceBuffer int `env:"PROJECTOR_ANNOUNCE_BUFFER" envDefault:"256"`
}

// MaxCatchUpBatch caps PROJECTOR_CATCHUP_BATCH. Repeated rather than imported
// for the same reason as MaxRebuildShards: config sits beneath the kernel in the
// import contract (CONVENTIONS §2).
const MaxCatchUpBatch = 512

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

// StripeConfig is what the billing integration needs to provision a tenant.
//
// Only the provisioning half is here. Invoicing, the customer portal and
// webhook ingestion arrive with the rest of billing and bring their own
// settings; adding them now would be configuration nothing reads.
type StripeConfig struct {
	// SecretKey is a RESTRICTED key (`rk_`), never a secret key (`sk_`).
	//
	// A restricted key is scoped to the resources this integration touches, so a
	// leak cannot be used to read every charge the account has ever taken. The
	// value belongs in OpenBao (ADR-028); it is read from the environment here
	// because that is where every other secret in this build still lives, and
	// moving them all is one change rather than six.
	SecretKey Secret `env:"STRIPE_SECRET_KEY"`

	// There is deliberately NO trial price id here, and no trial length.
	//
	// Both used to be environment variables, and both are now the plan
	// catalogue's (`billing/domain.Published`), which the worker mirrors into
	// Stripe at startup. A price id in configuration is a number that can differ
	// between two deployments of the same binary, which makes "what did this
	// customer sign up to" unanswerable across environments — and a trial length
	// held apart from the Price it applies to is how a fourteen-day plan ends up
	// running for thirty.

	// WebhookSecret verifies that an event genuinely came from Stripe.
	//
	// Without it the endpoint is an unauthenticated way to change billing state:
	// anybody who can reach it could suspend a tenant or mark one active.
	// Verification is therefore not optional, and the endpoint refuses to
	// register at all when this is unset rather than accepting events it cannot
	// check.
	WebhookSecret Secret `env:"STRIPE_WEBHOOK_SECRET"`

	// WebhookSecretPrevious is the secret being rotated OUT.
	//
	// Both are accepted while a rotation is in flight (billing.md §5 case 26).
	// Without an overlap window every event delivered between updating Stripe
	// and restarting the process fails verification — and Stripe retries for
	// three days, so the damage is bounded but the pager is not.
	WebhookSecretPrevious Secret `env:"STRIPE_WEBHOOK_SECRET_PREVIOUS"`
}

// Configured reports whether provisioning can run at all.
//
// The key alone, now that the plan catalogue supplies the Price: without a key
// nothing can be reached, and with one the worker mirrors the catalogue and
// discovers the price id itself. The reactor refuses to construct rather than
// failing per organization.
func (s StripeConfig) Configured() bool {
	return !s.SecretKey.IsZero()
}

// WebhookSecrets is every secret an incoming signature may be checked against,
// newest first.
//
// A slice rather than one value, because a rotation needs both live at once.
// Empty means the endpoint must not be served: an unverified webhook is an
// unauthenticated request that changes billing state.
func (s StripeConfig) WebhookSecrets() []string {
	var out []string
	if !s.WebhookSecret.IsZero() {
		out = append(out, s.WebhookSecret.Expose())
	}
	if !s.WebhookSecretPrevious.IsZero() {
		out = append(out, s.WebhookSecretPrevious.Expose())
	}
	return out
}

// Live reports whether the key addresses real money.
//
// Stripe distinguishes test and live by key PREFIX, and nothing else — the same
// code path, the same API, real charges. billing.md §5 case 20 requires a live
// key outside production to fail startup, and this is what that check reads.
// Expose is the right call here and the awkward name is doing its job: this is
// one of the few places that must read the value rather than log it, because the
// PREFIX is the whole signal. Secret.String() returns "[REDACTED]", so reading
// it here would report every key as a test key — including a live one.
func (s StripeConfig) Live() bool {
	key := s.SecretKey.Expose()
	return strings.HasPrefix(key, "sk_live_") || strings.HasPrefix(key, "rk_live_")
}

type OpenBaoConfig struct {
	Address string `env:"OPENBAO_ADDR" envDefault:"http://localhost:8200"`
	Token   Secret `env:"OPENBAO_DEV_TOKEN"`
	KEKName string `env:"OPENBAO_KEK_NAME" envDefault:"chronos-kek"`

	// KVMount is the KV v2 engine holding APPLICATION secrets.
	//
	// A different job from KEKName above: that key never leaves OpenBao, while
	// these values must, because a Stripe key is useless unless we can send it
	// to Stripe. This is custody — read once at startup over an authenticated
	// channel — not secrecy in use.
	KVMount string `env:"OPENBAO_KV_MOUNT" envDefault:"secret"`

	// StripePath is where the Stripe secrets live inside that mount.
	//
	// EMPTY MEANS "not in custody", and that is the switch: set, OpenBao is
	// authoritative and a missing value is a startup failure; unset, the
	// environment is used. There is deliberately no third mode where custody is
	// configured and the environment quietly fills a gap — a fallback that
	// silent means a rotation that failed to land looks like a rotation that
	// worked.
	StripePath string `env:"OPENBAO_STRIPE_PATH"`
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

	// A LIVE Stripe key outside production is a startup failure (ADR-008,
	// billing.md §5 case 20).
	//
	// Stripe distinguishes test from live by key prefix and nothing else: same
	// code path, same API, real money. So a live key in a developer's .env, or
	// in staging, does not misbehave — it works, and charges real cards against
	// real customers while every test passes. There is no runtime signal for
	// this and no way to undo it afterwards, which is why it is refused here
	// rather than warned about.
	if c.Env != Production && c.Stripe.Live() {
		add("STRIPE_SECRET_KEY is a LIVE key and APP_ENV is %q; a live key outside production "+
			"charges real cards while everything appears to work. Use a test key (sk_test_ "+
			"or rk_test_)", c.Env)
	}

	// A trial length Stripe cannot honour. Its maximum is 730 days, and a
	// non-positive trial is not a cardless trial at all — it is an immediate
	// charge against a customer who has given no payment method, which fails.

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

	// A batch holds every event's decoded payload in memory and holds one pooled
	// connection for as long as it takes to send, so an unbounded batch trades a
	// round trip for a stall.
	if c.Projector.CatchUpBatch < 1 {
		add("PROJECTOR_CATCHUP_BATCH must be at least 1, got %d (1 disables batching)",
			c.Projector.CatchUpBatch)
	}
	if c.Projector.CatchUpBatch > MaxCatchUpBatch {
		add("PROJECTOR_CATCHUP_BATCH %d exceeds the %d cap", c.Projector.CatchUpBatch, MaxCatchUpBatch)
	}
	if c.Projector.RebuildEventsPerSecond < 0 {
		add("PROJECTOR_REBUILD_EVENTS_PER_SECOND cannot be negative, got %d (0 is unthrottled)",
			c.Projector.RebuildEventsPerSecond)
	}
	// A zero-length announcement queue would drop every announcement while still
	// paying for the goroutine — silently turning realtime off.
	if c.Projector.AnnounceBuffer < 1 {
		add("PROJECTOR_ANNOUNCE_BUFFER must be at least 1, got %d: a zero-length queue "+
			"drops every announcement and turns realtime off without saying so",
			c.Projector.AnnounceBuffer)
	}

	if c.Tracing.Enabled && strings.TrimSpace(c.Tracing.Endpoint) == "" {
		add("OTEL_EXPORTER_OTLP_ENDPOINT is required when OTEL_ENABLED is true")
	}

	// The pprof surface. Every rule below refuses a combination that WORKS —
	// which is the point: a profiler bound to a routable address with no token
	// serves heap dumps and goroutine stacks to anyone who can reach the port,
	// and it does so with no error, no log line and no metric. The only moment
	// this is detectable is at startup, so this is where it is detected.
	if c.Profiling.Enabled {
		host, port, err := net.SplitHostPort(c.Profiling.Addr)
		switch {
		case err != nil:
			add("PPROF_ADDR %q is not a host:port: %v", c.Profiling.Addr, err)
		case port == "":
			add("PPROF_ADDR %q names no port", c.Profiling.Addr)
		default:
			// A wildcard or routable bind is a network-reachable heap dump. It is
			// allowed — a port-forward is not always available — but only behind a
			// credential, in every environment including local.
			if !isLoopbackHost(host) && c.Profiling.Token.IsZero() {
				add("PPROF_ADDR %q is not loopback and PPROF_TOKEN is empty: the profiler "+
					"would serve live heap contents and every goroutine's stack — bearer "+
					"tokens and email addresses among them — to anyone who can reach the "+
					"port (ADR-002)", c.Profiling.Addr)
			}
		}
		// Outside local, loopback is not a boundary. Every process in the pod
		// shares it, and `kubectl exec` into any container in it lands inside.
		if !c.Env.IsLocal() && c.Profiling.Token.IsZero() {
			add("PPROF_TOKEN must be set when PPROF_ENABLED is true and APP_ENV=%s: a "+
				"container's loopback is shared by every process in the pod, so binding "+
				"it is not an access control", c.Env)
		}
		if n := len(c.Profiling.Token.Expose()); n > 0 && n < MinProfilingTokenLength {
			add("PPROF_TOKEN is %d characters; the floor is %d. There is no lockout on a "+
				"debug listener, and what it guards is a heap dump",
				n, MinProfilingTokenLength)
		}
	}

	// The movable clock (ADR-054). Both rules below refuse a configuration that
	// WORKS, which is the whole point — a process whose clock a caller can push
	// forward is a process where every lockout, every token expiry and every
	// TOTP step is negotiable, and none of that produces an error, a metric or a
	// log line at the moment it is abused. Startup is the only place it is
	// detectable, so this is where it is detected.
	if c.ClockControl.Enabled {
		if !c.Env.IsLocal() {
			add("CLOCK_CONTROL_ENABLED is true and APP_ENV=%s: the movable clock is a "+
				"LOCAL-ONLY test control. Outside local it would let anyone who can reach "+
				"its port expire a session, elapse an account lockout and roll a TOTP "+
				"step on demand, with nothing in the request path able to tell the "+
				"difference from time actually passing (ADR-054)", c.Env)
		}
		host, port, err := net.SplitHostPort(c.ClockControl.Addr)
		switch {
		case err != nil:
			add("CLOCK_CONTROL_ADDR %q is not a host:port: %v", c.ClockControl.Addr, err)
		case port == "":
			add("CLOCK_CONTROL_ADDR %q names no port", c.ClockControl.Addr)
		case !isLoopbackHost(host):
			// No token option here, unlike PPROF_TOKEN. A credential would make a
			// routable bind *survivable*; it would not make it a good idea, and
			// there is no diagnostic this surface offers that a port-forward or a
			// loopback bind does not.
			add("CLOCK_CONTROL_ADDR %q is not loopback: the movable clock is never "+
				"offered on a routable interface, in any environment", c.ClockControl.Addr)
		}
	}

	// A task queue nobody agrees on is the failure mode Temporal makes hardest to
	// see: the run is created, the caller is told it started, and it sits in a
	// queue no worker polls.
	if c.Temporal.Enabled {
		if strings.TrimSpace(c.Temporal.HostPort) == "" {
			add("TEMPORAL_HOSTPORT is required when TEMPORAL_ENABLED is true")
		}
		if strings.TrimSpace(c.Temporal.Queue) == "" {
			add("TEMPORAL_TASK_QUEUE is required when TEMPORAL_ENABLED is true: work queued " +
				"where no worker listens is created and then never runs")
		}
		if strings.TrimSpace(c.Temporal.Namespace) == "" {
			add("TEMPORAL_NAMESPACE is required when TEMPORAL_ENABLED is true")
		}
	}

	// The idempotency TTL is how long a stored response stays replayable, and a
	// stored response can carry personal data — so it is a retention bound, and
	// an unbounded one is a compliance problem rather than a tuning mistake.
	if c.API.IdempotencyTTL <= 0 {
		add("API_IDEMPOTENCY_TTL must be positive, got %s: a record with no expiry is "+
			"replayable forever", c.API.IdempotencyTTL)
	}
	if c.API.IdempotencyTTL > MaxIdempotencyTTL {
		add("API_IDEMPOTENCY_TTL %s exceeds the %s cap: a mutation's response would be "+
			"retained past any use for it", c.API.IdempotencyTTL, MaxIdempotencyTTL)
	}
	// A sweep slower than the TTL leaves expired records — and the personal data
	// in them — sitting in the table between runs. The read path already refuses
	// to replay them, so this is about retention, not correctness.
	if c.API.IdempotencySweepEvery <= 0 {
		add("API_IDEMPOTENCY_SWEEP_EVERY must be positive, got %s: nothing would ever delete "+
			"an expired record", c.API.IdempotencySweepEvery)
	}
	if c.API.IdempotencyWait < 0 {
		add("API_IDEMPOTENCY_WAIT must not be negative, got %s", c.API.IdempotencyWait)
	}

	// The trust boundary for X-Forwarded-For. Both bounds are refused at boot
	// because neither mistake has a runtime symptom: a negative value is a typo,
	// and a value above the cap silently hands the rate-limit bucket key to
	// whoever is calling.
	if c.API.TrustedProxyHops < 0 {
		add("API_TRUSTED_PROXY_HOPS is %d; it cannot be negative (0 means trust nothing "+
			"and scope per-caller limits by the connection's peer address)",
			c.API.TrustedProxyHops)
	}
	if c.API.TrustedProxyHops > MaxTrustedProxyHops {
		add("API_TRUSTED_PROXY_HOPS %d exceeds the cap of %d: set it to the number of "+
			"proxies that APPEND to X-Forwarded-For and no more, because every hop above "+
			"that number selects an entry the caller wrote, which makes the client "+
			"address — and therefore every per-caller rate-limit bucket — spoofable",
			c.API.TrustedProxyHops, MaxTrustedProxyHops)
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

	c.validateIdentity(add)

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(problems, "\n  - "))
}

// validateIdentity checks the identity key material.
//
// Split out of validate because it has a shape the rest of that function does
// not: the keys are optional as a SET and mandatory individually once any of
// them is present. Half-configured identity is the dangerous state — two of
// three keys present means the module cannot be built, and a reader looking at
// the environment sees identity keys and concludes login works.
func (c *Config) validateIdentity(add func(string, ...any)) {
	id := c.Identity

	// Outside local, a server with no identity keys serves no login at all. That
	// is a deployment mistake rather than a degraded dependency, so it stops the
	// boot rather than being reported by a probe.
	if !c.Env.IsLocal() && !id.Configured() {
		add("IDENTITY_EMAIL_INDEX_KEY, IDENTITY_PASSWORD_PEPPER_KEY and IDENTITY_TOTP_SEAL_KEY "+
			"must all be set when APP_ENV=%s: without them no identity service can be built "+
			"and the server would start serving no registration, no login and no session", c.Env)
	}

	// Each key that IS present must be usable, whatever the environment. A
	// malformed key is never a deliberate "identity is off" — it is a typo, and
	// discovering it from a constructor at wiring time costs an incident.
	for name, key := range map[string]Secret{
		"IDENTITY_EMAIL_INDEX_KEY":     id.EmailIndexKey,
		"IDENTITY_PASSWORD_PEPPER_KEY": id.PasswordPepperKey,
		"IDENTITY_TOTP_SEAL_KEY":       id.TotpSealKey,
	} {
		if key.IsZero() {
			if id.Configured() {
				continue
			}
			// Some keys set and this one not: name it, because the partial state
			// is exactly what looks configured and is not.
			if !id.EmailIndexKey.IsZero() || !id.PasswordPepperKey.IsZero() || !id.TotpSealKey.IsZero() {
				add("%s is not set while other identity keys are: identity cannot be built "+
					"from a partial key set, so login is off despite the configuration "+
					"suggesting otherwise", name)
			}
			continue
		}
		if _, err := decodeIdentityKey(name, key); err != nil {
			add("%s", err.Error())
		}
	}

	// A version below 1 is invisible to the rotation work list, which selects on
	// `pepper_version < n`. The row is skipped silently and the account loses its
	// password — or its second factor — when the old key is destroyed.
	if id.PasswordPepperVersion < 1 {
		add("IDENTITY_PASSWORD_PEPPER_VERSION is %d; a verifier stored below version 1 is "+
			"invisible to key rotation and is lost when the old key is destroyed",
			id.PasswordPepperVersion)
	}
	if id.TotpSealKeyVersion < 1 {
		add("IDENTITY_TOTP_SEAL_KEY_VERSION is %d; a TOTP secret stored below version 1 is "+
			"invisible to key rotation", id.TotpSealKeyVersion)
	}

	if strings.TrimSpace(id.TotpIssuer) == "" {
		add("IDENTITY_TOTP_ISSUER must not be empty: it is the label a user sees above the " +
			"account in their authenticator app, and an unlabelled entry is one people delete")
	}

	// Negative is refused; zero means "resolve it from the CPU limit".
	if id.PasswordHashConcurrency < 0 {
		add("IDENTITY_PASSWORD_HASH_CONCURRENCY is %d; it must be zero (resolve from the "+
			"container's CPU limit) or positive", id.PasswordHashConcurrency)
	}
	// Each concurrent hash holds 32 MiB for its whole duration, so this bound IS
	// the memory ceiling on password verification. Measured on an 11-core machine:
	// 128 concurrent hashes is 4 GiB spent to do slightly less work than 16.
	if id.PasswordHashConcurrency > MaxPasswordHashConcurrency {
		add("IDENTITY_PASSWORD_HASH_CONCURRENCY %d exceeds the %d cap: at 32 MiB per hash "+
			"that is %d MiB of resident memory reachable by unauthenticated requests, and "+
			"throughput saturates at the core count long before it",
			id.PasswordHashConcurrency, MaxPasswordHashConcurrency,
			id.PasswordHashConcurrency*32)
	}
}

// MaxPasswordHashConcurrency caps IDENTITY_PASSWORD_HASH_CONCURRENCY.
//
// 256 concurrent hashes is 8 GiB of Argon2id working set, which is already well
// past any machine on which the setting is a good idea. The cap exists because
// the value is reachable by unauthenticated traffic: it is the supply-side half
// of the pair of controls that stop password verification being a memory
// amplification vector.
const MaxPasswordHashConcurrency = 256

// ErrMissing is returned when a required variable is absent.
var ErrMissing = errors.New("config: required environment variable is not set")

// PasswordPepperKeySet and TotpSealKeySet return every key version the process
// must be able to OPEN, current included, ready for argon2id.NewPepperKeys and
// totpseal.NewKeys.
//
// One function per key set rather than one shared helper taking two fields,
// because the error messages name the variable an operator has to fix, and a
// shared helper would either lose that or take the name as an argument nobody
// checks against the field it was read from.
func (i IdentityConfig) PasswordPepperKeySet() (map[int][]byte, error) {
	return identityKeySet(
		"IDENTITY_PASSWORD_PEPPER_KEY", i.PasswordPepperKey, i.PasswordPepperVersion,
		"IDENTITY_PASSWORD_PEPPER_RETIRED", i.PasswordPepperRetired)
}

func (i IdentityConfig) TotpSealKeySet() (map[int][]byte, error) {
	return identityKeySet(
		"IDENTITY_TOTP_SEAL_KEY", i.TotpSealKey, i.TotpSealKeyVersion,
		"IDENTITY_TOTP_SEAL_RETIRED", i.TotpSealRetired)
}

// identityKeySet merges the current key with the retired list.
//
// Every failure here is refused at BOOT rather than tolerated, and that is the
// whole design. A malformed retired list means some rows cannot be opened, and
// the symptom is a subset of users unable to authenticate — distributed over
// whoever happens not to have been re-sealed yet, which is the hardest possible
// shape to diagnose from a bug report. A startup error naming the variable costs
// one failed deploy instead.
func identityKeySet(
	currentName string, current Secret, currentVersion int,
	retiredName string, retired Secret,
) (map[int][]byte, error) {
	if err := validVersionNumber(currentName+"_VERSION", currentVersion); err != nil {
		return nil, err
	}
	key, err := decodeIdentityKey(currentName, current)
	if err != nil {
		return nil, err
	}
	set := map[int][]byte{currentVersion: key}

	for entry := range strings.SplitSeq(retired.Expose(), ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		version, material, found := strings.Cut(entry, ":")
		if !found {
			// The value is NOT echoed. This variable is entirely key material, and
			// an error string is the one place a key most reliably reaches a log
			// aggregator.
			return nil, fmt.Errorf("%s: an entry is not in `version:hex` form", retiredName)
		}
		n, convErr := strconv.Atoi(strings.TrimSpace(version))
		if convErr != nil {
			return nil, fmt.Errorf("%s: %q is not a version number", retiredName, version)
		}
		if err := validVersionNumber(retiredName, n); err != nil {
			return nil, err
		}
		if n == currentVersion {
			// Refused rather than merged. Two entries for one version is either a
			// copy-paste of the current key — harmless but a lie about what is
			// retired — or two DIFFERENT keys for one version, which silently
			// decides that half the rows at that version can never be opened.
			return nil, fmt.Errorf("%s: version %d is also %s_VERSION; a version has exactly "+
				"one key", retiredName, n, currentName)
		}
		if _, dup := set[n]; dup {
			return nil, fmt.Errorf("%s: version %d appears twice", retiredName, n)
		}
		decoded, err := decodeIdentityKey(retiredName, Secret(strings.TrimSpace(material)))
		if err != nil {
			return nil, err
		}
		set[n] = decoded
	}
	return set, nil
}

// validVersionNumber refuses a version below 1.
//
// Zero is the zero value of the `pepper_version` column, so a row written at 0 is
// invisible to the re-sealing job's `pepper_version < n` work list: it is skipped
// silently, the operator's done check reports zero rows outstanding, and the
// account loses its credential when the old key is destroyed.
// isLoopbackHost reports whether a bind host reaches only this machine.
//
// The empty host is the WILDCARD — ":6060" binds every interface — so it is
// deliberately not loopback. Getting that backwards is the single mistake this
// helper exists to prevent.
func isLoopbackHost(host string) bool {
	switch host {
	case "":
		return false
	case "localhost":
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validVersionNumber(name string, v int) error {
	if v < 1 {
		return fmt.Errorf("%s is %d; a key version must be at least 1, because 0 is "+
			"indistinguishable from an unset column and the re-sealing job cannot see it", name, v)
	}
	return nil
}

// SecretSource reads named secrets out of custody.
//
// Declared here rather than in the adapter because this is the package that
// knows WHICH fields are secret — the adapter only knows how to read a path.
type SecretSource interface {
	Values(ctx context.Context, path string) (map[string]string, error)
}

// ResolveSecrets overlays values held in custody onto the parsed config.
//
// # Why this is a separate step and not part of Load
//
// Load is pure: it parses the environment and validates it, with no I/O and no
// context. Folding a network read into it would make configuration loading fail
// on a blip, make every config test need a server, and make the failure arrive
// as "bad configuration" when the configuration is fine and OpenBao is down.
//
// So each binary calls this after Load, and the two failures stay distinct.
//
// # It is a no-op when custody is not configured
//
// Local development keeps its .env, which is the point of .env. Custody is
// switched on by naming a path, and from that moment it is AUTHORITATIVE: a key
// the path does not carry is an error rather than a silent fall back to the
// environment. A fallback would make a rotation that failed to land look exactly
// like a rotation that worked, which is the failure BILLING-PLAN.md §7's overlap
// window exists to avoid in the other direction.
func (c *Config) ResolveSecrets(ctx context.Context, src SecretSource) error {
	if c.OpenBao.StripePath == "" {
		return nil
	}
	if src == nil {
		return fmt.Errorf("config: OPENBAO_STRIPE_PATH names %q but no secret source was "+
			"wired, so the Stripe secrets would silently come from the environment that "+
			"setting exists to stop being trusted", c.OpenBao.StripePath)
	}

	values, err := src.Values(ctx, c.OpenBao.StripePath)
	if err != nil {
		return fmt.Errorf("config: reading Stripe secrets from custody: %w", err)
	}

	// The API key is REQUIRED once custody is on. The two webhook secrets are
	// not: a deployment that has not yet rotated has only one, and the previous
	// one is legitimately absent (billing.md §5 case 26).
	apiKey, ok := values["api_key"]
	if !ok || apiKey == "" {
		return fmt.Errorf("config: %q carries no non-empty api_key; custody is configured, "+
			"so this is a deployment step nobody ran rather than a reason to fall back to "+
			"the environment", c.OpenBao.StripePath)
	}
	c.Stripe.SecretKey = Secret(apiKey)

	if v, ok := values["webhook_secret"]; ok {
		c.Stripe.WebhookSecret = Secret(v)
	}
	if v, ok := values["webhook_secret_previous"]; ok {
		c.Stripe.WebhookSecretPrevious = Secret(v)
	}

	// Re-validated, because a value from custody has had none of the checks
	// Load applied to the environment — and the one that matters most is
	// ADR-008's: a LIVE key outside production is a startup failure however it
	// arrived, and custody is the more likely place for one to appear.
	return c.validate()
}

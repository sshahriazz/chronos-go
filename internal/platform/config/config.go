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
	if c.Postgres.MaxConns < 1 {
		add("POSTGRES_MAX_CONNS must be at least 1, got %d", c.Postgres.MaxConns)
	}

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(problems, "\n  - "))
}

// ErrMissing is returned when a required variable is absent.
var ErrMissing = errors.New("config: required environment variable is not set")

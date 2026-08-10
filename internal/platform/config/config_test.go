package config_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/config"
)

// minimum viable environment; individual tests override single keys
func base() map[string]string {
	// Every variable marked required in config.go must appear here. If one is
	// missing, these tests pass only when the developer's shell happens to
	// carry it — and fail in CI, which has no .env.
	return map[string]string{
		"POSTGRES_USER":         "chronos",
		"POSTGRES_PASSWORD":     "hunter2",
		"POSTGRES_APP_PASSWORD": "hunter3",
		"POSTGRES_DB":           "chronos",
		"OPENFGA_PRESHARED_KEY": "k",
	}
}

func withEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

func TestLoad_Defaults(t *testing.T) {
	withEnv(t, base())
	c, err := config.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Env != config.Local {
		t.Errorf("env: got %q want local", c.Env)
	}
	if c.Location().String() != "UTC" {
		t.Errorf("ADR-008: default timezone must be UTC, got %s", c.Location())
	}
}

func TestLoad_MissingRequiredIsAStartupFailure(t *testing.T) {
	e := base()
	delete(e, "POSTGRES_PASSWORD")
	withEnv(t, e)
	t.Setenv("POSTGRES_PASSWORD", "")

	if _, err := config.Load(); err == nil {
		t.Fatal("a missing required variable must fail at startup, not at request time")
	}
}

func TestValidate_ReportsEveryProblemAtOnce(t *testing.T) {
	withEnv(t, base())
	t.Setenv("APP_ENV", "nonsense")
	t.Setenv("APP_TIMEZONE", "Mars/Olympus")
	t.Setenv("POSTGRES_MAX_CONNS", "0")

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected failure")
	}
	msg := err.Error()
	for _, want := range []string{"APP_ENV", "APP_TIMEZONE", "POSTGRES_MAX_CONNS"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should name %s so all problems are fixed in one pass:\n%s", want, msg)
		}
	}
}

// ADR-014: an unauthenticated event store is local-only, enforced at boot.
func TestValidate_RefusesInsecureKurrentDBOutsideLocal(t *testing.T) {
	for _, env := range []string{"staging", "production"} {
		t.Run(env, func(t *testing.T) {
			withEnv(t, base())
			t.Setenv("APP_ENV", env)
			t.Setenv("KURRENTDB_CONNECTION_STRING", "kurrentdb://db:2113?tls=false")

			_, err := config.Load()
			if err == nil {
				t.Fatal("tls=false must be refused outside local")
			}
			if !strings.Contains(err.Error(), "ADR-014") {
				t.Errorf("error should cite the rule, got: %v", err)
			}
		})
	}
}

func TestValidate_AllowsInsecureKurrentDBLocally(t *testing.T) {
	withEnv(t, base())
	t.Setenv("APP_ENV", "local")
	t.Setenv("KURRENTDB_CONNECTION_STRING", "kurrentdb://localhost:2113?tls=false")
	if _, err := config.Load(); err != nil {
		t.Fatalf("local must permit tls=false: %v", err)
	}
}

// ADR-028: a dev-mode OpenBao token in production voids the erasure guarantee.
func TestValidate_RefusesDevVaultTokenOutsideLocal(t *testing.T) {
	withEnv(t, base())
	t.Setenv("APP_ENV", "production")
	t.Setenv("OPENBAO_DEV_TOKEN", "chronos_dev_root_token")

	_, err := config.Load()
	if err == nil {
		t.Fatal("a dev vault token must be refused in production")
	}
	if !strings.Contains(err.Error(), "ADR-028") {
		t.Errorf("error should cite the rule, got: %v", err)
	}
}

// The whole point of the Secret type: it cannot leak through logging.
func TestSecret_NeverRendersItsValue(t *testing.T) {
	s := config.Secret("super-secret-value")

	for name, got := range map[string]string{
		"String": s.String(),
		"%v":     fmt.Sprintf("%v", s),
		"%s":     fmt.Sprint(s),
		"%#v":    fmt.Sprintf("%#v", s),
		"%+v":    fmt.Sprintf("%+v", s),
	} {
		if strings.Contains(got, "super-secret-value") {
			t.Errorf("%s leaked the secret: %q", name, got)
		}
	}
	if s.Expose() != "super-secret-value" {
		t.Error("Expose must return the real value")
	}
}

// A struct containing secrets must not leak them when the whole struct is logged.
func TestSecret_DoesNotLeakViaEnclosingStruct(t *testing.T) {
	withEnv(t, base())
	t.Setenv("POSTGRES_PASSWORD", "hunter2")
	c, err := config.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if out := fmt.Sprintf(format, c.Postgres); strings.Contains(out, "hunter2") {
			t.Errorf("%s leaked the password: %s", format, out)
		}
	}
}

func TestTimezone_IsPresentationOnly(t *testing.T) {
	withEnv(t, base())
	t.Setenv("APP_TIMEZONE", "Asia/Dhaka")
	c, err := config.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Location().String() != "Asia/Dhaka" {
		t.Fatalf("got %s want Asia/Dhaka", c.Location())
	}
	// Storage stays UTC regardless — asserted in the clock package, restated
	// here because the coupling is what the rule is about (ADR-008).
}

// Mail carries password-reset links and sign-in alerts. Plaintext SMTP puts
// those on the wire, so it is a startup failure outside local.
func TestValidate_RefusesPlaintextSMTPOutsideLocal(t *testing.T) {
	for _, env := range []string{"staging", "production"} {
		t.Run(env, func(t *testing.T) {
			e := base()
			e["APP_ENV"] = env
			e["KURRENTDB_CONNECTION_STRING"] = "kurrentdb://es:2113?tls=true"
			e["SMTP_STARTTLS"] = "false"
			withEnv(t, e)

			_, err := config.Load()
			if err == nil {
				t.Fatal("plaintext SMTP must be refused outside local")
			}
			if !strings.Contains(err.Error(), "SMTP_STARTTLS") {
				t.Errorf("error should name the variable, got: %v", err)
			}
		})
	}
}

func TestValidate_AllowsPlaintextSMTPLocally(t *testing.T) {
	e := base()
	e["SMTP_STARTTLS"] = "false"
	withEnv(t, e)
	if _, err := config.Load(); err != nil {
		t.Fatalf("local must permit plaintext SMTP for Mailpit: %v", err)
	}
}

// The PII key cache TTL is the window in which an erased subject's key can still
// decrypt their data in a replica that missed the invalidation. Nothing at
// runtime reveals a value set too high — no error, no log line, only a guarantee
// quietly weakened — so the ceiling is enforced at startup.
func TestValidate_CapsPIIKeyCacheTTL(t *testing.T) {
	withEnv(t, base())
	withEnv(t, map[string]string{"PII_KEY_CACHE_TTL": "1h"})

	_, err := config.Load()
	if err == nil {
		t.Fatal("a one-hour key cache TTL must be refused at startup")
	}
	if !strings.Contains(err.Error(), "PII_KEY_CACHE_TTL") {
		t.Fatalf("the error must name the variable, got %q", err)
	}
	// The message has to say what the number MEANS, or whoever raised it will
	// simply raise the ceiling too.
	if !strings.Contains(err.Error(), "erased") {
		t.Fatalf("the error must explain the consequence, got %q", err)
	}
}

func TestValidate_RefusesUnboundedPIIKeyCache(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"zero ttl":       {"PII_KEY_CACHE_TTL": "0"},
		"zero capacity":  {"PII_KEY_CACHE_CAPACITY": "0"},
		"zero sweep":     {"PII_KEY_CACHE_SWEEP": "0"},
		"sweep over ttl": {"PII_KEY_CACHE_TTL": "10s", "PII_KEY_CACHE_SWEEP": "30s"},
	} {
		t.Run(name, func(t *testing.T) {
			withEnv(t, base())
			withEnv(t, env)
			if _, err := config.Load(); err == nil {
				t.Fatalf("%s must be refused: it leaves destroyed key material resident", name)
			}
		})
	}
}

func TestPIIKeyCacheDefaultsAreWithinTheCeiling(t *testing.T) {
	withEnv(t, base())
	c, err := config.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Valkey.KeyCacheTTL > config.MaxKeyCacheTTL {
		t.Fatalf("the default TTL %s exceeds its own ceiling %s",
			c.Valkey.KeyCacheTTL, config.MaxKeyCacheTTL)
	}
	if c.Valkey.KeyCacheSweep > c.Valkey.KeyCacheTTL {
		t.Fatalf("the default sweep %s is longer than the default TTL %s",
			c.Valkey.KeyCacheSweep, c.Valkey.KeyCacheTTL)
	}
	if len(c.Valkey.Addr) == 0 {
		t.Fatal("VALKEY_ADDR has no default")
	}
}

// Each rebuild shard holds a pooled connection for the whole rebuild, so more
// shards than the pool has connections deadlocks the rebuild against itself —
// the same failure already verified for projection leases, where a 3-connection
// pool with 3 leases could not execute SELECT 1.
func TestValidate_RebuildShardsMustFitThePool(t *testing.T) {
	withEnv(t, base())
	withEnv(t, map[string]string{
		"PROJECTOR_REBUILD_SHARDS": "8",
		"POSTGRES_MAX_CONNS":       "4",
	})
	_, err := config.Load()
	if err == nil {
		t.Fatal("more shards than pool connections must be refused at startup")
	}
	if !strings.Contains(err.Error(), "PROJECTOR_REBUILD_SHARDS") {
		t.Fatalf("the error must name the variable, got %q", err)
	}
}

func TestValidate_RebuildShardsBounds(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"zero":          {"PROJECTOR_REBUILD_SHARDS": "0"},
		"above the cap": {"PROJECTOR_REBUILD_SHARDS": "64", "POSTGRES_MAX_CONNS": "200"},
	} {
		t.Run(name, func(t *testing.T) {
			withEnv(t, base())
			withEnv(t, env)
			if _, err := config.Load(); err == nil {
				t.Fatalf("%s must be refused", name)
			}
		})
	}
}

// The default must be the sequential path: sharding is a decision, not something
// a deployment acquires by upgrading.
func TestRebuildShardsDefaultsToSequential(t *testing.T) {
	withEnv(t, base())
	c, err := config.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Projector.RebuildShards != 1 {
		t.Fatalf("default rebuild shards = %d, want 1", c.Projector.RebuildShards)
	}
}

package config_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/config"
)

// minimum viable environment; individual tests override single keys
func base() map[string]string {
	return map[string]string{
		"POSTGRES_USER":         "chronos",
		"POSTGRES_PASSWORD":     "hunter2",
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

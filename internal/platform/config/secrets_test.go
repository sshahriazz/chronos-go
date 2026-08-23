package config_test

import (
	"context"
	"errors"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/config"
)

type stubSource struct {
	values map[string]string
	err    error
	path   string
	calls  int
}

func (s *stubSource) Values(_ context.Context, path string) (map[string]string, error) {
	s.calls++
	s.path = path
	return s.values, s.err
}

// custodyConfig loads a config with custody switched on.
func custodyConfig(t *testing.T, path string) *config.Config {
	t.Helper()
	for k, v := range map[string]string{
		"POSTGRES_DB": "chronos", "POSTGRES_USER": "chronos",
		"POSTGRES_PASSWORD": "x", "POSTGRES_APP_PASSWORD": "y",
		"OPENFGA_PRESHARED_KEY": "k",
		"STRIPE_SECRET_KEY":     "rk_test_from_the_environment",
		"OPENBAO_STRIPE_PATH":   path,
	} {
		t.Setenv(k, v)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

// CUSTODY OVERRIDES THE ENVIRONMENT.
//
// The point of naming a path is that the environment is no longer trusted for
// these values. A resolution that left the environment's copy in place would
// leave the process using exactly the source the operator said not to.
func TestCustodyOverridesTheEnvironment(t *testing.T) {
	cfg := custodyConfig(t, "chronos/stripe")
	if cfg.Stripe.SecretKey.Expose() != "rk_test_from_the_environment" {
		t.Fatalf("the fixture did not load the environment's key")
	}

	src := &stubSource{values: map[string]string{
		"api_key":                 "rk_test_from_custody",
		"webhook_secret":          "whsec_current",
		"webhook_secret_previous": "whsec_previous",
	}}
	if err := cfg.ResolveSecrets(context.Background(), src); err != nil {
		t.Fatal(err)
	}

	if got := cfg.Stripe.SecretKey.Expose(); got != "rk_test_from_custody" {
		t.Errorf("the key is %q; the environment's copy survived custody", got)
	}
	if got := cfg.Stripe.WebhookSecret.Expose(); got != "whsec_current" {
		t.Errorf("the webhook secret is %q", got)
	}
	if got := cfg.Stripe.WebhookSecretPrevious.Expose(); got != "whsec_previous" {
		t.Errorf("the previous webhook secret is %q; a rotation in flight would drop "+
			"every event still signed with it", got)
	}
	if src.path != "chronos/stripe" {
		t.Errorf("read %q, want the configured path", src.path)
	}
}

// AN UNCONFIGURED CUSTODY IS A NO-OP, AND DOES NOT REACH FOR A SOURCE.
//
// Local development keeps its .env, which is what .env is for.
func TestWithoutAPathNothingIsResolved(t *testing.T) {
	cfg := custodyConfig(t, "")
	src := &stubSource{values: map[string]string{"api_key": "rk_test_from_custody"}}

	if err := cfg.ResolveSecrets(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	if src.calls != 0 {
		t.Error("custody was read even though no path is configured")
	}
	if got := cfg.Stripe.SecretKey.Expose(); got != "rk_test_from_the_environment" {
		t.Errorf("the key is %q, want the environment's", got)
	}
}

// A CONFIGURED PATH WITH NO SOURCE IS A FAILURE, NOT A FALLBACK.
//
// This is the wiring mistake worth catching: the setting is present, nothing
// implements it, and the process runs happily on the environment the setting
// exists to stop trusting.
func TestAConfiguredPathWithNoSourceIsRefused(t *testing.T) {
	cfg := custodyConfig(t, "chronos/stripe")

	if err := cfg.ResolveSecrets(context.Background(), nil); err == nil {
		t.Fatal("a configured custody path with no source was accepted; the process runs " +
			"on the environment the setting exists to stop trusting")
	}
}

// AN UNREADABLE CUSTODY IS A FAILURE.
//
// Falling back would use the environment at the exact moment something is
// wrong, and would do it silently.
func TestAnUnreadableCustodyIsRefused(t *testing.T) {
	cfg := custodyConfig(t, "chronos/stripe")
	unreachable := errors.New("openbao: connection refused")
	src := &stubSource{err: unreachable}

	err := cfg.ResolveSecrets(context.Background(), src)
	if err == nil {
		t.Fatal("an unreadable custody fell back to the environment")
	}
	// WRAPPED, not merely refused. Swallowing the read error still produces a
	// refusal — the nil map has no api_key, so the next check fails — and the
	// two are indistinguishable to a test that only asserts "an error came
	// back". They are not indistinguishable to a person: "OpenBao is down,
	// retry" and "custody was never populated, run the deployment step" have
	// different fixes, and an operator reading the wrong one at 3am tries the
	// wrong one.
	if !errors.Is(err, unreachable) {
		t.Fatalf("the failure is %v, which does not carry the read error; an outage now "+
			"reports as an unpopulated path and sends somebody to the wrong fix", err)
	}
	if got := cfg.Stripe.SecretKey.Expose(); got != "rk_test_from_the_environment" {
		t.Errorf("the key was changed to %q by a failed read", got)
	}
}

// A PATH WITH NO API KEY IS A FAILURE.
//
// Custody is configured, so this is a deployment step nobody ran — not a reason
// to use the environment. Both the missing key and the present-but-empty key,
// because an empty value in KV is the more likely of the two and produces an
// authentication error that reads like a revoked credential.
func TestAPathWithoutAnAPIKeyIsRefused(t *testing.T) {
	for name, values := range map[string]map[string]string{
		"absent": {"webhook_secret": "whsec_x"},
		"empty":  {"api_key": "", "webhook_secret": "whsec_x"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := custodyConfig(t, "chronos/stripe")
			if err := cfg.ResolveSecrets(context.Background(),
				&stubSource{values: values}); err == nil {
				t.Fatal("accepted; the process starts and fails at the moment a customer " +
					"tries to pay")
			}
		})
	}
}

// THE WEBHOOK SECRETS ARE OPTIONAL, AND THE PREVIOUS ONE ESPECIALLY SO.
//
// A deployment that has never rotated has only one; the previous one is
// legitimately absent (billing.md §5 case 26).
func TestOnlyTheAPIKeyIsRequired(t *testing.T) {
	cfg := custodyConfig(t, "chronos/stripe")

	if err := cfg.ResolveSecrets(context.Background(), &stubSource{
		values: map[string]string{"api_key": "rk_test_from_custody"},
	}); err != nil {
		t.Fatalf("a path with only an api_key was refused: %v", err)
	}
	if got := cfg.Stripe.SecretKey.Expose(); got != "rk_test_from_custody" {
		t.Errorf("the key is %q", got)
	}
}

// A LIVE KEY FROM CUSTODY STILL FAILS STARTUP OUTSIDE PRODUCTION.
//
// ADR-008 and billing.md §5 case 20. The check was written against the
// environment, and custody is the MORE likely place for a live key to appear —
// it is where the real ones are kept. Re-validating after the overlay is what
// makes the rule about the value rather than about where it came from.
func TestALiveKeyFromCustodyIsRefusedOutsideProduction(t *testing.T) {
	cfg := custodyConfig(t, "chronos/stripe")
	if cfg.Env.IsLocal() != true {
		t.Fatalf("the fixture is not local (%s); this test asserts the wrong thing", cfg.Env)
	}

	err := cfg.ResolveSecrets(context.Background(), &stubSource{
		values: map[string]string{"api_key": "sk_live_realmoney"},
	})
	if err == nil {
		t.Fatal("a LIVE Stripe key from custody started a non-production process; the " +
			"same code path, the same API, and real money")
	}
}

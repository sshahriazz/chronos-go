// Package stripetest gives integration tests the same trial Price production
// uses.
//
// # Why it exists
//
// The trial price id used to come from STRIPE_TRIAL_PRICE_ID, so every suite
// that needed one read the variable. The plan catalogue retired it: the worker
// mirrors the catalogue into Stripe at startup and asks it for the id. A test
// that kept reading a hand-set variable would be exercising a path the binary no
// longer has — and would pass against a Price nothing in the catalogue describes.
//
// Nothing outside a test imports this. It lives beside the adapter rather than
// in each suite so the three that need it cannot drift into three different
// answers to "which Price is the trial".
package stripetest

import (
	"context"
	"os"
	"strings"
	"testing"

	stripeadapter "github.com/chronos/chronos-go/internal/adapter/stripe"
	billingdomain "github.com/chronos/chronos-go/internal/modules/billing/domain"
)

// TrialPrice mirrors the published catalogue and returns the trial's Stripe
// price id, skipping the test when no key is configured.
//
// It really does mirror, rather than looking a Price up: the first run against a
// fresh test account has nothing to find, and a helper that only looked would
// make every suite depend on somebody having created the objects by hand.
func TrialPrice(ctx context.Context, t *testing.T) (string, billingdomain.PlanVersion) {
	t.Helper()

	key := Key(t)
	catalogue, err := billingdomain.Published()
	if err != nil {
		t.Fatalf("billing catalogue: %v", err)
	}
	trial, err := catalogue.Latest(billingdomain.TrialPlan, billingdomain.Monthly)
	if err != nil {
		t.Fatalf("the published catalogue has no trial plan: %v", err)
	}

	mirror, err := stripeadapter.NewMirror(key)
	if err != nil {
		t.Fatalf("stripe mirror: %v", err)
	}
	price, err := mirror.EnsurePrice(ctx, trial)
	if err != nil {
		t.Fatalf("mirroring %s: %v", trial.ID(), err)
	}
	return price, trial
}

// Key returns the Stripe test key, skipping when it is absent and FAILING when
// it is live.
//
// Live is a failure and not a skip, deliberately: these suites create customers
// and subscriptions, and against a live account that is real customer data and,
// the moment a price is not zero, real money. Skipping would let the mistake
// pass quietly.
func Key(t *testing.T) string {
	t.Helper()

	key := stripeKey()
	if key == "" {
		t.Skip("STRIPE_SECRET_KEY is not set")
	}
	if strings.Contains(key, "_live_") {
		t.Fatal("STRIPE_SECRET_KEY is a LIVE key; this suite creates customers, " +
			"subscriptions and Prices, and must only ever run against a test account")
	}
	return key
}

func stripeKey() string { return os.Getenv("STRIPE_SECRET_KEY") }

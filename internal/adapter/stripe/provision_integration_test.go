//go:build integration

package stripe_test

import (
	"context"
	"strings"
	"testing"
	"time"

	stripeadapter "github.com/chronos/chronos-go/internal/adapter/stripe"
	"github.com/chronos/chronos-go/internal/adapter/stripe/stripetest"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// provisioner builds one against the REAL Stripe test account.
//
// Skipped rather than failed when unconfigured: this suite runs in environments
// that have no Stripe credentials, and a hard failure there would say the code
// is broken when the environment simply is not set up.
func provisioner(t *testing.T) *stripeadapter.Provisioner {
	t.Helper()

	// The catalogue's Price and the catalogue's trial length, mirrored the same
	// way the worker mirrors them at startup. Reading STRIPE_TRIAL_PRICE_ID here
	// would exercise a path the binary no longer has.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	price, trial := stripetest.TrialPrice(ctx, t)

	p, err := stripeadapter.NewProvisioner(stripeadapter.Config{
		SecretKey: stripetest.Key(t), PriceID: price, TrialDays: trial.TrialDays,
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	return p
}

func freshOrgID() string {
	return ids.New[ids.Org](time.Now(), ids.Entropy()).String()
}

// A new organization gets a customer and a CARDLESS trialing subscription.
//
// This is the claim the whole cardless-trial design rests on, and only the real
// API can settle it: that a subscription can be created with a trial and NO
// payment method, and that Stripe reports a trial end for it.
func TestProvisioningCreatesACardlessTrial(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	orgID := freshOrgID()
	sub, err := provisioner(t).Provision(ctx, orgID, "sub_alice")
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	if !strings.HasPrefix(sub.CustomerID, "cus_") {
		t.Errorf("customer id %q does not look like a Stripe customer", sub.CustomerID)
	}
	if !strings.HasPrefix(sub.SubscriptionID, "sub_") {
		t.Errorf("subscription id %q does not look like a Stripe subscription", sub.SubscriptionID)
	}
	if sub.TrialEndsAt.IsZero() {
		t.Fatal("the subscription has no trial end. A trial that never ends is a free " +
			"forever account, and nothing in the system would alarm on it")
	}

	// Roughly fourteen days out. Asserted as a RANGE rather than an exact
	// timestamp: the deadline is Stripe's, computed from when Stripe received
	// the call, and pinning it to the second would make this test fail on a slow
	// network rather than on a wrong trial length.
	days := time.Until(sub.TrialEndsAt).Hours() / 24
	if days < 13 || days > 15 {
		t.Errorf("the trial ends in %.1f days, want ~14", days)
	}
	t.Logf("org %s -> customer %s, subscription %s, trial ends %s",
		orgID, sub.CustomerID, sub.SubscriptionID, sub.TrialEndsAt.Format(time.RFC3339))
}

// Provisioning the SAME organization twice yields the same objects.
//
// # Why this is the test that matters most in this file
//
// A reactor's delivery is at-least-once, so this WILL happen — a redelivery
// after a crash, a retry after a timeout. If the second call created a second
// customer with a second subscription, one organization would carry two
// subscriptions and the customer would be billed twice, with nothing in our
// system aware there were two.
//
// Both mechanisms are exercised at once: the metadata search, which has no
// expiry, and Stripe's own idempotency key, which covers the window before the
// search index catches up. Search is eventually consistent, which is precisely
// why both exist rather than either.
func TestProvisioningTwiceReturnsTheSameObjects(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	p := provisioner(t)
	orgID := freshOrgID()

	first, err := p.Provision(ctx, orgID, "sub_alice")
	if err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	second, err := p.Provision(ctx, orgID, "sub_alice")
	if err != nil {
		t.Fatalf("second Provision: %v", err)
	}

	if second.CustomerID != first.CustomerID {
		t.Errorf("a redelivery created a SECOND customer (%s then %s). One organization now "+
			"has two Stripe customers, and nothing in our system knows",
			first.CustomerID, second.CustomerID)
	}
	if second.SubscriptionID != first.SubscriptionID {
		t.Errorf("a redelivery created a SECOND subscription (%s then %s). The customer is "+
			"billed twice for one organization", first.SubscriptionID, second.SubscriptionID)
	}
}

// An organization id is required; provisioning without one cannot be idempotent.
func TestProvisioningWithoutAnOrganizationIsRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := provisioner(t).Provision(ctx, "", "sub_alice"); err == nil {
		t.Fatal("provisioning with no organization id was accepted; the id is what makes a " +
			"retry find the objects it already created")
	}
}

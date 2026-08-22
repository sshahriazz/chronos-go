//go:build integration

package stripe_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	stripeadapter "github.com/chronos/chronos-go/internal/adapter/stripe"
)

// portal builds one against the REAL Stripe test account.
//
// Skipped rather than failed when unconfigured, like the provisioner above: this
// suite runs where there are no Stripe credentials, and failing there would say
// the code is broken when the environment simply is not set up.
func portal(t *testing.T) *stripeadapter.Portal {
	t.Helper()

	key := os.Getenv("STRIPE_SECRET_KEY")
	if key == "" {
		t.Skip("STRIPE_SECRET_KEY is not set")
	}
	if strings.Contains(key, "_live_") {
		t.Fatal("STRIPE_SECRET_KEY is a LIVE key; this test mints portal sessions against " +
			"real customers and must only ever run against a test account")
	}

	p, err := stripeadapter.NewPortal(stripeadapter.PortalConfig{SecretKey: key})
	if err != nil {
		t.Fatalf("NewPortal: %v", err)
	}
	return p
}

// A REAL PORTAL SESSION IS MINTED FOR A REAL CUSTOMER.
//
// Only the live API settles this, and there are two claims in it that no unit
// test can reach. That the Customer Portal accepts a customer created by OUR
// provisioner — one with no payment method and a trialing subscription, which is
// the exact shape a cardless trial produces and the one somebody would expect
// the Portal to refuse. And that the account's Portal is CONFIGURED at all: an
// unconfigured Portal fails here with a message telling you to go and set it up
// in the Dashboard, which is a fact about the account that no amount of correct
// code substitutes for.
//
// The customer is provisioned rather than fabricated, so what is exercised is
// the object this system actually creates.
func TestAPortalSessionIsMintedForAProvisionedCustomer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sub, err := provisioner(t).Provision(ctx, freshOrgID(), "sub_portal")
	if err != nil {
		t.Fatalf("provisioning a customer to mint against: %v", err)
	}

	session, err := portal(t).Session(ctx, sub.CustomerID, "https://app.example.com/billing")
	if err != nil {
		t.Fatalf("creating a portal session for %s: %v\n\n"+
			"If this says the portal is not configured, that is an ACCOUNT fact, not a code "+
			"one: the Customer Portal's settings are configured once in the Stripe Dashboard "+
			"and no session can be created until they are. Nothing in this repository can "+
			"detect that state in advance.", sub.CustomerID, err)
	}

	if !strings.HasPrefix(session.URL, "https://") {
		t.Errorf("the session url is %q; a browser is redirected there, so anything but "+
			"https is both a downgrade and a broken payment page", session.URL)
	}
}

// A SESSION FOR A CUSTOMER THAT DOES NOT EXIST FAILS, RATHER THAN RETURNING A
// URL TO NOWHERE.
//
// The failure that matters is the silent one: a link that renders in a billing
// screen and 404s when the customer clicks it, at the moment they were going to
// pay. Asserted against the real API because it is Stripe's behaviour under
// test, not ours.
func TestAPortalSessionForAnUnknownCustomerFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := portal(t).Session(ctx,
		"cus_00000000000000", "https://app.example.com/billing")
	if err == nil {
		t.Fatal("Stripe minted a session for a customer that does not exist; that url " +
			"renders in a billing screen and fails when somebody clicks it")
	}
}

package main

import (
	"log/slog"
	"net/http"
	"testing"

	"github.com/chronos/chronos-go/gen/proto/chronos/billing/v1/billingv1connect"
)

// BILLINGSERVICE MUST BE REGISTERED, AND ITS ABSENCE IS THE QUIETEST FAILURE
// IN THE COMMERCIAL PATH.
//
// The trial is cardless, and the subscription is created with
// `trial_settings.end_behavior.missing_payment_method = pause`. So a trial that
// ends with no card leaves the organization Suspended — deliberately reversible,
// because a customer who forgot a card has not closed their account.
//
// The Customer Portal is the ONLY thing that reverses it. It is also the only
// way a card is ever added at all: there is no card field of ours, by design.
// So without this service registered, every trial in the system has exactly one
// outcome, no customer can pay, and no suspended tenant can recover — and
// nothing anywhere errors, because from the server's side nobody asked.
//
// Only a test of the COMPOSITION ROOT can see it. The adapter, the use case and
// the handler all pass their own tests while reaching no URL.
func TestBillingServiceIsRegistered(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.billing == nil {
		t.Fatal("no billing service was constructed: the Customer Portal is the only way a " +
			"card is ever added, so no trial can convert and no suspended tenant can pay")
	}

	if !servesBilling(t, d) {
		t.Fatalf("the service exists but %s is not routed; every call answers 404 while "+
			"every unit test below it passes", billingv1connect.BillingServiceName)
	}
}

// servesBilling reports whether the mux the server actually builds routes the
// billing service.
//
// Constructing the service is not the same as serving it, and the two failures
// look identical from every layer below: `d.billing` can be non-nil while the
// registration block that mounts it was never written.
func servesBilling(t *testing.T, d *dependencies) bool {
	t.Helper()
	served := registerServices(http.NewServeMux(), d, testConfig(t),
		testSystemService(t), slog.New(slog.DiscardHandler))
	for _, name := range served {
		if name == billingv1connect.BillingServiceName {
			return true
		}
	}
	return false
}

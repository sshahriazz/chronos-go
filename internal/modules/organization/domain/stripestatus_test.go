package domain_test

import (
	"testing"

	"github.com/chronos/chronos-go/internal/modules/organization/domain"
)

// EVERY Stripe subscription status maps somewhere deliberate.
//
// The expectation is transcribed from billing.md §3 and BILLING-PLAN §1,
// independently of the switch under test. A status that fell through to a
// default would move a real tenant into a lifecycle state nobody chose, and the
// only signal would be a customer asking why their account stopped working.
func TestEveryStripeStatusMaps(t *testing.T) {
	t.Parallel()

	want := map[domain.StripeStatus]domain.Status{
		domain.StripeTrialing: domain.StatusTrialing,
		domain.StripeActive:   domain.StatusActive,

		// SCA on a renewal. The subscription was already active, so dunning
		// handles it; there is no pending state to fall back to.
		domain.StripeIncomplete: domain.StatusPastDue,
		domain.StripePastDue:    domain.StatusPastDue,

		// The cardless trial lapsing, and payment retries exhausted. Both are
		// recoverable, and neither destroys anything.
		domain.StripePaused: domain.StatusSuspended,
		domain.StripeUnpaid: domain.StatusSuspended,

		domain.StripeCanceled: domain.StatusClosed,

		// No producer once the trial is cardless: nothing charges at signup, so
		// no first payment can expire. Refused rather than guessed.
		domain.StripeIncompleteExpired: domain.StatusUnknown,
	}

	for _, s := range domain.StripeStatuses() {
		t.Run(string(s), func(t *testing.T) {
			got := domain.StatusFromStripe(s)
			if got != want[s] {
				t.Errorf("Stripe %q maps to %q, want %q", s, got, want[s])
			}
		})
	}
	if len(want) != len(domain.StripeStatuses()) {
		t.Errorf("the expectation covers %d statuses and Stripe documents %d",
			len(want), len(domain.StripeStatuses()))
	}
}

// A status Stripe invents later is refused, not defaulted.
func TestAnUnknownStripeStatusIsRefused(t *testing.T) {
	t.Parallel()

	if got := domain.StatusFromStripe("something_stripe_added"); got != domain.StatusUnknown {
		t.Errorf("an unrecognised Stripe status mapped to %q; a tenant would be moved into a "+
			"lifecycle state nobody chose, and the only signal would be a support ticket", got)
	}
}

// The paused row is what makes a cardless trial actually end.
//
// Called out separately because deleting it breaks nothing that any other test
// would notice: provisioning still works, the trial still starts, and the org
// keeps working — forever, for free.
func TestAPausedSubscriptionSuspendsTheTenant(t *testing.T) {
	t.Parallel()

	if got := domain.StatusFromStripe(domain.StripePaused); got != domain.StatusSuspended {
		t.Fatalf("Stripe `paused` maps to %q. A cardless trial that lapsed would keep "+
			"working: the subscription is paused in Stripe, the tenant is not suspended "+
			"here, and no invoice is ever raised. A free forever account with nothing to "+
			"alarm on", got)
	}
}

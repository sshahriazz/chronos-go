// Package stripe is the only place in this repository that knows Stripe's SDK
// exists.
//
// The import contract bans `github.com/stripe/stripe-go` from the kernel, from
// every domain and from every use case, and the reason outlives the lint rule: a
// use case that imported it could not be exercised without a network, and the
// decision it makes — "this organization now has a trial" — has nothing to do
// with how the objects were created.
package stripe

import (
	"context"
	"fmt"
	"strings"
	"time"

	stripe "github.com/stripe/stripe-go/v86"

	"github.com/chronos/chronos-go/internal/modules/organization/app"
)

// APIVersion is the Stripe API version every request from this build carries.
//
// It is NOT configurable, and that is the SDK's design rather than an omission
// here: stripe-go pins it in `stripe.APIVersion` and sends it as `Stripe-Version`
// on every request, so the version is coupled to the module major. Upgrading the
// API version means upgrading the SDK, which is a dependency bump somebody
// reviews — not an environment variable that can differ between two deployments
// of the same binary.
//
// It is restated here because it is the version every REQUEST carries, and
// therefore the version the re-fetch in webhook.go speaks. Incoming events do
// NOT have to match it: the verifier relaxes that check deliberately, and
// webhook.go explains why it is safe given how little of a payload is read.
//
// The webhook tunnel is then just:
//
//	stripe listen --forward-to localhost:8090/stripe/webhook
//
// Port 8090 is API_PORT. 8080 belongs to OpenFGA — forwarding there sends
// Stripe's events to the authorization server, which answers 404 and logs
// nothing useful.
const APIVersion = stripe.APIVersion

// orgMetadataKey is our organization id, stored on both Stripe objects.
//
// It is what makes provisioning idempotent: a retry searches by it and finds
// what the last attempt created, rather than making a second customer with a
// second subscription and a second bill. Stripe's own idempotency keys expire
// after 24 hours; metadata does not, and a reactor can be redelivered long after
// that.
const orgMetadataKey = "chronos_org_id"

// Provisioner creates the billing objects for a new organization.
type Provisioner struct {
	api         *stripe.Client
	priceID     string
	trialDays   int64
	testClockID string
}

var _ app.Provisioner = (*Provisioner)(nil)

// Config is what the provisioner needs.
type Config struct {
	SecretKey string
	PriceID   string
	TrialDays int

	// TestClockID attaches the customer to a Stripe TEST CLOCK.
	//
	// Empty in production, and refused outright against a live key by
	// NewProvisioner. It exists because the single most important behaviour in
	// the cardless design — a trial that LAPSES suspends the tenant — cannot
	// otherwise be observed without waiting fourteen real days. A test clock
	// moves Stripe's own view of time, so the real subscription really does
	// reach its trial end and really does emit the event.
	//
	// The alternative is a test that builds its own customer and subscription
	// alongside this code, which would prove that the TEST can create a trial
	// rather than that this code does. Threading it through here keeps one
	// creation path, which is the point.
	TestClockID string
}

func NewProvisioner(cfg Config) (*Provisioner, error) {
	switch {
	case cfg.SecretKey == "":
		return nil, fmt.Errorf("stripe: an API key is required")
	case cfg.PriceID == "":
		return nil, fmt.Errorf("stripe: a trial price id is required; a subscription with no " +
			"price subscribes to nothing")
	case cfg.TrialDays < 1 || cfg.TrialDays > 730:
		return nil, fmt.Errorf("stripe: a trial of %d days is outside Stripe's 1..730",
			cfg.TrialDays)
	case cfg.TestClockID != "" && strings.Contains(cfg.SecretKey, "_live_"):
		// A test clock cannot exist in live mode, so this can only mean a test
		// configuration reached production. Refused at construction rather than
		// failing per organization.
		return nil, fmt.Errorf("stripe: a test clock was configured with a LIVE key")
	}
	return &Provisioner{
		api:         stripe.NewClient(cfg.SecretKey),
		priceID:     cfg.PriceID,
		trialDays:   int64(cfg.TrialDays),
		testClockID: cfg.TestClockID,
	}, nil
}

// Provision creates a customer and a CARDLESS trialing subscription.
//
// # What makes the trial cardless, and what happens when it ends
//
// No payment method is attached and none is collected.
// `trial_settings.end_behavior.missing_payment_method` is `pause`, which is the
// choice BILLING-PLAN.md §1 records and the reason it is forced rather than
// preferred:
//
//   - `pause` leaves the subscription `paused`, which billing.md §3 already maps
//     to `Suspended` — unreachable, not gone, reversible when a card arrives —
//     and generates NO invoices meanwhile, so no debt accrues.
//   - `cancel` maps to `Closed`, which opens the export window and starts
//     retention on a customer who merely forgot a card.
//   - `create_invoice` bills for a service nobody agreed to buy, and dunning
//     then chases it.
//
// # Idempotency, twice over
//
// A reactor's delivery is at-least-once, so this runs again for organizations it
// already provisioned. Two mechanisms cover different windows:
//
//   - The SEARCH below finds an existing customer by our organization id in
//     metadata. This is the one that matters, because it has no expiry.
//   - Stripe's own `Idempotency-Key`, derived from the organization id, collapses
//     a retry within 24 hours even if the search has not yet indexed the object.
//
// Search is eventually consistent — Stripe says so — which is exactly why the
// idempotency key is there as well rather than instead.
func (p *Provisioner) Provision(
	ctx context.Context, orgID, ownerSubject string,
) (app.Subscription, error) {
	if orgID == "" {
		return app.Subscription{}, fmt.Errorf("stripe: an organization id is required")
	}

	customer, err := p.findOrCreateCustomer(ctx, orgID, ownerSubject)
	if err != nil {
		return app.Subscription{}, err
	}

	sub, err := p.findOrCreateSubscription(ctx, orgID, customer.ID)
	if err != nil {
		return app.Subscription{}, err
	}

	if sub.TrialEnd == 0 {
		return app.Subscription{}, fmt.Errorf("stripe: subscription %s has no trial end; a "+
			"trial that never ends is a free forever account nothing alarms on", sub.ID)
	}

	return app.Subscription{
		CustomerID:     customer.ID,
		SubscriptionID: sub.ID,
		// Stripe's answer, not ours. Recomputing the deadline locally would give
		// one trial two clocks that can disagree.
		TrialEndsAt: time.Unix(sub.TrialEnd, 0).UTC(),
	}, nil
}

func (p *Provisioner) findOrCreateCustomer(
	ctx context.Context, orgID, ownerSubject string,
) (*stripe.Customer, error) {
	query := fmt.Sprintf("metadata['%s']:'%s'", orgMetadataKey, orgID)
	search := p.api.V1Customers.Search(ctx, &stripe.CustomerSearchParams{
		SearchParams: stripe.SearchParams{Query: query, Limit: stripe.Int64(1)},
	})
	for existing, err := range search.All(ctx) {
		if err != nil {
			return nil, fmt.Errorf("stripe: searching for the customer of %s: %w", orgID, err)
		}
		return existing, nil
	}

	// NO name, NO email. An organization's name is not personal data, but the
	// owner's address is, and it lives in the PII vault (ADR-002). What Stripe
	// holds is our pseudonym; the address is attached when the customer reaches
	// checkout and gives it to Stripe directly.
	params := &stripe.CustomerCreateParams{
		Metadata: map[string]string{
			orgMetadataKey:  orgID,
			"chronos_owner": ownerSubject,
		},
	}
	if p.testClockID != "" {
		params.TestClock = stripe.String(p.testClockID)
	}
	// Derived, so a retry inside 24 hours is collapsed by Stripe itself.
	params.SetIdempotencyKey("chronos-customer-" + orgID)

	customer, err := p.api.V1Customers.Create(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("stripe: creating the customer for %s: %w", orgID, err)
	}
	return customer, nil
}

func (p *Provisioner) findOrCreateSubscription(
	ctx context.Context, orgID, customerID string,
) (*stripe.Subscription, error) {
	// A customer may hold at most ONE subscription (billing.md §5 case 19), so
	// any existing one is the one we are looking for.
	list := p.api.V1Subscriptions.List(ctx, &stripe.SubscriptionListParams{
		Customer:   stripe.String(customerID),
		ListParams: stripe.ListParams{Limit: stripe.Int64(1)},
	})
	for existing, err := range list.All(ctx) {
		if err != nil {
			return nil, fmt.Errorf("stripe: listing subscriptions for %s: %w", orgID, err)
		}
		return existing, nil
	}

	params := &stripe.SubscriptionCreateParams{
		Customer: stripe.String(customerID),
		Items: []*stripe.SubscriptionCreateItemParams{
			{Price: stripe.String(p.priceID)},
		},
		TrialPeriodDays: stripe.Int64(p.trialDays),
		TrialSettings: &stripe.SubscriptionCreateTrialSettingsParams{
			EndBehavior: &stripe.SubscriptionCreateTrialSettingsEndBehaviorParams{
				// `pause`, for the reasons in Provision's comment above.
				MissingPaymentMethod: stripe.String("pause"),
			},
		},
		Metadata: map[string]string{orgMetadataKey: orgID},
	}
	params.SetIdempotencyKey("chronos-subscription-" + orgID)

	// NOTE: payment_method_types is deliberately NOT set, here or anywhere.
	// Omitting it lets Stripe serve whatever the Dashboard has configured;
	// hardcoding `card` locks out methods that convert better.
	sub, err := p.api.V1Subscriptions.Create(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("stripe: creating the subscription for %s: %w", orgID, err)
	}
	return sub, nil
}

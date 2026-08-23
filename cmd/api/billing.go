package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	stripeadapter "github.com/chronos/chronos-go/internal/adapter/stripe"
	billingpg "github.com/chronos/chronos-go/internal/modules/billing/adapter/postgres"
	billingapi "github.com/chronos/chronos-go/internal/modules/billing/api"
	billingapp "github.com/chronos/chronos-go/internal/modules/billing/app"
	orgapp "github.com/chronos/chronos-go/internal/modules/organization/app"
	orgdomain "github.com/chronos/chronos-go/internal/modules/organization/domain"
	"github.com/chronos/chronos-go/internal/platform/config"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// buildStripeWebhook assembles the endpoint Stripe posts to.
//
// # What its absence costs
//
// A cardless trial ends in STRIPE at day 14 — the subscription pauses — and
// nothing tells us. `org_status_view` keeps saying `trialing`, gate 3 keeps
// permitting everything, and the tenant works for free indefinitely. No error is
// raised anywhere, because from this system's point of view nothing happened.
//
// So the failure is loud, and the message says that rather than naming a
// missing environment variable.
func (d *dependencies) buildStripeWebhook(
	cfg *config.Config, log *slog.Logger,
) (http.Handler, error) {
	secrets := cfg.Stripe.WebhookSecrets()
	if len(secrets) == 0 {
		return nil, errors.New("STRIPE_WEBHOOK_SECRET is not set, so no incoming event could " +
			"be verified and the endpoint must not be served")
	}
	if d.store == nil {
		return nil, errors.New("no event store: a status change is an append")
	}
	if d.pool == nil {
		return nil, errors.New("no postgres pool: the webhook idempotency boundary is a table")
	}

	verifier, err := stripeadapter.NewVerifier(cfg.Stripe.SecretKey.Expose(), secrets)
	if err != nil {
		return nil, fmt.Errorf("stripe verifier: %w", err)
	}

	repo := eventsourcing.NewRepository[*orgdomain.Organization](
		d.store, d.codec, d.upcasters, orgdomain.Category, orgdomain.NewOrganization)

	sync, err := orgapp.NewSubscriptionSync(orgapp.SubscriptionSyncDeps{
		Repo: repo, Now: d.clock.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("subscription sync: %w", err)
	}

	// The trial warning shares the organization repository with the sync, and
	// is deliberately a SEPARATE use case rather than a branch inside it: the
	// two consume the same webhook and answer different questions, and
	// `trial_will_end` is the one event that changes no status at all.
	trials, err := orgapp.NewTrialWarnings(orgapp.TrialWarningsDeps{
		Repo: repo, Now: d.clock.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("trial warnings: %w", err)
	}

	log.Info("stripe webhook endpoint constructed",
		"path", billingapi.Path,
		// Named at startup because a rotation in flight is exactly when
		// somebody wants to know the old secret is still being accepted.
		"signing_secrets", len(secrets),
		"api_version", stripeadapter.APIVersion)

	events, err := billingpg.NewEventLog(pgadapter.New(d.pool))
	if err != nil {
		return nil, fmt.Errorf("webhook event log: %w", err)
	}

	return billingapi.NewWebhook(billingapi.WebhookDeps{
		Verifier: verifier,
		Sync:     sync,
		Trials:   trials,
		Events:   events,
		Log:      log,
	})
}

// orgCustomers answers "which Stripe customer is this organization", from the
// ORGANIZATION AGGREGATE rather than from a projection.
//
// # Why the aggregate and not org_status_view
//
// Two reasons, and the second is the one that bites. The view is what gate 3
// reads on EVERY request and its own comment says to keep it small, so a column
// only the billing portal needs would widen the hottest row in the system for
// its rarest caller.
//
// And a projection lags. An organization whose provisioning reactor has just
// appended `TrialStarted` would have a Stripe customer and a view that does not
// yet say so — and the caller would be told to wait for something that has
// already happened. The aggregate is authority and cannot be behind itself.
//
// The cost is one stream read per portal session. A portal session is a person
// deliberately clicking "manage billing", not a request path.
type orgCustomers struct {
	repo *eventsourcing.Repository[*orgdomain.Organization]
}

var _ billingapp.Customers = (*orgCustomers)(nil)

func (c *orgCustomers) CustomerID(ctx context.Context, orgID string) (string, error) {
	org, err := c.repo.Load(ctx, orgID)
	if err != nil {
		return "", fmt.Errorf("loading organization %s: %w", orgID, err)
	}
	if !org.Exists() {
		// Gate 1 resolved this organization from a membership, so it exists; a
		// stream that says otherwise means the id reaching here is not the one
		// that was authorised. Reported as a failure rather than as "not
		// provisioned yet", because waiting will not fix it.
		return "", fmt.Errorf("organization %s has no stream", orgID)
	}
	// Empty is not an error here — it is the provisioning window, and the use
	// case turns it into the retryable answer.
	return org.StripeCustomerID(), nil
}

// buildBilling assembles the billing service, or explains why it cannot.
//
// # What its absence costs
//
// The trial is cardless and ends in `pause`, so an organization that never adds
// a card is suspended — reversibly, by design. The Customer Portal is the ONLY
// way a card is ever added. Without this service every trial has exactly one
// outcome, no customer can pay, and no suspended tenant can recover.
func (d *dependencies) buildBilling(cfg *config.Config) (*billingapi.Service, error) {
	if cfg.Stripe.SecretKey.Expose() == "" {
		return nil, errors.New("STRIPE_SECRET_KEY is not set, so no portal session can be " +
			"minted and no customer can ever add a card")
	}
	if d.store == nil {
		return nil, errors.New("no event store: the Stripe customer id lives on the " +
			"organization aggregate")
	}

	portal, err := stripeadapter.NewPortal(stripeadapter.PortalConfig{
		SecretKey: cfg.Stripe.SecretKey.Expose(),
	})
	if err != nil {
		return nil, fmt.Errorf("stripe portal: %w", err)
	}

	repo := eventsourcing.NewRepository[*orgdomain.Organization](
		d.store, d.codec, d.upcasters, orgdomain.Category, orgdomain.NewOrganization)

	sessions, err := billingapp.NewPortalSessions(billingapp.PortalSessionsDeps{
		Portal: portal, Customers: &orgCustomers{repo: repo},
	})
	if err != nil {
		return nil, fmt.Errorf("portal sessions: %w", err)
	}
	return billingapi.New(billingapi.Deps{Sessions: sessions})
}

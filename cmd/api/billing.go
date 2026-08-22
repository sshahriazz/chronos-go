package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	stripeadapter "github.com/chronos/chronos-go/internal/adapter/stripe"
	billingpg "github.com/chronos/chronos-go/internal/modules/billing/adapter/postgres"
	billingapi "github.com/chronos/chronos-go/internal/modules/billing/api"
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
		Events:   events,
		Log:      log,
	})
}

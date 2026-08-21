package main

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	stripeadapter "github.com/chronos/chronos-go/internal/adapter/stripe"
	"github.com/chronos/chronos-go/internal/modules/organization"
	orgapp "github.com/chronos/chronos-go/internal/modules/organization/app"
	orgdomain "github.com/chronos/chronos-go/internal/modules/organization/domain"
	orgreactor "github.com/chronos/chronos-go/internal/modules/organization/reactor"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/reactor"
)

// newProvisionReactor builds the reactor that makes a new organization usable.
//
// # What its absence costs, precisely
//
// Every organization created stays in `provisioning`. That is not a degraded
// state — `provisioning` permits reading and billing and nothing else — so no
// workspace can be made, nobody can be invited, and the person who signed up is
// looking at a spinner. The API reports no error, because the API did its job:
// the organization exists.
//
// So the failure is loud here and the message says the consequence rather than
// the cause.
func newProvisionReactor(
	codec *eventcodec.JSON, d *dependencies, log *slog.Logger,
) (reactor.Reactor, error) {
	if !d.cfg.Stripe.Configured() {
		return nil, errors.New("STRIPE_SECRET_KEY and STRIPE_TRIAL_PRICE_ID are not both " +
			"set, so no Stripe customer or trialing subscription can be created")
	}
	if d.store == nil {
		return nil, errors.New("no event store: the trial cannot be recorded")
	}

	provisioner, err := stripeadapter.NewProvisioner(stripeadapter.Config{
		SecretKey: d.cfg.Stripe.SecretKey.Expose(),
		PriceID:   d.cfg.Stripe.TrialPriceID,
		TrialDays: d.cfg.Stripe.TrialDays,
	})
	if err != nil {
		return nil, fmt.Errorf("stripe provisioner: %w", err)
	}

	// Organization's OWN codec and registry, built together — the same pattern
	// newIdentityCodec follows, and for the same reason: the codec applies the
	// registry on the way in and the repository applies it on the way out, so
	// two registries would let those two disagree about which schema version a
	// stored event is (ADR-029).
	//
	// The reactor still decodes the TRIGGERING event with the shared worker
	// codec, which registers every module's events; this pair exists only for
	// the aggregate the reactor writes.
	orgCodec, orgUpcasters := newOrganizationCodec()
	repo := eventsourcing.NewRepository[*orgdomain.Organization](
		d.store, orgCodec, orgUpcasters, orgdomain.Category, orgdomain.NewOrganization)

	trials, err := orgapp.NewTrials(orgapp.TrialsDeps{Repo: repo, Now: clock.System{}.Now})
	if err != nil {
		return nil, fmt.Errorf("trials: %w", err)
	}

	provisioning, err := orgapp.NewProvisioning(orgapp.ProvisioningDeps{
		Provisioner: provisioner,
		Trials:      trials,
	})
	if err != nil {
		return nil, fmt.Errorf("provisioning: %w", err)
	}

	return orgreactor.NewProvision(provisioning, codec, log)
}

// newOrganizationCodec pairs a codec with the registry it was built from.
func newOrganizationCodec() (*eventcodec.JSON, *eventsourcing.UpcasterRegistry) {
	upcasters := eventsourcing.NewUpcasterRegistry()
	organization.RegisterSchemas(upcasters)

	codec := eventcodec.NewJSON(upcasters)
	organization.RegisterEvents(codec)
	return codec, upcasters
}

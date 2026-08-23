package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	stripeadapter "github.com/chronos/chronos-go/internal/adapter/stripe"
	billingdomain "github.com/chronos/chronos-go/internal/modules/billing/domain"
	"github.com/chronos/chronos-go/internal/modules/organization"
	orgpg "github.com/chronos/chronos-go/internal/modules/organization/adapter/postgres"
	orgapp "github.com/chronos/chronos-go/internal/modules/organization/app"
	orgdomain "github.com/chronos/chronos-go/internal/modules/organization/domain"
	orgreactor "github.com/chronos/chronos-go/internal/modules/organization/reactor"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/notify"
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
	ctx context.Context, codec *eventcodec.JSON, d *dependencies, log *slog.Logger,
) (reactor.Reactor, error) {
	if !d.cfg.Stripe.Configured() {
		return nil, errors.New("STRIPE_SECRET_KEY is not set, so no Stripe customer or " +
			"trialing subscription can be created")
	}
	if d.store == nil {
		return nil, errors.New("no event store: the trial cannot be recorded")
	}

	trial, priceID, err := mirrorCatalogue(ctx, d.cfg.Stripe.SecretKey.Expose(), log)
	if err != nil {
		return nil, err
	}

	provisioner, err := stripeadapter.NewProvisioner(stripeadapter.Config{
		SecretKey: d.cfg.Stripe.SecretKey.Expose(),
		PriceID:   priceID,
		// The catalogue's number, not configuration's. One plan version declares
		// both what a trial costs and how long it runs, and splitting them across
		// a Price and an environment variable is how a deployment ends up with a
		// fourteen-day plan running for thirty.
		TrialDays: trial.TrialDays,
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

// orgMembers builds the resolver for AudienceOrgMembers, or nil.
//
// NIL rather than a stub, and the difference is the design. An unwired audience
// stays UNANSWERABLE, so a notification that needs it PARKS — visibly, on a
// queue somebody looks at. A stub returning no recipients would instead report
// success having told nobody, which is indistinguishable from an organization
// that genuinely has no members and is precisely the silence this event was
// Silent about for so long.
func orgMembers(d *dependencies, log *slog.Logger) notify.Audiences {
	if d.pool == nil {
		log.Error("no organization-member audience: postgres is unreachable, so a " +
			"suspension parks instead of telling every member their access has ended")
		return nil
	}
	members, err := orgpg.NewMemberAudience(pgadapter.New(d.pool))
	if err != nil {
		log.Error("no organization-member audience; a suspension will park", "error", err)
		return nil
	}
	return members
}

// mirrorTimeout bounds the startup mirror.
const mirrorTimeout = time.Minute

// mirrorCatalogue makes the published plans exist in Stripe and returns the
// trial version with its price id.
//
// # Why this runs at startup rather than at signup
//
// The alternative is creating the Price the first time somebody subscribes to
// it, which puts an object-creation round trip inside a customer-facing request
// and turns a Stripe hiccup into a failed signup. Here the same failure stops a
// deployment, where somebody is watching — and the reactor refuses to construct
// rather than provisioning organizations against a plan that does not exist.
//
// It is safe to re-run: `Mirror.EnsurePrice` is idempotent on the Price's
// lookup key, so every deployment after the first finds what the first made.
func mirrorCatalogue(
	ctx context.Context, secretKey string, log *slog.Logger,
) (billingdomain.PlanVersion, string, error) {
	// BOUNDED, and the bound is the point. The caller's context carries SIGINT
	// and nothing else, so an unresponsive Stripe would leave the worker hanging
	// in construction — no reactors running, no health endpoint served, and
	// nothing in the log after "configuration loaded". A worker that has not
	// started is indistinguishable from one that is merely slow to start, which
	// is the failure this deadline turns into a message.
	//
	// Two API calls per published version, and the catalogue is small. A minute
	// is generous against a slow account and far short of a hang.
	ctx, cancel := context.WithTimeout(ctx, mirrorTimeout)
	defer cancel()

	catalogue, err := billingdomain.Published()
	if err != nil {
		return billingdomain.PlanVersion{}, "", fmt.Errorf("billing catalogue: %w", err)
	}
	trial, err := catalogue.Latest(billingdomain.TrialPlan, billingdomain.Monthly)
	if err != nil {
		return billingdomain.PlanVersion{}, "", fmt.Errorf(
			"billing catalogue: %w; provisioning subscribes every new organization to it", err)
	}

	mirror, err := stripeadapter.NewMirror(secretKey)
	if err != nil {
		return billingdomain.PlanVersion{}, "", fmt.Errorf("stripe mirror: %w", err)
	}
	prices, err := mirror.EnsureAll(ctx, catalogue)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return billingdomain.PlanVersion{}, "", fmt.Errorf("mirroring the plan catalogue "+
				"into Stripe did not finish within %s; the worker refuses to start rather "+
				"than hang, because a process stuck in construction runs no reactors and "+
				"serves no health endpoint: %w", mirrorTimeout, err)
		}
		return billingdomain.PlanVersion{}, "", fmt.Errorf("mirroring the plan catalogue "+
			"into Stripe: %w", err)
	}

	priceID := prices[trial.ID()]
	if priceID == "" {
		// Unreachable while EnsureAll returns an entry per published version, and
		// asserted anyway: an empty price id would reach the provisioner, which
		// refuses it, and the message there names a configuration variable that
		// no longer exists.
		return billingdomain.PlanVersion{}, "", fmt.Errorf("the mirror returned no price "+
			"for %s", trial.ID())
	}

	log.Info("plan catalogue mirrored",
		"versions", len(prices), "trial_price", priceID, "trial_days", trial.TrialDays)
	return trial, priceID, nil
}

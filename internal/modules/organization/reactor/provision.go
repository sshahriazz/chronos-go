// Package reactor holds organization's side effects on the outside world.
//
// One today: the billing objects a new organization needs before it can be
// used. Without it every organization created stays in `provisioning` forever —
// which is not a degraded state, it is an unusable tenant, since `provisioning`
// permits reading and billing and nothing else.
package reactor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/chronos/chronos-go/internal/modules/organization/contract"
	"github.com/chronos/chronos-go/internal/modules/organization/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/reactor"
)

// ProvisionReactorName is the persistent subscription group. PERMANENT:
// renaming it creates a fresh group starting at the END of the log, silently
// abandoning every organization that had not yet been provisioned.
const ProvisionReactorName = "organization-provision"

// Provisioner is the use case this reactor drives.
type Provisioner interface {
	Provision(ctx context.Context, orgID, ownerSubject, eventID string) error
}

// Provision creates the Stripe objects for a newly created organization and
// records that its trial has started.
type Provision struct {
	provisioning Provisioner
	codec        eventsourcing.Codec
	log          *slog.Logger
}

var _ reactor.Reactor = (*Provision)(nil)

// NewProvision wires the reactor.
func NewProvision(
	provisioning Provisioner, codec eventsourcing.Codec, log *slog.Logger,
) (*Provision, error) {
	switch {
	case provisioning == nil:
		return nil, fmt.Errorf("organization: a provisioning use case is required")
	case codec == nil:
		return nil, fmt.Errorf("organization: a codec is required")
	case log == nil:
		return nil, fmt.Errorf("organization: a logger is required")
	}
	return &Provision{provisioning: provisioning, codec: codec, log: log}, nil
}

func (p *Provision) Name() string { return ProvisionReactorName }

// Filter narrows $all to organization's own streams.
func (p *Provision) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		StreamPrefixes: []string{string(domain.Category) + "-"},
	}
}

// React provisions one organization.
//
// # Why this is safe to run twice
//
// Delivery is at-least-once and no bookkeeping makes a Stripe call and an event
// append atomic. Both halves are therefore idempotent on the organization id:
// the provisioner finds the customer and subscription it created last time by
// our id in Stripe's metadata, and the trial append is refused as a duplicate or
// as an illegal transition, both of which are treated as success.
//
// # What is deliberately NOT poison
//
// A Stripe outage returns an ordinary error, so the event is redelivered and
// retried. Parking it would leave an organization permanently unusable because
// somebody else's API had a bad afternoon — and the retry costs nothing, since
// the operation converges.
func (p *Provision) React(ctx context.Context, env eventsourcing.Envelope) error {
	decoded, err := p.codec.Unmarshal(env.Type, env.Payload)
	if err != nil {
		// An event this reactor cannot decode can never succeed, however many
		// times it is redelivered.
		return fmt.Errorf("%w: decoding %s: %w", eventsourcing.ErrPoison, env.Type, err)
	}

	created, ok := decoded.(*contract.OrganizationCreated)
	if !ok {
		// Every other organization event reaches this subscription and is not
		// this reactor's business. Not an error, and not poison.
		return nil
	}

	if err := p.provisioning.Provision(
		ctx, created.OrgID, created.OwnerID, env.ID.String(),
	); err != nil {
		if errors.Is(err, eventsourcing.ErrPoison) {
			return err
		}
		// Logged as well as returned, because the consequence is invisible
		// otherwise: the organization exists, the person who created it is
		// looking at a spinner, and nothing about the API says why.
		p.log.ErrorContext(ctx, "an organization could not be provisioned; it stays in "+
			"`provisioning` and is unusable until this succeeds",
			"org_id", created.OrgID, "error", err)
		return err
	}
	return nil
}

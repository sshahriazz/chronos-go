package app

import (
	"context"
	"fmt"
	"time"
)

// Subscription is what a provisioner hands back.
type Subscription struct {
	CustomerID     string
	SubscriptionID string
	TrialEndsAt    time.Time
}

// Provisioner creates the billing objects a new organization needs.
//
// A PORT, declared by the consumer and satisfied in internal/adapter/stripe.
// The vendor SDK is banned from this layer by the import contract, and the
// reason outlives the lint rule: a use case that imported stripe-go could not be
// exercised without a network, and the decision it makes — "this organization
// now has a trial, append the fact" — has nothing to do with how the objects
// were created.
type Provisioner interface {
	// Provision is IDEMPOTENT on orgID.
	//
	// A reactor's delivery is at-least-once, so this WILL be called twice for
	// one organization — and the second call must find the objects the first
	// created rather than making a second customer with a second subscription
	// and a second bill.
	Provision(ctx context.Context, orgID, ownerSubject string) (Subscription, error)
}

// TrialStarter records that an organization's trial is running.
//
// Separated from the reactor so the append can be tested without a Stripe
// client and the Stripe call without an event store.
type TrialStarter interface {
	StartTrial(ctx context.Context, orgID string, sub Subscription, eventID string) error
}

// Provisioning turns a created organization into a usable one.
type Provisioning struct {
	provisioner Provisioner
	trials      TrialStarter
}

// ProvisioningDeps is what Provisioning needs.
type ProvisioningDeps struct {
	Provisioner Provisioner
	Trials      TrialStarter
}

func NewProvisioning(d ProvisioningDeps) (*Provisioning, error) {
	switch {
	case d.Provisioner == nil:
		return nil, fmt.Errorf("organization: a provisioner is required; without one every " +
			"organization stays in `provisioning` forever and no tenant is ever usable")
	case d.Trials == nil:
		return nil, fmt.Errorf("organization: a trial starter is required")
	}
	return &Provisioning{provisioner: d.Provisioner, trials: d.Trials}, nil
}

// Provision creates the billing objects and appends the fact.
//
// # The ordering, and why it is this way round
//
// Stripe first, event second. That leaves one window: the objects exist and the
// event does not, because the process died between them. The reactor then runs
// again, Provision finds the SAME objects by the organization id in Stripe's
// metadata, and the append happens. The organization converges.
//
// The other order — append first, create after — has a worse window. The
// organization would be `trialing` with no subscription behind it: no trial
// clock, no `trial_will_end`, nothing to pause when it lapses. A free forever
// account that nothing alarms on, which is exactly the failure the scope
// document names as the reason Provisioning exists at all.
func (p *Provisioning) Provision(ctx context.Context, orgID, ownerSubject, eventID string) error {
	if orgID == "" || eventID == "" {
		return fmt.Errorf("organization: provisioning needs an organization and an event id")
	}
	sub, err := p.provisioner.Provision(ctx, orgID, ownerSubject)
	if err != nil {
		return fmt.Errorf("provisioning %s: %w", orgID, err)
	}
	if err := p.trials.StartTrial(ctx, orgID, sub, eventID); err != nil {
		return fmt.Errorf("recording the trial for %s: %w", orgID, err)
	}
	return nil
}

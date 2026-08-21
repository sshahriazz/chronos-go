package domain

import (
	"fmt"
	"slices"
	"time"

	"github.com/chronos/chronos-go/internal/modules/organization/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// Organization is the commercial boundary: one organization, one customer
// contract, one subscription.
//
// # What is in the aggregate, and what is deliberately not
//
// It is thin on data and heavy on authority (organization.md §1). It holds the
// status that gates the whole tenant, the owner, and the admin set — and
// nothing that churns.
//
// The admin set is INSIDE because of the rule organization.md §2 states:
// invariant-bearing sets go inside the aggregate; high-volume collections do
// not. "An organization always has exactly one owner" must hold
// transactionally, and a set of a handful of admins costs nothing to carry.
// Members number thousands and churn constantly, so they live in `workspace`
// and never enter this boundary.
type Organization struct {
	eventsourcing.Base

	orgID   string
	name    string
	slug    string
	status  Status
	ownerID string
	admins  []string

	stripeCustomerID     string
	stripeSubscriptionID string
	trialEndsAt          time.Time
}

var _ eventsourcing.Root = (*Organization)(nil)

// NewOrganization returns an empty aggregate for the repository to rebuild into.
func NewOrganization() *Organization { return &Organization{} }

func (o *Organization) OrgID() string   { return o.orgID }
func (o *Organization) Name() string    { return o.name }
func (o *Organization) Slug() string    { return o.slug }
func (o *Organization) Status() Status  { return o.status }
func (o *Organization) OwnerID() string { return o.ownerID }

// Admins returns a copy. Handing out the slice would let a caller reorder or
// truncate the aggregate's own invariant-bearing set from outside it.
func (o *Organization) Admins() []string { return slices.Clone(o.admins) }

// TrialEndsAt is Stripe's deadline, zero until the subscription exists.
func (o *Organization) TrialEndsAt() time.Time { return o.trialEndsAt }

// StripeCustomerID and StripeSubscriptionID are empty until the mirror lands.
func (o *Organization) StripeCustomerID() string     { return o.stripeCustomerID }
func (o *Organization) StripeSubscriptionID() string { return o.stripeSubscriptionID }

// Exists reports whether any event has been applied.
func (o *Organization) Exists() bool { return o.orgID != "" }

// IsAdmin reports whether id administers this organization.
//
// The owner is always an admin. Encoding that here rather than by writing the
// owner into the admin set keeps "exactly one owner" and "who may administer"
// as separate facts — removing an admin can then never remove the owner by
// accident, which is the failure the invariant exists to prevent.
func (o *Organization) IsAdmin(id string) bool {
	return id != "" && (id == o.ownerID || slices.Contains(o.admins, id))
}

// Apply replays one event.
//
// Pure, and it validates nothing: it runs during rebuild over events that are
// already facts, and refusing one there would make the stream unloadable.
func (o *Organization) Apply(e eventsourcing.Event) {
	switch ev := e.(type) {
	case *contract.OrganizationCreated:
		o.orgID = ev.OrgID
		o.name = ev.Name
		o.slug = ev.Slug
		o.ownerID = ev.OwnerID
		o.status = StatusProvisioning
	case *contract.OrganizationTrialStarted:
		o.stripeCustomerID = ev.StripeCustomerID
		o.stripeSubscriptionID = ev.StripeSubscriptionID
		o.trialEndsAt = ev.TrialEndsAt
		o.status = StatusTrialing
	case *contract.OrganizationActivated:
		o.status = StatusActive
	case *contract.OrganizationPastDue:
		o.status = StatusPastDue
	case *contract.OrganizationSuspended:
		o.status = StatusSuspended
	case *contract.OrganizationClosed:
		o.status = StatusClosed
	case *contract.OrgAdminAdded:
		if !slices.Contains(o.admins, ev.AdminID) {
			o.admins = append(o.admins, ev.AdminID)
		}
	case *contract.OrgAdminRemoved:
		o.admins = slices.DeleteFunc(o.admins, func(id string) bool { return id == ev.AdminID })
	}
}

// Create opens a new organization, owned by its creator.
//
// Ownership comes from CREATION, not from payment. organization.md §4 derives it
// from a confirmed Stripe payment and introduces `provisional_owner` to bridge
// the gap; a cardless trial removes the gap and with it the relation
// (BILLING-PLAN.md §1).
func (o *Organization) Create(orgID, name, slug, ownerID string, at time.Time) error {
	if o.Exists() {
		return fmt.Errorf("organization: %s already exists", o.orgID)
	}
	switch {
	case orgID == "":
		return fmt.Errorf("organization: an id is required")
	case name == "":
		return fmt.Errorf("organization: a name is required")
	case slug == "":
		return fmt.Errorf("organization: a slug is required")
	case ownerID == "":
		return fmt.Errorf("organization: an owner is required; an organization with no owner " +
			"is one nobody can administer or pay for")
	}
	eventsourcing.Record(o, &contract.OrganizationCreated{
		OrgID: orgID, Name: name, Slug: slug, OwnerID: ownerID, CreatedAt: at,
	})
	return nil
}

// StartTrial records the Stripe subscription and starts the trial clock.
func (o *Organization) StartTrial(customerID, subscriptionID string, endsAt, at time.Time) error {
	if err := o.require(StatusTrialing); err != nil {
		return err
	}
	if customerID == "" || subscriptionID == "" {
		return fmt.Errorf("organization: the trial needs both Stripe ids; without them no " +
			"webhook can be matched to this organization and the trial can never end")
	}
	if endsAt.IsZero() {
		return fmt.Errorf("organization: the trial needs an end; a trial that never ends is a " +
			"free forever account nothing alarms on")
	}
	eventsourcing.Record(o, &contract.OrganizationTrialStarted{
		OrgID: o.orgID, StripeCustomerID: customerID, StripeSubscriptionID: subscriptionID,
		TrialEndsAt: endsAt, StartedAt: at,
	})
	return nil
}

// Activate makes the organization a paying one.
func (o *Organization) Activate(at time.Time) error {
	if err := o.require(StatusActive); err != nil {
		return err
	}
	eventsourcing.Record(o, &contract.OrganizationActivated{OrgID: o.orgID, ActivatedAt: at})
	return nil
}

// MarkPastDue records a failed renewal, with a grace period.
func (o *Organization) MarkPastDue(graceEndsAt, at time.Time) error {
	if err := o.require(StatusPastDue); err != nil {
		return err
	}
	eventsourcing.Record(o, &contract.OrganizationPastDue{OrgID: o.orgID, GraceEndsAt: graceEndsAt, At: at})
	return nil
}

// Suspend switches the tenant off without destroying anything.
func (o *Organization) Suspend(reason contract.SuspensionReason, at time.Time) error {
	if err := o.require(StatusSuspended); err != nil {
		return err
	}
	if reason == "" {
		return fmt.Errorf("organization: a suspension needs a reason; the customer is told " +
			"why, and a lapsed trial and a failed payment need different messages")
	}
	eventsourcing.Record(o, &contract.OrganizationSuspended{OrgID: o.orgID, Reason: reason, SuspendedAt: at})
	return nil
}

// Close ends the commercial relationship. It never deletes anything.
func (o *Organization) Close(at time.Time) error {
	if err := o.require(StatusClosed); err != nil {
		return err
	}
	eventsourcing.Record(o, &contract.OrganizationClosed{OrgID: o.orgID, ClosedAt: at})
	return nil
}

// AddAdmin grants org-level administration.
func (o *Organization) AddAdmin(adminID string, at time.Time) error {
	if !o.Exists() {
		return fmt.Errorf("organization: does not exist")
	}
	if adminID == "" {
		return fmt.Errorf("organization: an admin id is required")
	}
	if adminID == o.ownerID {
		// Not an error and not an event. The owner already administers, so the
		// caller's intent is satisfied; raising one would put the owner in the
		// admin set and make RemoveAdmin able to strip their administration
		// while leaving them owner.
		return nil
	}
	if slices.Contains(o.admins, adminID) {
		return nil
	}
	eventsourcing.Record(o, &contract.OrgAdminAdded{OrgID: o.orgID, AdminID: adminID, AddedAt: at})
	return nil
}

// RemoveAdmin revokes org-level administration.
//
// The OWNER cannot be removed this way, and the error says what to do instead.
// Exactly one owner, always (ADR-027): the cardinality is invariant, the person
// is transferable, and a transfer is its own audited, accepted, time-boxed
// process rather than a side effect of removing an admin.
func (o *Organization) RemoveAdmin(adminID string, at time.Time) error {
	if !o.Exists() {
		return fmt.Errorf("organization: does not exist")
	}
	if adminID == o.ownerID {
		return fmt.Errorf("organization: %s is the OWNER and cannot be removed as an admin; "+
			"an organization always has exactly one owner. Transfer ownership first, which "+
			"the recipient must accept", adminID)
	}
	if !slices.Contains(o.admins, adminID) {
		return nil
	}
	eventsourcing.Record(o, &contract.OrgAdminRemoved{OrgID: o.orgID, AdminID: adminID, RemovedAt: at})
	return nil
}

// require refuses a transition the machine does not allow.
func (o *Organization) require(next Status) error {
	if !o.Exists() {
		return fmt.Errorf("organization: does not exist")
	}
	if !o.status.CanTransitionTo(next) {
		return errIllegalTransition(o.status, next)
	}
	return nil
}

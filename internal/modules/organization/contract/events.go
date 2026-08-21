// Package contract is the organization module's published event vocabulary.
//
// Everything here is a FACT that happened, named in the past tense, carrying
// SubjectID pseudonyms and never personal data (ADR-002). Other modules react to
// these; nothing outside organization writes them.
package contract

import "time"

// OrganizationCreated is the first event in an organization's life.
//
// The org is not usable yet — it has no Stripe subscription, so it has no trial
// clock and no way to end one. It becomes usable on OrganizationTrialStarted,
// which the billing reactor appends once the mirror is confirmed.
//
// # Why the owner is on this event
//
// Ownership does NOT come from payment in this system, and that is a departure
// from organization.md §4 worth stating where the code can see it: the trial is
// cardless (BILLING-PLAN.md §1), so there is no payment at signup to derive
// ownership from. The creator is the owner from the first fact, which is also
// what let `provisional_owner` be deleted — it existed only to give an unpaid
// creator a way to reach checkout.
type OrganizationCreated struct {
	OrgID     string
	Name      string
	Slug      string
	OwnerID   string // a SubjectID pseudonym
	CreatedAt time.Time
}

func (*OrganizationCreated) EventType() string { return "organization.Created.v1" }

// OrganizationTrialStarted records that the Stripe subscription exists and the
// trial clock is running.
//
// Appended by the billing reactor, not by the create handler: creating the
// Stripe customer and subscription is network I/O, which belongs in a reactor
// rather than a request path.
//
// It carries the Stripe ids because everything afterwards is keyed by them —
// every webhook names a subscription, and the mapping has to live somewhere our
// side. TrialEndsAt is Stripe's answer, not ours; recomputing it locally would
// give two clocks one deadline.
type OrganizationTrialStarted struct {
	OrgID                string
	StripeCustomerID     string
	StripeSubscriptionID string
	TrialEndsAt          time.Time
	StartedAt            time.Time
}

func (*OrganizationTrialStarted) EventType() string { return "organization.TrialStarted.v1" }

// OrganizationActivated is a paying organization.
//
// Reached from Trialing when a card is added and the subscription converts, and
// from PastDue or Suspended when payment recovers. One event for all three
// because the OUTCOME is identical — the tenant may do everything — and a
// separate event per route would make every consumer switch on which door was
// used to reach the same room.
type OrganizationActivated struct {
	OrgID       string
	ActivatedAt time.Time
}

func (*OrganizationActivated) EventType() string { return "organization.Activated.v1" }

// OrganizationPastDue records a failed renewal while Stripe's Smart Retries run.
//
// Writes are still permitted during the grace period. Blocking them is the
// hostile option and it costs more than it protects; `grow` is blocked instead
// (organization.md §5.2).
type OrganizationPastDue struct {
	OrgID       string
	GraceEndsAt time.Time
	At          time.Time
}

func (*OrganizationPastDue) EventType() string { return "organization.PastDue.v1" }

// OrganizationSuspended makes the tenant unreachable without destroying
// anything.
//
// Two ways in, and both are recoverable: a cardless trial that ended without a
// card (Stripe `paused`), and exhausted payment retries (Stripe `unpaid`).
// Reason distinguishes them for the notice the customer gets, not for the
// enforcement, which is identical.
//
// Reads still answer and export still works. Withholding a suspended tenant's
// own data is a GDPR portability violation rather than leverage
// (organization.md §5.2).
type OrganizationSuspended struct {
	OrgID       string
	Reason      SuspensionReason
	SuspendedAt time.Time
}

func (*OrganizationSuspended) EventType() string { return "organization.Suspended.v1" }

// SuspensionReason is why a tenant was switched off.
type SuspensionReason string

const (
	// TrialEnded is a cardless trial that lapsed. The subscription is paused in
	// Stripe and generates no invoices, so no debt accrues while suspended.
	TrialEnded SuspensionReason = "trial_ended"
	// PaymentFailed is a paying customer whose retries were exhausted.
	PaymentFailed SuspensionReason = "payment_failed"
)

// OrganizationClosed is the end of the commercial relationship.
//
// Closure never deletes. It opens the export window; destruction is
// `compliance`'s retention policy, and only ever that.
type OrganizationClosed struct {
	OrgID    string
	ClosedAt time.Time
}

func (*OrganizationClosed) EventType() string { return "organization.Closed.v1" }

// OrgAdminAdded grants org-level administration.
//
// Admins are inside the aggregate rather than a separate stream because the set
// is small, bounded, and carries an invariant that must hold transactionally:
// an organization always has exactly one owner, and an admin is never
// implicitly promoted into it (organization.md §2, ADR-027).
type OrgAdminAdded struct {
	OrgID   string
	AdminID string // a SubjectID pseudonym
	AddedAt time.Time
}

func (*OrgAdminAdded) EventType() string { return "organization.AdminAdded.v1" }

// OrgAdminRemoved revokes org-level administration.
type OrgAdminRemoved struct {
	OrgID     string
	AdminID   string
	RemovedAt time.Time
}

func (*OrgAdminRemoved) EventType() string { return "organization.AdminRemoved.v1" }

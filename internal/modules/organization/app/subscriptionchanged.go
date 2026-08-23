package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/organization/contract"
	"github.com/chronos/chronos-go/internal/modules/organization/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// SubscriptionState is what a webhook handler learned from Stripe.
//
// It is the RE-FETCHED object, never the webhook payload. billing.md §4 step 5
// is emphatic about the difference and so is this type's existence: Stripe does
// not guarantee ordering, so applying a payload as a delta will eventually apply
// a stale one.
type SubscriptionState struct {
	OrgID          string
	SubscriptionID string
	Status         domain.StripeStatus
	GraceEndsAt    time.Time

	// TrialEndsAt is the re-fetched deadline, zero when the subscription is not
	// trialing. SubscriptionSync ignores it — a trial end is not a status — and
	// TrialWarnings is what it is here for.
	TrialEndsAt time.Time
}

// SubscriptionSync applies a subscription's current state to an organization.
type SubscriptionSync struct {
	repo *eventsourcing.Repository[*domain.Organization]
	now  func() time.Time
}

// SubscriptionSyncDeps is what SubscriptionSync needs.
type SubscriptionSyncDeps struct {
	Repo *eventsourcing.Repository[*domain.Organization]
	Now  func() time.Time
}

func NewSubscriptionSync(d SubscriptionSyncDeps) (*SubscriptionSync, error) {
	switch {
	case d.Repo == nil:
		return nil, fmt.Errorf("organization: a repository is required")
	case d.Now == nil:
		return nil, fmt.Errorf("organization: a clock is required")
	}
	return &SubscriptionSync{repo: d.Repo, now: d.Now}, nil
}

// Apply moves the organization to the status Stripe reports, or does nothing.
//
// # Convergent, not incremental
//
// It is a function of the CURRENT state rather than of what changed. That is
// what makes processing an out-of-order or duplicate event harmless: two
// deliveries of the same state reach the same place, and an old event replayed
// after a newer one re-fetches the newer state and agrees with it.
//
// # Doing nothing is a normal outcome, not a failure
//
// Most webhooks name a state the organization is already in — Stripe emits
// `customer.subscription.updated` for changes that do not touch status at all.
// Returning an error for those would ask for redelivery of an event that will
// never do anything.
func (s *SubscriptionSync) Apply(
	ctx context.Context, state SubscriptionState, eventID string,
) error {
	if state.OrgID == "" || eventID == "" {
		return fmt.Errorf("organization: a subscription sync needs an organization and an " +
			"event id")
	}

	target := domain.StatusFromStripe(state.Status)
	if target == domain.StatusUnknown {
		// Refused rather than guessed. Moving a tenant into a lifecycle state
		// nobody chose is worse than parking the event for somebody to look at.
		return fmt.Errorf("%w: Stripe reports subscription %s as %q for %s, which maps to no "+
			"lifecycle state", eventsourcing.ErrPoison,
			state.SubscriptionID, state.Status, state.OrgID)
	}

	key := domain.StreamKey(state.OrgID)
	org, err := s.repo.Load(ctx, key)
	if err != nil {
		return fmt.Errorf("loading %s: %w", state.OrgID, err)
	}
	if !org.Exists() {
		// A subscription whose metadata names an organization we have never
		// heard of. It can never succeed by being retried.
		return fmt.Errorf("%w: subscription %s names organization %s, which has no events",
			eventsourcing.ErrPoison, state.SubscriptionID, state.OrgID)
	}

	if org.Status() == target {
		return nil // already there
	}
	if !org.Status().CanTransitionTo(target) {
		// Stripe and the aggregate disagree about what is possible — for
		// instance a `canceled` subscription for an organization already Closed,
		// or an event arriving after a later one already moved it on. Not an
		// error: the convergent read above means the organization is in the
		// state the LATEST re-fetch produced, and this delivery is stale.
		return nil
	}

	now := s.now().UTC()
	if err := s.transition(org, target, state, now); err != nil {
		return err
	}

	if _, err := s.repo.Save(ctx, key, org, eventID+":subscription",
		eventsourcing.Metadata{OrgID: state.OrgID, OccurredAt: now}); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			// Another delivery won the race and moved the organization. The
			// state Stripe reported is what the winner applied, because both
			// read the same re-fetched object.
			return nil
		}
		return fmt.Errorf("saving %s: %w", state.OrgID, err)
	}
	return nil
}

// transition asks the aggregate for the move, so its own rules apply.
func (s *SubscriptionSync) transition(
	org *domain.Organization, target domain.Status, state SubscriptionState, now time.Time,
) error {
	switch target {
	case domain.StatusActive:
		return org.Activate(now)
	case domain.StatusPastDue:
		grace := state.GraceEndsAt
		if grace.IsZero() {
			// Stripe owns the retry schedule; this is only what we show the
			// customer. A week is the outer bound of Smart Retries.
			grace = now.AddDate(0, 0, 7)
		}
		return org.MarkPastDue(grace, now)
	case domain.StatusSuspended:
		reason := contract.PaymentFailed
		if state.Status == domain.StripePaused {
			// `paused` is only ever reached by a cardless trial lapsing, because
			// that is the missing_payment_method behaviour the provisioner sets.
			reason = contract.TrialEnded
		}
		return org.Suspend(reason, now)
	case domain.StatusClosed:
		return org.Close(now)
	default:
		return fmt.Errorf("organization: no command moves an organization to %s", target)
	}
}

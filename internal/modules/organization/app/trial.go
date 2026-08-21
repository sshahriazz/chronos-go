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

// Trials appends the fact that an organization's trial has started.
type Trials struct {
	repo *eventsourcing.Repository[*domain.Organization]
	now  func() time.Time
}

// TrialsDeps is what Trials needs.
type TrialsDeps struct {
	Repo *eventsourcing.Repository[*domain.Organization]
	Now  func() time.Time
}

func NewTrials(d TrialsDeps) (*Trials, error) {
	switch {
	case d.Repo == nil:
		return nil, fmt.Errorf("organization: a repository is required")
	case d.Now == nil:
		return nil, fmt.Errorf("organization: a clock is required")
	}
	return &Trials{repo: d.Repo, now: d.Now}, nil
}

var _ TrialStarter = (*Trials)(nil)

// StartTrial moves an organization from provisioning to trialing.
//
// # Why running twice is not an error
//
// A reactor's delivery is at-least-once, so this WILL run again for an
// organization whose trial already started. The aggregate refuses the second
// transition — `trialing` cannot go to `trialing` — and that refusal is treated
// as SUCCESS here, not as a failure to retry.
//
// The alternative, returning the error, asks for redelivery of an event that can
// never be applied again. The reactor would retry until it parked, and an
// operator would investigate a parked event whose work was completed correctly
// the first time.
func (t *Trials) StartTrial(
	ctx context.Context, orgID string, sub Subscription, eventID string,
) error {
	// The repository takes the stream KEY and knows its own category, so the
	// category cannot be got wrong at one call site and right at another.
	key := domain.StreamKey(orgID)

	org, err := t.repo.Load(ctx, key)
	if err != nil {
		return fmt.Errorf("loading %s: %w", orgID, err)
	}
	if !org.Exists() {
		// The organization's own event has not been projected into the stream we
		// just read, which cannot happen: the append that created it is what
		// produced the event this reactor is handling.
		return fmt.Errorf("organization %s has no events but its creation is being reacted "+
			"to", orgID)
	}

	if org.Status() == domain.StatusTrialing {
		// Already done, by an earlier delivery of this same event.
		return nil
	}

	if err := org.StartTrial(
		sub.CustomerID, sub.SubscriptionID, sub.TrialEndsAt, t.now().UTC(),
	); err != nil {
		return fmt.Errorf("starting the trial for %s: %w", orgID, err)
	}

	// The event id is DERIVED from the triggering event, so a redelivery that
	// races past the status check above still produces a byte-identical id and
	// is refused by the store as a duplicate rather than appended twice.
	_, err = t.repo.Save(ctx, key, org, eventID+":trial",
		eventsourcing.Metadata{OrgID: orgID, OccurredAt: t.now().UTC()})
	if err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			// Another delivery won. The organization is trialing either way,
			// which is the outcome this call exists to reach.
			return nil
		}
		return fmt.Errorf("saving %s: %w", orgID, err)
	}
	return nil
}

// ensure the contract event is linked from this file for readers following the
// trail from the reactor to the fact it appends.
var _ = (*contract.OrganizationTrialStarted)(nil)

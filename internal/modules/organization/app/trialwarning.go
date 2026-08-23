package app

import (
	"errors"
	"fmt"
	"time"

	"context"

	"github.com/chronos/chronos-go/internal/modules/organization/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// TrialWarnings records the warning Stripe's `trial_will_end` announces.
//
// # Why this is separate from SubscriptionSync
//
// They consume the same webhook and answer different questions.
// `trial_will_end` names a subscription whose status is still `trialing`, so the
// sync correctly does nothing — the organization is already in the state Stripe
// reports. The warning is not about a status change at all; it is about a
// DEADLINE approaching, and folding it into a status machine would make the one
// event that changes no status the one the status machine has to special-case.
//
// For a CARDLESS trial this is the only warning anybody gets. The subscription
// then pauses, the organization is Suspended, and without this the first signal
// a customer has is being locked out of their own tenant.
type TrialWarnings struct {
	repo *eventsourcing.Repository[*domain.Organization]
	now  func() time.Time
}

// TrialWarningsDeps is what TrialWarnings needs.
type TrialWarningsDeps struct {
	Repo *eventsourcing.Repository[*domain.Organization]
	Now  func() time.Time
}

func NewTrialWarnings(d TrialWarningsDeps) (*TrialWarnings, error) {
	switch {
	case d.Repo == nil:
		return nil, fmt.Errorf("organization: a repository is required")
	case d.Now == nil:
		return nil, fmt.Errorf("organization: a clock is required")
	}
	return &TrialWarnings{repo: d.Repo, now: d.Now}, nil
}

// Warn records that the trial-ending warning was issued for an organization.
//
// # The owner is named in METADATA, which is what makes the mail reachable
//
// The notification reactor resolves `AudienceSubject` from the envelope's
// SubjectIDs, so an event appended without one notifies nobody — silently, and
// with every test below it passing. The owner is read from the aggregate rather
// than carried on the event because a pseudonym on the event would be personal
// data's nearest neighbour in the log, and the aggregate already knows.
//
// # Idempotency
//
// Twice over, because Stripe retries and the two mechanisms cover different
// windows. The aggregate refuses a second warning for the same deadline, and the
// idempotency key derives byte-identical event ids for one Stripe event so a
// redelivery collides at the append.
func (w *TrialWarnings) Warn(
	ctx context.Context, orgID string, trialEndsAt time.Time, eventID string,
) error {
	switch {
	case orgID == "":
		return fmt.Errorf("organization: a trial warning needs an organization")
	case eventID == "":
		return fmt.Errorf("organization: a trial warning needs the Stripe event id it " +
			"derives its idempotency from")
	case trialEndsAt.IsZero():
		// Poison: the re-fetched subscription reported no trial end for an event
		// that exists to announce one. A retry re-reads the same object.
		return fmt.Errorf("%w: trial_will_end for %s names no trial end; the mail states a "+
			"date and there is none", eventsourcing.ErrPoison, orgID)
	}

	key := domain.StreamKey(orgID)
	org, err := w.repo.Load(ctx, key)
	if err != nil {
		return fmt.Errorf("loading %s: %w", orgID, err)
	}
	if !org.Exists() {
		return fmt.Errorf("%w: trial_will_end names organization %s, which has no events",
			eventsourcing.ErrPoison, orgID)
	}

	now := w.now().UTC()
	if err := org.WarnTrialEnding(trialEndsAt.UTC(), now); err != nil {
		return fmt.Errorf("warning %s: %w", orgID, err)
	}

	if _, err := w.repo.Save(ctx, key, org, eventID+":trial-warning",
		eventsourcing.Metadata{
			OrgID: orgID, OccurredAt: now,
			// WITHOUT THIS THE MAIL GOES NOWHERE. AudienceSubject reads exactly
			// this field, and an empty one resolves to an empty recipient list —
			// which the dispatcher treats as "nobody to tell" rather than as an
			// error, so the warning would be recorded and never sent.
			SubjectIDs: []string{org.OwnerID()},
		}); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			// Another delivery won the race. The warning it appended is the same
			// warning, because both read the same re-fetched deadline.
			return nil
		}
		return fmt.Errorf("saving the trial warning for %s: %w", orgID, err)
	}
	return nil
}

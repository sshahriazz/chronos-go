package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// RestrictionCommand halts or resumes processing for one subject.
type RestrictionCommand struct {
	SubjectID string

	// ActorID is who is asking. Normally the subject; an operator when the
	// request arrived out of band.
	ActorID string

	IdempotencyKey string
}

// RestrictionResult reports what happened.
type RestrictionResult struct {
	// Changed is false when the subject was already in the state asked for. A
	// SUCCESS: the caller asked for a state that holds.
	Changed bool

	// Since is when the restriction began, zero when there is none.
	Since time.Time
}

// Restrictions is the Article 18 use case.
type Restrictions struct {
	repo *eventsourcing.Repository[*domain.Restriction]
	now  func() time.Time
}

// RestrictionsDeps is what Restrictions needs.
type RestrictionsDeps struct {
	Repo *eventsourcing.Repository[*domain.Restriction]
	Now  func() time.Time
}

func NewRestrictions(d RestrictionsDeps) (*Restrictions, error) {
	switch {
	case d.Repo == nil:
		return nil, fmt.Errorf("compliance: a restriction repository is required")
	case d.Now == nil:
		return nil, fmt.Errorf("compliance: a clock is required")
	}
	return &Restrictions{repo: d.Repo, now: d.Now}, nil
}

// Restrict halts processing for a subject (Article 18).
//
// Storage continues and nothing is deleted — that is the whole distinction from
// Article 17. The account keeps working, the projections keep building, and the
// subject stops being contacted.
func (r *Restrictions) Restrict(
	ctx context.Context, cmd RestrictionCommand,
) (RestrictionResult, error) {
	return r.apply(ctx, cmd, func(rest *domain.Restriction, at time.Time) error {
		return rest.Restrict(cmd.SubjectID, cmd.ActorID, at)
	})
}

// Lift resumes processing.
func (r *Restrictions) Lift(
	ctx context.Context, cmd RestrictionCommand,
) (RestrictionResult, error) {
	return r.apply(ctx, cmd, func(rest *domain.Restriction, at time.Time) error {
		return rest.Lift(cmd.SubjectID, cmd.ActorID, at)
	})
}

// State reports whether processing is currently restricted.
//
// Read from the AGGREGATE rather than the projection, because the caller is the
// subject asking about their own request and a stale "not restricted" would tell
// them their instruction had not taken effect when it had. The DISPATCHER reads
// the projection instead, where the lag is acceptable in the safe direction: a
// restriction not yet projected means one more notification, not a lost one.
func (r *Restrictions) State(ctx context.Context, subjectID string) (RestrictionResult, error) {
	if subjectID == "" {
		return RestrictionResult{}, errs.ValidationFailedf("a subject is required")
	}
	rest, err := r.repo.Load(ctx, domain.RestrictionStreamKey(subjectID))
	if err != nil {
		return RestrictionResult{}, errs.Internalf("loading the restriction").Wrap(err)
	}
	since, restricted := rest.Restricted()
	return RestrictionResult{Changed: restricted, Since: since}, nil
}

func (r *Restrictions) apply(
	ctx context.Context, cmd RestrictionCommand,
	decide func(*domain.Restriction, time.Time) error,
) (RestrictionResult, error) {
	switch {
	case cmd.SubjectID == "":
		return RestrictionResult{}, errs.ValidationFailedf("a subject is required")
	case cmd.ActorID == "":
		return RestrictionResult{}, errs.Internalf("no authenticated subject reached the " +
			"restriction handler")
	case cmd.IdempotencyKey == "":
		return RestrictionResult{}, errs.ValidationFailedf(
			"an Idempotency-Key is required on every mutating request")
	}

	key := domain.RestrictionStreamKey(cmd.SubjectID)
	rest, err := r.repo.Load(ctx, key)
	if err != nil {
		return RestrictionResult{}, errs.Internalf("loading the restriction").Wrap(err)
	}

	now := r.now().UTC()
	if err := decide(rest, now); err != nil {
		return RestrictionResult{}, errs.ValidationFailedf("%s", err)
	}
	if len(rest.Uncommitted()) == 0 {
		// Already in the state asked for. A success.
		since, _ := rest.Restricted()
		return RestrictionResult{Since: since}, nil
	}

	if _, err := r.repo.Save(ctx, key, rest, cmd.IdempotencyKey,
		eventsourcing.Metadata{
			OccurredAt: now,
			// The subject is named so the notification catalogue could address
			// them — though nothing does today, and deliberately: telling
			// somebody "we have stopped contacting you" by contacting them is
			// the one message a restriction should not produce.
			SubjectIDs: []string{cmd.SubjectID},
		}); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			return RestrictionResult{}, errs.Conflictf("this restriction changed concurrently")
		}
		return RestrictionResult{}, errs.Internalf("recording the restriction").Wrap(err)
	}

	since, _ := rest.Restricted()
	return RestrictionResult{Changed: true, Since: since}, nil
}

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

// ObjectionCommand stops or resumes one purpose for one subject (Article 21).
type ObjectionCommand struct {
	// SubjectID is the CALLER'S pseudonym, from the session.
	SubjectID string

	// ActorID is who is asking. The subject: an objection binds the controller
	// until its AUTHOR releases it, so there is no operator path here — an
	// operator who could withdraw one could resume processing the person stopped.
	ActorID string

	// Purpose is which processing to stop or resume.
	Purpose domain.Purpose

	IdempotencyKey string
}

// ObjectionResult reports the state after the call.
type ObjectionResult struct {
	// Changed is false when the subject was already in the state asked for. A
	// SUCCESS: the caller asked for a state that holds.
	Changed bool

	// Since is when the objection was FIRST made, zero when there is none.
	Since time.Time
}

// StandingObjection is one purpose a subject currently has stopped.
type StandingObjection struct {
	Purpose domain.Purpose
	Since   time.Time
}

// Objections is the Article 21 use case.
//
// # What it is not
//
// It is not a narrower Restrictions and it is not a preference store. The
// aggregate's doc comment carries the full argument; the operational form of it
// is that this use case never touches a notification preference and never reads
// the restriction stream. If it ever needs to, the two rights have been confused.
type Objections struct {
	repo *eventsourcing.Repository[*domain.Objection]
	now  func() time.Time
}

// ObjectionsDeps is what Objections needs.
type ObjectionsDeps struct {
	Repo *eventsourcing.Repository[*domain.Objection]
	Now  func() time.Time
}

func NewObjections(d ObjectionsDeps) (*Objections, error) {
	switch {
	case d.Repo == nil:
		return nil, fmt.Errorf("compliance: an objection repository is required")
	case d.Now == nil:
		return nil, fmt.Errorf("compliance: a clock is required")
	}
	return &Objections{repo: d.Repo, now: d.Now}, nil
}

// Object stops one purpose for the caller.
//
// Storage continues, the account keeps working, and every message that rests on
// contract or on a legal obligation keeps arriving. What stops is the one
// purpose — which is the whole difference from Article 18, and the property a
// test asserts by sending a transactional notification to an objecting subject
// and watching it arrive.
func (o *Objections) Object(
	ctx context.Context, cmd ObjectionCommand,
) (ObjectionResult, error) {
	return o.apply(ctx, cmd, func(agg *domain.Objection, at time.Time) error {
		return agg.Object(cmd.SubjectID, cmd.ActorID, cmd.Purpose, at)
	})
}

// Withdraw releases one objection.
func (o *Objections) Withdraw(
	ctx context.Context, cmd ObjectionCommand,
) (ObjectionResult, error) {
	return o.apply(ctx, cmd, func(agg *domain.Objection, at time.Time) error {
		return agg.Withdraw(cmd.SubjectID, cmd.ActorID, cmd.Purpose, at)
	})
}

// List reports every objection the caller currently holds.
//
// Read from the AGGREGATE rather than the projection, for the reason
// Restrictions.State is: the caller is the subject asking about their own
// instruction, and a stale "you have objected to nothing" would tell them their
// instruction had not taken effect when it had. The DISPATCHER reads the
// projection instead, where the lag is in the safe direction — an objection not
// yet projected means one more Activity notification, not a lost one.
func (o *Objections) List(
	ctx context.Context, subjectID string,
) ([]StandingObjection, error) {
	if subjectID == "" {
		return nil, errs.ValidationFailedf("a subject is required")
	}
	agg, err := o.repo.Load(ctx, domain.ObjectionStreamKey(subjectID))
	if err != nil {
		return nil, errs.Internalf("loading the objections").Wrap(err)
	}

	purposes := agg.Purposes()
	out := make([]StandingObjection, 0, len(purposes))
	for _, p := range purposes {
		since, _ := agg.Objected(p)
		out = append(out, StandingObjection{Purpose: p, Since: since})
	}
	return out, nil
}

func (o *Objections) apply(
	ctx context.Context, cmd ObjectionCommand,
	decide func(*domain.Objection, time.Time) error,
) (ObjectionResult, error) {
	switch {
	case cmd.SubjectID == "":
		return ObjectionResult{}, errs.ValidationFailedf("a subject is required")
	case cmd.ActorID == "":
		return ObjectionResult{}, errs.Internalf(
			"no authenticated subject reached the objection handler")
	case cmd.Purpose == "":
		return ObjectionResult{}, errs.ValidationFailedf("a processing purpose is required")
	case cmd.IdempotencyKey == "":
		return ObjectionResult{}, errs.ValidationFailedf(
			"an Idempotency-Key is required on every mutating request")
	}

	key := domain.ObjectionStreamKey(cmd.SubjectID)
	agg, err := o.repo.Load(ctx, key)
	if err != nil {
		return ObjectionResult{}, errs.Internalf("loading the objections").Wrap(err)
	}

	now := o.now().UTC()
	if err := decide(agg, now); err != nil {
		return ObjectionResult{}, errs.ValidationFailedf("%s", err).Wrap(err)
	}
	if len(agg.Uncommitted()) == 0 {
		// Already in the state asked for. A success, reporting the ORIGINAL
		// instant — the date has been given to the person and a repeated call
		// must not move it.
		since, _ := agg.Objected(cmd.Purpose)
		return ObjectionResult{Since: since}, nil
	}

	if _, err := o.repo.Save(ctx, key, agg, cmd.IdempotencyKey,
		eventsourcing.Metadata{
			OccurredAt: now,
			// The subject is named so the catalogue COULD address them. Nothing
			// does, deliberately: an objection is not a preference confirmation,
			// and mailing "we have stopped sending you activity notifications" is
			// itself a message the person did not ask for.
			SubjectIDs: []string{cmd.SubjectID},
			ActorID:    cmd.ActorID,
		}); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			return ObjectionResult{}, errs.Conflictf(
				"your objections changed concurrently; reload and try again")
		}
		return ObjectionResult{}, errs.Internalf("recording the objection").Wrap(err)
	}

	since, _ := agg.Objected(cmd.Purpose)
	return ObjectionResult{Changed: true, Since: since}, nil
}

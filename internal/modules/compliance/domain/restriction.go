// Package domain is compliance's aggregates.
package domain

import (
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// RestrictionCategory is the stream category, and it is PERMANENT: it is half of
// every stream name, so changing it orphans every restriction ever recorded.
const RestrictionCategory eventsourcing.Category = "restriction"

// RestrictionStreamKey is the subject's pseudonym.
//
// One stream per subject rather than one per request. A restriction is a STATE —
// processing is halted or it is not — and a stream per request would make
// "is this subject restricted right now" a question about the latest of several
// streams rather than the latest event of one.
func RestrictionStreamKey(subjectID string) string { return subjectID }

// Restriction is one subject's Article 18 state.
//
// # Why this is its own aggregate rather than a flag on the account
//
// It is a COMPLIANCE fact, not an identity one. The account is unchanged — it
// signs in, it works, its projections build — and folding the flag into the User
// aggregate would put a data-protection decision inside the state machine that
// decides whether somebody can authenticate, where every future change to one
// has to be reasoned about against the other.
//
// It also outlives the account's own vocabulary: an erased account is terminal
// and a restriction is not, and a suspended account can still be under
// restriction. Separate streams keep those independent, which they are.
type Restriction struct {
	eventsourcing.Base

	subjectID  string
	restricted bool
	since      time.Time
}

var _ eventsourcing.Root = (*Restriction)(nil)

// NewRestriction returns an empty aggregate for the repository to rebuild into.
func NewRestriction() *Restriction { return &Restriction{} }

// Restricted reports whether processing is currently halted, and since when.
func (r *Restriction) Restricted() (time.Time, bool) { return r.since, r.restricted }

// Exists reports whether anything has ever been recorded for this subject.
func (r *Restriction) Exists() bool { return r.subjectID != "" }

// Apply rebuilds state from the log.
func (r *Restriction) Apply(event eventsourcing.Event) {
	switch ev := event.(type) {
	case *contract.ProcessingRestricted:
		r.subjectID = ev.SubjectID
		r.restricted = true
		r.since = ev.RestrictedAt
	case *contract.ProcessingRestrictionLifted:
		r.subjectID = ev.SubjectID
		r.restricted = false
		r.since = time.Time{}
	}
}

// Restrict halts processing for this subject.
//
// Idempotent: a second request records nothing and keeps the FIRST instant. The
// alternative would let a repeated call move a date that has already been
// reported to the person, for no gain — the state is binary and it is already in
// the state asked for.
func (r *Restriction) Restrict(subjectID, actorID string, at time.Time) error {
	switch {
	case subjectID == "":
		return fmt.Errorf("compliance: a restriction needs a subject")
	case actorID == "":
		return fmt.Errorf("compliance: a restriction needs an actor")
	}
	if r.restricted {
		return nil
	}
	eventsourcing.Record(r, &contract.ProcessingRestricted{
		SubjectID: subjectID, ActorID: actorID, RestrictedAt: at.UTC(),
	})
	return nil
}

// Lift resumes processing.
//
// Idempotent in the same direction and for a stronger reason: lifting a
// restriction nobody placed is not an error, because the caller is asking for a
// state that already holds. Erroring would make the control fail for anybody who
// clicked it twice.
func (r *Restriction) Lift(subjectID, actorID string, at time.Time) error {
	switch {
	case subjectID == "":
		return fmt.Errorf("compliance: lifting a restriction needs a subject")
	case actorID == "":
		return fmt.Errorf("compliance: lifting a restriction needs an actor")
	}
	if !r.restricted {
		return nil
	}
	eventsourcing.Record(r, &contract.ProcessingRestrictionLifted{
		SubjectID: subjectID, ActorID: actorID, LiftedAt: at.UTC(),
	})
	return nil
}

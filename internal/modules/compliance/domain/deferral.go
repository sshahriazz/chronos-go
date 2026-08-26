package domain

import (
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// DeferralCategory is the stream category, and it is PERMANENT.
const DeferralCategory eventsourcing.Category = "erasuredeferral"

// DeferralStreamKey is the subject's pseudonym.
//
// One stream per subject, like Restriction and LegalHold, and for the same
// reason: deferral is a STATE — this request is waiting or it is not — and the
// question the erasure asks is "have we already told them", which a stream per
// deferral would turn into a fold across several.
func DeferralStreamKey(subjectID string) string { return subjectID }

// Deferral is whether an erasure request is currently waiting, and whether the
// person has been told.
//
// # It exists to make ONE MESSAGE idempotent
//
// The erasure workflow re-runs its execute step on a timer for as long as a
// hold stands — weeks, for a real matter. Every one of those attempts finds the
// subject held, and every one would mail them if nothing remembered that the
// first already had.
//
// The workflow could remember it in local state: Temporal replays deterministic
// history, so a boolean would survive. That is not enough here for two reasons.
// A request whose workflow is restarted from scratch — a worker rebuilt, a run
// re-triggered — would forget and mail again. And Article 12(4) compliance is
// something we may have to EVIDENCE, which a variable inside a workflow's
// history is a poor place to keep.
//
// So the fact lives in the log, where it is both the deduplication and the
// record.
type Deferral struct {
	eventsourcing.Base

	subjectID  string
	deferred   bool
	deferredAt time.Time
}

var _ eventsourcing.Root = (*Deferral)(nil)

// NewDeferral returns an empty aggregate for the repository to rebuild into.
func NewDeferral() *Deferral { return &Deferral{} }

// Deferred reports whether this request is currently waiting, and since when.
func (d *Deferral) Deferred() (time.Time, bool) { return d.deferredAt, d.deferred }

// Exists reports whether anything was ever recorded for this subject.
func (d *Deferral) Exists() bool { return d.subjectID != "" }

// Apply rebuilds state from the log.
func (d *Deferral) Apply(event eventsourcing.Event) {
	switch ev := event.(type) {
	case *contract.ErasureDeferred:
		d.subjectID = ev.SubjectID
		d.deferred = true
		d.deferredAt = ev.DeferredAt

	case *contract.ErasureResumed:
		d.subjectID = ev.SubjectID
		d.deferred = false
		d.deferredAt = time.Time{}
	}
}

// Defer records that the request is waiting, ONCE.
//
// Idempotent, and the idempotency is the entire purpose: a second call while
// already deferred records nothing and keeps the FIRST instant. Article 12(4)
// asks for one answer to one request, and a person told weekly that their
// erasure is still deferred is being harassed by a compliance obligation.
//
// Keeping the original instant matters for the same reason Restriction keeps
// its: the date has been reported to somebody, and a repeated call must not
// move it.
func (d *Deferral) Defer(subjectID string, at time.Time) error {
	if subjectID == "" {
		return fmt.Errorf("compliance: a deferral needs a subject")
	}
	if d.deferred {
		return nil
	}
	eventsourcing.Record(d, &contract.ErasureDeferred{
		SubjectID:  subjectID,
		DeferredAt: at.UTC(),
	})
	return nil
}

// Resume records that the obstacle cleared.
//
// Idempotent in the same direction: resuming a request that was never deferred
// is asking for a state that already holds. That case is the COMMON one — every
// erasure of an unheld subject passes through here — so it must be free and it
// must record nothing.
func (d *Deferral) Resume(subjectID string, at time.Time) error {
	if subjectID == "" {
		return fmt.Errorf("compliance: resuming a deferral needs a subject")
	}
	if !d.deferred {
		return nil
	}
	eventsourcing.Record(d, &contract.ErasureResumed{
		SubjectID: subjectID,
		ResumedAt: at.UTC(),
	})
	return nil
}

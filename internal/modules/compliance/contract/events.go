// Package contract is compliance's public event surface.
package contract

import "time"

// ProcessingRestricted records that a data subject invoked Article 18.
//
// # What restriction is, and what it is not
//
// It is NOT deletion and NOT deactivation. Article 18 exists for the case where
// somebody disputes what is held about them but does not want it destroyed while
// the dispute runs: storage continues, and everything else stops. The account
// keeps working, the projections keep building, the log keeps its history — and
// the subject stops being contacted or otherwise processed.
//
// compliance.md §6: "projectors continue, but reactors skip the subject — no
// email, no push, no export, no profiling."
//
// # The reason is not carried
//
// A restriction's justification is the subject's own account of a dispute, which
// is free text a person wrote about themselves. It belongs in a support system,
// not in a permanent replicated log (ADR-002) — and nothing in this system
// branches on it, so storing it would be keeping personal data to satisfy
// nobody's question.
type ProcessingRestricted struct {
	SubjectID string

	// ActorID is who invoked it. Normally the subject; an operator when the
	// request arrived out of band.
	ActorID string

	RestrictedAt time.Time
}

func (*ProcessingRestricted) EventType() string { return "compliance.ProcessingRestricted.v1" }

// ProcessingRestrictionLifted records that processing may resume.
//
// The dispute is settled, or the subject withdrew the restriction. Nothing was
// lost while it stood, which is the whole point of Article 18 as distinct from
// Article 17.
type ProcessingRestrictionLifted struct {
	SubjectID string

	ActorID string

	LiftedAt time.Time
}

func (*ProcessingRestrictionLifted) EventType() string {
	return "compliance.ProcessingRestrictionLifted.v1"
}

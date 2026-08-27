package domain

import (
	"github.com/chronos/chronos-go/internal/platform/pii"
	"github.com/chronos/chronos-go/internal/platform/subjectdata"
)

// SubjectDataFragment is identity's contribution to the subject graph
// (compliance.md §4 step 4).
//
// # Fields, and why declaring them is not a work list
//
// Erasure does not walk these. One key destruction makes every field of a
// subject unreadable at once, which is the whole design of ADR-002, and a
// per-field traversal would be a second way to do the same thing with a
// different set of bugs.
//
// What the declaration answers is the question a controller has to answer and
// nothing else in this codebase records: WHO puts personal data in the vault.
// The completeness gate reads it — a field the vault defines and no module
// claims is either dead vocabulary a subject access request still enumerates,
// or a writer that never declared itself, and somebody has to say which.
//
// `email` is also claimed by workspace, which writes an invitee's address under
// a pseudonym it mints for people who have no account yet. Two writers of one
// field is a fact rather than a conflict, for the reason above.
//
// # Reservations, which the key destruction genuinely does not reach
//
// The email reservation is EVENT-SOURCING §5's deliberate exception: the blind
// index is an HMAC under a key that is never rotated and never destroyed, so
// the reservation stays derivable after the subject's own key is gone. That is
// what lets a released address be re-registered, and it is why the reservation
// has to be released explicitly rather than shredded.
//
// The username is TOMBSTONED rather than released — the handle is published by
// design (ADR-051) and appears in mentions and in mail other people already
// hold, so reissuing it would attach a stranger to somebody else's history.
func SubjectDataFragment() subjectdata.Fragment {
	return subjectdata.Fragment{
		Module: "identity",
		VaultFields: []string{
			string(pii.FieldEmail),
			string(pii.FieldPendingEmail),
			string(pii.FieldPreviousEmail),
		},
		Reservations: []string{
			// Released on erasure, so the address can be registered again.
			"email_reservation",
			// Tombstoned on erasure, never reissued.
			"username_reservation",
		},
	}
}

package domain

import (
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// Release reasons. Stored in the event, so they are permanent strings rather
// than an enum whose meaning depends on ordering in a Go file.
const (
	// ReleaseExpired is an unverified claim that ran out. Routine.
	ReleaseExpired = "expired"

	// ReleaseChanged is the owner moving to a different address.
	ReleaseChanged = "changed"

	// ReleaseErased is the account being erased. The address becomes available
	// again, which is deliberate: identifier reuse after erasure is a stated
	// requirement (identity-features §12), and holding an address forever for an
	// account that no longer exists is itself a retention of personal data.
	ReleaseErased = "erased"
)

// EmailReservation is the uniqueness mechanism for an address.
//
// One aggregate per address, on a stream named from the address's blind index
// (ADR-044). That naming is the entire design: two concurrent registrations for
// the same address contend on the SAME STREAM, so KurrentDB's expected-revision
// check rejects one of them. Uniqueness holds at the moment of the write.
//
// The alternative — check a projection, then write — cannot work, and fails in
// the way that is hardest to notice: the projection is by definition behind the
// log, so under concurrency both registrations read "free", both succeed, and
// two accounts own one address. It would pass every test that did not run the
// two requests simultaneously.
type EmailReservation struct {
	eventsourcing.Base

	index     contract.EmailIndex
	subjectID string

	held      bool
	verified  bool
	expiresAt time.Time
}

// NewReservation returns an empty reservation for the repository to rebuild
// into.
func NewReservation() *EmailReservation { return &EmailReservation{} }

func (r *EmailReservation) Index() contract.EmailIndex { return r.index }
func (r *EmailReservation) SubjectID() string          { return r.subjectID }
func (r *EmailReservation) Held() bool                 { return r.held }
func (r *EmailReservation) Verified() bool             { return r.verified }
func (r *EmailReservation) ExpiresAt() time.Time       { return r.expiresAt }

// Available reports whether the address can be claimed at this instant.
//
// A verified claim is never available. An unverified one becomes available once
// it lapses — that lapse is what stops someone registering with an address they
// do not control and holding it forever, with no account to appeal to because
// none was ever proven.
func (r *EmailReservation) Available(now time.Time) bool {
	switch {
	case !r.held:
		return true
	case r.verified:
		return false
	default:
		return !now.Before(r.expiresAt)
	}
}

// Apply is the pure transition.
func (r *EmailReservation) Apply(e eventsourcing.Event) {
	switch ev := e.(type) {
	case *contract.EmailReserved:
		r.index = ev.Index
		r.subjectID = ev.SubjectID
		r.held = true
		r.verified = false
		r.expiresAt = ev.ExpiresAt

	case *contract.EmailReservationConfirmed:
		r.index = ev.Index
		r.subjectID = ev.SubjectID
		r.held = true
		r.verified = true
		// The deadline is cleared, not merely ignored. Leaving it set would let
		// any later reader compare against a time that has passed and conclude a
		// confirmed address is free.
		r.expiresAt = time.Time{}

	case *contract.EmailReleased:
		r.held = false
		r.verified = false
		r.subjectID = ""
		r.expiresAt = time.Time{}
	}
}

// Reserve claims the address.
//
// Idempotent for the SAME subject: a retried registration must not fail, and
// must not extend its own lease either — extending would let a squatter renew
// indefinitely by replaying one request.
//
// When an unverified claim has lapsed, this records the release AND the new
// reservation, in that order. Two events rather than one so the log says what
// happened to the previous holder: a claim that simply vanished when overwritten
// would leave the earlier registrant's disappearance unexplained.
func (r *EmailReservation) Reserve(
	index contract.EmailIndex, subjectID string, expiresAt, now time.Time,
) error {
	switch {
	case index == "":
		return errs.ValidationFailedf("an email index is required")
	case subjectID == "":
		return errs.ValidationFailedf("a subject id is required")
	case !expiresAt.After(now):
		return errs.ValidationFailedf("an unverified reservation must expire in the future")
	case r.held && r.index != index:
		// The stream is named from the index, so this cannot happen through the
		// repository — but it can through a hand-built aggregate, and silently
		// overwriting would move a claim between two addresses.
		return errs.Internalf("this reservation is for a different address")
	}

	if r.held && r.subjectID == subjectID {
		// Already ours. Records nothing, deliberately: see the doc comment.
		return nil
	}
	if !r.Available(now) {
		// Deliberately the SAME error whether the address is verified-and-taken
		// or unverified-and-still-within-its-lease. The difference tells a caller
		// whether someone has proven control of the address, which is an
		// account-existence oracle (identity.md §7).
		return errs.Conflictf("this address is not available")
	}

	if r.held {
		eventsourcing.Record(r, &contract.EmailReleased{
			Index:      r.index,
			SubjectID:  r.subjectID,
			Reason:     ReleaseExpired,
			ReleasedAt: now.UTC(),
		})
	}
	eventsourcing.Record(r, &contract.EmailReserved{
		Index:      index,
		SubjectID:  subjectID,
		ExpiresAt:  expiresAt.UTC(),
		ReservedAt: now.UTC(),
	})
	return nil
}

// Confirm makes the claim permanent, after the address has been proven.
//
// Refused for a subject that does not hold the claim. Without that check, an
// attacker who registered second — and whose reservation therefore failed — could
// still confirm the address out from under the holder by presenting a token for
// an address they never proved.
func (r *EmailReservation) Confirm(subjectID string, now time.Time) error {
	if !r.held {
		return errs.NotFoundf("this address is not reserved")
	}
	if r.subjectID != subjectID {
		return errs.Conflictf("this address is reserved by another account")
	}
	if r.verified {
		return nil // a repeated confirmation is not an error
	}
	// Confirming a LAPSED claim is refused. The holder's lease ran out, so the
	// address is available to anyone — and letting a late verification link
	// resurrect the claim would take the address back from whoever legitimately
	// claimed it in the meantime, with no event explaining why.
	if !now.Before(r.expiresAt) {
		return errs.Conflictf("this reservation has expired; register again")
	}
	eventsourcing.Record(r, &contract.EmailReservationConfirmed{
		Index:       r.index,
		SubjectID:   subjectID,
		ConfirmedAt: now.UTC(),
	})
	return nil
}

// Release frees the address.
func (r *EmailReservation) Release(subjectID, reason string, now time.Time) error {
	if !r.held {
		return nil // already free; releasing twice is not an error
	}
	if r.subjectID != subjectID {
		return errs.Conflictf("this address is reserved by another account")
	}
	switch reason {
	case ReleaseExpired, ReleaseChanged, ReleaseErased:
	default:
		// An unnamed reason produces a log entry that cannot be interpreted
		// later, and the projector branches on it.
		return errs.ValidationFailedf("a release must state a known reason")
	}
	eventsourcing.Record(r, &contract.EmailReleased{
		Index:      r.index,
		SubjectID:  r.subjectID,
		Reason:     reason,
		ReleasedAt: now.UTC(),
	})
	return nil
}

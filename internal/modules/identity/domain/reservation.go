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

	// noticedAt is when this address was last made to send a
	// duplicate-registration notice, oldest first.
	//
	// It is the ONLY state on this aggregate that exists to bound an outbound
	// message rather than to decide who owns an address, and it lives here rather
	// than in a cache for one reason: the notice is triggered by an
	// UNAUTHENTICATED caller and it WRITES TO THE LOG. A ceiling that fails open
	// — which the shared Valkey mail ceiling deliberately does, see
	// app.ResendVerification.spend — is a ceiling that stops bounding anything
	// during exactly the outage an attacker would wait for, and what is unbounded
	// here is not only mail to a stranger's mailbox but appends to a stream. This
	// one is derived from the log itself, so it cannot be degraded, cannot be
	// flushed, and rebuilds with the aggregate.
	//
	// Capped at retainedNotices. Nothing reads further back than the daily
	// ceiling, and an address under sustained attack must not grow an unbounded
	// slice in memory every time its aggregate is loaded.
	noticedAt []time.Time
}

// retainedNotices is how many duplicate-registration timestamps the aggregate
// keeps.
//
// Comfortably above any ceiling app.Registration applies, because the two are
// deliberately not the same number: the policy is the application's and may
// change, while this is the window of history the aggregate can answer questions
// about. Set it below the daily ceiling and NoticesSince silently under-counts,
// which reads as "the ceiling was never reached" — the failure direction that
// sends the mail.
const retainedNotices = 32

// NewReservation returns an empty reservation for the repository to rebuild
// into.
func NewReservation() *EmailReservation { return &EmailReservation{} }

func (r *EmailReservation) Index() contract.EmailIndex { return r.index }
func (r *EmailReservation) SubjectID() string          { return r.subjectID }
func (r *EmailReservation) Held() bool                 { return r.held }
func (r *EmailReservation) Verified() bool             { return r.verified }
func (r *EmailReservation) ExpiresAt() time.Time       { return r.expiresAt }

// NoticesSince counts the duplicate-registration notices recorded at or after t.
//
// The COUNT and not the times, because the only question anybody asks of it is
// whether a ceiling has been reached, and handing out the timestamps would invite
// a second caller to compute a different answer from the same data.
//
// It looks back at most retainedNotices entries. A window longer than that is
// answered from what is retained rather than refused, and the doc on
// retainedNotices says why that bound is set where it is.
func (r *EmailReservation) NoticesSince(t time.Time) int {
	n := 0
	for _, at := range r.noticedAt {
		if !at.Before(t) {
			n++
		}
	}
	return n
}

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
		// The notice history is deliberately NOT cleared. It bounds how much mail
		// one ADDRESS can be made to emit, and releasing a claim is something an
		// attacker can cause — a lapse is a timer they only have to wait for — so
		// clearing here would hand them a fresh budget for the price of patience.

	case *contract.DuplicateRegistrationAttempted:
		r.noticedAt = append(r.noticedAt, ev.AttemptedAt)
		if len(r.noticedAt) > retainedNotices {
			r.noticedAt = r.noticedAt[len(r.noticedAt)-retainedNotices:]
		}
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

// Ceilings on the duplicate-registration notice, per address.
//
// They MIRROR cmd/api's mailAddressRules — three an hour, ten a day — and the
// duplication is deliberate rather than an oversight to be factored out. That
// rule is a Valkey counter shared by every class of triggered mail, and it FAILS
// OPEN by design (app.ResendVerification.spend argues why, and the argument is
// right: failing closed would turn a cache blip into permanent account loss).
// These two numbers are the floor underneath it — derived from the log, so they
// hold while Valkey is down, while it is flushed, and while nothing has wired the
// shared ceiling at all.
//
// Keep them equal to mailAddressRules. If the shared rule is ever loosened, the
// symptom of forgetting this pair is that the loosening does not take effect for
// this one message, which is the harmless direction. Tightening the shared rule
// without tightening these leaves the mail bounded by the LOOSER of the two,
// which is not.
const (
	// MaxDuplicateNoticesPerHour caps hourly notices for one address.
	MaxDuplicateNoticesPerHour = 3

	// MaxDuplicateNoticesPerDay caps daily notices for one address. Three an
	// hour unbounded is 72 a day, which is a flood rather than an annoyance.
	MaxDuplicateNoticesPerDay = 10
)

// NoticeDuplicateRegistration records that somebody tried to register with this
// address while it was already claimed, and reports whether anything was
// recorded.
//
// It returns a bool rather than an error, and the difference is the whole point:
// every refusal below is a NON-EVENT, not a failure. Register must answer the
// same empty response whether this recorded something or nothing, so a caller
// that had to distinguish "no notice was warranted" from "the command failed"
// would be a caller with a branch that can leak onto the wire.
//
// # Refused for an UNVERIFIED claim
//
// Nobody has proven they can read mail at this address. Sending here would be
// unsolicited mail to a person who never asked for anything (NOTIFICATIONS §5),
// aimed at an address a stranger typed — which is the very act being reported.
// The pending registrant is not stranded by the silence: they hold a live
// verification link and ResendEmailVerification issues another (identity.md
// §12.1).
//
// # Refused above the ceiling
//
// The caller is unauthenticated and can repeat at will, so without a bound this
// endpoint mails a stranger's mailbox as often as it is asked to AND appends to
// their address's stream every time. Both halves matter; the second is why the
// bound is here, in state rebuilt from the log, rather than only in the shared
// counter that fails open.
//
// # Why this lives on the aggregate and not in the use case
//
// Because it cannot then be forgotten. The use case decides WHEN a registration
// was refused; this decides whether an address may say so again, and it is the
// only place that knows how often it already has.
func (r *EmailReservation) NoticeDuplicateRegistration(now time.Time) bool {
	if !r.held || !r.verified {
		return false
	}
	now = now.UTC()
	if r.NoticesSince(now.Add(-time.Hour)) >= MaxDuplicateNoticesPerHour {
		return false
	}
	if r.NoticesSince(now.Add(-24*time.Hour)) >= MaxDuplicateNoticesPerDay {
		return false
	}
	eventsourcing.Record(r, &contract.DuplicateRegistrationAttempted{
		Index:       r.index,
		SubjectID:   r.subjectID,
		AttemptedAt: now,
	})
	return true
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

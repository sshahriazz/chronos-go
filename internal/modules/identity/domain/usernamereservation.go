package domain

import (
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// UsernameReservation is the uniqueness mechanism for a public handle
// (ADR-051).
//
// One aggregate per handle, on a stream named from the handle ITSELF. That
// naming is the entire design, and it is the same design EmailReservation runs
// on: two concurrent claims for one handle contend on the SAME STREAM, so
// KurrentDB's expected-revision check rejects one of them and uniqueness holds
// at the moment of the write.
//
// The alternative — a UNIQUE index on the projection — cannot work and fails in
// the way that is hardest to notice. A projection is behind the log by
// construction, so under concurrency both claims read "free", both append, and
// two accounts own one handle. ADR-052 records what the read model does when it
// is asked to be the mechanism instead of the backstop: the projector stops, and
// the table stops being rebuildable from position zero.
//
// # Two differences from EmailReservation, and both follow from publicity
//
//   - The stream name is the handle in the clear, not a keyed HMAC. ADR-048
//     hides an address because an address is secret and a stream name can never
//     be shredded. A handle is published on purpose, so hiding it protects
//     nothing and costs the ability to read the log while debugging.
//
//   - There is NO LEASE and no release. An address is claimed by a registration
//     that has proven nothing, so an unverified claim must lapse or a squatter
//     holds it forever. A handle is claimed by an account that has just proven
//     its mailbox (identity.md §4.6), so there is nothing unproven to expire —
//     and the one terminal transition is a tombstone that is permanent by design.
type UsernameReservation struct {
	eventsourcing.Base

	username  string
	subjectID string

	held       bool
	tombstoned bool
}

// NewUsernameReservation returns an empty reservation for the repository to
// rebuild into.
func NewUsernameReservation() *UsernameReservation { return &UsernameReservation{} }

func (r *UsernameReservation) Username() string  { return r.username }
func (r *UsernameReservation) SubjectID() string { return r.subjectID }
func (r *UsernameReservation) Held() bool        { return r.held }
func (r *UsernameReservation) Tombstoned() bool  { return r.tombstoned }

// Available reports whether the handle can be claimed.
//
// It takes no time argument, and the absence is the design rather than an
// oversight: nothing about a handle's availability depends on the clock. A
// claimed handle is claimed forever and a tombstoned one is burned forever, so a
// signature with a `now` in it would advertise an expiry that does not exist and
// invite somebody to add a sweep for it.
func (r *UsernameReservation) Available() bool { return !r.held && !r.tombstoned }

// Apply is the pure transition.
func (r *UsernameReservation) Apply(e eventsourcing.Event) {
	switch ev := e.(type) {
	case *contract.UsernameReserved:
		r.username = ev.Username
		r.subjectID = ev.SubjectID
		r.held = true

	case *contract.UsernameTombstoned:
		r.username = ev.Username
		// The holder is FORGOTTEN, not merely superseded. The tombstone event
		// carries no subject and this clears the one the claim left behind, so an
		// aggregate rebuilt from a tombstoned stream holds nothing that names a
		// person — which is the property that makes retaining the tombstone after
		// an erasure lawful (ADR-051).
		r.subjectID = ""
		r.held = false
		r.tombstoned = true
	}
}

// Reserve claims the handle for a subject.
//
// Idempotent for the SAME subject, so a retried verification does not fail and
// does not record a second claim.
//
// # Every refusal says exactly what happened, and that is deliberate
//
// EmailReservation.Reserve answers "taken" and "held but not yet proven" with
// ONE error, because the difference tells a caller whether somebody has proven
// control of an address — an account-existence oracle. Nothing of the kind
// applies here. A handle is public, its availability is served by a public RPC
// whose whole purpose is to answer this question, and an attacker learns nothing
// from a refusal they could not learn by asking.
//
// The one distinction NOT drawn is between "somebody holds it" and "it was
// tombstoned", and that omission is a privacy decision rather than a security
// one: "this handle belonged to an account that was erased" is a fact about a
// person, and the tombstone exists precisely to protect that person.
func (r *UsernameReservation) Reserve(username, subjectID string, now time.Time) error {
	switch {
	case username == "":
		return errs.ValidationFailedf("a username is required")
	case subjectID == "":
		return errs.ValidationFailedf("a subject id is required")
	case r.username != "" && r.username != username:
		// The stream is named from the handle, so this cannot happen through the
		// repository — but it can through a hand-built aggregate, and silently
		// overwriting would move a claim between two handles.
		return errs.Internalf("this reservation is for a different username")
	}

	if r.held && r.subjectID == subjectID {
		return nil // already ours; records nothing
	}
	if !r.Available() {
		return errs.Conflictf("that username is not available; choose another")
	}

	eventsourcing.Record(r, &contract.UsernameReserved{
		Username:   username,
		SubjectID:  subjectID,
		ReservedAt: now.UTC(),
	})
	return nil
}

// Tombstone burns the handle permanently, on erasure.
//
// # It takes no subject, and refuses to record one
//
// The caller has already decided that this handle's account is being erased.
// What is written down is that the handle may never be reissued, and nothing
// else — no actor, no subject, no reason. A tombstone that named the erased
// account would be a permanent record linking a person to an erasure request,
// which is the opposite of what the request asked for.
//
// # It does not check who held it
//
// EmailReservation.Release refuses a subject that does not hold the claim,
// because releasing somebody else's address hands it to a stranger. A tombstone
// grants nothing to anybody: it makes the handle unusable by everyone including
// its holder, so there is no privilege for a mistaken caller to gain. Requiring a
// subject here would mean carrying the erased account's pseudonym to a call whose
// entire point is to record nothing about them.
//
// # Idempotent, and NOT reversible
//
// A second tombstone records nothing. There is deliberately no method that
// clears one: reissuing a handle is the failure this type exists to prevent, and
// an "untombstone" would be the one line of code that reintroduces it.
func (r *UsernameReservation) Tombstone(now time.Time) error {
	if r.tombstoned {
		return nil
	}
	if r.username == "" {
		// Nothing was ever claimed here. Refused rather than recorded, because a
		// tombstone on a handle nobody held would burn a name on the strength of a
		// typo, permanently and with no way back.
		return errs.NotFoundf("that username is not claimed")
	}
	eventsourcing.Record(r, &contract.UsernameTombstoned{
		Username:     r.username,
		TombstonedAt: now.UTC(),
	})
	return nil
}

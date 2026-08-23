package projection_test

import (
	"testing"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/projection"
)

// The account projection must HANDLE every event that changes what an account
// row says, and EmailReleased is the one that is easy to miss: it is the only
// such event that lives on the reservation stream rather than on the account's
// own, so nothing about reading user.go's other handlers suggests it belongs
// here.
//
// Missing it is not a stale column. user_view could then never say "this
// account used to hold this address", so the next registration for a lapsed
// address collided with the abandoned row's email_index, the identity projector
// stopped, and the table stopped being rebuildable from position zero.
//
// A unit test rather than an integration one on purpose: this asks whether the
// handler is REGISTERED, which is exactly the class of defect this repository
// has shipped repeatedly — code that is built and tested and wired into
// nothing. No database can answer it, and every database test that would have
// caught it needs a live stack and thirty seconds.
func TestUserProjectionHandlesEveryEventThatChangesAnAccountRow(t *testing.T) {
	// nil codec: Handles is a registration lookup and never decodes.
	p := projection.NewUser(nil)

	for _, e := range []interface {
		EventType() string
	}{
		&contract.UserRegistered{},
		&contract.EmailVerified{},
		&contract.EmailReleased{},
		&contract.UserActivated{},
		&contract.UserDeactivated{},
		&contract.UserReactivated{},
		&contract.UserSuspended{},

		// Not a state transition — the account keeps working until the grace
		// period ends. Projected because this row is the only place the request
		// is visible until then, AND because it is the OVERDUE SWEEP's work list:
		// a request the projection does not carry is one the backstop cannot find.
		&contract.UserDeletionRequested{},

		// The other two thirds of that lifecycle, and both were missing when the
		// events were added — this list is what should have caught it and did
		// not, because the list is also hand-maintained.
		//
		// The CANCELLATION is the one whose absence is actively harmful rather
		// than merely stale: `deletion_requested_at` is what
		// RecordDeletionRequest's `IS NULL` guard tests, so a row left set makes
		// a LATER request a silent no-op in the projection while the aggregate
		// records one. The log and the read model then disagree about whether
		// somebody is scheduled for erasure — and the overdue sweep reads the
		// read model, so it would erase an account whose owner cancelled.
		&contract.UserDeletionCancelled{},
		&contract.UserErased{},

		// The public handle (ADR-051), and the pair is the same trap EmailReleased
		// is, twice over. UsernameAssigned arrives on the ACCOUNT's stream;
		// UsernameTombstoned arrives on the HANDLE's own, so nothing about reading
		// user.go's other handlers suggests it belongs here.
		//
		// Missing the assignment leaves every account nameless in the read model
		// while the log says otherwise. Missing the TOMBSTONE is worse and is
		// silent: `user_view.username` is the ONE cleartext personal-data column in
		// this system, erasure DELETES it rather than shredding a key, and a
		// projector that ignored the tombstone would keep an erased person's handle
		// published — and would republish it on every rebuild.
		&contract.UsernameAssigned{},
		&contract.UsernameTombstoned{},
	} {
		t.Run(e.EventType(), func(t *testing.T) {
			if !p.Handles(e.EventType()) {
				t.Errorf("the account projection ignores %s, so user_view cannot represent "+
					"the state that event produces", e.EventType())
			}
		})
	}

	// And the filter must still deliver them. The handler and the subscription
	// are two independent decisions, and a handler for an event the filter drops
	// is the same defect wearing a passing test.
	f := p.Filter()
	if err := f.Validate(); err != nil {
		t.Fatalf("the account projection's filter is invalid: %v", err)
	}
	if len(f.EventTypePrefixes) != 1 || f.EventTypePrefixes[0] != "identity." {
		t.Fatalf("the filter is %+v; EmailReleased is written to a reservation_email- "+
			"stream and UsernameTombstoned to a reservation_username- one, so anything "+
			"narrower than the shared event-type prefix drops them", f)
	}
}

// The account projection must NOT handle the handle's CLAIM.
//
// UsernameReserved and UsernameAssigned are two facts about one moment, on two
// streams, and only the second one names an account. Projecting the claim here
// as well would mean writing user_view from an event whose subject is the
// claimant of a NAME rather than the holder of an account — the same value
// today, and two different things the moment a username-change flow exists,
// where the old handle's stream is released by an account that no longer
// answers to it.
//
// Stated as a test rather than as a comment because the wrong version is the
// tempting one: UsernameReserved carries both the handle and a subject, so it
// looks like it would do the job on its own.
func TestTheAccountProjectionIgnoresTheHandlesOwnClaim(t *testing.T) {
	p := projection.NewUser(nil)
	if e := (&contract.UsernameReserved{}); p.Handles(e.EventType()) {
		t.Errorf("the account projection handles %s. The account's handle comes from "+
			"UsernameAssigned, on the account's own stream; the claim is a fact about "+
			"the NAME and belongs to the reservation aggregate", e.EventType())
	}
}

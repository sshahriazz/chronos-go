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
			"stream, so anything narrower than the shared event-type prefix drops it", f)
	}
}

package domain

import (
	"regexp"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// MaxServiceAccountNameLen bounds the label an admin gives a service account.
//
// Sixty-four characters, matching every other machine-readable label in this
// module (`reason`, the revocation labels). It is a display bound rather than a
// security one — the PATTERN is the security control, see serviceAccountName.
const MaxServiceAccountNameLen = 64

// serviceAccountName is what a service account may be called.
//
// Lower-case snake, and the restriction is ADR-002 rather than aesthetics. The
// name goes into an event in cleartext, the log is append-only, and free text is
// exactly where personal data arrives in a field like this: an admin naming a
// bot after the colleague who owns it writes a person's name into a record that
// can never be erased. `deploy_bot` cannot hold a sentence, so it cannot hold a
// person.
//
// The same reasoning already governs `SessionRevoked.Reason`, whose proto rule
// says so in as many words. This is that rule applied to the one other field in
// identity where a human types text that reaches the log — the public username
// being the deliberate, documented exception (ADR-051), and it is deliberate
// precisely because a handle is PUBLISHED and a service account's name is not.
var serviceAccountName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// ServiceAccountState is the lifecycle of one service account.
type ServiceAccountState int

const (
	// ServiceAccountNone does not exist. Zero value, so an unloaded account is
	// never mistaken for a live one — the same reason SessionNone is the zero
	// value of SessionState.
	ServiceAccountNone ServiceAccountState = iota
	ServiceAccountActive
)

// ServiceAccount is a non-human principal owned by an organization.
//
// # Why it is an aggregate and not a row on an account
//
// identity.md §10 draws the line at what happens when a person leaves: an
// integration that authenticates as a departing employee stops working the day
// their account is closed, and the failure surfaces as a production incident
// with no obvious cause. A principal the ORGANIZATION owns does not have that
// failure, and the only way to have one is for it to be a distinct thing rather
// than a mode of a user.
//
// The operator plane reached the same conclusion about operators for the same
// reason and stated it more sharply (operator.md §3): a boolean that grants
// something is exactly the field an injection bug sets. `user_view.is_service_
// account = true` would put every human account one flipped bit away from being
// a machine principal that outlives its owner, and no type in the system would
// object.
//
// # What it deliberately cannot do
//
// It holds no secret. A service account that has just been created can
// authenticate nothing at all; an API key is a separate aggregate on a separate
// stream, and minting one is a separate decision that separately notifies. That
// split is what makes "somebody created a principal" and "somebody gave a
// principal a way in" two facts an incident timeline can tell apart.
//
// It also has no lifecycle beyond creation in this slice — there is no Disable
// and no Delete. That is a GAP and not a decision: the containment that exists
// today is that revoking a service account's keys removes everything it can do,
// which is the operation an incident actually needs. See the module's worklist
// entry.
type ServiceAccount struct {
	eventsourcing.Base

	id    ids.ServiceAccountID
	orgID string
	name  string
	state ServiceAccountState
}

// NewServiceAccount returns an empty aggregate for the repository to rebuild
// into.
func NewServiceAccount() *ServiceAccount { return &ServiceAccount{} }

func (s *ServiceAccount) ID() ids.ServiceAccountID   { return s.id }
func (s *ServiceAccount) OrgID() string              { return s.orgID }
func (s *ServiceAccount) Name() string               { return s.name }
func (s *ServiceAccount) State() ServiceAccountState { return s.state }
func (s *ServiceAccount) Exists() bool               { return s.state != ServiceAccountNone }

// Apply is the pure transition.
func (s *ServiceAccount) Apply(e eventsourcing.Event) {
	if ev, ok := e.(*contract.ServiceAccountCreated); ok {
		s.id, _ = ids.Parse[ids.ServiceAccount](ev.ServiceAccountID)
		s.orgID = ev.OrgID
		s.name = ev.Name
		s.state = ServiceAccountActive
	}
}

// Create brings the principal into existence.
//
// The organization is a parameter and is fixed here forever. There is no
// command that changes it and there must not be one: a principal that could be
// moved between organizations would carry one customer's automation into
// another customer's data, which is the cross-tenant failure identity.md §10
// (review D2) describes for keys and which applies at least as hard to the
// principal a key acts as.
func (s *ServiceAccount) Create(
	id ids.ServiceAccountID, orgID, name, createdBy string, at time.Time,
) error {
	if s.state != ServiceAccountNone {
		return errs.Conflictf("this service account already exists")
	}
	switch {
	case id.IsZero():
		return errs.ValidationFailedf("a service account id is required")
	case orgID == "":
		// Refused rather than defaulted to "the caller's organization". A
		// service account with no tenant is one row-level security cannot scope
		// and one no revocation path can find.
		return errs.ValidationFailedf("a service account belongs to exactly one organization")
	case createdBy == "":
		// The actor decides who the security mail names (NOTIFICATIONS §4), and
		// an event with no actor is one AudienceActor cannot resolve — the
		// reactor parks it rather than sending it, so the alert about a new
		// non-human principal would be lost with no error anybody sees.
		return errs.ValidationFailedf("a service account records who created it")
	case name == "":
		return errs.ValidationFailedf("a service account needs a name")
	case len(name) > MaxServiceAccountNameLen:
		return errs.ValidationFailedf("a service account name is at most %d characters",
			MaxServiceAccountNameLen)
	case !serviceAccountName.MatchString(name):
		// The message names the RULE and not the offending value. The value is
		// what a person typed, and echoing it into an error that may be logged
		// is the leak this pattern exists to prevent.
		return errs.ValidationFailedf(
			"a service account name is lower-case letters, digits and underscores, starting " +
				"with a letter; free text would put whatever an admin typed into an " +
				"append-only log")
	}

	eventsourcing.Record(s, &contract.ServiceAccountCreated{
		ServiceAccountID: id.String(),
		OrgID:            orgID,
		Name:             name,
		CreatedBy:        createdBy,
		CreatedAt:        at.UTC(),
	})
	return nil
}

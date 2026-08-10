package notify

import (
	"context"
	"fmt"

	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// Registry composes one resolver per audience.
//
// Audiences are answered by different things: the subject comes from event
// metadata, the operator from configuration, and the org roles from a read model
// that does not exist until the organization module lands. A registry lets each
// arrive independently, and lets an unanswerable role stay unanswerable —
// loudly — instead of being approximated.
type Registry struct {
	byAudience map[Audience]Audiences
}

func NewRegistry() *Registry {
	return &Registry{byAudience: map[Audience]Audiences{}}
}

// Register wires a resolver for one audience. Registering twice panics: two
// answers to "who is the org owner" is a wiring bug, and the wrong one being
// picked is a notification sent to the wrong person.
func (r *Registry) Register(a Audience, res Audiences) *Registry {
	if _, dup := r.byAudience[a]; dup {
		panic(fmt.Sprintf("notify: audience %s already has a resolver", a))
	}
	r.byAudience[a] = res
	return r
}

var _ Audiences = (*Registry)(nil)

func (r *Registry) Resolve(
	ctx context.Context, a Audience, env eventsourcing.Envelope,
) ([]Recipient, error) {
	res, ok := r.byAudience[a]
	if !ok {
		return nil, fmt.Errorf("%w: %s has no resolver wired", ErrAudienceUnsupported, a)
	}
	return res.Resolve(ctx, a, env)
}

// Cardinality is how many recipients an audience must resolve to.
//
// It exists because "nobody" is a legitimate answer for some roles and a bug for
// others, and the two are indistinguishable at the call site. An org always has
// exactly one owner (workspace.md §2), so zero owners means the read model is
// wrong — and silently notifying nobody about a failed payment is precisely the
// failure that surfaces weeks later as a cancelled subscription.
type Cardinality uint8

const (
	// AnyNumber allows zero. Correct for admins and for subjects: an event may
	// concern nobody in particular.
	AnyNumber Cardinality = iota

	// AtLeastOne treats zero as a failure.
	AtLeastOne

	// ExactlyOne treats zero or many as a failure.
	ExactlyOne
)

// cardinalityOf is the rule for each audience. Not configurable per
// notification: "how many owners does an org have" is a property of the domain,
// not of the message being sent.
func cardinalityOf(a Audience) Cardinality {
	switch a {
	case AudienceOrgOwner:
		// Exactly one owner holds the payment relationship, and that is not
		// changeable (workspace.md §2).
		return ExactlyOne
	case AudienceOperator:
		// An operator alert nobody receives is an outage nobody hears about.
		return AtLeastOne
	default:
		return AnyNumber
	}
}

// validateRecipients rejects anything a resolver returns that could deliver to
// the wrong person.
//
// This runs between resolution and delivery, on every notification, because a
// resolver is the one place in this system where a bug becomes a cross-tenant
// leak rather than a missing message. A read model that joins one column wrong
// returns another organization's administrators, and without this check they
// would each be told about a tenant they have nothing to do with.
func validateRecipients(spec Spec, env eventsourcing.Envelope, rs []Recipient) error {
	switch c := cardinalityOf(spec.Audience); c {
	case ExactlyOne:
		if len(rs) != 1 {
			return fmt.Errorf("%w: %s resolved to %d recipients, expected exactly one",
				ErrAudienceUnsupported, spec.Audience, len(rs))
		}
	case AtLeastOne:
		if len(rs) == 0 {
			return fmt.Errorf("%w: %s resolved to nobody", ErrAudienceUnsupported, spec.Audience)
		}
	case AnyNumber:
	}

	seen := make(map[string]struct{}, len(rs))
	for i, rcpt := range rs {
		if spec.Audience == AudienceOperator {
			// Operators are not tenants. A subject id here means a tenant
			// address was resolved for an operator alert, which would send
			// operational detail about one customer to another.
			if rcpt.SubjectID != "" {
				return fmt.Errorf("%w: operator recipient %d carries a tenant subject id",
					ErrAudienceUnsupported, i)
			}
			if rcpt.Address == "" {
				return fmt.Errorf("%w: operator recipient %d has no address",
					ErrAudienceUnsupported, i)
			}
			continue
		}

		// Tenant-facing recipients are addressed by pseudonym only. An address
		// arriving from a resolver means it came from somewhere other than the
		// vault — an event payload, a read model column — and personal data
		// must not travel that way (ADR-002).
		if rcpt.SubjectID == "" {
			return fmt.Errorf("%w: %s recipient %d has no subject id",
				ErrAudienceUnsupported, spec.Audience, i)
		}
		if rcpt.Address != "" {
			return fmt.Errorf("%w: %s recipient %d arrived with an address already set; "+
				"contact details come from the vault at delivery time, never from a resolver",
				ErrAudienceUnsupported, spec.Audience, i)
		}

		// THE cross-tenant check. A resolver reading the wrong org, or joining
		// one column wrong, returns people who belong to another customer.
		if rcpt.OrgID != "" && env.Meta.OrgID != "" && rcpt.OrgID != env.Meta.OrgID {
			return fmt.Errorf("%w: %s recipient %d belongs to org %q but the event is org %q",
				ErrCrossTenant, spec.Audience, i, rcpt.OrgID, env.Meta.OrgID)
		}

		if _, dup := seen[rcpt.SubjectID]; dup {
			// Two entries for one person means two notifications about one
			// event — someone who is both the owner and an admin, resolved
			// twice.
			return fmt.Errorf("%w: %s resolved subject %q twice",
				ErrAudienceUnsupported, spec.Audience, rcpt.SubjectID)
		}
		seen[rcpt.SubjectID] = struct{}{}
	}
	return nil
}

// ErrCrossTenant means a resolver returned someone from another organization.
//
// Separate from ErrAudienceUnsupported because it is not a gap — it is a
// containment failure, and it should read as one in logs and alerts.
var ErrCrossTenant = fmt.Errorf("notify: recipient belongs to a different organization")

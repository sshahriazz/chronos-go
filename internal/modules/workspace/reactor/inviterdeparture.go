package reactor

import (
	"context"
	"errors"
	"fmt"

	orgcontract "github.com/chronos/chronos-go/internal/modules/organization/contract"
	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// DepartureReactorName is the persistent subscription group, and it is
// PERMANENT. Renaming it creates a fresh group positioned at the END of the log,
// silently abandoning every departure the old group had not yet processed
// (ADR-019) — and each one is a live credential for an invitation nobody can
// vouch for.
const DepartureReactorName = "workspace-inviter-departure"

// Departures is the port this reactor drives.
//
// Declared by its consumer (CONVENTIONS §2). The implementation is workspace's
// InviterDepartures; this reactor knows only that calling it withdraws whatever
// the person left outstanding in that organization.
type Departures interface {
	Depart(ctx context.Context, orgID, subjectID string) error
}

// InviterDeparture revokes what somebody left outstanding when they leave an
// organization.
//
// workspace.md §5. The authorisation to join came from somebody who is no longer
// there, and an invitation nobody can vouch for should not still be redeemable
// by whoever holds the mail.
//
// # Two events, one meaning
//
// Belonging to an organization ends in two ways today. An org ADMIN grant is
// withdrawn — organization's own event — or somebody's LAST workspace membership
// is removed, which is what `MemberRemoved.SeatReleased` records: the seat went
// back precisely because they left the organization entirely.
//
// Reading SeatReleased rather than counting memberships is the whole reason this
// reactor can be correct. "Was that their last membership" is a question about
// the past, the event answers it, and re-deriving it from a projection that lags
// would revoke the invitations of somebody who is still very much here.
type InviterDeparture struct {
	departures Departures
	codec      eventsourcing.Codec
}

// NewInviterDeparture builds the reactor.
//
// Both dependencies are required. A nil departures port produces a reactor that
// consumes the event, does nothing, and acks — indistinguishable at runtime from
// the gap this exists to close, and the gap is a live credential.
func NewInviterDeparture(
	departures Departures, codec eventsourcing.Codec,
) (*InviterDeparture, error) {
	switch {
	case departures == nil:
		return nil, errors.New("workspace/reactor: the inviter-departure reactor needs a " +
			"departures port; without one every invitation a departing inviter left stays " +
			"live and redeemable")
	case codec == nil:
		return nil, errors.New("workspace/reactor: the inviter-departure reactor needs a " +
			"codec; without one the event cannot be decoded and every departure parks")
	}
	return &InviterDeparture{departures: departures, codec: codec}, nil
}

// Name is the persistent subscription group.
func (r *InviterDeparture) Name() string { return DepartureReactorName }

// Filter narrows the subscription to the two events that mean "left the
// organization".
func (r *InviterDeparture) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		EventTypePrefixes: []string{orgAdminRemovedType, memberRemovedType},
	}
}

// Taken from the contract types rather than written out, so they cannot drift
// from what the codec registers and the domains append.
var (
	orgAdminRemovedType = (&orgcontract.OrgAdminRemoved{}).EventType()
	memberRemovedType   = (&contract.MemberRemoved{}).EventType()
)

// React withdraws what the departing person left outstanding.
//
// Idempotent by construction rather than by dedup: a second run finds the
// invitations already revoked and settles nothing, because the aggregate refuses
// a second settlement. That matters because a reactor's delivery is
// at-least-once and this one has no fingerprint to key on — the work is "settle
// whatever is still pending", and running it twice is running it once.
func (r *InviterDeparture) React(ctx context.Context, env eventsourcing.Envelope) error {
	orgID, subjectID, ok, err := r.departure(env)
	if err != nil || !ok {
		return err
	}
	if err := r.departures.Depart(ctx, orgID, subjectID); err != nil {
		return fmt.Errorf("workspace/reactor: revoking what %s left outstanding: %w",
			subjectID, err)
	}
	return nil
}

// departure decodes the event and reports whether it means somebody left.
//
// A MemberRemoved with SeatReleased=false is NOT a departure: the person is
// still in another workspace of the same organization, still holds their seat,
// and still stands behind whatever they invited. Treating every removal as a
// departure would revoke the outstanding invitations of anybody who moved
// between workspaces.
func (r *InviterDeparture) departure(
	env eventsourcing.Envelope,
) (orgID, subjectID string, ok bool, err error) {
	switch env.Type {
	case orgAdminRemovedType, memberRemovedType:
	default:
		// The filter over-delivered, or the group predates the filter. Not an
		// error, and deliberately not a revocation: reacting to whatever arrives
		// would let a filter change withdraw live invitations.
		return "", "", false, nil
	}

	event, err := r.codec.Unmarshal(env.Type, env.Payload)
	if err != nil {
		return "", "", false, fmt.Errorf("%w: workspace/reactor: decoding %s: %w",
			eventsourcing.ErrPoison, env.Type, err)
	}

	switch e := event.(type) {
	case *orgcontract.OrgAdminRemoved:
		orgID, subjectID = e.OrgID, e.AdminID
	case *contract.MemberRemoved:
		if !e.SeatReleased {
			// Still in the organization: they moved between workspaces, or they
			// are in several. Their invitations stand.
			return "", "", false, nil
		}
		orgID, subjectID = e.OrgID, e.SubjectID
	default:
		return "", "", false, fmt.Errorf("%w: workspace/reactor: %s decoded as %T",
			eventsourcing.ErrPoison, env.Type, event)
	}

	// Retrying re-reads the same bytes, so each of these is poison rather than a
	// failure — and an empty subject would list every invitation in the
	// organization whose inviter column happens to be empty.
	switch {
	case orgID == "":
		return "", "", false, fmt.Errorf("%w: workspace/reactor: %s names no organization",
			eventsourcing.ErrPoison, env.Type)
	case subjectID == "":
		return "", "", false, fmt.Errorf("%w: workspace/reactor: %s names no subject",
			eventsourcing.ErrPoison, env.Type)
	}
	return orgID, subjectID, true, nil
}

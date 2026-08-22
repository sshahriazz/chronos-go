package app

import (
	"context"
	"fmt"

	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
)

// OrgMembership answers questions about the ORGANIZATION that the workspace
// module cannot answer for itself.
//
// A port, because a seat is per person per organization and this module owns
// neither. `workspace -> organization` is the only permitted direction
// (ADR-020), and a port is how that dependency is expressed without importing
// the module.
type OrgMembership interface {
	// WorkspaceCount is how many workspaces in this organization the person is
	// already a member of.
	//
	// The number, not a boolean, because both seat questions are about it: zero
	// means joining consumes a seat, and one means the removal being processed
	// is their last and releases it.
	WorkspaceCount(ctx context.Context, orgID, subjectID string) (int, error)
}

// Seats reserves and releases against the organization's pools.
//
// # Why this is not gate 4
//
// Gate 4 reserves UNCONDITIONALLY whenever an RPC declares an entitlement, which
// is right for `workspaces.count` — every workspace is a new one. It is wrong
// for seats: workspace.md §2 requires the reservation to be conditional,
// "reserve only if this person is not already an org member", and somebody in
// five workspaces of one organization must hold ONE seat.
//
// Declaring `seats.member` on the RPC would therefore take a seat from somebody
// who already has one, every time they joined another workspace — which
// overcharges the customer, silently, in the direction they notice last.
type Seats struct {
	reserver Reserver
	members  OrgMembership
}

// Reserver is entitlement's protocol, narrowed to what this module needs.
type Reserver interface {
	ReserveFor(ctx context.Context, orgID, limitKey, subjectRef string) (string, error)
	Commit(ctx context.Context, reservationID string) error
	Release(ctx context.Context, reservationID string) error
	ReleaseFor(ctx context.Context, orgID, limitKey, subjectRef string) error
}

// SeatsDeps is what Seats needs.
type SeatsDeps struct {
	Reserver Reserver
	Members  OrgMembership
}

func NewSeats(d SeatsDeps) (*Seats, error) {
	switch {
	case d.Reserver == nil:
		return nil, fmt.Errorf("workspace: a reserver is required")
	case d.Members == nil:
		return nil, fmt.Errorf("workspace: an organization membership source is required; " +
			"whether a join consumes a seat is a question about the ORGANIZATION")
	}
	return &Seats{reserver: d.Reserver, members: d.Members}, nil
}

// ReserveForJoin takes a seat only if the person is new to the organization.
//
// Returns the reservation id and whether one was actually taken. An empty id
// with consumed=false is the normal case for somebody joining their second
// workspace, and is NOT a failure.
func (s *Seats) ReserveForJoin(
	ctx context.Context, orgID, subjectID string, role contract.MemberRole,
) (reservationID string, consumed bool, err error) {
	existing, err := s.members.WorkspaceCount(ctx, orgID, subjectID)
	if err != nil {
		return "", false, fmt.Errorf("workspace: counting existing memberships: %w", err)
	}
	if existing > 0 {
		// Already in the organization, already holding a seat. Joining another
		// workspace costs nothing.
		return "", false, nil
	}

	id, err := s.reserver.ReserveFor(ctx, orgID, role.SeatPool(), subjectID)
	if err != nil {
		return "", false, err
	}
	if err := s.reserver.Commit(ctx, id); err != nil {
		// The reservation is held but not committed. Released here rather than
		// left to its TTL, because the join is not going to happen and a seat
		// held for a minute is a seat somebody else cannot take.
		_ = s.reserver.Release(ctx, id)
		return "", false, err
	}
	return id, true, nil
}

// ReleaseOnRemoval returns a seat only when the person leaves the ORGANIZATION.
//
// `remaining` is how many memberships they have AFTER this removal. One or more
// means they are still in the organization and keep their seat; zero means this
// was the last, and the seat goes back.
func (s *Seats) ReleaseOnRemoval(
	ctx context.Context, orgID, subjectID string, role contract.MemberRole, remaining int,
) (released bool, err error) {
	if remaining > 0 {
		// Still in the organization. Removing somebody from one workspace of
		// several releases NOTHING — this is the half of the rule that leaks
		// revenue if inverted, because every removal would hand back a seat the
		// person still holds.
		return false, nil
	}
	if err := s.reserver.ReleaseFor(ctx, orgID, role.SeatPool(), subjectID); err != nil {
		return false, fmt.Errorf("workspace: releasing the seat for %s: %w", subjectID, err)
	}
	return true, nil
}

// MovePools releases one pool's seat and takes the other's, for a role change
// that crosses them (ADR-027).
//
// # Why the reserve comes first
//
// Taking the new seat before returning the old one means a promotion fails when
// the target pool is full — which is correct and visible. The reverse would
// return the guest seat, fail to take a member seat, and leave the person
// holding neither: a member of the organization consuming nothing, which is a
// seat leaked in the customer's favour and invisible until an audit.
func (s *Seats) MovePools(
	ctx context.Context, orgID, subjectID string, from, to contract.MemberRole,
) error {
	if from.SeatPool() == to.SeatPool() {
		return nil
	}
	id, err := s.reserver.ReserveFor(ctx, orgID, to.SeatPool(), subjectID)
	if err != nil {
		return fmt.Errorf("workspace: no %s seat available for %s: %w", to.SeatPool(), subjectID, err)
	}
	if err := s.reserver.Commit(ctx, id); err != nil {
		_ = s.reserver.Release(ctx, id)
		return fmt.Errorf("workspace: committing the %s seat: %w", to.SeatPool(), err)
	}
	if err := s.reserver.ReleaseFor(ctx, orgID, from.SeatPool(), subjectID); err != nil {
		// The new seat is held and the old one is not returned: the person
		// consumes one from each pool. Reported rather than swallowed, because
		// the correction is a release and somebody has to know to make it.
		return fmt.Errorf("workspace: %s now holds seats in BOTH pools; the %s seat was not "+
			"released: %w", subjectID, from.SeatPool(), err)
	}
	return nil
}

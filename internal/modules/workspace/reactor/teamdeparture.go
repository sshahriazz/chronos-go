package reactor

import (
	"context"
	"errors"
	"fmt"

	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// TeamDepartureReactorName is the persistent subscription group, and it is
// PERMANENT. Renaming it creates a fresh group positioned at the END of the log
// (ADR-019), silently abandoning every removal the old group had not processed —
// and each one leaves a removed person holding whatever their teams are granted.
const TeamDepartureReactorName = "workspace-team-departure"

// TeamDepartures is the port this reactor drives.
//
// Declared by its consumer (CONVENTIONS §2). The implementation is workspace's
// app.TeamDepartures; this reactor knows only that calling it strips the team
// memberships that the workspace membership was holding up.
type TeamDepartures interface {
	Depart(ctx context.Context, workspaceID, subjectID string) error
}

// TeamDeparture takes somebody out of a workspace's teams when they leave it.
//
// workspace.md §6 runs in both directions: a team member must be a workspace
// member, so a workspace removal has to take the team memberships with it. The
// use case documents what the gap costs; the short version is that a removed
// person keeps `team:x member user:y`, and the first thing shared with that team
// reaches them.
//
// # Every removal, not only departures
//
// InviterDeparture reads `SeatReleased` and ignores a removal that left the
// person in the organization. This one MUST NOT: the rule is per WORKSPACE, and
// somebody removed from one workspace while remaining in another has left that
// workspace's teams whether or not their seat went back.
type TeamDeparture struct {
	departures TeamDepartures
	codec      eventsourcing.Codec
}

// NewTeamDeparture builds the reactor.
//
// Both dependencies are required. A nil port produces a reactor that consumes
// the event, does nothing and acks — indistinguishable at runtime from the gap
// it exists to close, which is the failure this repository has already shipped
// three times.
func NewTeamDeparture(
	departures TeamDepartures, codec eventsourcing.Codec,
) (*TeamDeparture, error) {
	switch {
	case departures == nil:
		return nil, errors.New("workspace/reactor: the team-departure reactor needs a " +
			"departures port; without one everybody removed from a workspace stays in its " +
			"teams and keeps whatever those teams are granted")
	case codec == nil:
		return nil, errors.New("workspace/reactor: the team-departure reactor needs a " +
			"codec; without one the event cannot be decoded and every removal parks")
	}
	return &TeamDeparture{departures: departures, codec: codec}, nil
}

// Name is the persistent subscription group.
func (r *TeamDeparture) Name() string { return TeamDepartureReactorName }

// Filter narrows the subscription to the one event that means "left a
// workspace".
func (r *TeamDeparture) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{EventTypePrefixes: []string{memberRemovedType}}
}

// React strips the team memberships the workspace membership was holding up.
func (r *TeamDeparture) React(ctx context.Context, env eventsourcing.Envelope) error {
	if env.Type != memberRemovedType {
		// The filter over-delivered, or the group predates the filter. Not an
		// error, and deliberately not a removal: acting on whatever arrives would
		// let a filter change strip live memberships.
		return nil
	}

	event, err := r.codec.Unmarshal(env.Type, env.Payload)
	if err != nil {
		return fmt.Errorf("%w: workspace/reactor: decoding %s: %w",
			eventsourcing.ErrPoison, env.Type, err)
	}
	removed, ok := event.(*contract.MemberRemoved)
	if !ok {
		return fmt.Errorf("%w: workspace/reactor: %s decoded as %T",
			eventsourcing.ErrPoison, env.Type, event)
	}

	// Retrying re-reads the same bytes, so each of these is poison rather than a
	// failure — and an empty subject would list every team membership in the
	// workspace whose subject column happens to be empty.
	switch {
	case removed.WorkspaceID == "":
		return fmt.Errorf("%w: workspace/reactor: %s names no workspace",
			eventsourcing.ErrPoison, env.Type)
	case removed.SubjectID == "":
		return fmt.Errorf("%w: workspace/reactor: %s names no subject",
			eventsourcing.ErrPoison, env.Type)
	}

	if err := r.departures.Depart(ctx, removed.WorkspaceID, removed.SubjectID); err != nil {
		return fmt.Errorf("workspace/reactor: removing %s from the teams of %s: %w",
			removed.SubjectID, removed.WorkspaceID, err)
	}
	return nil
}

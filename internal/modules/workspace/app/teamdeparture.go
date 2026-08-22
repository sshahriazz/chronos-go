package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// TeamRoster lists the teams of one workspace somebody belongs to.
//
// Declared by its consumer (CONVENTIONS §2). It reads a projection, which is the
// one place in this cascade where lag is visible — see TeamDepartures.Depart for
// what that costs and why it is acceptable here and nowhere else.
type TeamRoster interface {
	TeamsOf(ctx context.Context, workspaceID, subjectID string) ([]string, error)
}

// TeamDepartures strips somebody's team memberships when they leave a workspace.
//
// # The rule
//
// A team member must be a workspace member (workspace.md §6). Add enforces one
// direction — a non-member cannot be put into a team — and this enforces the
// other: losing the workspace membership has to lose the team memberships.
//
// Without it the two halves disagree, and the disagreement is not cosmetic. A
// removed person keeps `team:x member user:y` in the access graph, so the first
// thing ever shared with that team reaches somebody who was removed from the
// workspace — with no event, no log line, and nothing that looks wrong from
// inside. It is the same shape as the revocation tombstone ADR-045 exists for:
// access that outlives the fact that granted it.
//
// # Not a user's act
//
// This bypasses the maintainer-or-admin check that guards TeamMembers, and that
// is the point: the system is settling a consequence of a removal that was
// already authorised, not performing a change on somebody's behalf. Routing it
// through the user-facing use case would make the cascade depend on the REMOVER
// happening to maintain every team the removed person was in, which is neither
// true nor checkable.
type TeamDepartures struct {
	memberships *eventsourcing.Repository[*domain.TeamMembership]
	roster      TeamRoster
	now         func() time.Time
}

// TeamDeparturesDeps is what TeamDepartures needs.
type TeamDeparturesDeps struct {
	Memberships *eventsourcing.Repository[*domain.TeamMembership]
	Roster      TeamRoster
	Now         func() time.Time
}

func NewTeamDepartures(d TeamDeparturesDeps) (*TeamDepartures, error) {
	switch {
	case d.Memberships == nil:
		return nil, fmt.Errorf("workspace: a team membership repository is required")
	case d.Roster == nil:
		return nil, fmt.Errorf("workspace: a team roster is required; without one every " +
			"removal reports success having stripped nothing, and a removed person keeps " +
			"whatever their teams are ever granted")
	case d.Now == nil:
		return nil, fmt.Errorf("workspace: a clock is required")
	}
	return &TeamDepartures{memberships: d.Memberships, roster: d.Roster, now: d.Now}, nil
}

// Depart removes somebody from every team of one workspace.
//
// # Idempotent by construction, not by dedup
//
// A reactor's delivery is at-least-once. A second run finds each membership
// already inactive and appends nothing, because the aggregate refuses a second
// removal — the same property InviterDeparture relies on. The idempotency key is
// derived from the three ids rather than the event, so a redelivery under a
// different envelope id still collides.
//
// # What the projection lag costs
//
// The roster is a projection, so a membership added moments before the removal
// may not be in it yet and would be missed. That is survivable HERE and would
// not be elsewhere: the sweep in the reconciliation workflow re-runs this, and
// the missed row grants nothing until something is shared with the team. It is
// recorded rather than hidden because the fix — reading the log — is the wrong
// trade for a projection this cheap to re-drive.
//
// # Partial failure is a retry, not a silent gap
//
// The first failure stops the loop and returns, so the reactor parks and retries
// the WHOLE departure. Continuing past a failure would ack an event whose work
// is half done, and the half left undone is a live grant.
func (t *TeamDepartures) Depart(ctx context.Context, workspaceID, subjectID string) error {
	if workspaceID == "" || subjectID == "" {
		return fmt.Errorf("workspace: a team departure needs both a workspace and a subject")
	}

	teams, err := t.roster.TeamsOf(ctx, workspaceID, subjectID)
	if err != nil {
		return fmt.Errorf("workspace: listing %s's teams in %s: %w", subjectID, workspaceID, err)
	}

	now := t.now().UTC()
	for _, teamID := range teams {
		if err := t.leave(ctx, teamID, subjectID, now); err != nil {
			return err
		}
	}
	return nil
}

// leave removes one membership, and treats "already out" as done.
func (t *TeamDepartures) leave(ctx context.Context, teamID, subjectID string, now time.Time) error {
	key := domain.TeamMembershipStreamKey(teamID, subjectID)

	membership, err := t.memberships.Load(ctx, key)
	if err != nil {
		return fmt.Errorf("workspace: loading %s's membership of %s: %w", subjectID, teamID, err)
	}
	// Exists only. A membership that is present but already inactive needs no
	// guard here: Remove returns nil and records nothing for it, so a check
	// would be a second copy of the aggregate's rule that no test can
	// distinguish from its absence.
	//
	// A membership that never existed is different, and reachable: the roster is
	// a PROJECTION, so a row that outlived its stream — a rebuild in flight, a
	// truncated table refilling — names a membership Remove would reject. That
	// failure would park the whole departure on a row that is not coming back.
	if !membership.Exists() {
		return nil
	}
	if err := membership.Remove(now); err != nil {
		return fmt.Errorf("workspace: removing %s from %s: %w", subjectID, teamID, err)
	}

	_, err = t.memberships.Save(ctx, key, membership,
		"departure:"+membership.WorkspaceID()+":"+subjectID+":"+teamID,
		eventsourcing.Metadata{
			OrgID:       membership.OrgID(),
			WorkspaceID: membership.WorkspaceID(),
			OccurredAt:  now,
		})
	if err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			// Somebody else settled it between the load and the append. The state
			// this wanted now holds, which is what the caller asked for.
			return nil
		}
		return fmt.Errorf("workspace: recording %s's departure from %s: %w",
			subjectID, teamID, err)
	}
	return nil
}

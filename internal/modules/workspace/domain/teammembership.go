package domain

import (
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// TeamMembership is one person's place in one team.
//
// Its own aggregate, for the reason workspace memberships have one: a team may
// hold thousands of people — access.md §6 measured a thousand — and they churn,
// so putting them in the team's stream would make every join contend with every
// other for the same revision.
type TeamMembership struct {
	eventsourcing.Base

	teamID      string
	workspaceID string
	orgID       string
	subjectID   string
	active      bool
}

var _ eventsourcing.Root = (*TeamMembership)(nil)

// NewTeamMembership returns an empty aggregate for the repository to rebuild
// into.
func NewTeamMembership() *TeamMembership { return &TeamMembership{} }

func (m *TeamMembership) TeamID() string      { return m.teamID }
func (m *TeamMembership) WorkspaceID() string { return m.workspaceID }
func (m *TeamMembership) OrgID() string       { return m.orgID }
func (m *TeamMembership) SubjectID() string   { return m.subjectID }
func (m *TeamMembership) Active() bool        { return m.active }
func (m *TeamMembership) Exists() bool        { return m.subjectID != "" }

// Apply replays one event. Pure, and it validates nothing.
func (m *TeamMembership) Apply(e eventsourcing.Event) {
	switch ev := e.(type) {
	case *contract.TeamMemberAdded:
		m.teamID = ev.TeamID
		m.workspaceID = ev.WorkspaceID
		m.orgID = ev.OrgID
		m.subjectID = ev.SubjectID
		m.active = true
	case *contract.TeamMemberRemoved:
		m.active = false
	}
}

// Add records somebody joining a team.
//
// # It takes no seat, and that is not an omission
//
// A team member must ALREADY be a workspace member (workspace.md §6), so they
// already hold whatever seat their membership took. A team is a grouping of
// people who are here, never a way in — which is why the caller checks workspace
// membership before calling this, and why adding a non-member is refused rather
// than implicitly admitting them.
//
// The aggregate cannot make that check itself: "is this person in the workspace"
// is a question about the WORKSPACE, and a version that tried would be reaching
// across an aggregate boundary to guess.
func (m *TeamMembership) Add(teamID, workspaceID, orgID, subjectID, addedBy string, at time.Time) error {
	if m.Exists() && m.active {
		// Already there. The caller asked for a state that holds, and reporting
		// a conflict would make a retried request look like a failure.
		return nil
	}
	switch {
	case teamID == "":
		return fmt.Errorf("workspace: a team is required")
	case workspaceID == "":
		return fmt.Errorf("workspace: a workspace is required")
	case orgID == "":
		return fmt.Errorf("workspace: an organization is required")
	case subjectID == "":
		return fmt.Errorf("workspace: a subject is required")
	case addedBy == "":
		return fmt.Errorf("workspace: an actor is required; membership of a team is " +
			"managed by its maintainers, and who did it has to be attributable")
	}

	eventsourcing.Record(m, &contract.TeamMemberAdded{
		TeamID: teamID, WorkspaceID: workspaceID, OrgID: orgID,
		SubjectID: subjectID, AddedBy: addedBy, AddedAt: at,
	})
	return nil
}

// Remove records somebody leaving a team.
//
// It releases no seat, the mirror of Add taking none: they are still a workspace
// member, and the seat belongs to that membership.
func (m *TeamMembership) Remove(at time.Time) error {
	if !m.Exists() {
		return fmt.Errorf("workspace: not a member of that team")
	}
	if !m.active {
		return nil // already gone
	}
	eventsourcing.Record(m, &contract.TeamMemberRemoved{
		TeamID: m.teamID, WorkspaceID: m.workspaceID, OrgID: m.orgID,
		SubjectID: m.subjectID, RemovedAt: at,
	})
	return nil
}

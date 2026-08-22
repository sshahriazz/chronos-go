package domain

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// TeamCategory holds one stream per team.
const TeamCategory eventsourcing.Category = "team"

// TeamStreamKey names the stream holding one team's history.
//
// The team id itself. A team is not a data subject, so there is no pseudonym to
// protect and nothing for erasure to destroy — the same reasoning workspace's
// StreamKey records.
func TeamStreamKey(teamID string) string { return teamID }

// TeamMembershipCategory holds one stream per (team, person).
//
// Its OWN aggregate rather than a set inside Team, for the reason workspace
// memberships have one: workspace.md §1 puts invariant-bearing sets inside the
// aggregate and high-volume collections outside it, and a team's membership is
// the second. access.md §6 measured a thousand-member team, so the set is
// expected to be large and to churn — and every join would otherwise contend
// with every other for the team's stream revision.
//
// MAINTAINERS are different and do live inside Team: they are a small set, and
// the never-zero rule is an invariant across the whole of it.
const TeamMembershipCategory eventsourcing.Category = "teammember"

// TeamMembershipStreamKey names one person's membership of one team.
//
// Joined with '.', for the reason MembershipStreamKey gives: a stream key may
// not contain '-', and both ids already use '_' to separate their own prefix.
func TeamMembershipStreamKey(teamID, subjectID string) string {
	return teamID + "." + subjectID
}

// MaxTeamNameLen bounds the display name. The published bound and the refused
// request are one number.
const MaxTeamNameLen = 60

// NewTeamName validates a team's display name.
func NewTeamName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	switch {
	case name == "":
		return "", fmt.Errorf("workspace: a team name is required")
	case len(name) > MaxTeamNameLen:
		return "", fmt.Errorf("workspace: a team name may not exceed %d characters",
			MaxTeamNameLen)
	}
	return name, nil
}

// Team is a grantable subject inside a workspace.
//
// # Flat, never nested
//
// The engine could model a team whose member set includes another team's, and
// the reason not to is not technical. Nesting makes effective membership
// non-obvious to the people managing it — "who is actually in this team" stops
// being answerable by looking — and that is precisely the problem teams exist to
// solve (workspace.md §6).
//
// # Ids are never reused
//
// A team id is a fresh ULID and nothing recycles one. access.md §7.5 makes this
// load-bearing: grants target `team:x#member`, so a reused id would silently
// inherit the deleted team's access. Deletion is terminal here for the same
// reason — a team is never un-deleted, because the id that came back would be
// the same id.
type Team struct {
	eventsourcing.Base

	teamID      string
	workspaceID string
	orgID       string
	name        string
	deleted     bool

	// maintainers manage membership WITHOUT being workspace admins
	// (workspace.md §6). Inside the aggregate because "never zero" is an
	// invariant across the whole set, which is the same reason the workspace
	// holds its admins.
	maintainers []string
}

var _ eventsourcing.Root = (*Team)(nil)

// NewTeam returns an empty aggregate for the repository to rebuild into.
func NewTeam() *Team { return &Team{} }

func (t *Team) TeamID() string      { return t.teamID }
func (t *Team) WorkspaceID() string { return t.workspaceID }
func (t *Team) OrgID() string       { return t.orgID }
func (t *Team) Name() string        { return t.name }
func (t *Team) Deleted() bool       { return t.deleted }
func (t *Team) Exists() bool        { return t.teamID != "" }

// Maintainers returns a copy. Handing out the slice would let a caller edit the
// roster without an event, and the next replay would disagree with the caller.
func (t *Team) Maintainers() []string { return slices.Clone(t.maintainers) }

// IsMaintainer reports whether somebody may manage this team's membership.
func (t *Team) IsMaintainer(subjectID string) bool {
	return slices.Contains(t.maintainers, subjectID)
}

// Apply replays one event. Pure, and it validates nothing.
func (t *Team) Apply(e eventsourcing.Event) {
	switch ev := e.(type) {
	case *contract.TeamCreated:
		t.teamID = ev.TeamID
		t.workspaceID = ev.WorkspaceID
		t.orgID = ev.OrgID
		t.name = ev.Name
		t.maintainers = []string{ev.CreatedBy}
	case *contract.TeamRenamed:
		t.name = ev.Name
	case *contract.TeamMaintainerAdded:
		if !slices.Contains(t.maintainers, ev.MaintainerID) {
			t.maintainers = append(t.maintainers, ev.MaintainerID)
		}
	case *contract.TeamMaintainerRemoved:
		t.maintainers = slices.DeleteFunc(t.maintainers, func(id string) bool {
			return id == ev.MaintainerID
		})
	case *contract.TeamDeleted:
		t.deleted = true
	}
}

// Create opens a team inside a workspace.
//
// The creator is its first maintainer, from the creation event rather than a
// second one — a team that existed for even one event with no maintainer would
// violate the never-zero rule from birth, and a replay would reproduce that.
func (t *Team) Create(teamID, workspaceID, orgID, name, createdBy string, at time.Time) error {
	if t.Exists() {
		return fmt.Errorf("workspace: team %s already exists", t.teamID)
	}
	switch {
	case teamID == "":
		return fmt.Errorf("workspace: a team id is required")
	case workspaceID == "":
		return fmt.Errorf("workspace: a team belongs to a workspace")
	case orgID == "":
		return fmt.Errorf("workspace: an organization is required")
	case createdBy == "":
		return fmt.Errorf("workspace: a creator is required; they become the first " +
			"maintainer, and a team with none can never be managed again")
	}
	clean, err := NewTeamName(name)
	if err != nil {
		return err
	}

	eventsourcing.Record(t, &contract.TeamCreated{
		TeamID: teamID, WorkspaceID: workspaceID, OrgID: orgID,
		Name: clean, CreatedBy: createdBy, CreatedAt: at,
	})
	return nil
}

// Rename changes the display name.
func (t *Team) Rename(name string, at time.Time) error {
	if err := t.mustBeLive(); err != nil {
		return err
	}
	clean, err := NewTeamName(name)
	if err != nil {
		return err
	}
	if clean == t.name {
		return nil
	}
	eventsourcing.Record(t, &contract.TeamRenamed{
		TeamID: t.teamID, WorkspaceID: t.workspaceID, OrgID: t.orgID,
		Name: clean, RenamedAt: at,
	})
	return nil
}

// AddMaintainer grants somebody the right to manage this team's membership.
func (t *Team) AddMaintainer(subjectID string, at time.Time) error {
	if err := t.mustBeLive(); err != nil {
		return err
	}
	if subjectID == "" {
		return fmt.Errorf("workspace: a maintainer is required")
	}
	if t.IsMaintainer(subjectID) {
		return nil
	}
	eventsourcing.Record(t, &contract.TeamMaintainerAdded{
		TeamID: t.teamID, WorkspaceID: t.workspaceID, OrgID: t.orgID,
		MaintainerID: subjectID, AddedAt: at,
	})
	return nil
}

// RemoveMaintainer withdraws that right.
//
// # Never the last one
//
// A team with no maintainer cannot have its membership managed by anybody who is
// not a workspace admin, which is the entire point of maintainers
// (workspace.md §6) — and no event from outside can appoint one, because
// appointing is itself a maintainer's act. The same never-zero rule the workspace
// applies to its admins, for the same reason.
func (t *Team) RemoveMaintainer(subjectID string, at time.Time) error {
	if err := t.mustBeLive(); err != nil {
		return err
	}
	if !t.IsMaintainer(subjectID) {
		return nil
	}
	if len(t.maintainers) == 1 {
		return fmt.Errorf("workspace: %s is the last maintainer of team %s; a team with "+
			"none cannot be managed by anybody who is not a workspace admin, and nothing "+
			"outside it can appoint one", subjectID, t.teamID)
	}
	eventsourcing.Record(t, &contract.TeamMaintainerRemoved{
		TeamID: t.teamID, WorkspaceID: t.workspaceID, OrgID: t.orgID,
		MaintainerID: subjectID, RemovedAt: at,
	})
	return nil
}

// Delete ends the team.
//
// TERMINAL, and deliberately: access.md §7.5 requires that a team id is never
// reused, because grants target `team:x#member` and a reused id would silently
// inherit the deleted team's access. Restoring a team would BE reusing the id.
//
// What this event does not do is remove the grants naming the team. That cascade
// is access.md §7.5's, and it is not built: a grant to a team is a share, sharing
// needs resources, and feature verticals inside a workspace are out of scope
// (ADR-006) — so no such tuple can exist yet. The id never being reused is what
// holds the invariant until it does.
func (t *Team) Delete(at time.Time) error {
	if err := t.mustBeLive(); err != nil {
		return err
	}
	eventsourcing.Record(t, &contract.TeamDeleted{
		TeamID: t.teamID, WorkspaceID: t.workspaceID, OrgID: t.orgID, DeletedAt: at,
	})
	return nil
}

// mustBeLive is the guard every command shares.
func (t *Team) mustBeLive() error {
	if !t.Exists() {
		return fmt.Errorf("workspace: no such team")
	}
	if t.deleted {
		return fmt.Errorf("workspace: team %s is deleted, and a team is never restored — "+
			"its id would come back with it, and a grant naming that id would be inherited "+
			"by the new team", t.teamID)
	}
	return nil
}

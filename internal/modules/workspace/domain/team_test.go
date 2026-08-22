package domain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/modules/workspace/domain"
	"github.com/chronos/chronos-go/internal/platform/authz/model"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

const (
	teamID    = "team_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	teamWS    = "ws_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	teamOrg   = "org_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	maintainr = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAA"
	other     = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAB"
)

var teamAt = time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

func newTeam(t *testing.T) *domain.Team {
	t.Helper()
	team := domain.NewTeam()
	if err := team.Create(teamID, teamWS, teamOrg, "Engineering", maintainr, teamAt); err != nil {
		t.Fatalf("creating: %v", err)
	}
	team.ClearUncommitted()
	return team
}

// THE CREATOR IS THE FIRST MAINTAINER, from the creation event.
//
// A team that existed for even one event with no maintainer would violate the
// never-zero rule from birth, and a replay would faithfully reproduce that.
func TestTheCreatorIsTheFirstMaintainer(t *testing.T) {
	team := newTeam(t)

	if !team.IsMaintainer(maintainr) {
		t.Fatal("the creator is not a maintainer, so the team can only be managed by a " +
			"workspace admin — which is the thing maintainers exist to avoid")
	}
	if got := team.Maintainers(); len(got) != 1 {
		t.Errorf("the roster is %v, want exactly the creator", got)
	}
}

// THE LAST MAINTAINER CANNOT BE REMOVED.
//
// A team with none cannot have its membership managed by anybody who is not a
// workspace admin, and nothing outside the team can appoint one — appointing is
// itself a maintainer's act. The same never-zero rule the workspace applies to
// its admins.
func TestTheLastMaintainerCannotBeRemoved(t *testing.T) {
	team := newTeam(t)

	if err := team.RemoveMaintainer(maintainr, teamAt); err == nil {
		t.Fatal("the last maintainer was removed; the team is now unmanageable by anybody " +
			"but a workspace admin, and no request from outside can repair it")
	}
	if !team.IsMaintainer(maintainr) {
		t.Error("a refused removal changed the roster")
	}
}

// A SECOND MAINTAINER MAKES THE FIRST REMOVABLE, which is what proves the rule
// above refuses for the right reason rather than refusing every removal.
func TestAMaintainerCanBeRemovedOnceThereIsAnother(t *testing.T) {
	team := newTeam(t)
	if err := team.AddMaintainer(other, teamAt); err != nil {
		t.Fatal(err)
	}
	team.ClearUncommitted()

	if err := team.RemoveMaintainer(maintainr, teamAt); err != nil {
		t.Fatalf("a maintainer could not be removed from a team with two: %v", err)
	}
	if team.IsMaintainer(maintainr) {
		t.Error("the roster still holds the removed maintainer")
	}
	if !team.IsMaintainer(other) {
		t.Error("the wrong maintainer was removed")
	}
}

// ADDING A MAINTAINER TWICE IS A NO-OP, not a conflict.
func TestAddingAMaintainerTwiceIsANoOp(t *testing.T) {
	team := newTeam(t)
	if err := team.AddMaintainer(other, teamAt); err != nil {
		t.Fatal(err)
	}
	team.ClearUncommitted()

	if err := team.AddMaintainer(other, teamAt); err != nil {
		t.Fatalf("re-adding an existing maintainer failed: %v", err)
	}
	if n := len(team.Uncommitted()); n != 0 {
		t.Errorf("recorded %d events for a maintainer who was already one", n)
	}
}

// DELETION IS TERMINAL, and a deleted team is never restored.
//
// access.md §7.5: grants target `team:x#member`, so a reused id would silently
// inherit the deleted team's access. Restoring a team would BE reusing the id.
func TestADeletedTeamIsNeverUsableAgain(t *testing.T) {
	team := newTeam(t)
	if err := team.Delete(teamAt); err != nil {
		t.Fatal(err)
	}
	team.ClearUncommitted()

	for name, cmd := range map[string]func() error{
		"rename":            func() error { return team.Rename("Platform", teamAt) },
		"add maintainer":    func() error { return team.AddMaintainer(other, teamAt) },
		"remove maintainer": func() error { return team.RemoveMaintainer(maintainr, teamAt) },
		"delete again":      func() error { return team.Delete(teamAt) },
	} {
		t.Run(name, func(t *testing.T) {
			err := cmd()
			if err == nil {
				t.Fatal("succeeded on a deleted team")
			}
			if !strings.Contains(err.Error(), "deleted") {
				t.Errorf("refused with %q, which does not say the team is gone", err)
			}
		})
	}
	if n := len(team.Uncommitted()); n != 0 {
		t.Errorf("a deleted team recorded %d events", n)
	}
}

// THE ZERO TEAM IS UNUSABLE.
func TestTheZeroTeamIsUnusable(t *testing.T) {
	team := domain.NewTeam()

	if team.Exists() || team.IsMaintainer(maintainr) {
		t.Fatal("a never-loaded team reports itself as usable")
	}
	for name, cmd := range map[string]func() error{
		"rename":         func() error { return team.Rename("Platform", teamAt) },
		"add maintainer": func() error { return team.AddMaintainer(other, teamAt) },
		"delete":         func() error { return team.Delete(teamAt) },
	} {
		t.Run(name, func(t *testing.T) {
			err := cmd()
			if err == nil {
				t.Fatal("succeeded on a team that does not exist")
			}
			if !strings.Contains(err.Error(), "no such team") {
				t.Errorf("refused with %q; a mistyped id should read as not found", err)
			}
		})
	}
}

// CREATION REQUIRES EVERYTHING THE LIFECYCLE DEPENDS ON.
func TestCreateRefusesAnIncompleteTeam(t *testing.T) {
	type args struct{ id, ws, org, name, by string }
	full := args{teamID, teamWS, teamOrg, "Engineering", maintainr}

	if err := domain.NewTeam().Create(full.id, full.ws, full.org, full.name, full.by, teamAt); err != nil {
		t.Fatalf("precondition: a complete team was refused: %v", err)
	}

	tests := []struct {
		name string
		mut  func(*args)
		why  string
	}{
		{"no id", func(a *args) { a.id = "" }, "the stream is named by it"},
		{"no workspace", func(a *args) { a.ws = "" }, "a team belongs to one"},
		{"no organization", func(a *args) { a.org = "" }, "nothing scopes it"},
		{
			"no creator", func(a *args) { a.by = "" },
			"they become the first maintainer, and a team with none can never be managed",
		},
		{"no name", func(a *args) { a.name = "" }, "nothing renders it"},
		{"blank name", func(a *args) { a.name = "   " }, "the same, after trimming"},
		{
			"oversized name", func(a *args) { a.name = strings.Repeat("x", domain.MaxTeamNameLen+1) },
			"the published bound and the refused request are one number",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := full
			tt.mut(&a)
			team := domain.NewTeam()
			if err := team.Create(a.id, a.ws, a.org, a.name, a.by, teamAt); err == nil {
				t.Fatalf("accepted it: %s", tt.why)
			}
			if n := len(team.Uncommitted()); n != 0 {
				t.Error("a refused creation still recorded an event")
			}
		})
	}
}

// THE ROSTER IS A COPY.
//
// Handing out the slice would let a caller edit it without an event, and the
// next replay would disagree with the caller.
func TestTheMaintainerRosterIsACopy(t *testing.T) {
	team := newTeam(t)
	got := team.Maintainers()
	got[0] = "subj_someone_else"

	if !team.IsMaintainer(maintainr) {
		t.Fatal("editing the returned slice changed the team's roster, so a caller can " +
			"grant themselves maintenance with no event saying so")
	}
}

// THE TEAM REBUILDS FROM ITS OWN EVENTS.
func TestATeamRebuildsFromItsLog(t *testing.T) {
	events := []eventsourcing.Event{
		&contract.TeamCreated{
			TeamID: teamID, WorkspaceID: teamWS, OrgID: teamOrg,
			Name: "Engineering", CreatedBy: maintainr, CreatedAt: teamAt,
		},
		&contract.TeamMaintainerAdded{
			TeamID: teamID, WorkspaceID: teamWS, OrgID: teamOrg,
			MaintainerID: other, AddedAt: teamAt,
		},
		&contract.TeamRenamed{
			TeamID: teamID, WorkspaceID: teamWS, OrgID: teamOrg,
			Name: "Platform", RenamedAt: teamAt,
		},
		&contract.TeamMaintainerRemoved{
			TeamID: teamID, WorkspaceID: teamWS, OrgID: teamOrg,
			MaintainerID: maintainr, RemovedAt: teamAt,
		},
	}

	team := domain.NewTeam()
	for _, e := range events {
		team.Apply(e)
	}

	switch {
	case team.TeamID() != teamID:
		t.Errorf("id is %q", team.TeamID())
	case team.WorkspaceID() != teamWS:
		t.Errorf("workspace is %q", team.WorkspaceID())
	case team.OrgID() != teamOrg:
		t.Errorf("organization is %q", team.OrgID())
	case team.Name() != "Platform":
		t.Errorf("name is %q, want the RENAMED one", team.Name())
	case team.IsMaintainer(maintainr):
		t.Error("the removed maintainer is still on the roster after a replay")
	case !team.IsMaintainer(other):
		t.Error("the added maintainer is not on the roster after a replay")
	case team.Deleted():
		t.Error("the team replayed as deleted")
	}
}

// ---------------------------------------------------------------------------
// the graph
// ---------------------------------------------------------------------------

// A TEAM IS A GRANTABLE SUBJECT, and that is the whole economics of teams.
//
// `team:eng#member` as a valid subject on `workspace.member` is what makes
// granting to a team of any size cost ONE tuple. Without the userset entry a
// team is a list nothing can be shared with.
func TestATeamIsAGrantableSubject(t *testing.T) {
	fragment := domain.AccessFragment()

	var workspace *model.Type
	for i := range fragment.Types {
		if fragment.Types[i].Name == "workspace" {
			workspace = &fragment.Types[i]
		}
	}
	if workspace == nil {
		t.Fatal("the fragment declares no workspace type")
	}

	var member *model.Relation
	for i := range workspace.Relations {
		if workspace.Relations[i].Name == "member" {
			member = &workspace.Relations[i]
		}
	}
	if member == nil {
		t.Fatal("workspace declares no member relation")
	}

	var userset bool
	for _, ref := range member.Direct {
		if ref.Type == "team" && ref.Relation == "member" {
			userset = true
		}
	}
	if !userset {
		t.Fatal("`team:x#member` is not a valid subject for workspace membership, so a " +
			"team is a list nothing can be granted anything — and sharing with N people " +
			"costs N tuples instead of one")
	}
}

// TEAMS ARE FLAT: a team's members are users, never another team's members.
//
// The engine would model nesting happily. The reason to refuse it is that nesting
// makes effective membership non-obvious to the people managing it, which is the
// problem teams exist to solve.
func TestTeamsAreFlat(t *testing.T) {
	fragment := domain.AccessFragment()

	var team *model.Type
	for i := range fragment.Types {
		if fragment.Types[i].Name == "team" {
			team = &fragment.Types[i]
		}
	}
	if team == nil {
		t.Fatal("the fragment declares no team type, so nothing can be granted to a team")
	}

	for _, rel := range team.Relations {
		for _, ref := range rel.Direct {
			if ref.Type == "team" {
				t.Fatalf("team.%s admits `team:*#%s`, so teams nest. Effective membership "+
					"then stops being answerable by looking, which is the problem teams "+
					"exist to solve", rel.Name, ref.Relation)
			}
		}
		if len(rel.Inherits) != 0 {
			t.Errorf("team.%s inherits through %v; a team is not a container and nothing "+
				"is stored in it, so an inherited relation here would quietly make every "+
				"workspace admin a maintainer", rel.Name, rel.Inherits)
		}
	}
}

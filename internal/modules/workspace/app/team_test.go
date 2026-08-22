package app_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/app"
	"github.com/chronos/chronos-go/internal/modules/workspace/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

type teamHarness struct {
	teams *app.Teams
	repo  *eventsourcing.Repository[*domain.Team]
	store *memStore
}

func newTeamHarness(t *testing.T) *teamHarness {
	t.Helper()
	store := newMemStore()
	repo := eventsourcing.NewRepository[*domain.Team](
		store, jsonCodec{}, nil, domain.TeamCategory, domain.NewTeam)

	teams, err := app.NewTeams(app.TeamsDeps{
		Repo: repo, Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("NewTeams: %v", err)
	}
	return &teamHarness{teams: teams, repo: repo, store: store}
}

func (h *teamHarness) create(t *testing.T, name string) app.CreateTeamResult {
	t.Helper()
	result, err := h.teams.Create(context.Background(), app.CreateTeamCommand{
		OrgID: testOrg, WorkspaceID: inviteWS, Name: name, CreatedBy: founder,
		IdempotencyKey: "key-team-" + name,
	})
	if err != nil {
		t.Fatalf("creating %q: %v", name, err)
	}
	return result
}

func (h *teamHarness) load(t *testing.T, teamID string) *domain.Team {
	t.Helper()
	team, err := h.repo.Load(context.Background(), domain.TeamStreamKey(teamID))
	if err != nil {
		t.Fatal(err)
	}
	return team
}

// A TEAM ID IS A FRESH ULID AND IS NEVER REUSED.
//
// access.md §7.5 makes this load-bearing: grants target `team:x#member`, so a
// reused id would silently inherit a deleted team's access. Two teams created
// with the same NAME must not collide, and a deleted team's id must not come
// back.
func TestTeamIdsAreNeverReused(t *testing.T) {
	h := newTeamHarness(t)

	first := h.create(t, "Engineering")
	if !strings.HasPrefix(first.TeamID, "team_") {
		t.Errorf("team id %q is not a prefixed ULID", first.TeamID)
	}

	// Deleting it, then creating another with the SAME name.
	if err := h.teams.Delete(context.Background(), app.DeleteTeamCommand{
		OrgID: testOrg, WorkspaceID: inviteWS, TeamID: first.TeamID,
		IdempotencyKey: "key-delete",
	}); err != nil {
		t.Fatalf("deleting: %v", err)
	}

	second, err := h.teams.Create(context.Background(), app.CreateTeamCommand{
		OrgID: testOrg, WorkspaceID: inviteWS, Name: "Engineering", CreatedBy: founder,
		IdempotencyKey: "key-team-again",
	})
	if err != nil {
		t.Fatalf("recreating: %v", err)
	}
	if second.TeamID == first.TeamID {
		t.Fatal("a recreated team took the deleted team's id. Grants target " +
			"`team:x#member`, so the new team silently inherits everything the old one " +
			"could reach (access.md §7.5)")
	}
}

// A DELETED TEAM STAYS DELETED, and the refusal says why.
func TestADeletedTeamCannotBeChanged(t *testing.T) {
	h := newTeamHarness(t)
	team := h.create(t, "Engineering")

	if err := h.teams.Delete(context.Background(), app.DeleteTeamCommand{
		OrgID: testOrg, WorkspaceID: inviteWS, TeamID: team.TeamID,
		IdempotencyKey: "key-delete",
	}); err != nil {
		t.Fatal(err)
	}

	err := h.teams.Rename(context.Background(), app.RenameTeamCommand{
		OrgID: testOrg, WorkspaceID: inviteWS, TeamID: team.TeamID, Name: "Platform",
		IdempotencyKey: "key-rename",
	})
	if err == nil {
		t.Fatal("a deleted team was renamed")
	}
	if got := errs.ReasonOf(err); got != errs.Conflict {
		t.Errorf("refused with %s, want CONFLICT: the request is well formed and the "+
			"caller is permitted, and it is the current state that says no", got)
	}
}

// A TEAM OF ANOTHER WORKSPACE CANNOT BE TOUCHED.
//
// The authz gate checked `admin` on the WORKSPACE the request named. Nothing
// checks that the TEAM belongs to it — an id is just a string — so without this
// an admin of one workspace could DELETE another's team, and deletion is
// terminal.
func TestATeamOfAnotherWorkspaceIsNotFound(t *testing.T) {
	h := newTeamHarness(t)
	team := h.create(t, "Engineering")

	for name, call := range map[string]func() error{
		"rename through the wrong workspace": func() error {
			return h.teams.Rename(context.Background(), app.RenameTeamCommand{
				OrgID: testOrg, WorkspaceID: "ws_01ARZ3NDEKTSV4RRFFQ69G5FAZ",
				TeamID: team.TeamID, Name: "Platform", IdempotencyKey: "k1",
			})
		},
		"delete through the wrong workspace": func() error {
			return h.teams.Delete(context.Background(), app.DeleteTeamCommand{
				OrgID: testOrg, WorkspaceID: "ws_01ARZ3NDEKTSV4RRFFQ69G5FAZ",
				TeamID: team.TeamID, IdempotencyKey: "k2",
			})
		},
		"delete from another organization": func() error {
			return h.teams.Delete(context.Background(), app.DeleteTeamCommand{
				OrgID: "org_01ARZ3NDEKTSV4RRFFQ69G5FAZ", WorkspaceID: inviteWS,
				TeamID: team.TeamID, IdempotencyKey: "k3",
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := call()
			if err == nil {
				t.Fatal("accepted it; deletion is terminal, so this is somebody else's " +
					"team destroyed for good")
			}
			if got := errs.ReasonOf(err); got != errs.NotFound {
				t.Errorf("refused with %s, want NOT_FOUND: distinguishing 'not yours' "+
					"from 'no such team' confirms the id exists (ADR-036)", got)
			}
		})
	}

	// And it is still there, which proves the refusals above did nothing rather
	// than failing after the fact.
	if h.load(t, team.TeamID).Deleted() {
		t.Fatal("the team was deleted by a refused request")
	}
}

// A RENAME TO THE SAME NAME APPENDS NOTHING.
//
// Not an error either: the caller asked for a state that holds. An append would
// put a no-op event in a log that is replayed forever.
func TestRenamingToTheSameNameAppendsNothing(t *testing.T) {
	h := newTeamHarness(t)
	team := h.create(t, "Engineering")
	before := len(h.store.streams[eventsourcing.StreamID("team-"+team.TeamID)])

	if err := h.teams.Rename(context.Background(), app.RenameTeamCommand{
		OrgID: testOrg, WorkspaceID: inviteWS, TeamID: team.TeamID,
		Name: "  Engineering  ", IdempotencyKey: "key-rename",
	}); err != nil {
		t.Fatalf("renaming to the trimmed same name: %v", err)
	}

	after := len(h.store.streams[eventsourcing.StreamID("team-"+team.TeamID)])
	if after != before {
		t.Errorf("appended %d events for a rename that changed nothing", after-before)
	}
}

// AN UNKNOWN TEAM IS NOT_FOUND.
func TestAnUnknownTeamIsNotFound(t *testing.T) {
	h := newTeamHarness(t)

	err := h.teams.Delete(context.Background(), app.DeleteTeamCommand{
		OrgID: testOrg, WorkspaceID: inviteWS,
		TeamID: "team_01ARZ3NDEKTSV4RRFFQ69G5FAZ", IdempotencyKey: "k",
	})
	if err == nil {
		t.Fatal("a team that does not exist was deleted")
	}
	if got := errs.ReasonOf(err); got != errs.NotFound {
		t.Errorf("refused with %s, want NOT_FOUND", got)
	}
}

// EVERY MUTATION NEEDS AN IDEMPOTENCY KEY.
func TestTeamCommandsNeedAnIdempotencyKey(t *testing.T) {
	h := newTeamHarness(t)
	team := h.create(t, "Engineering")

	for name, call := range map[string]func() error{
		"create": func() error {
			_, err := h.teams.Create(context.Background(), app.CreateTeamCommand{
				OrgID: testOrg, WorkspaceID: inviteWS, Name: "X", CreatedBy: founder,
			})
			return err
		},
		"rename": func() error {
			return h.teams.Rename(context.Background(), app.RenameTeamCommand{
				OrgID: testOrg, WorkspaceID: inviteWS, TeamID: team.TeamID, Name: "X",
			})
		},
		"delete": func() error {
			return h.teams.Delete(context.Background(), app.DeleteTeamCommand{
				OrgID: testOrg, WorkspaceID: inviteWS, TeamID: team.TeamID,
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatal("accepted a mutation with no key, so a retry is a fresh command")
			}
		})
	}
}

// EVERY DEPENDENCY IS REQUIRED.
func TestTeamsRefusesAnIncompleteWiring(t *testing.T) {
	store := newMemStore()
	repo := eventsourcing.NewRepository[*domain.Team](
		store, jsonCodec{}, nil, domain.TeamCategory, domain.NewTeam)

	if _, err := app.NewTeams(app.TeamsDeps{Repo: repo, Now: time.Now}); err != nil {
		t.Fatalf("precondition: a complete wiring was refused: %v", err)
	}
	if _, err := app.NewTeams(app.TeamsDeps{Now: time.Now}); err == nil {
		t.Error("constructed with no repository")
	}
	if _, err := app.NewTeams(app.TeamsDeps{Repo: repo}); err == nil {
		t.Error("constructed with no clock")
	}
}

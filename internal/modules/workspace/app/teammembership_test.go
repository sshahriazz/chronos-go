package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/app"
	"github.com/chronos/chronos-go/internal/modules/workspace/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// fakeWorkspaceMembers is the workspace roster the rule turns on.
//
// A set rather than a stub returning true: the RULE is that a non-member is
// refused, so a source that cannot say "no" makes every test of it vacuous.
type fakeWorkspaceMembers struct {
	members map[string]bool
	err     error
	calls   int
}

func (f *fakeWorkspaceMembers) IsMember(_ context.Context, _, subjectID string) (bool, error) {
	f.calls++
	if f.err != nil {
		return false, f.err
	}
	return f.members[subjectID], nil
}

type fakeWorkspaceAdmins struct {
	admins map[string]bool
	err    error
}

// The value is returned ALONGSIDE the error, deliberately.
//
// A fake that returns false whenever it errors cannot test the guard that reads
// the error first: with it, denial happens either way and removing the check
// changes nothing observable. A real adapter can and does return a garbage
// value with a failure — a partially-decoded batch response, a zero struct from
// a timed-out client — and the whole point of checking err before the value is
// that the value is meaningless when it is set.
func (f *fakeWorkspaceAdmins) IsAdmin(_ context.Context, _, subjectID string) (bool, error) {
	return f.admins[subjectID], f.err
}

type teamMemberHarness struct {
	*teamHarness

	members     *app.TeamMembers
	roster      *fakeWorkspaceMembers
	admins      *fakeWorkspaceAdmins
	memberships *eventsourcing.Repository[*domain.TeamMembership]
}

func newTeamMemberHarness(t *testing.T) *teamMemberHarness {
	t.Helper()
	base := newTeamHarness(t)

	memberships := eventsourcing.NewRepository[*domain.TeamMembership](
		base.store, jsonCodec{}, nil,
		domain.TeamMembershipCategory, domain.NewTeamMembership)

	// The founder is a workspace member because they created it, and a
	// maintainer of every team they open. Nobody else is either until a test
	// says so.
	roster := &fakeWorkspaceMembers{members: map[string]bool{founder: true}}
	admins := &fakeWorkspaceAdmins{admins: map[string]bool{}}

	members, err := app.NewTeamMembers(app.TeamMembersDeps{
		Teams: base.repo, Memberships: memberships,
		Workspace: roster, Admins: admins,
		Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("NewTeamMembers: %v", err)
	}
	return &teamMemberHarness{
		teamHarness: base, members: members,
		roster: roster, admins: admins, memberships: memberships,
	}
}

func (h *teamMemberHarness) add(teamID, subjectID, actedBy string) error {
	return h.members.Add(context.Background(), app.AddTeamMemberCommand{
		OrgID: testOrg, WorkspaceID: inviteWS, TeamID: teamID,
		SubjectID: subjectID, ActedBy: actedBy,
		IdempotencyKey: "key-add-" + teamID + "-" + subjectID + "-" + actedBy,
	})
}

func (h *teamMemberHarness) isInTeam(t *testing.T, teamID, subjectID string) bool {
	t.Helper()
	m, err := h.memberships.Load(context.Background(),
		domain.TeamMembershipStreamKey(teamID, subjectID))
	if err != nil {
		t.Fatal(err)
	}
	return m.Exists() && m.Active()
}

// A TEAM IS NOT A WAY INTO A WORKSPACE.
//
// This is workspace.md §6's rule and the reason this use case exists at all.
// Without it anybody who maintains a team could put a stranger into the
// workspace with no invitation, no seat and no entitlement check — and every
// downstream gate would then treat them as legitimately present, because a team
// membership tuple grants exactly what a workspace membership grants.
//
// The assertion is on BOTH halves: refused, AND not quietly recorded anyway.
func TestAddingANonMemberToATeamIsRefused(t *testing.T) {
	h := newTeamMemberHarness(t)
	team := h.create(t, "engineering")

	const stranger = "subj_stranger00000000000000"
	err := h.add(team.TeamID, stranger, founder)
	if err == nil {
		t.Fatal("a stranger was added to a team; a team is now a side entrance into " +
			"the workspace, bypassing invitations, seats and the entitlement gate")
	}
	if got := errs.ReasonOf(err); got != errs.ValidationFailed {
		t.Errorf("reason is %q, want VALIDATION_FAILED — the request is well formed and "+
			"the caller is permitted; it is the subject that is not here", got)
	}
	if h.isInTeam(t, team.TeamID, stranger) {
		t.Error("the call was refused and the membership was recorded anyway")
	}
}

// AND A MEMBER IS ADMITTED.
//
// The other half, without which "refuse everybody" passes the test above.
func TestAddingAWorkspaceMemberToATeamWorks(t *testing.T) {
	h := newTeamMemberHarness(t)
	team := h.create(t, "engineering")

	const colleague = "subj_colleague0000000000000"
	h.roster.members[colleague] = true

	if err := h.add(team.TeamID, colleague, founder); err != nil {
		t.Fatalf("adding a workspace member to a team: %v", err)
	}
	if !h.isInTeam(t, team.TeamID, colleague) {
		t.Fatal("the call succeeded and recorded nothing")
	}
}

// ONLY A MAINTAINER OR A WORKSPACE ADMIN MAY CHANGE A TEAM.
//
// The gate cannot answer this: it admits any workspace MEMBER, because
// workspace.md §6 requires maintainers to manage their team without being
// workspace admins. So an ordinary member reaches the handler, and the handler
// is the only thing between them and somebody else's team.
func TestAnOrdinaryMemberCannotChangeATeam(t *testing.T) {
	h := newTeamMemberHarness(t)
	team := h.create(t, "engineering")

	const bystander = "subj_bystander0000000000000"
	const colleague = "subj_colleague0000000000000"
	h.roster.members[bystander] = true
	h.roster.members[colleague] = true

	err := h.add(team.TeamID, colleague, bystander)
	if err == nil {
		t.Fatal("any member of the workspace can change any team's membership; teams are " +
			"grantable subjects, so this is a way to grant yourself somebody else's access")
	}
	if got := errs.ReasonOf(err); got != errs.AccessDenied {
		t.Errorf("reason is %q, want ACCESS_DENIED", got)
	}
	if h.isInTeam(t, team.TeamID, colleague) {
		t.Error("refused, and recorded anyway")
	}
}

// A WORKSPACE ADMIN CAN, AND THAT IS NOT A COURTESY.
//
// Without the admin half a team whose last maintainer leaves the workspace can
// never be managed again by anybody: appointing a maintainer is itself a
// maintainer's act, so there is no way back in and the team is stuck granting
// whatever it grants forever.
func TestAWorkspaceAdminCanChangeAnyTeam(t *testing.T) {
	h := newTeamMemberHarness(t)
	team := h.create(t, "engineering")

	const admin = "subj_admin00000000000000000"
	const colleague = "subj_colleague0000000000000"
	h.roster.members[admin] = true
	h.roster.members[colleague] = true
	h.admins.admins[admin] = true

	if err := h.add(team.TeamID, colleague, admin); err != nil {
		t.Fatalf("a workspace admin was refused: %v; a team whose last maintainer left "+
			"is now unmanageable forever", err)
	}
	if !h.isInTeam(t, team.TeamID, colleague) {
		t.Fatal("succeeded and recorded nothing")
	}
}

// AN UNREADABLE PERMISSION ANSWER DENIES.
//
// ADR-010, and the direction matters more here than almost anywhere: the
// alternative is that an OpenFGA outage hands management of every team to every
// member of every workspace, all at once and with no log line saying so.
func TestAnUnreadableAdminAnswerDenies(t *testing.T) {
	h := newTeamMemberHarness(t)
	team := h.create(t, "engineering")

	const bystander = "subj_bystander0000000000000"
	const colleague = "subj_colleague0000000000000"
	h.roster.members[bystander] = true
	h.roster.members[colleague] = true
	// Not an admin, AND the answer is unreadable. The `true` is what makes this
	// test discriminate: the refusal has to come from the ERROR being checked
	// first, not from the value happening to be false.
	h.admins.admins[bystander] = true
	h.admins.err = errors.New("openfga: connection refused")

	err := h.add(team.TeamID, colleague, bystander)
	if err == nil {
		t.Fatal("an unreachable permission service ALLOWED the change; an outage now hands " +
			"team management to every member of every workspace")
	}
	if got := errs.ReasonOf(err); got != errs.AccessDenied {
		t.Errorf("reason is %q, want ACCESS_DENIED", got)
	}
}

// THE ROSTER IS NOT CONSULTED BEFORE THE CALLER IS.
//
// Ordering, asserted because it is invisible in the success path and is a real
// disclosure: an unauthorised caller who could learn "that account is not a
// member of this workspace" from the error has an oracle over the roster of a
// workspace they may not read (ADR-036).
func TestAnUnauthorisedCallerLearnsNothingAboutTheRoster(t *testing.T) {
	h := newTeamMemberHarness(t)
	team := h.create(t, "engineering")

	const bystander = "subj_bystander0000000000000"
	h.roster.members[bystander] = true
	before := h.roster.calls

	_ = h.add(team.TeamID, "subj_probe000000000000000000", bystander)

	if h.roster.calls != before {
		t.Error("the workspace roster was read for a caller who is not permitted to change " +
			"this team, so the error distinguishes 'not a member here' from 'permitted' — " +
			"an oracle over a roster they may not read")
	}
}

// REMOVAL IS IDEMPOTENT AND STILL AUTHORISED.
//
// Two properties in one test because they share a subject: removing somebody
// who is already out succeeds quietly (the caller asked for a state that holds),
// but an unauthorised caller is still refused — a no-op is not a reason to skip
// the check, or "remove" becomes a free probe for team membership.
func TestRemovingSomebodyWhoIsAlreadyOut(t *testing.T) {
	h := newTeamMemberHarness(t)
	team := h.create(t, "engineering")

	const colleague = "subj_colleague0000000000000"
	const bystander = "subj_bystander0000000000000"
	h.roster.members[colleague] = true
	h.roster.members[bystander] = true

	remove := func(actedBy string) error {
		return h.members.Remove(context.Background(), app.RemoveTeamMemberCommand{
			OrgID: testOrg, WorkspaceID: inviteWS, TeamID: team.TeamID,
			SubjectID: colleague, ActedBy: actedBy, IdempotencyKey: "key-rm-" + actedBy,
		})
	}

	if err := remove(founder); err != nil {
		t.Errorf("removing somebody who is already out: %v, want success — the caller "+
			"asked for a state that already holds", err)
	}
	if err := remove(bystander); errs.ReasonOf(err) != errs.AccessDenied {
		t.Errorf("an unauthorised removal returned %v; a no-op still has to be authorised, "+
			"or 'remove' is a free probe for who is in a team", err)
	}
}

// A TEAM OF ANOTHER WORKSPACE IS NOT FOUND.
//
// The gate checked `member` on the workspace the REQUEST named. Nothing checked
// that the TEAM belongs to it — an id is just a string — so without this guard a
// member of one workspace could add people to another's team.
func TestATeamOfAnotherWorkspaceCannotBeChanged(t *testing.T) {
	h := newTeamMemberHarness(t)
	team := h.create(t, "engineering")

	const colleague = "subj_colleague0000000000000"
	h.roster.members[colleague] = true

	err := h.members.Add(context.Background(), app.AddTeamMemberCommand{
		OrgID: testOrg, WorkspaceID: "ws_01ARZ3NDEKTSV4RRFFQ69G5FBB",
		TeamID: team.TeamID, SubjectID: colleague, ActedBy: founder,
		IdempotencyKey: "key-cross",
	})
	if got := errs.ReasonOf(err); got != errs.NotFound {
		t.Fatalf("reason is %q, want NOT_FOUND; a member of one workspace can add people "+
			"to another workspace's team", got)
	}
}

// A DELETED TEAM TAKES NO MORE MEMBERS.
//
// Deletion is terminal, and the projection has already emptied the team's
// membership. An add that landed after it would put a row in a table the
// deletion event explains as empty, and a tuple in the graph for a team nothing
// will ever clean up.
func TestADeletedTeamTakesNoMembers(t *testing.T) {
	h := newTeamMemberHarness(t)
	team := h.create(t, "engineering")

	const colleague = "subj_colleague0000000000000"
	h.roster.members[colleague] = true

	if err := h.teams.Delete(context.Background(), app.DeleteTeamCommand{
		OrgID: testOrg, WorkspaceID: inviteWS, TeamID: team.TeamID,
		IdempotencyKey: "key-delete",
	}); err != nil {
		t.Fatal(err)
	}

	err := h.add(team.TeamID, colleague, founder)
	if got := errs.ReasonOf(err); got != errs.Conflict {
		t.Fatalf("reason is %q, want CONFLICT; somebody joined a team that is gone", got)
	}
	if h.isInTeam(t, team.TeamID, colleague) {
		t.Error("recorded a membership in a deleted team")
	}
}

// A TEAM ALWAYS HAS A MAINTAINER.
//
// The aggregate's rule, asserted through the use case because that is where it
// is reachable. A team with none cannot be managed by anybody who is not a
// workspace admin, and nothing outside it can appoint one.
func TestTheLastMaintainerCannotStepDown(t *testing.T) {
	h := newTeamMemberHarness(t)
	team := h.create(t, "engineering")

	err := h.members.RemoveMaintainer(context.Background(), app.TeamMaintainerCommand{
		OrgID: testOrg, WorkspaceID: inviteWS, TeamID: team.TeamID,
		SubjectID: founder, ActedBy: founder, IdempotencyKey: "key-step-down",
	})
	if got := errs.ReasonOf(err); got != errs.Conflict {
		t.Fatalf("reason is %q, want CONFLICT; the team now has no maintainer and nothing "+
			"outside it can appoint one", got)
	}
	if !h.load(t, team.TeamID).IsMaintainer(founder) {
		t.Error("refused, and stepped them down anyway")
	}
}

// A MAINTAINER MUST BE A WORKSPACE MEMBER.
//
// For the reason a team member must be: a maintainer who is not in the workspace
// could add people to a team inside it while having no standing there at all.
func TestAMaintainerMustBeAWorkspaceMember(t *testing.T) {
	h := newTeamMemberHarness(t)
	team := h.create(t, "engineering")

	err := h.members.AddMaintainer(context.Background(), app.TeamMaintainerCommand{
		OrgID: testOrg, WorkspaceID: inviteWS, TeamID: team.TeamID,
		SubjectID: "subj_stranger00000000000000", ActedBy: founder,
		IdempotencyKey: "key-maint",
	})
	if got := errs.ReasonOf(err); got != errs.ValidationFailed {
		t.Fatalf("reason is %q, want VALIDATION_FAILED; somebody with no standing in the "+
			"workspace now manages a team inside it", got)
	}
}

// EVERY MUTATING COMMAND NEEDS AN IDEMPOTENCY-KEY.
//
// CONVENTIONS §6. Asserted per command rather than once, because the check is
// per command and a missing one is invisible until a retry duplicates a change.
func TestTeamMembershipCommandsNeedAnIdempotencyKey(t *testing.T) {
	h := newTeamMemberHarness(t)
	team := h.create(t, "engineering")
	ctx := context.Background()

	const colleague = "subj_colleague0000000000000"
	h.roster.members[colleague] = true

	tests := map[string]func() error{
		"Add": func() error {
			return h.members.Add(ctx, app.AddTeamMemberCommand{
				OrgID: testOrg, WorkspaceID: inviteWS, TeamID: team.TeamID,
				SubjectID: colleague, ActedBy: founder,
			})
		},
		"Remove": func() error {
			return h.members.Remove(ctx, app.RemoveTeamMemberCommand{
				OrgID: testOrg, WorkspaceID: inviteWS, TeamID: team.TeamID,
				SubjectID: colleague, ActedBy: founder,
			})
		},
		"AddMaintainer": func() error {
			return h.members.AddMaintainer(ctx, app.TeamMaintainerCommand{
				OrgID: testOrg, WorkspaceID: inviteWS, TeamID: team.TeamID,
				SubjectID: colleague, ActedBy: founder,
			})
		},
		"RemoveMaintainer": func() error {
			return h.members.RemoveMaintainer(ctx, app.TeamMaintainerCommand{
				OrgID: testOrg, WorkspaceID: inviteWS, TeamID: team.TeamID,
				SubjectID: founder, ActedBy: founder,
			})
		},
	}

	for name, call := range tests {
		t.Run(name, func(t *testing.T) {
			if got := errs.ReasonOf(call()); got != errs.ValidationFailed {
				t.Errorf("%s without a key returned %q, want VALIDATION_FAILED", name, got)
			}
		})
	}
}

// AN INCOMPLETE WIRING IS REFUSED AT CONSTRUCTION.
//
// The composition-root check WORKFLOW.md asks for. A nil roster is the one that
// matters most: it does not crash, it makes IsMember unreachable, and a team
// becomes a way into the workspace with every test still green.
func TestTeamMembersRefusesAnIncompleteWiring(t *testing.T) {
	store := newMemStore()
	teams := eventsourcing.NewRepository[*domain.Team](
		store, jsonCodec{}, nil, domain.TeamCategory, domain.NewTeam)
	memberships := eventsourcing.NewRepository[*domain.TeamMembership](
		store, jsonCodec{}, nil, domain.TeamMembershipCategory, domain.NewTeamMembership)
	now := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

	full := app.TeamMembersDeps{
		Teams: teams, Memberships: memberships,
		Workspace: &fakeWorkspaceMembers{}, Admins: &fakeWorkspaceAdmins{}, Now: now,
	}
	if _, err := app.NewTeamMembers(full); err != nil {
		t.Fatalf("a complete wiring was refused: %v", err)
	}

	for name, drop := range map[string]func(*app.TeamMembersDeps){
		"teams":       func(d *app.TeamMembersDeps) { d.Teams = nil },
		"memberships": func(d *app.TeamMembersDeps) { d.Memberships = nil },
		"workspace":   func(d *app.TeamMembersDeps) { d.Workspace = nil },
		"admins":      func(d *app.TeamMembersDeps) { d.Admins = nil },
		"now":         func(d *app.TeamMembersDeps) { d.Now = nil },
	} {
		t.Run(name, func(t *testing.T) {
			deps := full
			drop(&deps)
			if _, err := app.NewTeamMembers(deps); err == nil {
				t.Errorf("a wiring with no %s was accepted", name)
			}
		})
	}
}

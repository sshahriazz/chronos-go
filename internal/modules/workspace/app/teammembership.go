package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// WorkspaceMembers answers "is this person in this workspace".
//
// It is the guard workspace.md §6 asks for: a team member must ALREADY be a
// workspace member, and adding a non-member is refused rather than implicitly
// admitting them. A team is a grouping of people who are here, never a way in —
// and a version that admitted people would let anybody with a team to manage
// bypass invitations, seats and the entitlement gate in one call.
type WorkspaceMembers interface {
	IsMember(ctx context.Context, workspaceID, subjectID string) (bool, error)
}

// WorkspaceAdmins answers "may this person administer this workspace".
//
// Needed because the RPC's gate cannot answer it. workspace.md §6 requires that
// MAINTAINERS manage a team's membership without being workspace admins, so the
// gate has to admit any member — which means the handler carries the real
// decision, and the real decision is "a maintainer, or an admin".
//
// The admin half is not a courtesy. Without it a team whose last maintainer
// leaves the workspace can never be managed again by anybody: appointing a
// maintainer is itself a maintainer's act, so there is no way back in.
type WorkspaceAdmins interface {
	IsAdmin(ctx context.Context, workspaceID, subjectID string) (bool, error)
}

// AddTeamMemberCommand puts a workspace member into a team.
type AddTeamMemberCommand struct {
	OrgID       string
	WorkspaceID string
	TeamID      string
	SubjectID   string
	ActedBy     string

	IdempotencyKey string
}

// RemoveTeamMemberCommand takes somebody out of a team.
type RemoveTeamMemberCommand struct {
	OrgID       string
	WorkspaceID string
	TeamID      string
	SubjectID   string
	ActedBy     string

	IdempotencyKey string
}

// TeamMaintainerCommand grants or withdraws the right to manage a team.
type TeamMaintainerCommand struct {
	OrgID       string
	WorkspaceID string
	TeamID      string
	SubjectID   string
	ActedBy     string

	IdempotencyKey string
}

// TeamMembers is the team membership use case.
type TeamMembers struct {
	teams       *eventsourcing.Repository[*domain.Team]
	memberships *eventsourcing.Repository[*domain.TeamMembership]
	workspace   WorkspaceMembers
	admins      WorkspaceAdmins
	now         func() time.Time
}

// TeamMembersDeps is what TeamMembers needs.
type TeamMembersDeps struct {
	Teams       *eventsourcing.Repository[*domain.Team]
	Memberships *eventsourcing.Repository[*domain.TeamMembership]
	Workspace   WorkspaceMembers
	Admins      WorkspaceAdmins
	Now         func() time.Time
}

func NewTeamMembers(d TeamMembersDeps) (*TeamMembers, error) {
	switch {
	case d.Teams == nil:
		return nil, fmt.Errorf("workspace: a team repository is required; the maintainer " +
			"roster lives there and every one of these commands is decided against it")
	case d.Memberships == nil:
		return nil, fmt.Errorf("workspace: a team membership repository is required")
	case d.Workspace == nil:
		return nil, fmt.Errorf("workspace: a workspace membership source is required; " +
			"without it a team becomes a way INTO a workspace, bypassing invitations, " +
			"seats and the entitlement gate in one call")
	case d.Admins == nil:
		return nil, fmt.Errorf("workspace: a workspace admin source is required; without " +
			"it a team whose last maintainer leaves can never be managed again")
	case d.Now == nil:
		return nil, fmt.Errorf("workspace: a clock is required")
	}
	return &TeamMembers{
		teams: d.Teams, memberships: d.Memberships,
		workspace: d.Workspace, admins: d.Admins, now: d.Now,
	}, nil
}

// Add puts a workspace member into a team.
//
// The two checks are the whole of it. The CALLER must be a maintainer or a
// workspace admin, and the SUBJECT must already be a workspace member — the
// second is workspace.md §6's rule, and refusing rather than admitting is what
// keeps a team from being a side entrance.
func (t *TeamMembers) Add(ctx context.Context, cmd AddTeamMemberCommand) error {
	team, err := t.authorize(ctx, cmd.OrgID, cmd.WorkspaceID, cmd.TeamID,
		cmd.ActedBy, cmd.SubjectID, cmd.IdempotencyKey)
	if err != nil {
		return err
	}

	member, err := t.workspace.IsMember(ctx, team.WorkspaceID(), cmd.SubjectID)
	if err != nil {
		return errs.Internalf("checking workspace membership").Wrap(err)
	}
	if !member {
		// FAILED as a validation rather than silently admitting them. A team is
		// a grouping of people who are already here; letting this add somebody
		// would hand anybody who maintains a team a way to put a stranger in the
		// workspace with no invitation, no seat and no entitlement check.
		return errs.ValidationFailedf("that account is not a member of this workspace; " +
			"a team groups people who are already here, so invite them first")
	}

	key := domain.TeamMembershipStreamKey(cmd.TeamID, cmd.SubjectID)
	membership, err := t.memberships.Load(ctx, key)
	if err != nil {
		return errs.Internalf("loading the team membership").Wrap(err)
	}
	now := t.now().UTC()
	if err := membership.Add(cmd.TeamID, team.WorkspaceID(), team.OrgID(),
		cmd.SubjectID, cmd.ActedBy, now); err != nil {
		return errs.ValidationFailedf("%s", err)
	}

	return t.save(ctx, key, membership, cmd.IdempotencyKey, team, now)
}

// Remove takes somebody out of a team.
func (t *TeamMembers) Remove(ctx context.Context, cmd RemoveTeamMemberCommand) error {
	team, err := t.authorize(ctx, cmd.OrgID, cmd.WorkspaceID, cmd.TeamID,
		cmd.ActedBy, cmd.SubjectID, cmd.IdempotencyKey)
	if err != nil {
		return err
	}

	key := domain.TeamMembershipStreamKey(cmd.TeamID, cmd.SubjectID)
	membership, err := t.memberships.Load(ctx, key)
	if err != nil {
		return errs.Internalf("loading the team membership").Wrap(err)
	}
	if !membership.Exists() || !membership.Active() {
		// Already out. The caller asked for a state that holds.
		return nil
	}

	now := t.now().UTC()
	if err := membership.Remove(now); err != nil {
		return errs.ValidationFailedf("%s", err)
	}
	return t.save(ctx, key, membership, cmd.IdempotencyKey, team, now)
}

// AddMaintainer grants somebody the right to manage a team.
//
// The person must be a workspace MEMBER for the reason a team member must be:
// a maintainer who is not in the workspace could add people to a team inside it
// while having no standing there at all.
func (t *TeamMembers) AddMaintainer(ctx context.Context, cmd TeamMaintainerCommand) error {
	team, err := t.authorize(ctx, cmd.OrgID, cmd.WorkspaceID, cmd.TeamID,
		cmd.ActedBy, cmd.SubjectID, cmd.IdempotencyKey)
	if err != nil {
		return err
	}

	member, err := t.workspace.IsMember(ctx, team.WorkspaceID(), cmd.SubjectID)
	if err != nil {
		return errs.Internalf("checking workspace membership").Wrap(err)
	}
	if !member {
		return errs.ValidationFailedf("that account is not a member of this workspace, so " +
			"it cannot be given anything to manage inside it")
	}

	now := t.now().UTC()
	if err := team.AddMaintainer(cmd.SubjectID, now); err != nil {
		return errs.Conflictf("%s", err)
	}
	return t.saveTeam(ctx, team, cmd.IdempotencyKey, now)
}

// RemoveMaintainer withdraws that right.
//
// Never the last one — the aggregate refuses, because a team with no maintainer
// cannot be managed by anybody who is not a workspace admin and nothing outside
// it can appoint one.
func (t *TeamMembers) RemoveMaintainer(ctx context.Context, cmd TeamMaintainerCommand) error {
	team, err := t.authorize(ctx, cmd.OrgID, cmd.WorkspaceID, cmd.TeamID,
		cmd.ActedBy, cmd.SubjectID, cmd.IdempotencyKey)
	if err != nil {
		return err
	}

	now := t.now().UTC()
	if err := team.RemoveMaintainer(cmd.SubjectID, now); err != nil {
		return errs.Conflictf("%s", err)
	}
	return t.saveTeam(ctx, team, cmd.IdempotencyKey, now)
}

// authorize loads the team and decides whether the caller may manage it.
//
// # Why this is here and not in the gate
//
// The authz gate asks OpenFGA one question about one object, and the question
// this needs — "a maintainer of THIS team, or an admin of the workspace" — is
// half in a graph and half in an aggregate. Maintainers are deliberately not in
// the graph: a `maintainer` relation would need a tuple per maintainer per team,
// kept in step with the roster by a projector, and the roster is already the
// aggregate's.
//
// So the RPC's gate admits any workspace MEMBER, which bounds it to the tenant,
// and the real decision is taken here against the aggregate — where it is not
// eventually consistent.
func (t *TeamMembers) authorize(
	ctx context.Context, orgID, workspaceID, teamID, actedBy, subjectID, key string,
) (*domain.Team, error) {
	switch {
	case orgID == "":
		return nil, errs.Internalf("no organization reached the team handler; gate 1 " +
			"resolved none")
	case teamID == "":
		return nil, errs.ValidationFailedf("a team is required")
	case subjectID == "":
		return nil, errs.ValidationFailedf("a subject is required")
	case actedBy == "":
		return nil, errs.Internalf("no authenticated subject reached the team handler")
	case key == "":
		return nil, errs.ValidationFailedf(
			"an Idempotency-Key is required on every mutating request")
	}

	team, err := t.teams.Load(ctx, domain.TeamStreamKey(teamID))
	if err != nil {
		return nil, errs.Internalf("loading the team").Wrap(err)
	}
	// Same guard the lifecycle commands use: the gate checked the WORKSPACE the
	// request named, and nothing checked that the TEAM belongs to it.
	if !team.Exists() || team.OrgID() != orgID ||
		(workspaceID != "" && team.WorkspaceID() != workspaceID) {
		return nil, errs.NotFoundf("not found")
	}
	if team.Deleted() {
		return nil, errs.Conflictf("that team is deleted")
	}

	if team.IsMaintainer(actedBy) {
		return team, nil
	}
	admin, err := t.admins.IsAdmin(ctx, team.WorkspaceID(), actedBy)
	if err != nil {
		// FAILS CLOSED. An unreadable answer is not an absent restriction
		// (ADR-010), and the alternative is that an OpenFGA outage hands team
		// management to every member of every workspace at once.
		return nil, errs.AccessDeniedf("this team's permissions could not be evaluated, so " +
			"the change is refused")
	}
	if !admin {
		return nil, errs.AccessDeniedf("only a maintainer of this team or an administrator " +
			"of the workspace may change its membership")
	}
	return team, nil
}

func (t *TeamMembers) save(
	ctx context.Context, key string, membership *domain.TeamMembership,
	idempotencyKey string, team *domain.Team, now time.Time,
) error {
	if _, err := t.memberships.Save(ctx, key, membership, idempotencyKey,
		eventsourcing.Metadata{
			OrgID: team.OrgID(), WorkspaceID: team.WorkspaceID(), OccurredAt: now,
		},
	); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			return errs.Conflictf("this team membership changed concurrently")
		}
		return errs.Internalf("recording the team membership").Wrap(err)
	}
	return nil
}

func (t *TeamMembers) saveTeam(
	ctx context.Context, team *domain.Team, idempotencyKey string, now time.Time,
) error {
	if _, err := t.teams.Save(ctx, domain.TeamStreamKey(team.TeamID()), team, idempotencyKey,
		eventsourcing.Metadata{
			OrgID: team.OrgID(), WorkspaceID: team.WorkspaceID(), OccurredAt: now,
		},
	); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			return errs.Conflictf("this team changed concurrently")
		}
		return errs.Internalf("recording the change").Wrap(err)
	}
	return nil
}

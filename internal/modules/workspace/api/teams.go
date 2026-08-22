package api

import (
	"context"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	workspacev1 "github.com/chronos/chronos-go/gen/proto/chronos/workspace/v1"
	"github.com/chronos/chronos-go/internal/modules/workspace/app"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/server/interceptor"
)

// CreateTeam opens a team inside a workspace.
func (s *Service) CreateTeam(
	ctx context.Context, req *connect.Request[workspacev1.CreateTeamRequest],
) (*connect.Response[workspacev1.CreateTeamResponse], error) {
	tenant, err := db.RequireTenant(ctx)
	if err != nil {
		return nil, fail(errs.Internalf("no tenant scope reached the workspace handler; " +
			"gate 1 resolved no organization").Wrap(err))
	}
	creator, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}

	result, err := s.teams.Create(ctx, app.CreateTeamCommand{
		OrgID:          tenant.OrgID,
		WorkspaceID:    req.Msg.GetWorkspaceId(),
		Name:           req.Msg.GetName(),
		CreatedBy:      creator,
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}

	return connect.NewResponse(&workspacev1.CreateTeamResponse{
		TeamId: result.TeamID,
		Name:   result.Name,
	}), nil
}

// RenameTeam changes a team's display name.
func (s *Service) RenameTeam(
	ctx context.Context, req *connect.Request[workspacev1.RenameTeamRequest],
) (*connect.Response[workspacev1.RenameTeamResponse], error) {
	tenant, err := db.RequireTenant(ctx)
	if err != nil {
		return nil, fail(errs.Internalf("no tenant scope reached the workspace handler; " +
			"gate 1 resolved no organization").Wrap(err))
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}

	if err := s.teams.Rename(ctx, app.RenameTeamCommand{
		OrgID:          tenant.OrgID,
		WorkspaceID:    req.Msg.GetWorkspaceId(),
		TeamID:         req.Msg.GetTeamId(),
		Name:           req.Msg.GetName(),
		IdempotencyKey: key,
	}); err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&workspacev1.RenameTeamResponse{}), nil
}

// DeleteTeam ends a team.
//
// There is deliberately no RestoreTeam. access.md §7.5 requires that a team id is
// never reused — grants target `team:x#member`, so a recreated id would silently
// inherit the deleted team's access — and restoring would BE reusing the id.
func (s *Service) DeleteTeam(
	ctx context.Context, req *connect.Request[workspacev1.DeleteTeamRequest],
) (*connect.Response[workspacev1.DeleteTeamResponse], error) {
	tenant, err := db.RequireTenant(ctx)
	if err != nil {
		return nil, fail(errs.Internalf("no tenant scope reached the workspace handler; " +
			"gate 1 resolved no organization").Wrap(err))
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}

	if err := s.teams.Delete(ctx, app.DeleteTeamCommand{
		OrgID:          tenant.OrgID,
		WorkspaceID:    req.Msg.GetWorkspaceId(),
		TeamID:         req.Msg.GetTeamId(),
		IdempotencyKey: key,
	}); err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&workspacev1.DeleteTeamResponse{}), nil
}

// ListTeams returns one page of a workspace's teams.
func (s *Service) ListTeams(
	ctx context.Context, req *connect.Request[workspacev1.ListTeamsRequest],
) (*connect.Response[workspacev1.ListTeamsResponse], error) {
	if _, err := db.RequireTenant(ctx); err != nil {
		return nil, fail(errs.Internalf("no tenant scope reached the workspace handler; " +
			"gate 1 resolved no organization").Wrap(err))
	}

	result, err := s.teamQueries.List(ctx, app.ListTeamsQuery{
		WorkspaceID: req.Msg.GetWorkspaceId(),
		PageSize:    int(req.Msg.GetPageSize()),
		PageToken:   req.Msg.GetPageToken(),
	})
	if err != nil {
		return nil, fail(err)
	}

	out := make([]*workspacev1.Team, 0, len(result.Teams))
	for _, team := range result.Teams {
		out = append(out, &workspacev1.Team{
			TeamId:    team.TeamID,
			Name:      team.Name,
			CreatedBy: team.CreatedBy,
			CreatedAt: timestamppb.New(team.CreatedAt.UTC()),
		})
	}

	return connect.NewResponse(&workspacev1.ListTeamsResponse{
		Teams:         out,
		NextPageToken: result.NextPageToken,
	}), nil
}

// teamMemberCommand is the shape all four membership RPCs share.
//
// Extracted because the four handlers differ only in which use-case method they
// call: same gate, same tenant, same three fields, same idempotency key. Four
// copies would be four places for the caller to be read from the request by
// mistake — which is the one field here that must never come from it.
type teamMemberCommand struct {
	orgID       string
	workspaceID string
	teamID      string
	subjectID   string
	actedBy     string
	key         string
}

func (s *Service) teamMemberCommand(
	ctx context.Context, header interceptor.Header,
	workspaceID, teamID, subjectID string,
) (teamMemberCommand, error) {
	tenant, err := db.RequireTenant(ctx)
	if err != nil {
		return teamMemberCommand{}, fail(errs.Internalf("no tenant scope reached the " +
			"workspace handler; gate 1 resolved no organization").Wrap(err))
	}
	// From the SESSION and nowhere else. A request that could name its own actor
	// would let any workspace member claim to be a maintainer.
	actor, err := callerSubject(ctx)
	if err != nil {
		return teamMemberCommand{}, fail(err)
	}
	key, err := idempotencyKey(header)
	if err != nil {
		return teamMemberCommand{}, fail(err)
	}
	return teamMemberCommand{
		orgID: tenant.OrgID, workspaceID: workspaceID, teamID: teamID,
		subjectID: subjectID, actedBy: actor, key: key,
	}, nil
}

// AddTeamMember puts a workspace member into a team.
func (s *Service) AddTeamMember(
	ctx context.Context, req *connect.Request[workspacev1.AddTeamMemberRequest],
) (*connect.Response[workspacev1.AddTeamMemberResponse], error) {
	cmd, err := s.teamMemberCommand(ctx, req.Header(),
		req.Msg.GetWorkspaceId(), req.Msg.GetTeamId(), req.Msg.GetSubjectId())
	if err != nil {
		return nil, err
	}
	if err := s.teamMembers.Add(ctx, app.AddTeamMemberCommand{
		OrgID: cmd.orgID, WorkspaceID: cmd.workspaceID, TeamID: cmd.teamID,
		SubjectID: cmd.subjectID, ActedBy: cmd.actedBy, IdempotencyKey: cmd.key,
	}); err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&workspacev1.AddTeamMemberResponse{}), nil
}

// RemoveTeamMember takes somebody out of a team.
func (s *Service) RemoveTeamMember(
	ctx context.Context, req *connect.Request[workspacev1.RemoveTeamMemberRequest],
) (*connect.Response[workspacev1.RemoveTeamMemberResponse], error) {
	cmd, err := s.teamMemberCommand(ctx, req.Header(),
		req.Msg.GetWorkspaceId(), req.Msg.GetTeamId(), req.Msg.GetSubjectId())
	if err != nil {
		return nil, err
	}
	if err := s.teamMembers.Remove(ctx, app.RemoveTeamMemberCommand{
		OrgID: cmd.orgID, WorkspaceID: cmd.workspaceID, TeamID: cmd.teamID,
		SubjectID: cmd.subjectID, ActedBy: cmd.actedBy, IdempotencyKey: cmd.key,
	}); err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&workspacev1.RemoveTeamMemberResponse{}), nil
}

// AddTeamMaintainer grants somebody the right to manage a team.
func (s *Service) AddTeamMaintainer(
	ctx context.Context, req *connect.Request[workspacev1.AddTeamMaintainerRequest],
) (*connect.Response[workspacev1.AddTeamMaintainerResponse], error) {
	cmd, err := s.teamMemberCommand(ctx, req.Header(),
		req.Msg.GetWorkspaceId(), req.Msg.GetTeamId(), req.Msg.GetSubjectId())
	if err != nil {
		return nil, err
	}
	if err := s.teamMembers.AddMaintainer(ctx, app.TeamMaintainerCommand{
		OrgID: cmd.orgID, WorkspaceID: cmd.workspaceID, TeamID: cmd.teamID,
		SubjectID: cmd.subjectID, ActedBy: cmd.actedBy, IdempotencyKey: cmd.key,
	}); err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&workspacev1.AddTeamMaintainerResponse{}), nil
}

// RemoveTeamMaintainer withdraws that right, never the last one.
func (s *Service) RemoveTeamMaintainer(
	ctx context.Context, req *connect.Request[workspacev1.RemoveTeamMaintainerRequest],
) (*connect.Response[workspacev1.RemoveTeamMaintainerResponse], error) {
	cmd, err := s.teamMemberCommand(ctx, req.Header(),
		req.Msg.GetWorkspaceId(), req.Msg.GetTeamId(), req.Msg.GetSubjectId())
	if err != nil {
		return nil, err
	}
	if err := s.teamMembers.RemoveMaintainer(ctx, app.TeamMaintainerCommand{
		OrgID: cmd.orgID, WorkspaceID: cmd.workspaceID, TeamID: cmd.teamID,
		SubjectID: cmd.subjectID, ActedBy: cmd.actedBy, IdempotencyKey: cmd.key,
	}); err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&workspacev1.RemoveTeamMaintainerResponse{}), nil
}

package api

import (
	"context"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	workspacev1 "github.com/chronos/chronos-go/gen/proto/chronos/workspace/v1"
	"github.com/chronos/chronos-go/internal/modules/workspace/app"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/errs"
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

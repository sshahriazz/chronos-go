package api

import (
	"context"

	"connectrpc.com/connect"

	workspacev1 "github.com/chronos/chronos-go/gen/proto/chronos/workspace/v1"
	"github.com/chronos/chronos-go/internal/modules/workspace/app"
	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/errs"
)

// AddWorkspaceMember puts an existing account into a workspace.
//
// The workspace comes from the request and the organization from the tenant
// scope, and the pairing is checked by the authz gate rather than here: gate 2
// asked OpenFGA for `admin` on THIS workspace, and the `parent` edge that
// answers it is what ties the workspace to the organization. A workspace of
// another tenant fails that check, so a handler re-checking the pairing would be
// asking a question that has already been answered — and answering it from the
// read model would answer it from a projection that may lag.
func (s *Service) AddWorkspaceMember(
	ctx context.Context, req *connect.Request[workspacev1.AddWorkspaceMemberRequest],
) (*connect.Response[workspacev1.AddWorkspaceMemberResponse], error) {
	tenant, err := db.RequireTenant(ctx)
	if err != nil {
		return nil, fail(errs.Internalf("no tenant scope reached the workspace handler; " +
			"gate 1 resolved no organization").Wrap(err))
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}

	result, err := s.members.Add(ctx, app.AddMemberCommand{
		OrgID:          tenant.OrgID,
		WorkspaceID:    req.Msg.GetWorkspaceId(),
		SubjectID:      req.Msg.GetSubjectId(),
		Role:           contract.MemberRole(req.Msg.GetRole()),
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}

	return connect.NewResponse(&workspacev1.AddWorkspaceMemberResponse{
		Role:         string(result.Role),
		SeatConsumed: result.SeatConsumed,
	}), nil
}

// RemoveWorkspaceMember takes an account out of a workspace.
func (s *Service) RemoveWorkspaceMember(
	ctx context.Context, req *connect.Request[workspacev1.RemoveWorkspaceMemberRequest],
) (*connect.Response[workspacev1.RemoveWorkspaceMemberResponse], error) {
	tenant, err := db.RequireTenant(ctx)
	if err != nil {
		return nil, fail(errs.Internalf("no tenant scope reached the workspace handler; " +
			"gate 1 resolved no organization").Wrap(err))
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}

	result, err := s.members.Remove(ctx, app.RemoveMemberCommand{
		OrgID:          tenant.OrgID,
		WorkspaceID:    req.Msg.GetWorkspaceId(),
		SubjectID:      req.Msg.GetSubjectId(),
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}

	return connect.NewResponse(&workspacev1.RemoveWorkspaceMemberResponse{
		SeatReleased: result.SeatReleased,
	}), nil
}

// ChangeWorkspaceMemberRole promotes or demotes an existing member.
func (s *Service) ChangeWorkspaceMemberRole(
	ctx context.Context, req *connect.Request[workspacev1.ChangeWorkspaceMemberRoleRequest],
) (*connect.Response[workspacev1.ChangeWorkspaceMemberRoleResponse], error) {
	tenant, err := db.RequireTenant(ctx)
	if err != nil {
		return nil, fail(errs.Internalf("no tenant scope reached the workspace handler; " +
			"gate 1 resolved no organization").Wrap(err))
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}

	result, err := s.members.ChangeRole(ctx, app.ChangeRoleCommand{
		OrgID:          tenant.OrgID,
		WorkspaceID:    req.Msg.GetWorkspaceId(),
		SubjectID:      req.Msg.GetSubjectId(),
		Role:           contract.MemberRole(req.Msg.GetRole()),
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}

	return connect.NewResponse(&workspacev1.ChangeWorkspaceMemberRoleResponse{
		Role: string(result.Role),
	}), nil
}

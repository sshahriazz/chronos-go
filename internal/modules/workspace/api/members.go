package api

import (
	"context"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

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

// InviteToWorkspace invites an address into a workspace.
//
// The response is deliberately thin. It carries no token — the link is a
// credential and the only party entitled to it is the person at the address —
// and it does not echo the address back, so it cannot be used to confirm what
// was typed.
func (s *Service) InviteToWorkspace(
	ctx context.Context, req *connect.Request[workspacev1.InviteToWorkspaceRequest],
) (*connect.Response[workspacev1.InviteToWorkspaceResponse], error) {
	tenant, err := db.RequireTenant(ctx)
	if err != nil {
		return nil, fail(errs.Internalf("no tenant scope reached the workspace handler; " +
			"gate 1 resolved no organization").Wrap(err))
	}
	inviter, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}

	result, err := s.invitations.Issue(ctx, app.IssueInvitationCommand{
		OrgID:          tenant.OrgID,
		WorkspaceID:    req.Msg.GetWorkspaceId(),
		Email:          req.Msg.GetEmail(),
		Role:           contract.MemberRole(req.Msg.GetRole()),
		InvitedBy:      inviter,
		IdempotencyKey: key,
	})
	if err != nil {
		// A PARTIAL success reaches here: the invitation exists and holds its
		// seat, and only the link is missing. It is still an error to the caller,
		// because an invitation nobody can redeem is not what they asked for —
		// and the message says to resend rather than to re-invite, so they do not
		// take a second seat for one person.
		return nil, fail(err)
	}

	// result.Token is deliberately dropped here. It exists so the notification
	// path can put it in the mail, and this is the layer that must not let it
	// travel any further.
	return connect.NewResponse(&workspacev1.InviteToWorkspaceResponse{
		InvitationId: result.InvitationID,
		Role:         string(result.Role),
		SeatConsumed: result.SeatConsumed,
		ExpiresAt:    timestamppb.New(result.ExpiresAt.UTC()),
	}), nil
}

// AcceptInvitation redeems an invitation link.
//
// # No tenant scope, deliberately
//
// Every other handler in this file starts with db.RequireTenant. This one cannot:
// the person clicking the link is not in the organization yet, so gate 1 had
// nothing to resolve — the RPC is self-scoped for exactly that reason. The
// organization comes out of the TOKEN, inside the use case, and the checks gates
// 1 and 3 would have made happen there.
func (s *Service) AcceptInvitation(
	ctx context.Context, req *connect.Request[workspacev1.AcceptInvitationRequest],
) (*connect.Response[workspacev1.AcceptInvitationResponse], error) {
	// The accepting account comes from the SESSION and from nowhere else — not
	// from the request, not from a header. A request that could name its own
	// acceptor would let anybody bind an invitation to any account.
	acceptor, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}

	result, err := s.invitations.Accept(ctx, app.AcceptInvitationCommand{
		Token:          req.Msg.GetToken(),
		AcceptedBy:     acceptor,
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}

	return connect.NewResponse(&workspacev1.AcceptInvitationResponse{
		WorkspaceId:   result.WorkspaceID,
		OrgId:         result.OrgID,
		Role:          string(result.Role),
		AlreadyMember: result.AlreadyMember,
	}), nil
}

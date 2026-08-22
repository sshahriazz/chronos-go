package api

import (
	"context"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	workspacev1 "github.com/chronos/chronos-go/gen/proto/chronos/workspace/v1"
	"github.com/chronos/chronos-go/internal/modules/workspace/app"
	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/modules/workspace/domain"
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
		return nil, fail(err)
	}

	// The response carries no link, and there is none to carry: the handler
	// mints nothing. The reactor that consumes InvitationIssued mints it, puts
	// it in the mail and discards it — see app.InvitationIssuer.
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

// RevokeInvitation withdraws an outstanding invitation.
func (s *Service) RevokeInvitation(
	ctx context.Context, req *connect.Request[workspacev1.RevokeInvitationRequest],
) (*connect.Response[workspacev1.RevokeInvitationResponse], error) {
	tenant, err := db.RequireTenant(ctx)
	if err != nil {
		return nil, fail(errs.Internalf("no tenant scope reached the workspace handler; " +
			"gate 1 resolved no organization").Wrap(err))
	}
	revoker, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}

	result, err := s.invitations.Revoke(ctx, app.RevokeInvitationCommand{
		OrgID:          tenant.OrgID,
		WorkspaceID:    req.Msg.GetWorkspaceId(),
		InvitationID:   req.Msg.GetInvitationId(),
		RevokedBy:      revoker,
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}

	return connect.NewResponse(&workspacev1.RevokeInvitationResponse{
		SeatReleased: result.SeatReleased,
	}), nil
}

// ResendInvitation issues a fresh link and extends the window.
func (s *Service) ResendInvitation(
	ctx context.Context, req *connect.Request[workspacev1.ResendInvitationRequest],
) (*connect.Response[workspacev1.ResendInvitationResponse], error) {
	tenant, err := db.RequireTenant(ctx)
	if err != nil {
		return nil, fail(errs.Internalf("no tenant scope reached the workspace handler; " +
			"gate 1 resolved no organization").Wrap(err))
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}

	result, err := s.invitations.Resend(ctx, app.ResendInvitationCommand{
		OrgID:          tenant.OrgID,
		WorkspaceID:    req.Msg.GetWorkspaceId(),
		InvitationID:   req.Msg.GetInvitationId(),
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}

	// No link here either. Resend appends InvitationTokenRotated; the reactor
	// voids the old link and mints the new one, so the administrator who pressed
	// resend never holds a credential addressed to somebody else.
	return connect.NewResponse(&workspacev1.ResendInvitationResponse{
		ExpiresAt: timestamppb.New(result.ExpiresAt.UTC()),
	}), nil
}

// DeclineInvitation refuses an invitation.
//
// PUBLIC: no tenant scope and no caller. The person declining may have no
// account, and requiring one to say no would hold the seat until expiry for
// everybody who is not interested — which is the case a decline exists to
// shorten. The token is the authorization, and nothing on this path grants
// anything.
func (s *Service) DeclineInvitation(
	ctx context.Context, req *connect.Request[workspacev1.DeclineInvitationRequest],
) (*connect.Response[workspacev1.DeclineInvitationResponse], error) {
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}

	if err := s.invitations.Decline(ctx, app.DeclineInvitationCommand{
		Token:          req.Msg.GetToken(),
		IdempotencyKey: key,
	}); err != nil {
		return nil, fail(err)
	}

	// EMPTY, and identical whether the token was real, spent or invented.
	return connect.NewResponse(&workspacev1.DeclineInvitationResponse{}), nil
}

// ListWorkspaceInvitations returns one page of a workspace's invitations.
func (s *Service) ListWorkspaceInvitations(
	ctx context.Context, req *connect.Request[workspacev1.ListWorkspaceInvitationsRequest],
) (*connect.Response[workspacev1.ListWorkspaceInvitationsResponse], error) {
	if _, err := db.RequireTenant(ctx); err != nil {
		return nil, fail(errs.Internalf("no tenant scope reached the workspace handler; " +
			"gate 1 resolved no organization").Wrap(err))
	}

	result, err := s.invitationQueries.List(ctx, app.ListInvitationsQuery{
		WorkspaceID: req.Msg.GetWorkspaceId(),
		Status:      domain.InvitationStatus(req.Msg.GetStatus()),
		PageSize:    int(req.Msg.GetPageSize()),
		PageToken:   req.Msg.GetPageToken(),
	})
	if err != nil {
		return nil, fail(err)
	}

	out := make([]*workspacev1.WorkspaceInvitation, 0, len(result.Invitations))
	for _, inv := range result.Invitations {
		out = append(out, &workspacev1.WorkspaceInvitation{
			InvitationId: inv.InvitationID,
			SubjectId:    inv.SubjectID,
			InvitedBy:    inv.InvitedBy,
			Role:         string(inv.Role),
			Status:       string(inv.Status),
			ExpiresAt:    timestamppb.New(inv.ExpiresAt.UTC()),
			IssuedAt:     timestamppb.New(inv.IssuedAt.UTC()),
		})
	}

	return connect.NewResponse(&workspacev1.ListWorkspaceInvitationsResponse{
		Invitations:   out,
		NextPageToken: result.NextPageToken,
	}), nil
}

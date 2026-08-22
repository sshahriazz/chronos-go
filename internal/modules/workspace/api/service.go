// Package api adapts workspace's use cases to the transport layer.
package api

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	workspacev1 "github.com/chronos/chronos-go/gen/proto/chronos/workspace/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/workspace/v1/workspacev1connect"
	entitlementapi "github.com/chronos/chronos-go/internal/modules/entitlement/api"
	"github.com/chronos/chronos-go/internal/modules/workspace/app"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/errs"
	srvconnect "github.com/chronos/chronos-go/internal/server/connect"
	"github.com/chronos/chronos-go/internal/server/interceptor"
)

// Creation is workspace's write side, narrowed to what this layer calls.
type Creation interface {
	Create(ctx context.Context, cmd app.CreateCommand) (app.CreateResult, error)
}

// Membership is workspace's member write side, narrowed to what this layer
// calls.
type Membership interface {
	Add(ctx context.Context, cmd app.AddMemberCommand) (app.AddMemberResult, error)
	Remove(ctx context.Context, cmd app.RemoveMemberCommand) (app.RemoveMemberResult, error)
	ChangeRole(ctx context.Context, cmd app.ChangeRoleCommand) (app.ChangeRoleResult, error)
}

// Invitation is workspace's invitation write side, narrowed to what this layer
// calls.
type Invitation interface {
	Issue(ctx context.Context, cmd app.IssueInvitationCommand) (app.IssueInvitationResult, error)
	Accept(ctx context.Context, cmd app.AcceptInvitationCommand) (app.AcceptInvitationResult, error)
}

// Service serves WorkspaceService.
type Service struct {
	workspacev1connect.UnimplementedWorkspaceServiceHandler

	creation    Creation
	members     Membership
	invitations Invitation
}

// Deps is what Service needs.
type Deps struct {
	Creation    Creation
	Members     Membership
	Invitations Invitation
}

func New(d Deps) (*Service, error) {
	switch {
	case d.Creation == nil:
		return nil, fmt.Errorf("workspace: a creation use case is required")
	case d.Members == nil:
		// Required, not optional. An embedded UnimplementedWorkspaceServiceHandler
		// means a nil here would compile and serve UNIMPLEMENTED at request time
		// instead of failing the boot — and three RPCs that answer UNIMPLEMENTED
		// look like a deployment that is merely behind.
		return nil, fmt.Errorf("workspace: a membership use case is required; without one " +
			"the member RPCs answer UNIMPLEMENTED and no seat is ever counted")
	case d.Invitations == nil:
		return nil, fmt.Errorf("workspace: an invitation use case is required; without one " +
			"InviteToWorkspace answers UNIMPLEMENTED, which reads as a deployment that is " +
			"merely behind")
	}
	return &Service{creation: d.Creation, members: d.Members, invitations: d.Invitations}, nil
}

// CreateWorkspace opens a workspace in the caller's organization.
//
// Every input except the name comes from the CONTEXT, and none of them from the
// request: the organization from gate 1's tenant scope, the creator from the
// authn gate, and the quota reservation from gate 4. A request that could name
// its own organization would create a workspace inside somebody else's tenant,
// and one that could name its own reservation would be claiming quota it was
// never granted.
func (s *Service) CreateWorkspace(
	ctx context.Context, req *connect.Request[workspacev1.CreateWorkspaceRequest],
) (*connect.Response[workspacev1.CreateWorkspaceResponse], error) {
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

	// Gate 4 granted this, and the use case commits it. Absent means the gate
	// did not run, which the use case refuses rather than working around — the
	// cap would silently not apply.
	reservation, ok := entitlementapi.ReservationFrom(ctx)
	if !ok {
		return nil, fail(errs.Internalf("no quota reservation reached the workspace handler, " +
			"so gate 4 did not run and the workspace cap would not apply"))
	}

	result, err := s.creation.Create(ctx, app.CreateCommand{
		OrgID:          tenant.OrgID,
		Name:           req.Msg.GetName(),
		CreatedBy:      creator,
		ReservationID:  reservation.ID,
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}

	return connect.NewResponse(&workspacev1.CreateWorkspaceResponse{
		WorkspaceId: result.WorkspaceID,
		Name:        result.Name,
		Status:      string(result.Status),
	}), nil
}

// callerSubject reads the authenticated caller's pseudonym from the context.
//
// A KindAPIKey or KindServiceAccount principal carries the KEY's identifier
// rather than a person's pseudonym, and the creator becomes the workspace's
// first admin — so reading one as a subject would make a machine credential the
// only administrator of a workspace.
func callerSubject(ctx context.Context) (string, error) {
	principal, ok := interceptor.PrincipalFrom(ctx)
	if !ok || principal.Subject.Kind != authz.KindUser || principal.Subject.ID == "" {
		return "", errs.Unauthenticatedf("this request has not authenticated")
	}
	return principal.Subject.ID, nil
}

// idempotencyKey reads the client-generated key every mutating command needs.
func idempotencyKey(header interceptor.Header) (string, error) {
	key := header.Get(interceptor.IdempotencyHeader)
	if key == "" {
		return "", errs.ValidationFailedf(
			"%s is required on every mutating request", interceptor.IdempotencyHeader)
	}
	return key, nil
}

func fail(err error) error { return srvconnect.Error(err) }

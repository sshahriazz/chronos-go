package api

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	organizationv1 "github.com/chronos/chronos-go/gen/proto/chronos/organization/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/organization/v1/organizationv1connect"
	"github.com/chronos/chronos-go/internal/modules/organization/app"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/errs"
	srvconnect "github.com/chronos/chronos-go/internal/server/connect"
	"github.com/chronos/chronos-go/internal/server/interceptor"
)

// Creation is organization's write side, narrowed to what this layer calls.
//
// A port declared by the consumer (ADR-001, CONVENTIONS §2). Narrow rather than
// the concrete struct for a reason beyond testability: a handler holding
// *app.Creation could reach every method on it, including ones no RPC exposes.
type Creation interface {
	Create(ctx context.Context, cmd app.CreateCommand) (app.CreateResult, error)
}

// Service serves OrganizationService.
type Service struct {
	organizationv1connect.UnimplementedOrganizationServiceHandler

	creation Creation
}

// Deps is what Service needs.
type Deps struct {
	Creation Creation
}

func New(d Deps) (*Service, error) {
	if d.Creation == nil {
		return nil, fmt.Errorf("organization: a creation use case is required")
	}
	return &Service{creation: d.Creation}, nil
}

// CreateOrganization opens an organization owned by the caller.
//
// The owner comes from the CONTEXT and never from the request. There is no field
// for it in the schema, and there must not be: a request that names its own
// owner is a request that creates an organization belonging to somebody else.
func (s *Service) CreateOrganization(
	ctx context.Context, req *connect.Request[organizationv1.CreateOrganizationRequest],
) (*connect.Response[organizationv1.CreateOrganizationResponse], error) {
	owner, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}

	result, err := s.creation.Create(ctx, app.CreateCommand{
		Name:           req.Msg.GetName(),
		Slug:           req.Msg.GetSlug(),
		Owner:          owner,
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}

	return connect.NewResponse(&organizationv1.CreateOrganizationResponse{
		OrgId:  result.OrgID,
		Slug:   result.Slug,
		Status: string(result.Status),
	}), nil
}

// callerSubject reads the authenticated caller's pseudonym from the context.
//
// The context, and never the request. `interceptor.PrincipalFrom` reads a value
// only the authn gate can write, so a subject obtained here cannot have been
// chosen by whoever sent the request.
//
// A KindAPIKey or KindServiceAccount principal carries the KEY's identifier
// rather than a person's pseudonym, so reading it as a subject would create an
// organization owned by whatever account that string happened to name. Refused
// rather than resolved: ownership binds a real person to a payment obligation,
// and there is no delegation convention for that yet.
func callerSubject(ctx context.Context) (string, error) {
	principal, ok := interceptor.PrincipalFrom(ctx)
	if !ok || principal.Subject.Kind != authz.KindUser || principal.Subject.ID == "" {
		return "", errs.Unauthenticatedf("this request has not authenticated")
	}
	return principal.Subject.ID, nil
}

// idempotencyKey reads the client-generated key every mutating command needs.
//
// The same header gate 5 claims, so a retry the gate collapses and a retry that
// reaches the app layer derive the same event ids rather than two chains for one
// command. Absent is a refusal, never a server-generated substitute.
func idempotencyKey(header interceptor.Header) (string, error) {
	key := header.Get(interceptor.IdempotencyHeader)
	if key == "" {
		return "", errs.ValidationFailedf(
			"%s is required on every mutating request", interceptor.IdempotencyHeader)
	}
	return key, nil
}

// fail hands the error to the transport mapping the rest of the server uses.
// There is no branch on the reason here and there must not be one — the app
// layer has already decided what a caller may be told (ADR-036).
func fail(err error) error { return srvconnect.Error(err) }

package api

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	operatorv1 "github.com/chronos/chronos-go/gen/proto/chronos/operator/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/operator/v1/operatorv1connect"
	"github.com/chronos/chronos-go/internal/operator/app"
)

// Service serves OperatorService.
//
// The handlers hold no enforcement: the guard resolved the operator and checked
// the capability before any of this runs, and the use cases record the audit at
// the point in their own flow where the record is correct. What is left here is
// translation between the wire and the domain, which is what an API layer is
// for (CONVENTIONS §5).
type Service struct {
	signIn    *app.SignIn
	customers *app.Customers
	elevation *app.Elevation
}

// NewService builds the handlers.
func NewService(signIn *app.SignIn, customers *app.Customers, elevation *app.Elevation) (*Service, error) {
	if signIn == nil || customers == nil || elevation == nil {
		return nil, errors.New("operator api: the service needs its three use cases")
	}
	return &Service{signIn: signIn, customers: customers, elevation: elevation}, nil
}

var _ operatorv1connect.OperatorServiceHandler = (*Service)(nil)

// BeginSignIn starts the OIDC ceremony.
func (s *Service) BeginSignIn(
	ctx context.Context, _ *connect.Request[operatorv1.BeginSignInRequest],
) (*connect.Response[operatorv1.BeginSignInResponse], error) {
	res, err := s.signIn.Begin(ctx)
	if err != nil {
		return nil, wire(err)
	}
	return connect.NewResponse(&operatorv1.BeginSignInResponse{
		AuthorizationUrl: res.AuthorizationURL,
		CeremonyId:       res.CeremonyID,
		ExpiresAt:        timestamppb.New(res.ExpiresAt),
	}), nil
}

// CompleteSignIn exchanges the IdP's code for a pending session.
//
// The ceremony id arrives in a HEADER rather than in the request body, because
// the browser is redirected here by the provider and carries only what the
// provider put in the URL. The console reads its own stored ceremony id and
// sends it; a request field would have to be filled from the same place.
func (s *Service) CompleteSignIn(
	ctx context.Context, req *connect.Request[operatorv1.CompleteSignInRequest],
) (*connect.Response[operatorv1.CompleteSignInResponse], error) {
	ceremonyID := req.Header().Get(CeremonyHeader)
	if ceremonyID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("this request needs a %s header naming the ceremony it completes", CeremonyHeader))
	}

	res, err := s.signIn.Complete(ctx, ceremonyID, app.IdPCallback{
		Code:   req.Msg.GetCode(),
		State:  req.Msg.GetState(),
		Issuer: req.Msg.GetIss(),
	})
	if err != nil {
		return nil, wire(err)
	}
	return connect.NewResponse(&operatorv1.CompleteSignInResponse{
		PendingToken:       res.PendingToken,
		CredentialEnrolled: res.CredentialEnrolled,
		ExpiresAt:          timestamppb.New(res.ExpiresAt),
	}), nil
}

// CeremonyHeader names the sign-in ceremony a request continues.
const CeremonyHeader = "Operator-Ceremony"

// BeginWebAuthn issues the second factor's challenge.
func (s *Service) BeginWebAuthn(
	ctx context.Context, _ *connect.Request[operatorv1.BeginWebAuthnRequest],
) (*connect.Response[operatorv1.BeginWebAuthnResponse], error) {
	sess, err := s.pending(ctx)
	if err != nil {
		return nil, err
	}
	res, err := s.signIn.BeginSecondFactor(ctx, sess)
	if err != nil {
		return nil, wire(err)
	}
	return connect.NewResponse(&operatorv1.BeginWebAuthnResponse{
		OptionsJson: string(res.OptionsJSON),
		Enrolment:   res.Enrolment,
		CeremonyId:  res.CeremonyID,
	}), nil
}

// FinishWebAuthn verifies the assertion and issues the live session.
func (s *Service) FinishWebAuthn(
	ctx context.Context, req *connect.Request[operatorv1.FinishWebAuthnRequest],
) (*connect.Response[operatorv1.FinishWebAuthnResponse], error) {
	sess, err := s.pending(ctx)
	if err != nil {
		return nil, err
	}
	digest, ok := DigestFrom(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeInternal,
			errors.New("this request's own bearer was not carried through"))
	}

	actor, _ := ActorFrom(ctx)
	res, err := s.signIn.FinishSecondFactor(ctx, sess, digest,
		req.Msg.GetCeremonyId(), []byte(req.Msg.GetCredentialJson()),
		req.Msg.GetLabel(), actor.FromIP)
	if err != nil {
		return nil, wire(err)
	}
	return connect.NewResponse(&operatorv1.FinishWebAuthnResponse{
		Token:      res.Token,
		OperatorId: res.OperatorID,
		Role:       string(res.Role),
		ExpiresAt:  timestamppb.New(res.ExpiresAt),
	}), nil
}

// SignOut ends the caller's own session.
func (s *Service) SignOut(
	ctx context.Context, _ *connect.Request[operatorv1.SignOutRequest],
) (*connect.Response[operatorv1.SignOutResponse], error) {
	actor, ok := ActorFrom(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, app.ErrSessionRefused)
	}
	digest, ok := DigestFrom(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeInternal,
			errors.New("this request's own bearer was not carried through"))
	}
	changed, err := s.signIn.SignOut(ctx, actor, digest)
	if err != nil {
		return nil, wire(err)
	}
	return connect.NewResponse(&operatorv1.SignOutResponse{Changed: changed}), nil
}

// RequestElevation takes a capability this operator's role does not hold.
func (s *Service) RequestElevation(
	ctx context.Context, req *connect.Request[operatorv1.RequestElevationRequest],
) (*connect.Response[operatorv1.RequestElevationResponse], error) {
	actor, ok := ActorFrom(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, app.ErrSessionRefused)
	}
	digest, ok := DigestFrom(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeInternal,
			errors.New("this request's own bearer was not carried through"))
	}

	res, err := s.elevation.Request(ctx, actor, digest,
		req.Msg.GetCapability(), req.Msg.GetReason())
	if err != nil {
		return nil, wire(err)
	}
	return connect.NewResponse(&operatorv1.RequestElevationResponse{
		Capability:   res.Capability,
		ExpiresAt:    timestamppb.New(res.ExpiresAt),
		AuditEntryId: res.AuditEntryID,
	}), nil
}

// ListCustomers pages the directory.
func (s *Service) ListCustomers(
	ctx context.Context, req *connect.Request[operatorv1.ListCustomersRequest],
) (*connect.Response[operatorv1.ListCustomersResponse], error) {
	actor, ok := ActorFrom(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, app.ErrSessionRefused)
	}
	page, err := s.customers.List(ctx, actor, MethodName(req),
		req.Msg.GetQuery(), req.Msg.GetLifecycleState(),
		req.Msg.GetPageToken(), req.Msg.GetPageSize())
	if err != nil {
		return nil, wire(err)
	}

	out := make([]*operatorv1.Customer, 0, len(page.Customers))
	for _, c := range page.Customers {
		out = append(out, customerToWire(c))
	}
	return connect.NewResponse(&operatorv1.ListCustomersResponse{
		Customers:     out,
		NextPageToken: page.NextPageToken,
	}), nil
}

// GetCustomer reads one organization's record.
func (s *Service) GetCustomer(
	ctx context.Context, req *connect.Request[operatorv1.GetCustomerRequest],
) (*connect.Response[operatorv1.GetCustomerResponse], error) {
	actor, ok := ActorFrom(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, app.ErrSessionRefused)
	}
	c, err := s.customers.Get(ctx, actor, MethodName(req), req.Msg.GetOrgId())
	if err != nil {
		return nil, wire(err)
	}
	return connect.NewResponse(&operatorv1.GetCustomerResponse{Customer: customerToWire(c)}), nil
}

// RevealPersonalData resolves one subject's vault fields.
func (s *Service) RevealPersonalData(
	ctx context.Context, req *connect.Request[operatorv1.RevealPersonalDataRequest],
) (*connect.Response[operatorv1.RevealPersonalDataResponse], error) {
	actor, ok := ActorFrom(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, app.ErrSessionRefused)
	}
	res, err := s.customers.Reveal(ctx, actor, MethodName(req),
		req.Msg.GetSubjectId(), req.Msg.GetOrgId(), req.Msg.GetFields(), req.Msg.GetReason())
	if err != nil {
		return nil, wire(err)
	}
	return connect.NewResponse(&operatorv1.RevealPersonalDataResponse{
		Fields:       res.Fields,
		AuditEntryId: res.AuditEntryID,
	}), nil
}

// pending resolves the sso_only session behind the caller's bearer.
//
// The guard already resolved and validated it; this rebuilds the record from
// what the guard put in the context rather than reading the header again,
// because a handler that re-parsed the bearer could act on a different session
// from the one that was authenticated.
func (s *Service) pending(ctx context.Context) (app.SessionRecord, error) {
	actor, ok := ActorFrom(ctx)
	if !ok {
		return app.SessionRecord{}, connect.NewError(connect.CodeUnauthenticated, app.ErrSessionRefused)
	}
	return app.SessionRecord{
		SessionID:  actor.SessionID,
		OperatorID: actor.OperatorID,
		SubjectID:  actor.SubjectID,
		Role:       actor.Role,
		Stage:      app.StageSSOOnly,
	}, nil
}

func customerToWire(c app.Customer) *operatorv1.Customer {
	return &operatorv1.Customer{
		OrgId:              c.OrgID,
		OrgName:            c.OrgName,
		Slug:               c.Slug,
		LifecycleState:     c.LifecycleState,
		PlanId:             c.PlanID,
		PlanVersionId:      c.PlanVersionID,
		SubscriptionStatus: c.SubscriptionStatus,
		TrialEndsAt:        stamp(c.TrialEndsAt),
		WorkspaceCount:     c.WorkspaceCount,
		MemberCount:        c.MemberCount,
		LastActiveAt:       stamp(c.LastActiveAt),
		SignupSource:       c.SignupSource,
		SuspendedAt:        stamp(c.SuspendedAt),
		SuspensionReason:   c.SuspensionReason,
		OwnerSubjectId:     c.OwnerSubjectID,
		CreatedAt:          timestamppb.New(c.CreatedAt),
	}
}

func stamp(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

// wire maps a use-case error to a Connect code.
//
// # Every sign-in failure is one code and one message
//
// ErrNotAnOperator and ErrCeremonyRefused both become Unauthenticated with the
// text the error already carries, which says nothing about which check failed.
// That is the same rule the WebAuthn adapter states for its own single error:
// telling a caller which check failed tells an attacker which one to work on —
// and here it would additionally answer "does this colleague have back-office
// access", which is a question about our staff.
//
// The DIAGNOSIS is not lost, it is moved: every branch logs its own cause
// server-side with the operator or the ceremony named, so the person debugging
// has more than the caller does. That asymmetry is the point, and it is the
// property this repository has had to restore five times in flows that were
// opaque to the caller AND to us.
func wire(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, app.ErrNotAnOperator), errors.Is(err, app.ErrCeremonyRefused),
		errors.Is(err, app.ErrSessionRefused):
		return connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, app.ErrForbidden):
		return connect.NewError(connect.CodePermissionDenied, err)

	// A refused break-glass explains itself, which nothing else here does. The
	// caller is an authenticated operator asking for a privilege, and telling
	// them their role cannot reach it is how they learn to ask a human rather
	// than retry — see ErrElevationRefused for why that is safe here and not
	// elsewhere.
	case errors.Is(err, app.ErrElevationRefused):
		return connect.NewError(connect.CodePermissionDenied, err)

	case errors.Is(err, app.ErrElevationInProgress):
		// FailedPrecondition, not AlreadyExists: the caller's request was
		// well-formed and the state refuses it, which is exactly what the code
		// means — and a client can tell "wait for the window to close" from
		// "you may never do this".
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, app.ErrNoSuchCustomer):
		return connect.NewError(connect.CodeNotFound, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

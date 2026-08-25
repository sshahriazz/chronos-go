package api

import (
	"context"

	connect "connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/errs"
)

// federationSuffix namespaces the session events a federated sign-in appends.
//
// Both the link and the session derive their event ids from one idempotency key,
// so without a suffix the two would collide — the same defect the passkey and
// email-change flows namespace around.
const federationSuffix = ":federated"

// unconfiguredFederation is what every federation RPC answers when no provider
// is wired.
//
// NOT_FOUND naming the variables to set, rather than a generic error: a
// deployment with no provider is a supported state, and the person reading this
// is an operator who needs to know which configuration is missing — not a
// caller, who learns only that the endpoint is not served here.
func unconfiguredFederation() error {
	return errs.NotFoundf("federated sign-in is not configured on this deployment; set " +
		"IDENTITY_FEDERATION_PROVIDERS and the client credentials for each provider")
}

// ListFederatedProviders names what this deployment supports.
//
// Answers an empty list rather than an error when nothing is configured: the
// question is "what can I offer the user", and "nothing" is a valid answer a
// client can render. It is the one federation RPC that does not refuse.
func (s *Service) ListFederatedProviders(
	_ context.Context, _ *connect.Request[identityv1.ListFederatedProvidersRequest],
) (*connect.Response[identityv1.ListFederatedProvidersResponse], error) {
	var names []string
	if s.federation != nil {
		names = s.federation.Providers()
	}
	return connect.NewResponse(&identityv1.ListFederatedProvidersResponse{Providers: names}), nil
}

// BeginFederatedSignIn starts a provider ceremony for an unauthenticated caller.
func (s *Service) BeginFederatedSignIn(
	ctx context.Context, req *connect.Request[identityv1.BeginFederatedSignInRequest],
) (*connect.Response[identityv1.BeginFederatedSignInResponse], error) {
	if s.federation == nil {
		return nil, fail(unconfiguredFederation())
	}
	got, err := s.federation.Begin(ctx, app.BeginFederatedCommand{
		Provider: req.Msg.GetProvider(),
		// No subject: this is a SIGN-IN, and the ceremony's purpose is bound to
		// that. A link ceremony cannot be answered here and vice versa.
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.BeginFederatedSignInResponse{
		AuthorizationUrl: got.AuthorizationURL,
		ExpiresAt:        timestamppb.New(got.ExpiresAt.UTC()),
	}), nil
}

// FinishFederatedSignIn redeems the callback and mints a session when §7 allows.
//
// # A refused auto-link is a 200
//
// identity.md §7 rule 2: a genuine sign-in that cannot be linked creates no
// link, and the person authenticates with an existing method and links
// explicitly. That is an OUTCOME, not a failure — answering it as an error would
// make a client show "sign-in failed" for a flow that worked exactly as designed
// and whose next step is a different screen.
func (s *Service) FinishFederatedSignIn(
	ctx context.Context, req *connect.Request[identityv1.FinishFederatedSignInRequest],
) (*connect.Response[identityv1.FinishFederatedSignInResponse], error) {
	if s.federation == nil {
		return nil, fail(unconfiguredFederation())
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}

	attempt, err := s.federation.FinishLogin(ctx, app.FinishFederatedLoginCommand{
		Provider:       req.Msg.GetProvider(),
		Code:           req.Msg.GetCode(),
		State:          req.Msg.GetState(),
		Issuer:         req.Msg.GetIss(),
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}
	if attempt.LinkRefused {
		// No session, and no error. See the doc comment.
		return connect.NewResponse(&identityv1.FinishFederatedSignInResponse{
			LinkRefused:   true,
			AccountExists: attempt.AccountExists,
		}), nil
	}

	session, err := s.authn.CreateSession(ctx, app.CreateSessionCommand{
		Proof:          attempt.Proof,
		IdempotencyKey: key + federationSuffix,
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.FinishFederatedSignInResponse{
		Token:          session.Token,
		SessionId:      session.SessionID.String(),
		AssuranceLevel: protoAAL(session.AAL),
		ExpiresAt:      timestamppb.New(session.IdleExpiresAt.UTC()),
	}), nil
}

// BeginFederatedLink starts attaching a provider to the caller's own account.
func (s *Service) BeginFederatedLink(
	ctx context.Context, req *connect.Request[identityv1.BeginFederatedLinkRequest],
) (*connect.Response[identityv1.BeginFederatedLinkResponse], error) {
	if s.federation == nil {
		return nil, fail(unconfiguredFederation())
	}
	subject, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	got, err := s.federation.Begin(ctx, app.BeginFederatedCommand{
		Provider: req.Msg.GetProvider(),
		// The subject is what makes this a LINK ceremony. It is bound into the
		// stored purpose, so the callback can only be answered by the link
		// handler and only for this account.
		SubjectID: subject,
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.BeginFederatedLinkResponse{
		AuthorizationUrl: got.AuthorizationURL,
		ExpiresAt:        timestamppb.New(got.ExpiresAt.UTC()),
	}), nil
}

// FinishFederatedLink completes the link.
func (s *Service) FinishFederatedLink(
	ctx context.Context, req *connect.Request[identityv1.FinishFederatedLinkRequest],
) (*connect.Response[identityv1.FinishFederatedLinkResponse], error) {
	if s.federation == nil {
		return nil, fail(unconfiguredFederation())
	}
	subject, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	if err := s.federation.FinishLink(ctx, app.FinishFederatedLinkCommand{
		SubjectID:      subject,
		Provider:       req.Msg.GetProvider(),
		Code:           req.Msg.GetCode(),
		State:          req.Msg.GetState(),
		Issuer:         req.Msg.GetIss(),
		IdempotencyKey: key,
	}); err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.FinishFederatedLinkResponse{}), nil
}

// UnlinkFederatedIdentity removes a provider from the caller's account.
func (s *Service) UnlinkFederatedIdentity(
	ctx context.Context, req *connect.Request[identityv1.UnlinkFederatedIdentityRequest],
) (*connect.Response[identityv1.UnlinkFederatedIdentityResponse], error) {
	if s.federation == nil {
		return nil, fail(unconfiguredFederation())
	}
	subject, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	if err := s.federation.Unlink(ctx, app.UnlinkFederatedCommand{
		SubjectID:       subject,
		Issuer:          req.Msg.GetIssuer(),
		ProviderSubject: req.Msg.GetProviderSubject(),
		IdempotencyKey:  key,
	}); err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.UnlinkFederatedIdentityResponse{}), nil
}

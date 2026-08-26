package api

import (
	"context"
	"time"

	"connectrpc.com/connect"
	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/page"
)

// callerOrg reads the organization gate 1 resolved.
//
// From the TENANT SCOPE and never from the request. The scope is written by
// `organization/api.OrgResolver`, which verifies the caller's membership of
// whichever organization the request named rather than trusting the header — so
// an org obtained here has already been checked, and one taken from a request
// field would not have been.
//
// It is also the same value every query in the request runs under `SET LOCAL
// app.org_id`, so the organization a handler writes into an event and the
// organization row-level security scopes its reads by cannot disagree. A second
// copy anywhere would be a second thing to keep in step.
//
// An absent scope is INTERNAL rather than a refusal aimed at the caller: these
// methods are org-scoped, so the pipeline cannot have reached a handler without
// gate 1 having run. Reaching this branch means the gate was skipped, which is
// our misconfiguration and must look like one.
func callerOrg(ctx context.Context) (string, error) {
	tenant, err := db.RequireTenant(ctx)
	if err != nil {
		return "", errs.Internalf(
			"an organization-scoped handler ran with no tenant scope; gate 1 resolved none").
			Wrap(err)
	}
	if tenant.OrgID == "" {
		return "", errs.Internalf(
			"an organization-scoped handler ran with an empty organization in scope")
	}
	return tenant.OrgID, nil
}

// CreateServiceAccount opens a non-human principal in the caller's organization.
//
// The organization comes from the resolved scope and the actor from the session;
// the only thing the request supplies is the name. That is the whole of what a
// caller may choose here, and it is deliberate — every other input is a fact
// about who is calling and where, and a request field for either would be a
// field an attacker gets to set.
func (s *Service) CreateServiceAccount(
	ctx context.Context, req *connect.Request[identityv1.CreateServiceAccountRequest],
) (*connect.Response[identityv1.CreateServiceAccountResponse], error) {
	if s.apiKeys == nil {
		return nil, fail(unconfiguredAPIKeys())
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	orgID, err := callerOrg(ctx)
	if err != nil {
		return nil, fail(err)
	}

	result, err := s.apiKeys.CreateServiceAccount(ctx, app.CreateServiceAccountCommand{
		OrgID:          orgID,
		ActorID:        subjectID,
		Name:           req.Msg.GetName(),
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.CreateServiceAccountResponse{
		ServiceAccountId: result.ServiceAccountID.String(),
		Name:             req.Msg.GetName(),
		CreatedAt:        protoTime(result.ServiceAccountID.Time()),
	}), nil
}

// ListServiceAccounts shows the organization's non-human principals.
func (s *Service) ListServiceAccounts(
	ctx context.Context, req *connect.Request[identityv1.ListServiceAccountsRequest],
) (*connect.Response[identityv1.ListServiceAccountsResponse], error) {
	orgID, err := callerOrg(ctx)
	if err != nil {
		return nil, fail(err)
	}
	result, err := s.queries.ListServiceAccounts(
		ctx, orgID, page.Token(req.Msg.GetPageToken()), int(req.Msg.GetPageSize()))
	if err != nil {
		return nil, fail(err)
	}

	accounts := make([]*identityv1.ServiceAccount, 0, len(result.Items))
	for _, item := range result.Items {
		accounts = append(accounts, &identityv1.ServiceAccount{
			ServiceAccountId: item.ID.String(),
			Name:             item.Name,
			CreatedBy:        item.CreatedBy,
			CreatedAt:        protoTime(item.CreatedAt),
		})
	}
	return connect.NewResponse(&identityv1.ListServiceAccountsResponse{
		ServiceAccounts: accounts,
		NextPageToken:   string(result.Next),
	}), nil
}

// CreateApiKey mints a machine credential and returns it exactly once.
//
// # The owner is either a named service account or the caller, and nothing else
//
// The request carries a `service_account_id` and no user field. Absent means the
// key is a personal access token owned by the CALLER, resolved from the session.
// There is deliberately no way to name somebody else as the owner: an admin able
// to do so could mint a credential that acts as a colleague, which is
// impersonation with an audit trail saying the colleague did it.
//
// The receiver name is `CreateApiKey` and not `CreateAPIKey` because it has to
// satisfy the generated `identityv1connect.IdentityServiceHandler`, which spells
// it from the RPC. The app layer below uses the Go spelling.
func (s *Service) CreateApiKey(
	ctx context.Context, req *connect.Request[identityv1.CreateApiKeyRequest],
) (*connect.Response[identityv1.CreateApiKeyResponse], error) {
	if s.apiKeys == nil {
		return nil, fail(unconfiguredAPIKeys())
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	orgID, err := callerOrg(ctx)
	if err != nil {
		return nil, fail(err)
	}

	owner := domain.UserOwner(subjectID)
	if raw := req.Msg.GetServiceAccountId(); raw != "" {
		accountID, parseErr := ids.Parse[ids.ServiceAccount](raw)
		if parseErr != nil {
			// NotFound rather than InvalidArgument, so a malformed id and a
			// well-formed id for somebody else's service account are the same
			// answer. protovalidate has already refused anything that is not a
			// `svc_` ULID, so this is a guard against a handler invoked without
			// the interceptor.
			return nil, fail(errs.NotFoundf("no such service account"))
		}
		owner = domain.ServiceAccountOwner(accountID)
	}

	result, err := s.apiKeys.CreateAPIKey(ctx, app.CreateAPIKeyCommand{
		OrgID:          orgID,
		ActorID:        subjectID,
		Owner:          owner,
		Scopes:         req.Msg.GetScopes(),
		Lifetime:       seconds(req.Msg.GetLifetimeSeconds()),
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.CreateApiKeyResponse{
		KeyId: result.KeyID.String(),
		// The one moment the token exists anywhere this system can reach. This
		// package logs nothing at all, which is the cheapest way to guarantee it
		// reaches no log line.
		Token:     result.Token,
		OwnerKind: protoOwnerKind(result.Owner.Kind),
		OwnerId:   result.Owner.ID,
		Scopes:    result.Scopes,
		ExpiresAt: protoTime(result.ExpiresAt),
	}), nil
}

// RotateApiKey replaces a key's secret without replacing the key.
//
// Named from the generated handler interface — see CreateApiKey.
func (s *Service) RotateApiKey(
	ctx context.Context, req *connect.Request[identityv1.RotateApiKeyRequest],
) (*connect.Response[identityv1.RotateApiKeyResponse], error) {
	if s.apiKeys == nil {
		return nil, fail(unconfiguredAPIKeys())
	}
	idem, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	orgID, err := callerOrg(ctx)
	if err != nil {
		return nil, fail(err)
	}
	keyID, err := ids.Parse[ids.APIKey](req.Msg.GetKeyId())
	if err != nil {
		return nil, fail(errs.NotFoundf("no such API key"))
	}

	result, err := s.apiKeys.RotateAPIKey(ctx, app.RotateAPIKeyCommand{
		OrgID:   orgID,
		ActorID: subjectID,
		KeyID:   keyID,
		Overlap: seconds(req.Msg.GetOverlapSeconds()),
		// Passed through rather than collapsed into a zero overlap here: the app
		// layer is where "the caller said nothing" and "the caller said
		// immediately" are told apart, and they have opposite consequences.
		Immediate:      req.Msg.GetImmediate(),
		Lifetime:       seconds(req.Msg.GetLifetimeSeconds()),
		IdempotencyKey: idem,
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.RotateApiKeyResponse{
		Token:             result.Token,
		PreviousRetiresAt: protoTime(result.PreviousRetiresAt),
		ExpiresAt:         protoTime(result.ExpiresAt),
	}), nil
}

// RevokeApiKey ends a key and destroys every secret it ever had.
//
// Named from the generated handler interface — see CreateApiKey.
func (s *Service) RevokeApiKey(
	ctx context.Context, req *connect.Request[identityv1.RevokeApiKeyRequest],
) (*connect.Response[identityv1.RevokeApiKeyResponse], error) {
	if s.apiKeys == nil {
		return nil, fail(unconfiguredAPIKeys())
	}
	idem, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	orgID, err := callerOrg(ctx)
	if err != nil {
		return nil, fail(err)
	}
	keyID, err := ids.Parse[ids.APIKey](req.Msg.GetKeyId())
	if err != nil {
		return nil, fail(errs.NotFoundf("no such API key"))
	}

	result, err := s.apiKeys.RevokeAPIKey(ctx, app.RevokeAPIKeyCommand{
		OrgID:          orgID,
		ActorID:        subjectID,
		KeyID:          keyID,
		Reason:         req.Msg.GetReason(),
		IdempotencyKey: idem,
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.RevokeApiKeyResponse{
		Changed:          result.Changed,
		SecretsDestroyed: wireCount(result.SecretsDestroyed),
	}), nil
}

// ListApiKeys shows the organization's machine credentials, revoked ones
// included.
//
// Named from the generated handler interface — see CreateApiKey.
func (s *Service) ListApiKeys(
	ctx context.Context, req *connect.Request[identityv1.ListApiKeysRequest],
) (*connect.Response[identityv1.ListApiKeysResponse], error) {
	orgID, err := callerOrg(ctx)
	if err != nil {
		return nil, fail(err)
	}
	result, err := s.queries.ListAPIKeys(
		ctx, orgID, page.Token(req.Msg.GetPageToken()), int(req.Msg.GetPageSize()))
	if err != nil {
		return nil, fail(err)
	}

	keys := make([]*identityv1.ApiKey, 0, len(result.Items))
	for _, item := range result.Items {
		keys = append(keys, &identityv1.ApiKey{
			KeyId:     item.ID.String(),
			OwnerKind: protoOwnerKind(contract.OwnerKind(item.OwnerKind)),
			OwnerId:   item.OwnerID,
			Scopes:    item.Scopes,
			ExpiresAt: protoTime(item.ExpiresAt),
			// optionalTime, not protoTime: these three are zero when the thing has
			// not happened, and a zero timestamp rendered as 0001-01-01 is a
			// rendering bug wearing a date.
			RevokedAt:  optionalTime(item.RevokedAt),
			RotatedAt:  optionalTime(item.RotatedAt),
			LastUsedAt: optionalTime(item.LastUsedAt),
			CreatedBy:  item.CreatedBy,
			CreatedAt:  protoTime(item.CreatedAt),
		})
	}
	return connect.NewResponse(&identityv1.ListApiKeysResponse{
		ApiKeys:       keys,
		NextPageToken: string(result.Next),
	}), nil
}

// protoOwnerKind renders the stored owner kind onto the wire enum.
//
// An explicit switch over the contract's constants, not a lookup with a
// fall-through to USER. A row written by a newer build carrying a kind this one
// does not recognise must render as UNSPECIFIED — which a client displays as
// "unknown" — rather than as `user`, because "unknown principal" and "a person"
// are very different things to read off a credential screen, and only one of
// them is honest about what this build knows.
func protoOwnerKind(kind contract.OwnerKind) identityv1.ApiKeyOwnerKind {
	switch kind {
	case contract.OwnerUser:
		return identityv1.ApiKeyOwnerKind_API_KEY_OWNER_KIND_USER
	case contract.OwnerServiceAccount:
		return identityv1.ApiKeyOwnerKind_API_KEY_OWNER_KIND_SERVICE_ACCOUNT
	default:
		return identityv1.ApiKeyOwnerKind_API_KEY_OWNER_KIND_UNSPECIFIED
	}
}

// unconfiguredAPIKeys is what the four key RPCs answer on a deployment that has
// not named its token environment.
//
// The environment segment cannot be defaulted, for the reason the WebAuthn
// relying-party id cannot: a default would be the SAME in staging and in
// production, and the whole purpose of the segment is that a staging token
// hashes to a value production's table does not contain. A defaulted one would
// silently remove that separation on every deployment nobody configured.
//
// So an unconfigured deployment serves these RPCs with this error rather than
// refusing to start, exactly as passkeys do — and it names the variable, because
// the only person who can act on it is whoever configures the deployment.
//
// NOT_FOUND rather than a new reason, for `unconfigured`'s reason: the endpoint
// does not exist on this deployment, and adding a catalogue entry for a
// configuration state would make "API keys are off here" a documented part of
// the API's error surface rather than a property of one installation.
func unconfiguredAPIKeys() error {
	return errs.NotFoundf("API keys are not configured on this deployment; set " +
		"IDENTITY_API_KEY_ENVIRONMENT")
}

// seconds turns a wire duration into a Go one.
//
// A NEGATIVE value becomes zero rather than a negative duration. protovalidate
// already refuses one with `gte: 0`, so this is a guard against a handler
// invoked without the interceptor — and zero is the safe reading, because it
// means "the server's default" while a negative duration would mean a deadline
// in the past, which the aggregate would refuse with a message nobody could
// explain.
func seconds(n int64) time.Duration {
	if n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

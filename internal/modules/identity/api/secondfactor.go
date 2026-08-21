package api

import (
	"context"

	"connectrpc.com/connect"
	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
)

// The three RPCs in this file all mint a secret and return it exactly once. Each
// one copies that secret from the app result directly into the response and does
// nothing else with it: no log line, no error message, no second response. There
// is deliberately no endpoint anywhere that re-displays any of them — one that did
// would turn a stolen session into a permanent bypass of every factor on the
// account.
//
// All three act on the CALLER'S account, resolved through Service.callerUser. None
// of their request messages carries an account identifier.

// EnrollTotp provisions a new authenticator secret and returns it once.
//
// `account_name` comes from the request and is the one piece of personal data
// these calls handle. It is supplied by the caller rather than read server-side
// because the vault port is write-only by design — a port that could read is a
// port through which an address reaches a log — and it travels no further than the
// provisioning URI rendered onto the enrolling user's own screen.
func (s *Service) EnrollTotp(
	ctx context.Context, req *connect.Request[identityv1.EnrollTotpRequest],
) (*connect.Response[identityv1.EnrollTotpResponse], error) {
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	userID, err := s.callerUser(ctx)
	if err != nil {
		return nil, fail(err)
	}
	// The authenticator label is NOT taken from the request. The server derives it
	// from the account's own public handle (ADR-051) — see EnrollTotp. The wire
	// field is reserved rather than read.
	result, err := s.secondFactor.EnrollTotp(ctx, app.EnrollTotpCommand{
		UserID:         userID,
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}
	// Secret and URI are returned here and are then unrecoverable. The URI CONTAINS
	// the secret, so both carry the same handling rule.
	return connect.NewResponse(&identityv1.EnrollTotpResponse{
		CredentialId:    result.CredentialID.String(),
		Secret:          result.Secret,
		ProvisioningUri: result.URI,
		ExpiresAt:       protoTime(result.ExpiresAt),
	}), nil
}

// ConfirmTotp proves possession of a provisioned secret, and may be what activates
// the account.
//
// Every failure looks the same from outside — a wrong code, an account with no
// enrolment, a secret that will not open and a code already spent are one refusal,
// decided in `app`. This handler adds no branch that could tell them apart.
func (s *Service) ConfirmTotp(
	ctx context.Context, req *connect.Request[identityv1.ConfirmTotpRequest],
) (*connect.Response[identityv1.ConfirmTotpResponse], error) {
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	userID, err := s.callerUser(ctx)
	if err != nil {
		return nil, fail(err)
	}
	result, err := s.secondFactor.ConfirmTotp(ctx, app.ConfirmTotpCommand{
		UserID:         userID,
		Code:           req.Msg.GetCode(),
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.ConfirmTotpResponse{
		CredentialId: result.CredentialID.String(),
		Activated:    result.Activated,
		Changed:      result.Changed,
	}), nil
}

// GenerateRecoveryCodes replaces the whole set and returns the new plaintext codes
// once.
//
// `count` goes through unchanged, zero included: zero means "the server's
// default", and both bounds are the app layer's to enforce. Substituting a default
// here would put the number in two places, and the two would eventually disagree
// about how many codes a user was told to write down.
//
// The result carries no `activated` flag, and there is no wire field for one. A
// recovery-code set is recorded as a method whose strength is below every real
// factor, so generating codes never completes a pending account — which is the
// rule that stops "you must enrol a second factor" being answered with a printout.
func (s *Service) GenerateRecoveryCodes(
	ctx context.Context, req *connect.Request[identityv1.GenerateRecoveryCodesRequest],
) (*connect.Response[identityv1.GenerateRecoveryCodesResponse], error) {
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	userID, err := s.callerUser(ctx)
	if err != nil {
		return nil, fail(err)
	}
	result, err := s.secondFactor.GenerateRecoveryCodes(ctx, app.GenerateRecoveryCodesCommand{
		UserID:         userID,
		Count:          int(req.Msg.GetCount()),
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}
	// Plaintext, shown once. Only digests are stored, so this is the only moment
	// the codes exist anywhere this system can reach.
	return connect.NewResponse(&identityv1.GenerateRecoveryCodesResponse{
		CredentialId: result.CredentialID.String(),
		Codes:        result.Codes,
	}), nil
}

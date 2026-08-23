package api

import (
	"context"

	"connectrpc.com/connect"
	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The two lifecycle writes. Both act on the CALLER'S OWN account and neither
// request message carries an identifier for it — the account comes from
// `callerSubject`, which reads a value only the authn gate can write.
//
// There is deliberately no ReactivateAccount handler and no SuspendAccount
// handler. The reasons are in app.Lifecycle's doc comment and in the proto, and
// they are the same reason stated from two ends: reactivation cannot be a call
// that needs a session, and suspension is not the holder's to perform.

// DeactivateAccount switches the caller's own account off.
//
// The response is built from the app result and nothing else. In particular the
// bearer token that made this call is now revoked — a deactivation spares no
// session, its own caller's included — and this layer does not soften that by
// returning anything the client could mistake for a still-valid session.
func (s *Service) DeactivateAccount(
	ctx context.Context, req *connect.Request[identityv1.DeactivateAccountRequest],
) (*connect.Response[identityv1.DeactivateAccountResponse], error) {
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	result, err := s.lifecycle.Deactivate(ctx, app.DeactivateAccountCommand{
		SubjectID:      subjectID,
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.DeactivateAccountResponse{
		Changed: result.Changed,
		//nolint:gosec // a session count cannot exceed what a work list returned
		SessionsRevoked: int32(result.SessionsRevoked),
		//nolint:gosec // likewise
		SessionsScanned: int32(result.SessionsScanned),
	}), nil
}

// RequestAccountDeletion records the caller's request to have the account erased.
//
// The `confirmation` field is NOT read here. protovalidate has already refused
// every value but the exact literal, as an interceptor, before this handler ran
// (ADR-007) — re-checking it in Go would be a second definition of the rule, and
// two definitions of a rule disagree eventually. The field is not passed to the
// app layer for the same reason: a confirmation is a property of the request, and
// the command carries decisions rather than form fields.
func (s *Service) RequestAccountDeletion(
	ctx context.Context, req *connect.Request[identityv1.RequestAccountDeletionRequest],
) (*connect.Response[identityv1.RequestAccountDeletionResponse], error) {
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	result, err := s.lifecycle.RequestDeletion(ctx, app.RequestAccountDeletionCommand{
		SubjectID:      subjectID,
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.RequestAccountDeletionResponse{
		Changed:      result.Changed,
		ScheduledFor: timestamppb.New(result.ScheduledFor.UTC()),
	}), nil
}

// CancelAccountDeletion withdraws the caller's own outstanding erasure request.
//
// The subject comes from the CONTEXT and never from the request — there is no
// field for one, and there must not be: a request that could name an account is
// a request to cancel somebody else's decision.
//
// Cancelling nothing returns `changed: false` and no error. That is the shape
// the cancel link in the "deletion scheduled" mail needs: clicked twice, or
// after an operator already withdrew the request, and neither person is told
// they did something wrong.
func (s *Service) CancelAccountDeletion(
	ctx context.Context, req *connect.Request[identityv1.CancelAccountDeletionRequest],
) (*connect.Response[identityv1.CancelAccountDeletionResponse], error) {
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	result, err := s.lifecycle.CancelDeletion(ctx, app.CancelAccountDeletionCommand{
		SubjectID:      subjectID,
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.CancelAccountDeletionResponse{
		Changed: result.Changed,
	}), nil
}

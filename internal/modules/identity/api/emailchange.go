package api

import (
	"context"

	connect "connectrpc.com/connect"

	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
)

// RequestEmailChange starts a move to a different address (identity.md §12).
//
// # Nothing comes back, and that is a security decision
//
// The app layer knows whether the address was free, already claimed by another
// account, or the one this account already holds. All three produce these zero
// bytes, and the wire message has no field for the difference.
//
// The reason is the reason every other refusal in this module is flattened: an
// authenticated caller who could tell "claimed" from "free" could walk a list of
// addresses and learn which have accounts, one request at a time. Being signed
// in does not entitle somebody to that — the account they are signed in to is
// their own, and every other address belongs to a stranger.
//
// The one refusal that IS specific is "that is already this account's address",
// because it discloses only the caller's own state to the caller.
func (s *Service) RequestEmailChange(
	ctx context.Context, req *connect.Request[identityv1.RequestEmailChangeRequest],
) (*connect.Response[identityv1.RequestEmailChangeResponse], error) {
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	if err := s.emails.Request(ctx, app.RequestEmailChangeCommand{
		SubjectID:      subjectID,
		NewEmail:       req.Msg.GetNewEmail(),
		IdempotencyKey: key,
	}); err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.RequestEmailChangeResponse{}), nil
}

// CancelEmailChange calls off a pending change.
//
// The action the security warning tells somebody to take when a change they did
// not ask for is in flight. It releases the claim and voids the link already
// sitting in the new mailbox, so a change the holder refused cannot complete
// afterwards.
func (s *Service) CancelEmailChange(
	ctx context.Context, req *connect.Request[identityv1.CancelEmailChangeRequest],
) (*connect.Response[identityv1.CancelEmailChangeResponse], error) {
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	if err := s.emails.Cancel(ctx, app.CancelEmailChangeCommand{
		SubjectID:      subjectID,
		IdempotencyKey: key,
	}); err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.CancelEmailChangeResponse{}), nil
}

// ConfirmEmailChange redeems the link mailed to the new address.
//
// It grants NOTHING beyond the address move: no session is created and no bearer
// is returned. That is ResetPassword's rule and it applies here for the same
// reason — an attacker who can read the new mailbox must not be advanced one
// step towards a session by proving they can (ASVS 5.0 V6.4.3). The surest way
// not to hand back a session is to have nothing to put one in.
//
// The call also VOIDS every session on the account, including the one that asked
// for the change (identity.md §4.4), so the caller's next act is an ordinary
// CreateSession with the new address.
//
// Every unusable link — unknown, spent, expired, or naming a change that was
// cancelled — is one undifferentiated refusal produced by the app layer. There
// is no switch here, deliberately: a switch is how one answer becomes several
// distinguishable Connect codes (ADR-036).
func (s *Service) ConfirmEmailChange(
	ctx context.Context, req *connect.Request[identityv1.ConfirmEmailChangeRequest],
) (*connect.Response[identityv1.ConfirmEmailChangeResponse], error) {
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	if err := s.emails.Confirm(ctx, app.ConfirmEmailChangeCommand{
		Token:          req.Msg.GetToken(),
		IdempotencyKey: key,
	}); err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.ConfirmEmailChangeResponse{}), nil
}

// RevertEmailChange undoes a completed change.
//
// Reached from a link mailed to the address the account moved AWAY from, so
// whoever redeems it has proven control of the address the account had BEFORE
// the change. This is the remedy identity.md §12 asks for, and it is the one RPC
// in this file whose absence would be an unrecoverable account takeover rather
// than an inconvenience.
//
// Like the confirm, it grants nothing and returns nothing.
func (s *Service) RevertEmailChange(
	ctx context.Context, req *connect.Request[identityv1.RevertEmailChangeRequest],
) (*connect.Response[identityv1.RevertEmailChangeResponse], error) {
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	if err := s.emails.Revert(ctx, app.RevertEmailChangeCommand{
		Token:          req.Msg.GetToken(),
		IdempotencyKey: key,
	}); err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.RevertEmailChangeResponse{}), nil
}

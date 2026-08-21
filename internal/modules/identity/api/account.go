package api

import (
	"context"

	"connectrpc.com/connect"
	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/internal/platform/page"
)

// The four reads in this file are the account screen and the security-settings
// screen. Each one names its account with the CALLER'S pseudonym and with nothing
// from the request: none of the four request messages carries a subject id, and
// that is the schema's decision rather than this layer's convenience — a field
// naming the account would turn each of these into an existence probe for any
// pseudonym a caller can obtain.

// GetUser returns the caller's own account.
//
// No address comes back, by construction: the result type has no field for one.
// Whatever renders a human-readable identity resolves the pseudonym against the
// vault, which is what keeps erasure the destruction of a key rather than a sweep
// across every projection that ever copied an address (ADR-002).
func (s *Service) GetUser(
	ctx context.Context, _ *connect.Request[identityv1.GetUserRequest],
) (*connect.Response[identityv1.GetUserResponse], error) {
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	account, err := s.queries.GetUser(ctx, subjectID)
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.GetUserResponse{
		SubjectId:     account.SubjectID,
		UserId:        account.UserID.String(),
		State:         protoState(account.State),
		EmailVerified: account.EmailVerified,
		RegisteredAt:  protoTime(account.RegisteredAt),
		ActivatedAt:   protoTime(account.ActivatedAt),
		DeactivatedAt: protoTime(account.DeactivatedAt),
		SuspendedAt:   protoTime(account.SuspendedAt),

		// Reported, and reported as timestamps rather than as a state. An
		// outstanding deletion request changes nothing the account can do — nothing
		// consumes it yet — so folding it into `state` would make this screen
		// contradict every other endpoint, which will keep serving this account.
		DeletionRequestedAt:  protoTime(account.DeletionRequestedAt),
		DeletionScheduledFor: protoTime(account.DeletionScheduledFor),

		// The public handle, in the clear, and the ONE piece of personal data any
		// response in this package carries (ADR-051). It is returned for the same
		// reason the address is not: a handle is published by design, so the vault
		// cannot protect it and there is nothing for a pseudonym to stand in for.
		// Empty means the account has not claimed one yet, or that it was erased.
		Username: account.Username,
	}), nil
}

// ListSessions returns the caller's device list, newest first, one page at a time.
//
// The page token and page size go straight through to `app.Queries`, which owns
// the whole pagination contract: it clamps an oversized size, refuses a negative
// one, and treats an unusable token as an ERROR rather than as "start again". This
// layer must not soften any of those — a client handed page one for a token it
// believes points into the middle of a list walks that list forever, and nothing
// in the loop looks like a failure.
//
// The token is bound to the query it came from, and that binding includes the
// SUBJECT. So a device-list token is unusable against the activity list, and a
// token minted for one account is a decode failure against another, independently
// of the caller check above.
func (s *Service) ListSessions(
	ctx context.Context, req *connect.Request[identityv1.ListSessionsRequest],
) (*connect.Response[identityv1.ListSessionsResponse], error) {
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	result, err := s.queries.ListSessions(
		ctx, subjectID, page.Token(req.Msg.GetPageToken()), int(req.Msg.GetPageSize()))
	if err != nil {
		return nil, fail(err)
	}

	sessions := make([]*identityv1.Session, 0, len(result.Items))
	for _, item := range result.Items {
		sessions = append(sessions, &identityv1.Session{
			SessionId:         item.SessionID.String(),
			DeviceId:          item.DeviceID,
			AssuranceLevel:    protoAAL(item.AAL),
			IdleExpiresAt:     protoTime(item.IdleExpiresAt),
			AbsoluteExpiresAt: protoTime(item.AbsoluteExpiresAt),
			CreatedAt:         protoTime(item.CreatedAt),
			LastSeenAt:        protoTime(item.LastSeenAt),
		})
	}
	return connect.NewResponse(&identityv1.ListSessionsResponse{
		Sessions:      sessions,
		NextPageToken: string(result.Next),
	}), nil
}

// ListMethods returns the authentication methods on the caller's account.
//
// Unpaginated, because an account holds at most one usable credential per kind and
// there are five kinds.
//
// `usable` is computed by the aggregate and copied, never re-derived here. That is
// the reason app.AuthMethod embeds domain.Method rather than flattening it: a
// second definition of "can this factor be used now" eventually disagrees with the
// one the login enforces, and the disagreement shows up as a screen that hides a
// factor the login accepts.
func (s *Service) ListMethods(
	ctx context.Context, _ *connect.Request[identityv1.ListMethodsRequest],
) (*connect.Response[identityv1.ListMethodsResponse], error) {
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	found, err := s.queries.ListMethods(ctx, subjectID)
	if err != nil {
		return nil, fail(err)
	}

	methods := make([]*identityv1.AuthMethod, 0, len(found))
	for _, m := range found {
		methods = append(methods, &identityv1.AuthMethod{
			CredentialId: m.ID.String(),
			Kind:         protoMethodKind(m.Kind),
			Usable:       m.Usable(),
			AddedAt:      protoTime(m.AddedAt),
			EnabledAt:    protoTime(m.EnabledAt),
			LastUsedAt:   protoTime(m.LastUsedAt),
		})
	}
	return connect.NewResponse(&identityv1.ListMethodsResponse{Methods: methods}), nil
}

// ListLoginHistory returns recent authentication attempts against the caller's
// account, successes and failures alike, newest first.
//
// `LoginRecord.ID` is deliberately not rendered. It is a server-side sequence,
// global across every account, so its gaps would leak how much authentication
// traffic the whole system carries; it exists to make the page boundary correct
// and is folded into the opaque cursor instead.
func (s *Service) ListLoginHistory(
	ctx context.Context, req *connect.Request[identityv1.ListLoginHistoryRequest],
) (*connect.Response[identityv1.ListLoginHistoryResponse], error) {
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	result, err := s.queries.ListLoginHistory(
		ctx, subjectID, page.Token(req.Msg.GetPageToken()), int(req.Msg.GetPageSize()))
	if err != nil {
		return nil, fail(err)
	}

	attempts := make([]*identityv1.LoginAttempt, 0, len(result.Items))
	for _, r := range result.Items {
		attempts = append(attempts, &identityv1.LoginAttempt{
			Succeeded:      r.Succeeded,
			Reason:         protoFailureReason(r.Reason),
			Methods:        protoMethodKinds(r.Methods),
			AssuranceLevel: protoAAL(r.AAL),
			DeviceId:       r.DeviceID,
			OccurredAt:     protoTime(r.OccurredAt),
		})
	}
	return connect.NewResponse(&identityv1.ListLoginHistoryResponse{
		Attempts:      attempts,
		NextPageToken: string(result.Next),
	}), nil
}

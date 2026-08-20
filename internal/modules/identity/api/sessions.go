package api

import (
	"context"

	"connectrpc.com/connect"
	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// RevokeSession ends one of the caller's sessions.
//
// The session id names WHICH session; the caller's pseudonym decides WHOSE it must
// be, and it comes from the principal. The app layer checks the pair against the
// session's own stream and answers a session belonging to somebody else exactly as
// it answers one that does not exist — telling the two apart would turn a device
// list into a probe for which session ids exist.
//
// `ActorID` is left empty so the app layer defaults it to the subject. It differs
// only when an operator or a password reset revokes on the holder's behalf, and
// neither of those arrives through this RPC; setting it from anything a caller
// sent would let a request claim to be somebody else's action in the event log.
func (s *Service) RevokeSession(
	ctx context.Context, req *connect.Request[identityv1.RevokeSessionRequest],
) (*connect.Response[identityv1.RevokeSessionResponse], error) {
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	sessionID, err := ids.Parse[ids.Session](req.Msg.GetSessionId())
	if err != nil {
		// protovalidate has already refused anything that is not a `sess_` ULID, so
		// this is unreachable through the pipeline and is a guard against a handler
		// invoked without it. NotFound rather than InvalidArgument, so the two paths
		// agree: a well-formed id for a session that is not the caller's is a
		// NotFound from the app layer, and a malformed one must not be
		// distinguishable from it here.
		return nil, fail(errs.NotFoundf("no such session"))
	}

	result, err := s.authn.RevokeSession(ctx, app.RevokeSessionCommand{
		SessionID:      sessionID,
		SubjectID:      subjectID,
		Reason:         req.Msg.GetReason(),
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.RevokeSessionResponse{
		Changed: result.Changed,
	}), nil
}

// RevokeAllSessions ends every live session on the caller's account, in one atomic
// append.
//
// `except_session_id` is OPTIONAL and empty is meaningful: it spares nothing, which
// is what a compromise response needs — a password reset must void every session
// including the one that asked, because the party asking may be the attacker. An
// empty value therefore becomes the ZERO session id rather than an error, and the
// app layer reads a zero id as "spare nothing".
func (s *Service) RevokeAllSessions(
	ctx context.Context, req *connect.Request[identityv1.RevokeAllSessionsRequest],
) (*connect.Response[identityv1.RevokeAllSessionsResponse], error) {
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}

	var except ids.SessionID
	if raw := req.Msg.GetExceptSessionId(); raw != "" {
		except, err = ids.Parse[ids.Session](raw)
		if err != nil {
			return nil, fail(errs.NotFoundf("no such session"))
		}
	}

	result, err := s.authn.RevokeAllSessions(ctx, app.RevokeAllSessionsCommand{
		SubjectID:      subjectID,
		Except:         except,
		Reason:         req.Msg.GetReason(),
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.RevokeAllSessionsResponse{
		Revoked: wireCount(result.Revoked),
		Scanned: wireCount(result.Scanned),
	}), nil
}

// wireCount narrows a count from the app layer's int to the wire's int32.
//
// Saturating rather than truncating. Neither value can realistically approach the
// limit — they count the live sessions one account holds — but a plain conversion
// turns any value that did into a NEGATIVE count, and "sign out everywhere ended
// -2 sessions" is a worse answer than a capped one. The floor is here for the same
// reason: a count is never negative, and rendering one would be reporting a number
// the caller cannot act on.
func wireCount(n int) int32 {
	const maxInt32 = 1<<31 - 1
	switch {
	case n < 0:
		return 0
	case n > maxInt32:
		return maxInt32
	default:
		return int32(n)
	}
}

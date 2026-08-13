package connect

import (
	"errors"

	"connectrpc.com/connect"
	errorsv1 "github.com/chronos/chronos-go/gen/proto/chronos/errors/v1"
	"github.com/chronos/chronos-go/internal/platform/errs"
)

// Error renders a domain error onto the wire.
//
// It lives HERE, not in the errs kernel, because the mapping is a transport
// concern: `errs` names what went wrong in terms the domain understands, and
// `connect.Code` is one of several possible renderings of that. A kernel that
// imported connectrpc would have let a transport dictate the shape of a business
// rule (CONVENTIONS §2).
//
// Everything outward-facing is opaque: reason plus stable metadata, never SQL,
// driver text or a stack trace. The unsafe detail stays in the wrapped error,
// which the interceptor logs against the trace id (ADR-015).
func Error(err error) error {
	if err == nil {
		return nil
	}
	var e *errs.Error
	if !errors.As(err, &e) {
		// An error that never passed through errs has not been through the
		// disclosure ladder, so nothing is known about what it is safe to say.
		// Internal, with no message.
		return connect.NewError(connect.CodeInternal, errors.New("internal error"))
	}

	wire := connect.NewError(codeFor(e.Reason), errors.New(e.Message))

	// The reason is part of the public API — clients branch on
	// PLAN_UPGRADE_REQUIRED versus ACCESS_DENIED to show completely different UI
	// (CONVENTIONS §5.1). Sent as a trailer rather than folded into the message,
	// so a client parses a field instead of a string.
	if detail, derr := connect.NewErrorDetail(&errorsv1.ErrorDetail{
		Reason:   string(e.Reason),
		Metadata: e.Meta,
	}); derr == nil {
		wire.AddDetail(detail)
	}
	return wire
}

// codeFor maps a reason to a transport code.
//
// NOT_FOUND is what every sub-authz failure collapses to, which is ADR-036's
// point: a caller who has not proven they belong learns nothing, and "forbidden"
// and "does not exist" must be indistinguishable to them.
func codeFor(r errs.Reason) connect.Code {
	switch r {
	case errs.Unauthenticated:
		return connect.CodeUnauthenticated
	case errs.StepUpRequired, errs.AccessDenied, errs.PlanUpgradeRequired, errs.OrgSuspended:
		// PermissionDenied, not FailedPrecondition: all four mean "you are known,
		// and the answer is still no". The distinction the client acts on is the
		// REASON, which travels in the detail above.
		return connect.CodePermissionDenied
	case errs.QuotaExceeded, errs.RateLimited:
		return connect.CodeResourceExhausted
	case errs.NotFound:
		return connect.CodeNotFound
	case errs.Conflict:
		return connect.CodeAlreadyExists
	case errs.ValidationFailed:
		return connect.CodeInvalidArgument
	case errs.Internal:
		return connect.CodeInternal
	default:
		// A reason with no mapping is a bug in this switch, and guessing would
		// hide it. Internal is the one code that is never actionable by a
		// client, so it cannot be mistaken for a deliberate answer.
		return connect.CodeInternal
	}
}

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
		// Internal, with no message — and the cause pinned to it, because this
		// is the line at which it would otherwise cease to exist.
		return &wireError{
			wire:  connect.NewError(connect.CodeInternal, errors.New("internal error")),
			cause: err,
		}
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

	// INTERNAL is the one code that tells the caller nothing, so it is the one
	// code whose cause has no other way out of this function. Carry it. Every
	// other code names its own failure, and a caller who can read the reason off
	// the wire does not need an operator to read it out of a log.
	if wire.Code() == connect.CodeInternal {
		return &wireError{wire: wire, cause: err}
	}
	return wire
}

// wireError couples the response a caller receives with the cause that produced
// it.
//
// It exists because of a real outage. A handler returned
// `fmt.Errorf("loading the account…: %w", err)`, Error mapped it — correctly —
// to a bare INTERNAL with no message and no detail, and the cause reached
// NOBODY: not the caller, by design, and not the operator, by accident. The
// total evidence for a completely broken slice was `internal: internal error` on
// the wire and silence in the log.
//
// Fixing that means the cause has to survive one more hop, from here to the
// boundary interceptor that has the procedure name and the request's trace. This
// type is that hop, and it is deliberately inert in every other respect:
//
//   - Error returns the WIRE text verbatim, so a code path that formats this
//     error instead of extracting the *connect.Error still discloses nothing.
//   - Unwrap exposes only the *connect.Error, which is what connect's own
//     asError walk needs. The cause is deliberately NOT on that chain: putting
//     it there would make every sentinel inside a handler's failure newly
//     visible to errors.Is at layers above, and the idempotency gate already
//     branches on sentinels it expects to come from its own store.
//
// The cause is read back through Cause, and only there.
type wireError struct {
	wire  *connect.Error
	cause error
}

func (e *wireError) Error() string { return e.wire.Error() }

// Unwrap yields the transport error, never the cause. See the type comment.
func (e *wireError) Unwrap() error { return e.wire }

// serverCause is how the cause is retrieved, and the method is unexported so
// that only this package can produce a value satisfying it. An exported
// `Cause() error` would be satisfied by half the error types in the ecosystem —
// github.com/pkg/errors named it that — and Cause below would then hand back
// something this package never classified.
func (e *wireError) serverCause() error { return e.cause }

// Cause returns the server-side cause of an error this package mapped to the
// wire, or nil when none was carried.
//
// Only errors mapped to INTERNAL carry one. A nil return means either that the
// error was mapped to a code that speaks for itself, or that it never came
// through Error at all — the second is worth recording on its own, and the
// caller of this function is the one that does it.
func Cause(err error) error {
	var c interface{ serverCause() error }
	if !errors.As(err, &c) {
		return nil
	}
	return c.serverCause()
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

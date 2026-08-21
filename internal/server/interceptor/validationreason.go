package interceptor

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	errorsv1 "github.com/chronos/chronos-go/gen/proto/chronos/errors/v1"

	"github.com/chronos/chronos-go/internal/platform/errs"
	srvconnect "github.com/chronos/chronos-go/internal/server/connect"
)

// NewValidationReason gives a protovalidate refusal the machine-readable reason
// every other refusal on this server carries.
//
// # Why this exists
//
// CONVENTIONS §5.1 and §7.1 are explicit that clients branch on the
// `chronos.errors.v1.ErrorDetail` reason and NEVER on the HTTP status or the
// message. Every refusal this server produces goes through `errs` and then
// through server/connect.Error, which is the only place that detail is attached.
//
// connectrpc.com/validate does not. It builds its own connect.Error directly, so
// a schema refusal arrived carrying `buf.validate.Violations` and nothing else —
// no reason at all. A client then sees a bare `invalid_argument` and cannot tell
// "your input broke a field rule, show the field errors" from "you forgot the
// Idempotency-Key", which is precisely the distinction §5's reason column exists
// to make. Found by internal/adapter/protocolit.
//
// # What it does, and what it deliberately does not
//
// It re-raises the refusal as errs.ValidationFailed so the standard detail is
// attached, and it CARRIES THE VIOLATIONS ACROSS. The violations are the useful
// half — they name the offending fields — and dropping them to gain a reason
// would trade one gap for another.
//
// It only touches errors that are already InvalidArgument and carry no reason of
// our own. An error that has been through `errs` is left exactly as it is: this
// must not rewrite a handler's considered refusal into a generic one, and a
// handler's ValidationFailed already has its own message and metadata.
//
// It wraps the validation interceptor rather than replacing it, because the
// rule-checking itself is correct — only its error shape is wrong.
func NewValidationReason() connect.Interceptor {
	return validationReason{}
}

type validationReason struct{}

func (validationReason) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		res, err := next(ctx, req)
		if err == nil {
			return res, nil
		}
		return res, reasonForValidation(err)
	}
}

// reasonForValidation rebuilds a reasonless InvalidArgument as a proper
// ValidationFailed, preserving whatever details it already carried.
func reasonForValidation(err error) error {
	var wire *connect.Error
	if !errors.As(err, &wire) {
		return err
	}
	if wire.Code() != connect.CodeInvalidArgument {
		return err
	}

	// Already ours? Leave it alone. srvconnect.Error attaches exactly one
	// ErrorDetail, so its presence is the signal that this error has been through
	// the disclosure ladder and had its message chosen deliberately.
	for _, d := range wire.Details() {
		// The full name of chronos.errors.v1.ErrorDetail, taken from the generated
		// descriptor rather than written as a literal so a rename cannot leave this
		// check silently matching nothing.
		if d.Type() == string((&errorsv1.ErrorDetail{}).ProtoReflect().Descriptor().FullName()) {
			return err
		}
	}

	rebuilt := srvconnect.Error(errs.ValidationFailedf("%s", wire.Message()))
	var out *connect.Error
	if !errors.As(rebuilt, &out) {
		// srvconnect.Error always produces a *connect.Error for a non-nil errs
		// error; if that ever stops being true, the original refusal is still the
		// correct answer and is returned unchanged rather than swallowed.
		return err
	}
	for _, d := range wire.Details() {
		out.AddDetail(d)
	}
	return out
}

func (validationReason) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler passes through: this server serves no streaming method,
// and the gate interceptor already refuses one outright.
func (validationReason) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

package connect_test

import (
	"errors"
	"fmt"
	"testing"

	connectrpc "connectrpc.com/connect"
	errorsv1 "github.com/chronos/chronos-go/gen/proto/chronos/errors/v1"
	"github.com/chronos/chronos-go/internal/platform/errs"
	srvconnect "github.com/chronos/chronos-go/internal/server/connect"
)

// What this file constrains is a pair of properties that pull against each
// other: the caller must learn NOTHING from an unclassified failure, and the
// server must lose nothing about it. Before Cause existed only the first half
// held, and the second half failed silently — which is the harder half to
// notice, because a discarded cause looks exactly like a system with no
// failures.

// The wire rendering is the contract, and it must not have moved. Every
// assertion here would have passed before this change and must keep passing
// after it.
func TestErrorRendersTheSameWireResponseAsBefore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		in          error
		wantCode    connectrpc.Code
		wantMessage string
		wantReason  string
	}{
		{
			name:        "an unclassified error discloses nothing at all",
			in:          fmt.Errorf("loading the account: %w", errors.New("connection refused")),
			wantCode:    connectrpc.CodeInternal,
			wantMessage: "internal error",
		},
		{
			name:        "a classified INTERNAL keeps its safe message",
			in:          errs.Internalf("the user directory is unavailable").Wrap(errors.New("boom")),
			wantCode:    connectrpc.CodeInternal,
			wantMessage: "the user directory is unavailable",
			wantReason:  string(errs.Internal),
		},
		{
			name:        "a classified refusal keeps its code and its reason",
			in:          errs.NotFoundf("no such session"),
			wantCode:    connectrpc.CodeNotFound,
			wantMessage: "no such session",
			wantReason:  string(errs.NotFound),
		},
		{
			name:        "an entitlement failure still reaches the client as its own reason",
			in:          errs.PlanUpgradeRequiredf("audit log is not on this plan"),
			wantCode:    connectrpc.CodePermissionDenied,
			wantMessage: "audit log is not on this plan",
			wantReason:  string(errs.PlanUpgradeRequired),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := srvconnect.Error(tt.in)

			if got := connectrpc.CodeOf(err); got != tt.wantCode {
				t.Errorf("code = %v, want %v", got, tt.wantCode)
			}

			var wire *connectrpc.Error
			if !errors.As(err, &wire) {
				t.Fatalf("the mapped error is not a *connect.Error: %v", err)
			}
			if wire.Message() != tt.wantMessage {
				t.Errorf("message = %q, want %q", wire.Message(), tt.wantMessage)
			}
			// Error() is what a fallback path would print. It must be the wire
			// text and nothing more, so that carrying the cause cannot become a
			// disclosure by accident.
			if got, want := err.Error(), tt.wantCode.String()+": "+tt.wantMessage; got != want {
				t.Errorf("Error() = %q, want %q", got, want)
			}

			gotReason := ""
			for _, d := range wire.Details() {
				value, verr := d.Value()
				if verr != nil {
					t.Fatalf("decoding a detail: %v", verr)
				}
				if detail, ok := value.(*errorsv1.ErrorDetail); ok {
					gotReason = detail.GetReason()
				}
			}
			if gotReason != tt.wantReason {
				t.Errorf("detail reason = %q, want %q", gotReason, tt.wantReason)
			}
		})
	}
}

// The cause survives the mapping for exactly the errors whose code says nothing.
func TestCauseIsCarriedOnlyWhereTheWireSaysNothing(t *testing.T) {
	t.Parallel()

	unclassified := fmt.Errorf("loading the account: %w", errors.New("connection refused"))
	classifiedInternal := errs.Internalf("idempotency is unavailable").Wrap(errors.New("no route to host"))
	refusal := errs.NotFoundf("no such session")

	tests := []struct {
		name     string
		in       error
		wantOK   bool
		wantText string
	}{
		{
			name:     "an unclassified error carries the whole chain",
			in:       unclassified,
			wantOK:   true,
			wantText: "loading the account: connection refused",
		},
		{
			name:     "a classified INTERNAL carries its wrapped cause",
			in:       classifiedInternal,
			wantOK:   true,
			wantText: "INTERNAL: idempotency is unavailable: no route to host",
		},
		{
			// Nothing to recover and nothing to log: the caller was told what
			// happened, so there is no operator evidence to preserve.
			name:   "a classified refusal carries nothing",
			in:     refusal,
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cause := srvconnect.Cause(srvconnect.Error(tt.in))
			if got := cause != nil; got != tt.wantOK {
				t.Fatalf("Cause present = %v, want %v (cause %v)", got, tt.wantOK, cause)
			}
			if !tt.wantOK {
				return
			}
			if cause.Error() != tt.wantText {
				t.Errorf("cause = %q, want %q", cause.Error(), tt.wantText)
			}
			// The identity of the original error is preserved, not a copy of its
			// text: whoever logs it can still classify it.
			if !errors.Is(cause, tt.in) {
				t.Errorf("cause %v is not the error that was mapped", cause)
			}
		})
	}
}

// Cause reports nothing for an error this package never mapped. That is the
// signal the boundary uses to say "this reached the wire through no mapping at
// all", which is a different defect from an unclassified one.
func TestCauseIsAbsentForAnErrorThisPackageNeverMapped(t *testing.T) {
	t.Parallel()

	for _, err := range []error{
		nil,
		errors.New("raw"),
		connectrpc.NewError(connectrpc.CodeInternal, errors.New("hand-rolled")),
	} {
		if cause := srvconnect.Cause(err); cause != nil {
			t.Errorf("Cause(%v) = %v, want nil", err, cause)
		}
	}
}

// The cause is deliberately NOT on the Unwrap chain.
//
// This is the property that keeps carrying it from changing anything else: the
// idempotency gate branches on sentinels with errors.Is, and a handler failure
// that happened to wrap one of them would be re-mapped by that gate if the
// sentinel became reachable from the returned error.
func TestTheCauseIsNotReachableByErrorsIs(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("a sentinel some gate branches on")
	mapped := srvconnect.Error(fmt.Errorf("handler failed: %w", sentinel))

	if errors.Is(mapped, sentinel) {
		t.Error("the cause is reachable by errors.Is; a gate above can now be misled by it")
	}
	if cause := srvconnect.Cause(mapped); !errors.Is(cause, sentinel) {
		t.Errorf("the cause is not retrievable through Cause: %v", cause)
	}
}

func TestErrorOfNilIsNil(t *testing.T) {
	t.Parallel()

	if err := srvconnect.Error(nil); err != nil {
		t.Errorf("Error(nil) = %v, want nil", err)
	}
}

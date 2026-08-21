package api_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// fieldNames lists a message's field names, from the descriptor.
func fieldNames(m proto.Message) []string {
	fields := m.ProtoReflect().Descriptor().Fields()
	out := make([]string, 0, fields.Len())
	for i := range fields.Len() {
		out = append(out, string(fields.Get(i).Name()))
	}
	return out
}

// Both lifecycle writes name the CALLER'S OWN account and nothing else.
//
// Neither request message has a field that could name an account, so this is
// really a check that the handler reads the principal rather than inventing a
// subject — but it is the assertion that would catch a later commit adding one.
func TestTheLifecycleWritesNameTheCallersOwnAccount(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	if _, err := h.client.DeactivateAccount(ctx,
		withKey(&identityv1.DeactivateAccountRequest{}, "idem-deactivate")); err != nil {
		t.Fatalf("DeactivateAccount: %v", err)
	}
	if _, err := h.client.RequestAccountDeletion(ctx,
		withKey(&identityv1.RequestAccountDeletionRequest{Confirmation: "DELETE"},
			"idem-delete")); err != nil {
		t.Fatalf("RequestAccountDeletion: %v", err)
	}

	if got := len(h.lifecycle.deactivateCmds); got != 1 {
		t.Fatalf("the app layer saw %d deactivations, want 1", got)
	}
	if got := h.lifecycle.deactivateCmds[0].SubjectID; got != callerSubject {
		t.Errorf("deactivation named %q, want the principal's %q", got, callerSubject)
	}
	if got := h.lifecycle.deactivateCmds[0].IdempotencyKey; got != "idem-deactivate" {
		t.Errorf("deactivation key = %q, want the header's", got)
	}

	if got := len(h.lifecycle.deletionCmds); got != 1 {
		t.Fatalf("the app layer saw %d deletion requests, want 1", got)
	}
	if got := h.lifecycle.deletionCmds[0].SubjectID; got != callerSubject {
		t.Errorf("deletion request named %q, want the principal's %q", got, callerSubject)
	}
}

// Neither request message carries anything that could name an account.
//
// Asserted against the DESCRIPTOR rather than against a rendered message: a
// value-level check passes for as long as nobody sets the field, while a field
// that could name an account is a field a later commit fills — and both of these
// RPCs are destructive.
func TestTheLifecycleRequestsCannotNameAnotherAccount(t *testing.T) {
	t.Parallel()

	forbidden := []string{"subject", "user", "account", "email", "identifier"}
	for _, tc := range []struct {
		name   string
		fields []string
	}{
		{"DeactivateAccountRequest", fieldNames(&identityv1.DeactivateAccountRequest{})},
		{"RequestAccountDeletionRequest", fieldNames(&identityv1.RequestAccountDeletionRequest{})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, f := range tc.fields {
				for _, bad := range forbidden {
					if strings.Contains(f, bad) {
						t.Errorf("%s carries the field %q; identity has no delegation "+
							"convention, so a field naming an account would let any "+
							"authenticated caller destroy any account whose pseudonym they "+
							"could obtain", tc.name, f)
					}
				}
			}
		})
	}
}

// The results map through unchanged, including the deadline.
func TestTheLifecycleResultsAreMappedOntoTheWire(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	due := time.Date(2026, 9, 19, 8, 15, 0, 0, time.UTC)

	h.lifecycle.deactivateFn = func(app.DeactivateAccountCommand) (app.DeactivateAccountResult, error) {
		return app.DeactivateAccountResult{Changed: true, SessionsRevoked: 2, SessionsScanned: 3}, nil
	}
	h.lifecycle.deletionFn = func(app.RequestAccountDeletionCommand) (app.RequestAccountDeletionResult, error) {
		return app.RequestAccountDeletionResult{Changed: true, ScheduledFor: due}, nil
	}

	deact, err := h.client.DeactivateAccount(context.Background(),
		withKey(&identityv1.DeactivateAccountRequest{}, "idem-1"))
	if err != nil {
		t.Fatalf("DeactivateAccount: %v", err)
	}
	if !deact.Msg.GetChanged() ||
		deact.Msg.GetSessionsRevoked() != 2 || deact.Msg.GetSessionsScanned() != 3 {
		t.Errorf("response = %+v, want changed=true revoked=2 scanned=3", deact.Msg)
	}

	del, err := h.client.RequestAccountDeletion(context.Background(),
		withKey(&identityv1.RequestAccountDeletionRequest{Confirmation: "DELETE"}, "idem-2"))
	if err != nil {
		t.Fatalf("RequestAccountDeletion: %v", err)
	}
	if !del.Msg.GetChanged() || !del.Msg.GetScheduledFor().AsTime().Equal(due) {
		t.Errorf("response = %+v, want changed=true scheduledFor=%s", del.Msg, due)
	}
}

// A missing idempotency key is refused BEFORE the app layer is reached.
//
// A key minted server-side would make every retry look like a new request, which
// is the exact failure the header exists to prevent — and on these two calls a
// "new request" is a second deactivation or a second deadline.
func TestTheLifecycleWritesRequireAnIdempotencyKey(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	_, err := h.client.DeactivateAccount(ctx,
		connect.NewRequest(&identityv1.DeactivateAccountRequest{}))
	requireCode(t, err, connect.CodeInvalidArgument)

	_, err = h.client.RequestAccountDeletion(ctx,
		connect.NewRequest(&identityv1.RequestAccountDeletionRequest{Confirmation: "DELETE"}))
	requireCode(t, err, connect.CodeInvalidArgument)

	if len(h.lifecycle.deactivateCmds)+len(h.lifecycle.deletionCmds) != 0 {
		t.Error("a request refused for a missing key still reached the app layer")
	}
}

// ---------------------------------------------------------------------------
// The two lifecycle commands that are deliberately NOT reachable
// ---------------------------------------------------------------------------

// No RPC on this service suspends an account, and none reactivates one.
//
// # Why this is a test and not a comment
//
// Both absences are decisions that a later commit could reverse in one line, and
// neither reversal looks dangerous from the diff.
//
//   - SUSPEND. identity.md §1 makes suspension administrative and explicitly not
//     reversible by the holder. Every method on this service is reached by the
//     account holder acting on their own account — api.callerSubject refuses an
//     API-key and a service-account principal outright — so an RPC here could only
//     ever be a SELF-suspension. One call and the account is unreachable by every
//     route this module has: Reactivate refuses Suspended, RequestPasswordReset
//     refuses it, ResendEmailVerification refuses it, and there is no operator
//     surface anywhere in this repository to undo it. domain.User.Suspend stays
//     built and tested; it acquires a caller when the operator module exists.
//
//   - REACTIVATE. Its only precondition would be a session, and a deactivated
//     account cannot authenticate to obtain one. An RPC would therefore be
//     reachable only by accounts that do not need it — the enrolment deadlock's
//     exact shape. The reversal happens inside the authentication instead
//     (domain.User.NeedsReactivation), which is why nothing here calls it.
//
// Matched on the method name rather than on an exact list, so a method called
// SuspendUser, SuspendMyAccount or ReactivateAccount all fail this.
func TestNoRpcSuspendsOrReactivatesAnAccount(t *testing.T) {
	t.Parallel()

	svc := (&identityv1.DeactivateAccountRequest{}).ProtoReflect().
		Descriptor().ParentFile().Services().ByName("IdentityService")
	if svc == nil {
		t.Fatal("IdentityService is not in the descriptor this test read")
	}

	for i := range svc.Methods().Len() {
		name := strings.ToLower(string(svc.Methods().Get(i).Name()))
		switch {
		case strings.Contains(name, "suspend"):
			t.Errorf("the service declares %q. A suspension reached by the account holder "+
				"is a self-suspension, and this module has no route back out of one",
				svc.Methods().Get(i).Name())
		case strings.Contains(name, "reactivate"):
			t.Errorf("the service declares %q. A deactivated account cannot authenticate, "+
				"so it can never hold the session such a call needs — the reversal belongs "+
				"in the authentication itself", svc.Methods().Get(i).Name())
		}
	}
}

// Both lifecycle writes declare AAL2 and neither declares a bootstrap exemption.
//
// Read from the descriptor, so it is the annotation the GATE reads rather than a
// comment about it. A bootstrap floor here would let a password-only session —
// the one an account with no second factor is allowed to mint — switch an account
// off or start its erasure.
func TestTheLifecycleWritesDeclareAAL2WithNoBootstrapExemption(t *testing.T) {
	t.Parallel()

	svc := (&identityv1.DeactivateAccountRequest{}).ProtoReflect().
		Descriptor().ParentFile().Services().ByName("IdentityService")

	for _, want := range []string{"DeactivateAccount", "RequestAccountDeletion"} {
		t.Run(want, func(t *testing.T) {
			t.Parallel()
			m := svc.Methods().ByName(protoreflect.Name(want))
			if m == nil {
				t.Fatalf("the service does not declare %s", want)
			}
			opts := m.Options()
			if got := proto.GetExtension(opts, optionsv1.E_MinAal).(optionsv1.AssuranceLevel); //nolint:errcheck
			got != optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2 {
				t.Errorf("min_aal = %v, want ASSURANCE_LEVEL_2", got)
			}
			if got := proto.GetExtension(opts, optionsv1.E_BootstrapMinAal).(optionsv1.AssuranceLevel); //nolint:errcheck
			got != optionsv1.AssuranceLevel_ASSURANCE_LEVEL_UNSPECIFIED {
				t.Errorf("bootstrap_min_aal = %v, want unset: a password-only session must "+
					"not switch an account off or start its erasure", got)
			}
			if proto.GetExtension(opts, optionsv1.E_Public).(bool) { //nolint:errcheck
				t.Error("the method is public; both of these destroy access and must be gated")
			}
		})
	}
}

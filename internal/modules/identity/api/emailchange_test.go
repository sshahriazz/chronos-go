package api_test

import (
	"context"
	"testing"

	connect "connectrpc.com/connect"

	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/internal/platform/errs"
)

// THE CALLER'S OWN PSEUDONYM REACHES THE COMMAND, AND THE REQUEST CANNOT NAME
// ANOTHER.
//
// RequestEmailChangeRequest has ONE field and it is the address. There is
// deliberately no subject on the wire, because a field naming a subject would be
// a field an administrator — or anyone who could forge one — could use to move
// somebody else's account. This asserts the handler takes the subject from the
// authenticated principal and from nowhere else.
func TestAnEmailChangeActsOnTheCallersOwnAccount(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	if _, err := h.client.RequestEmailChange(context.Background(),
		withKey(&identityv1.RequestEmailChangeRequest{
			NewEmail: "new@example.test",
		}, "k-req")); err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}

	if len(h.emails.requested) != 1 {
		t.Fatalf("the handler passed %d commands to the app layer, want 1",
			len(h.emails.requested))
	}
	got := h.emails.requested[0]
	if got.SubjectID != callerSubject {
		t.Errorf("the command carried subject %q, want the authenticated caller %q. A "+
			"subject taken from anywhere but the principal is a subject a request can "+
			"choose", got.SubjectID, callerSubject)
	}
	if got.NewEmail != "new@example.test" {
		t.Errorf("the address reached the app layer as %q", got.NewEmail)
	}
	if got.IdempotencyKey != "k-req" {
		t.Errorf("the idempotency key reached the app layer as %q", got.IdempotencyKey)
	}
}

// CANCELLING ALSO ACTS ONLY ON THE CALLER.
func TestCancellingAnEmailChangeActsOnTheCallersOwnAccount(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	if _, err := h.client.CancelEmailChange(context.Background(),
		withKey(&identityv1.CancelEmailChangeRequest{}, "k-cancel")); err != nil {
		t.Fatalf("CancelEmailChange: %v", err)
	}
	if len(h.emails.cancelled) != 1 {
		t.Fatalf("the handler passed %d commands, want 1", len(h.emails.cancelled))
	}
	if got := h.emails.cancelled[0].SubjectID; got != callerSubject {
		t.Errorf("the command carried subject %q, want %q", got, callerSubject)
	}
}

// EVERY MUTATION REQUIRES AN IDEMPOTENCY KEY, AND A REFUSED ONE REACHES NOTHING.
//
// The two PUBLIC calls matter most here. Gate 5 returns early for a public
// method, so the interceptor never sees them and api.idempotencyKey is what
// refuses — which means a regression in that one helper would silently make two
// account-critical endpoints non-idempotent.
func TestEveryEmailChangeWriteRequiresAnIdempotencyKey(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	_, err := h.client.RequestEmailChange(ctx,
		connect.NewRequest(&identityv1.RequestEmailChangeRequest{NewEmail: "a@b.test"}))
	requireCode(t, err, connect.CodeInvalidArgument)

	_, err = h.client.CancelEmailChange(ctx,
		connect.NewRequest(&identityv1.CancelEmailChangeRequest{}))
	requireCode(t, err, connect.CodeInvalidArgument)

	_, err = h.client.ConfirmEmailChange(ctx,
		connect.NewRequest(&identityv1.ConfirmEmailChangeRequest{Token: "t"}))
	requireCode(t, err, connect.CodeInvalidArgument)

	_, err = h.client.RevertEmailChange(ctx,
		connect.NewRequest(&identityv1.RevertEmailChangeRequest{Token: "t"}))
	requireCode(t, err, connect.CodeInvalidArgument)

	if n := len(h.emails.requested) + len(h.emails.cancelled) +
		len(h.emails.confirmed) + len(h.emails.reverted); n != 0 {
		t.Errorf("%d requests refused for a missing key still reached the app layer", n)
	}
}

// THE TWO REDEMPTION CALLS ARE PUBLIC, AND THE TOKEN IS THE ONLY THING THEY
// CARRY.
//
// Public is forced rather than preferred: both are reached from a mailbox by a
// browser with no session — and completing a change VOIDS every session on the
// account, so a caller who had one would not have it by the time they needed it.
//
// Asserted by calling them with NO principal at all. If either ever acquired an
// authz annotation, this fails — and the symptom in production would be that the
// only remedy for a stolen account is unreachable by the person it was stolen
// from.
func TestTheRedemptionCallsNeedNoSession(t *testing.T) {
	t.Parallel()
	h := newHarness(t, options{authnErr: errString("no session")})
	ctx := context.Background()

	if _, err := h.client.ConfirmEmailChange(ctx,
		withKey(&identityv1.ConfirmEmailChangeRequest{Token: "tok"}, "k1")); err != nil {
		t.Fatalf("ConfirmEmailChange refused an unauthenticated caller: %v. It is reached "+
			"from a mailbox, and after it runs there is no session to reach it with", err)
	}
	if _, err := h.client.RevertEmailChange(ctx,
		withKey(&identityv1.RevertEmailChangeRequest{Token: "tok"}, "k2")); err != nil {
		t.Fatalf("RevertEmailChange refused an unauthenticated caller: %v. This is the "+
			"ONLY remedy for an account whose address was moved by somebody else, and "+
			"that somebody has already voided every session on it", err)
	}

	if len(h.emails.confirmed) != 1 || h.emails.confirmed[0].Token != "tok" {
		t.Errorf("the confirm token reached the app layer as %v", h.emails.confirmed)
	}
	if len(h.emails.reverted) != 1 || h.emails.reverted[0].Token != "tok" {
		t.Errorf("the revert token reached the app layer as %v", h.emails.reverted)
	}
}

// THE TWO AUTHENTICATED CALLS DO NEED ONE.
//
// The mirror of the test above, and the pair is what makes either meaningful: a
// build where all four were public would pass the first test and fail this one.
func TestTheRequestingCallsNeedASession(t *testing.T) {
	t.Parallel()
	h := newHarness(t, options{authnErr: errString("no session")})
	ctx := context.Background()

	_, err := h.client.RequestEmailChange(ctx,
		withKey(&identityv1.RequestEmailChangeRequest{NewEmail: "a@b.test"}, "k1"))
	requireCode(t, err, connect.CodeUnauthenticated)

	_, err = h.client.CancelEmailChange(ctx,
		withKey(&identityv1.CancelEmailChangeRequest{}, "k2"))
	requireCode(t, err, connect.CodeUnauthenticated)

	if n := len(h.emails.requested) + len(h.emails.cancelled); n != 0 {
		t.Errorf("%d unauthenticated requests reached the app layer", n)
	}
}

// AN APP-LAYER REFUSAL IS NOT TRANSLATED INTO SOMETHING MORE SPECIFIC.
//
// The app layer flattens "unknown token", "spent", "expired" and "cancelled"
// into ONE refusal on purpose (ADR-036): distinguishing them tells whoever holds
// a stale link that the address it was sent to is real. A switch in the handler
// is how one answer becomes several distinguishable Connect codes, so there is
// none — and this asserts the absence.
func TestARefusedRedemptionIsOneUndifferentiatedAnswer(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	// The exact refusal the app layer produces for all four unusable-link cases.
	h.emails.err = errs.ValidationFailedf("this link is no longer valid")
	ctx := context.Background()

	_, confirmErr := h.client.ConfirmEmailChange(ctx,
		withKey(&identityv1.ConfirmEmailChangeRequest{Token: "spent"}, "k1"))
	_, revertErr := h.client.RevertEmailChange(ctx,
		withKey(&identityv1.RevertEmailChangeRequest{Token: "expired"}, "k2"))

	requireCode(t, confirmErr, connect.CodeInvalidArgument)
	requireCode(t, revertErr, connect.CodeInvalidArgument)
	if connect.CodeOf(confirmErr) != connect.CodeOf(revertErr) {
		t.Errorf("a spent confirm answers %v and an expired revert answers %v; the two "+
			"are distinguishable and each is an oracle",
			connect.CodeOf(confirmErr), connect.CodeOf(revertErr))
	}
}

type errString string

func (e errString) Error() string { return string(e) }

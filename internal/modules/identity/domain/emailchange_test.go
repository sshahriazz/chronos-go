package domain_test

import (
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
)

// verified returns an account whose current address is proven.
func verified(t *testing.T) *domain.User {
	t.Helper()
	u := registered(t)
	if err := u.VerifyEmail("idx_1", at); err != nil {
		t.Fatalf("verify: %v", err)
	}
	u.ClearUncommitted()
	return u
}

func recorded(u *domain.User) []string {
	out := make([]string, 0, len(u.Uncommitted()))
	for _, e := range u.Uncommitted() {
		out = append(out, e.EventType())
	}
	return out
}

// NOTHING CHANGES WHEN A CHANGE IS REQUESTED.
//
// identity.md §12: the NEW address is proven before the switch. If a request
// moved the account's identifier, an attacker holding a session would take
// ownership by naming an address they cannot read — which is the entire attack
// the flow exists to prevent, arriving through the flow itself.
func TestRequestingAnEmailChangeMovesNothing(t *testing.T) {
	u := verified(t)

	if err := u.RequestEmailChange("idx_2", at.Add(time.Hour), at); err != nil {
		t.Fatalf("request: %v", err)
	}
	if got := u.EmailIndex(); got != "idx_1" {
		t.Fatalf("the account's address became %q on REQUEST; the new address has not "+
			"been proven and an attacker holding a session has just taken the account",
			got)
	}
	if !u.EmailVerified() {
		t.Error("requesting a change un-verified the account's current address")
	}
	pending, ok := u.PendingEmailIndex()
	if !ok || pending != "idx_2" {
		t.Fatalf("pending index is %q (present=%t), want idx_2", pending, ok)
	}
}

// AN UNVERIFIED ACCOUNT CANNOT CHAIN A CHANGE.
//
// The route out of an unproven address is the verification link or a fresh
// registration once the claim lapses. Allowing a change would let somebody
// register an address they do not control and then walk it to another, holding
// each in turn without ever proving one.
func TestAnUnverifiedAccountCannotRequestAChange(t *testing.T) {
	if err := registered(t).RequestEmailChange("idx_2", at.Add(time.Hour), at); err == nil {
		t.Fatal("an account that has never proven its own address was allowed to move")
	}
}

// A SECOND REQUEST SUPERSEDES THE FIRST, AND SAYS SO.
//
// The cancellation is not tidiness: the reservation on the superseded address is
// released off the back of that event. Without it, somebody who mistyped an
// address once holds it away from its real owner until the lease runs out.
func TestASecondRequestCancelsTheFirst(t *testing.T) {
	u := verified(t)
	if err := u.RequestEmailChange("idx_2", at.Add(time.Hour), at); err != nil {
		t.Fatal(err)
	}
	u.ClearUncommitted()

	if err := u.RequestEmailChange("idx_3", at.Add(time.Hour), at); err != nil {
		t.Fatal(err)
	}
	got := recorded(u)
	want := []string{
		"identity.EmailChangeCancelled.v1",
		"identity.EmailChangeRequested.v1",
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("recorded %v, want %v — the cancellation must come FIRST so a reader "+
			"sees the address released before the next is claimed", got, want)
	}
	if u.Uncommitted()[0].(*contract.EmailChangeCancelled).Reason != contract.CancelSuperseded {
		t.Error("the superseding cancellation did not say why")
	}
	if pending, _ := u.PendingEmailIndex(); pending != "idx_3" {
		t.Errorf("pending is %q after superseding, want idx_3", pending)
	}
}

// REPEATING THE SAME REQUEST RECORDS NOTHING.
//
// Not merely idempotence: recording again would MOVE the deadline, and a
// deadline a caller can move by repeating one request is an address held
// indefinitely. EmailReservation.Reserve refuses renewal for the same reason.
func TestRepeatingARequestDoesNotExtendIt(t *testing.T) {
	u := verified(t)
	if err := u.RequestEmailChange("idx_2", at.Add(time.Hour), at); err != nil {
		t.Fatal(err)
	}
	u.ClearUncommitted()

	if err := u.RequestEmailChange("idx_2", at.Add(24*time.Hour), at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := recorded(u); len(got) != 0 {
		t.Fatalf("repeating a request recorded %v; the deadline can now be pushed out "+
			"indefinitely by replaying one request", got)
	}
}

// A TOKEN FOR ONE ADDRESS CANNOT COMPLETE A CHANGE TO ANOTHER.
func TestCompletingRequiresTheAddressThatWasClaimed(t *testing.T) {
	u := verified(t)
	if err := u.RequestEmailChange("idx_2", at.Add(time.Hour), at); err != nil {
		t.Fatal(err)
	}
	u.ClearUncommitted()

	if err := u.CompleteEmailChange("idx_9", at.Add(48*time.Hour), at.Add(time.Minute)); err == nil {
		t.Fatal("a change to idx_2 was completed by proving idx_9")
	}
	if got := u.EmailIndex(); got != "idx_1" {
		t.Fatalf("the refused completion still moved the address to %q", got)
	}
}

// A LAPSED REQUEST CANNOT BE COMPLETED.
//
// After the deadline the claimed address is available to anybody, so completing
// would take it from whoever claimed it since — the same harm
// EmailReservation.Confirm's lapse check exists to prevent.
func TestALapsedRequestCannotBeCompleted(t *testing.T) {
	u := verified(t)
	if err := u.RequestEmailChange("idx_2", at.Add(time.Hour), at); err != nil {
		t.Fatal(err)
	}
	if err := u.CompleteEmailChange("idx_2", at.Add(48*time.Hour), at.Add(time.Hour)); err == nil {
		t.Fatal("a change was completed at the exact instant its request expired")
	}
	if err := u.CompleteEmailChange("idx_2", at.Add(48*time.Hour), at.Add(2*time.Hour)); err == nil {
		t.Fatal("a change was completed an hour after its request expired")
	}
}

// COMPLETING SWITCHES THE ADDRESS AND OPENS THE REVERT WINDOW.
func TestCompletingSwitchesAndOpensTheWindow(t *testing.T) {
	u := verified(t)
	if err := u.RequestEmailChange("idx_2", at.Add(time.Hour), at); err != nil {
		t.Fatal(err)
	}
	revertUntil := at.Add(72 * time.Hour)
	if err := u.CompleteEmailChange("idx_2", revertUntil, at.Add(time.Minute)); err != nil {
		t.Fatalf("complete: %v", err)
	}

	if got := u.EmailIndex(); got != "idx_2" {
		t.Fatalf("the address is %q after a completed change, want idx_2", got)
	}
	if !u.EmailVerified() {
		t.Error("the new address is not verified, though it was just proven")
	}
	if _, still := u.PendingEmailIndex(); still {
		t.Error("the pending change survived its own completion")
	}
	back, open := u.RevertibleEmailIndex(at.Add(time.Hour))
	if !open || back != "idx_1" {
		t.Fatalf("revertible=%q open=%t inside the window, want idx_1 and open", back, open)
	}
	if _, open := u.RevertibleEmailIndex(revertUntil); open {
		t.Error("the revert window is still open at the instant it ends")
	}
}

// THE REVERT PUTS THE OLD ADDRESS BACK, ONCE, INSIDE THE WINDOW.
func TestRevertingRestoresTheOldAddress(t *testing.T) {
	u := verified(t)
	if err := u.RequestEmailChange("idx_2", at.Add(time.Hour), at); err != nil {
		t.Fatal(err)
	}
	if err := u.CompleteEmailChange("idx_2", at.Add(72*time.Hour), at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	u.ClearUncommitted()

	if err := u.RevertEmailChange(at.Add(time.Hour)); err != nil {
		t.Fatalf("revert: %v", err)
	}
	if got := u.EmailIndex(); got != "idx_1" {
		t.Fatalf("the address is %q after a revert, want idx_1", got)
	}
	// The window is SPENT. Offering another would let the two addresses be
	// swapped back and forth indefinitely from whichever mailbox answered last.
	if _, open := u.RevertibleEmailIndex(at.Add(2 * time.Hour)); open {
		t.Error("the revert window survived the revert; the change can be re-applied " +
			"from the other mailbox, and then undone again, forever")
	}
}

// THE WINDOW IS A DEADLINE, AND IT CLOSES.
func TestRevertingAfterTheWindowIsRefused(t *testing.T) {
	u := verified(t)
	if err := u.RequestEmailChange("idx_2", at.Add(time.Hour), at); err != nil {
		t.Fatal(err)
	}
	closesAt := at.Add(72 * time.Hour)
	if err := u.CompleteEmailChange("idx_2", closesAt, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	u.ClearUncommitted()

	if err := u.RevertEmailChange(closesAt); err == nil {
		t.Fatal("a revert succeeded at the exact instant the window closed")
	}
	if got := u.EmailIndex(); got != "idx_2" {
		t.Fatalf("a refused revert still moved the address to %q", got)
	}
}

// §4.4: A PASSWORD RESET VOIDS A PENDING CHANGE.
//
// The variant this closes is Sudhodanan & Paverd's "unexpired email change": an
// attacker queues a change to their own address, the victim recovers the account
// believing they have secured it, and the queued change completes afterwards and
// hands it straight back.
//
// This method recorded NOTHING until this commit, because no event could create
// a pending change. Every existing caller — the password reset calls it on every
// run — inherited the enforcement without being modified.
func TestAPasswordResetVoidsAPendingChange(t *testing.T) {
	u := verified(t)
	if err := u.RequestEmailChange("idx_attacker", at.Add(time.Hour), at); err != nil {
		t.Fatal(err)
	}
	u.ClearUncommitted()

	if err := u.VoidPendingIdentifierChange(at.Add(time.Minute)); err != nil {
		t.Fatalf("voiding: %v", err)
	}
	got := recorded(u)
	if len(got) != 1 || got[0] != "identity.EmailChangeCancelled.v1" {
		t.Fatalf("a reset recorded %v; the attacker's queued change survives the victim's "+
			"recovery and completes minutes later", got)
	}
	if r := u.Uncommitted()[0].(*contract.EmailChangeCancelled).Reason; r != contract.CancelPasswordReset {
		t.Errorf("the cancellation reason is %q; an operator asking whether a recovery "+
			"killed a pending change cannot tell", r)
	}
	if _, still := u.PendingEmailIndex(); still {
		t.Fatal("the pending change survived being voided")
	}

	// And the voided change can no longer be completed, which is the property
	// the whole variant turns on.
	if err := u.CompleteEmailChange("idx_attacker", at.Add(72*time.Hour), at.Add(2*time.Minute)); err == nil {
		t.Fatal("the voided change was completed anyway")
	}
}

// VOIDING WHEN THERE IS NOTHING PENDING RECORDS NOTHING.
//
// The reset calls this on EVERY run. An unconditional event would put a
// cancellation on the stream of every account that ever reset a password, for a
// change none of them made.
func TestVoidingWithNothingPendingIsSilent(t *testing.T) {
	u := verified(t)
	if err := u.VoidPendingIdentifierChange(at); err != nil {
		t.Fatal(err)
	}
	if got := recorded(u); len(got) != 0 {
		t.Fatalf("voiding nothing recorded %v", got)
	}
}

// §4.4 FROM THE OTHER SIDE: VERIFYING VOIDS A PENDING CHANGE.
//
// Enforced in the TRANSITION rather than by a caller, so it holds however the
// event arrived — including on a replay of a log written by a build that
// enforced it somewhere else.
func TestVerifyingAnAddressClearsAPendingChange(t *testing.T) {
	u := verified(t)
	if err := u.RequestEmailChange("idx_2", at.Add(time.Hour), at); err != nil {
		t.Fatal(err)
	}
	u.Apply(&contract.EmailVerified{SubjectID: u.SubjectID(), Index: "idx_1", VerifiedAt: at})
	if _, still := u.PendingEmailIndex(); still {
		t.Fatal("a pending change survived the account's address being re-verified")
	}
}

// A SUSPENDED ACCOUNT CANNOT MOVE ITS ADDRESS.
func TestASuspendedAccountCannotChangeItsAddress(t *testing.T) {
	u := verified(t)
	if err := u.Suspend("op_1", "abuse", at); err != nil {
		t.Fatal(err)
	}
	if err := u.RequestEmailChange("idx_2", at.Add(time.Hour), at); err == nil {
		t.Error("a suspended account moved its address")
	}
	if err := u.CompleteEmailChange("idx_2", at.Add(72*time.Hour), at); err == nil {
		t.Error("a suspended account completed an address change")
	}
}

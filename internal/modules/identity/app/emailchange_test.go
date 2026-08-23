package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

// ---------------------------------------------------------------------------
// A fake address book, which is where an address would leak if one ever did
// ---------------------------------------------------------------------------

// fakeAddresses records the MOVES, which is the whole surface of the port.
//
// It holds values so a test can assert the flow's effect on the vault, and the
// production adapter deliberately does not: the port is four moves and no reads
// precisely so that no address crosses back into `identity`.
type fakeAddresses struct {
	primary  string
	pending  string
	previous string

	staged   []string
	promotes int
	discards int
	restores int

	err error
}

func (f *fakeAddresses) StagePending(_ context.Context, _ pii.SubjectID, address string) error {
	if f.err != nil {
		return f.err
	}
	f.staged = append(f.staged, address)
	f.pending = address
	return nil
}

func (f *fakeAddresses) PromotePending(context.Context, pii.SubjectID) error {
	if f.err != nil {
		return f.err
	}
	f.promotes++
	if f.pending == "" {
		return nil
	}
	f.previous, f.primary, f.pending = f.primary, f.pending, ""
	return nil
}

func (f *fakeAddresses) DiscardPending(context.Context, pii.SubjectID) error {
	if f.err != nil {
		return f.err
	}
	f.discards++
	f.pending = ""
	return nil
}

func (f *fakeAddresses) RestorePrevious(context.Context, pii.SubjectID) error {
	if f.err != nil {
		return f.err
	}
	f.restores++
	if f.previous == "" {
		return nil
	}
	f.primary, f.previous, f.pending = f.previous, "", ""
	return nil
}

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

const (
	changeSubject = "subj_holder"
	oldIndex      = contract.EmailIndex("idx_old")
	newIndex      = contract.EmailIndex("idx_new")
)

type changeHarness struct {
	flow  *EmailChange
	clock *clock.Fixed

	user   *domain.User
	claims map[contract.EmailIndex]*domain.EmailReservation

	appender  *fakeAppender
	revoker   *fakeRevoker
	tokens    *liveTokens
	addresses *fakeAddresses
}

// verifiedAt builds an account whose current address is proven.
func (h *changeHarness) reservationFor(idx contract.EmailIndex) *domain.EmailReservation {
	if r, ok := h.claims[idx]; ok {
		return r
	}
	r := eventsourcing.NewAggregate(domain.NewReservation)
	h.claims[idx] = r
	return r
}

func newChangeHarness(t *testing.T) *changeHarness {
	t.Helper()

	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFixed(now)

	userID := ids.New[ids.User](now, &fixedEntropy{})
	user := eventsourcing.NewAggregate(domain.New)
	if err := user.Register(userID, changeSubject, oldIndex, now); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := user.VerifyEmail(oldIndex, now); err != nil {
		t.Fatalf("verify: %v", err)
	}
	user.ClearUncommitted()

	h := &changeHarness{
		clock:     clk,
		user:      user,
		claims:    map[contract.EmailIndex]*domain.EmailReservation{},
		appender:  &fakeAppender{},
		revoker:   &fakeRevoker{},
		tokens:    newLiveTokens(),
		addresses: &fakeAddresses{primary: "old@example.test"},
	}

	// The OLD address is already claimed and confirmed by this account, which is
	// the state a verified account is always in.
	old := h.reservationFor(oldIndex)
	if err := old.Reserve(oldIndex, changeSubject, now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if err := old.Confirm(changeSubject, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	old.ClearUncommitted()

	flow, err := NewEmailChange(EmailChangeDeps{
		Clock:    clk,
		Index:    fakeIndexer{},
		Subjects: fakeDirectory{user: userID},
		Users:    staticLoader[*domain.User](user, nil),
		Claims: loaderFunc[*domain.EmailReservation](
			func(_ context.Context, key string) (*domain.EmailReservation, error) {
				return h.reservationFor(contract.EmailIndex(key)), nil
			}),
		Appender:    h.appender,
		Schemas:     eventsourcing.NewUpcasterRegistry(),
		Addresses:   h.addresses,
		Tokens:      h.tokens,
		Digest:      testDigest,
		Revocations: h.revoker,
	})
	if err != nil {
		t.Fatalf("NewEmailChange: %v", err)
	}
	h.flow = flow
	return h
}

// appended returns every event type written across every stream, in order.
func (h *changeHarness) appended() []string {
	var out []string
	for _, call := range h.appender.calls {
		for _, a := range call {
			for _, e := range a.Events {
				out = append(out, e.Event.EventType())
			}
		}
	}
	return out
}

func (h *changeHarness) has(eventType string) bool {
	for _, got := range h.appended() {
		if got == eventType {
			return true
		}
	}
	return false
}

// request drives a change to the new address and returns the minted token.
func (h *changeHarness) request(t *testing.T) {
	t.Helper()
	if err := h.flow.Request(context.Background(), RequestEmailChangeCommand{
		SubjectID:      changeSubject,
		NewEmail:       "new@example.test",
		IdempotencyKey: "k-request",
	}); err != nil {
		t.Fatalf("Request: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The properties identity.md §12 turns on
// ---------------------------------------------------------------------------

// A REQUEST MOVES NOTHING AND CLAIMS THE ADDRESS.
//
// If a request moved the account's identifier, an attacker holding a session
// would take ownership by naming an address they cannot read — the entire attack
// the flow exists to prevent, arriving through the flow itself.
func TestARequestClaimsTheAddressAndMovesNothing(t *testing.T) {
	h := newChangeHarness(t)
	h.request(t)

	if got := h.user.EmailIndex(); got != oldIndex {
		t.Fatalf("the account's address became %q on REQUEST", got)
	}
	if !h.has("identity.EmailChangeRequested.v1") {
		t.Fatalf("appended %v, want the change request", h.appended())
	}
	if !h.has("identity.EmailReserved.v1") {
		t.Fatalf("appended %v; the new address was never CLAIMED, so two accounts can "+
			"request it at once and both win", h.appended())
	}
	// The vault has somewhere to mail the link.
	if len(h.addresses.staged) != 1 || h.addresses.staged[0] != "new@example.test" {
		t.Fatalf("staged %v; the reactor has nowhere to send the proof link",
			h.addresses.staged)
	}
	// And NOTHING was revoked: the account holder is still signed in, because
	// nothing has been proven yet.
	if len(h.revoker.calls) != 0 {
		t.Errorf("a mere request revoked %d session sets; the holder is signed out for "+
			"an address nobody has proven", len(h.revoker.calls))
	}
}

// THE ACCOUNT AND BOTH CLAIMS MOVE IN ONE APPEND.
//
// Three sequential single-stream writes would leave an account pointing at an
// address whose claim was never confirmed, or an address confirmed for an
// account that never moved.
func TestTheChangeIsOneAtomicAppend(t *testing.T) {
	h := newChangeHarness(t)
	h.request(t)
	h.confirm(t)

	// Two commands, so two appends — and the SECOND must carry all three streams.
	if len(h.appender.calls) != 2 {
		t.Fatalf("the flow made %d appends for a request and a confirm", len(h.appender.calls))
	}
	confirmCall := h.appender.calls[1]
	if len(confirmCall) != 3 {
		var streams []string
		for _, a := range confirmCall {
			streams = append(streams, a.Stream.String())
		}
		t.Fatalf("the confirm wrote %d streams (%v), want the account, the new claim and "+
			"the old one together", len(confirmCall), streams)
	}
	// Every part carries its loaded revision, so a claim taken in between loses
	// the WHOLE change rather than overwriting somebody.
	for _, a := range confirmCall {
		if a.Expected.IsAny() {
			t.Errorf("the append to %s expects ANY revision; an address claimed between "+
				"the load and the commit is silently overwritten instead of losing the "+
				"whole change", a.Stream)
		}
	}
}

// CONFIRMING VOIDS EVERY SESSION, SPARING NONE (§4.4).
//
// The "unexpired session" variant is an attacker keeping a live session across
// the change they performed. Re-verification is the trigger that closes it.
func TestConfirmingVoidsEverySessionWithNoException(t *testing.T) {
	h := newChangeHarness(t)
	h.request(t)
	h.confirm(t)

	if len(h.revoker.calls) != 1 {
		t.Fatalf("a completed change made %d revocation calls, want exactly 1. An "+
			"attacker's session survives the change they performed",
			len(h.revoker.calls))
	}
	got := h.revoker.calls[0]
	if !got.Except.IsZero() {
		t.Errorf("the revocation SPARED session %v. The party who requested the change "+
			"may be an attacker, so sparing the session that asked assumes exactly what "+
			"is in question", got.Except)
	}
	if got.SubjectID != changeSubject {
		t.Errorf("the revocation named subject %q", got.SubjectID)
	}
	if got.Reason != RevokeReasonEmailChanged {
		t.Errorf("the revocation recorded reason %q; an operator asking why a session "+
			"died cannot tell it from a password reset", got.Reason)
	}
}

// THE OLD ADDRESS IS DEMOTED, NOT RELEASED.
//
// Releasing it would let whoever performed the change re-register it immediately
// and leave the revert with nowhere to go back to — which is the attack the
// window exists to defeat.
func TestTheOldAddressIsHeldForTheRevertWindow(t *testing.T) {
	h := newChangeHarness(t)
	h.request(t)
	h.confirm(t)

	if !h.has("identity.EmailReservationDemoted.v1") {
		t.Fatalf("appended %v; the old address was not held for the window", h.appended())
	}
	if h.has("identity.EmailReleased.v1") {
		t.Fatalf("the old address was RELEASED at the moment of the change. Whoever "+
			"performed it can re-register it immediately and the revert has nowhere "+
			"to go: %v", h.appended())
	}

	old := h.reservationFor(oldIndex)
	inside := h.clock.Now().Add(time.Hour)
	if old.Available(inside) {
		t.Fatal("the old address is available DURING the revert window")
	}
	if !old.Available(h.clock.Now().Add(DefaultEmailRevertWindow)) {
		t.Fatal("the old address is still unavailable once the window closes; nothing " +
			"else releases it, so it is held forever")
	}
}

// A TOKEN OF THE WRONG PURPOSE DOES NOT COMPLETE A CHANGE.
//
// The binding is what stops anyone who can cause a VERIFICATION mail — by
// registering an address they own — from holding a token that completes a change
// on somebody else's account.
func TestAVerificationTokenCannotConfirmAChange(t *testing.T) {
	h := newChangeHarness(t)
	h.request(t)

	// A live verification token for the same subject, issued the way a resend
	// would issue one.
	if err := h.tokens.Issue(context.Background(), PurposeEmailVerification,
		changeSubject, testDigest(PurposeEmailVerification, "verify-me"),
		h.clock.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	before := len(h.appender.calls)
	err := h.flow.Confirm(context.Background(), ConfirmEmailChangeCommand{
		Token: "verify-me", IdempotencyKey: "k-confirm",
	})
	if err == nil {
		t.Fatal("a verification token completed an email change. Anybody who can cause a " +
			"verification mail for an address they own holds a token that moves another " +
			"account")
	}
	if len(h.appender.calls) != before {
		t.Error("the refused confirmation still appended")
	}
	if got := h.user.EmailIndex(); got != oldIndex {
		t.Errorf("the account moved to %q on a refused confirmation", got)
	}
}

// AN UNKNOWN, SPENT AND EXPIRED TOKEN ARE ONE ANSWER.
//
// Distinguishing them tells whoever holds a stale link that the address it was
// sent to is real.
func TestEveryUnusableLinkIsTheSameRefusal(t *testing.T) {
	h := newChangeHarness(t)
	h.request(t)
	plaintext := h.mintedChangeToken(t)

	// Spend it once, legitimately.
	h.confirm(t)

	messages := map[string]bool{}
	for _, token := range []string{plaintext, "never-issued", "also-never-issued"} {
		err := h.flow.Confirm(context.Background(), ConfirmEmailChangeCommand{
			Token: token, IdempotencyKey: "k-again",
		})
		if err == nil {
			t.Fatalf("token %q was accepted a second time", token)
		}
		messages[err.Error()] = true
	}
	if len(messages) != 1 {
		var got []string
		for m := range messages {
			got = append(got, m)
		}
		t.Fatalf("a spent token and two unknown ones produced %d distinct refusals: %v. "+
			"The difference tells whoever holds a stale link that its address is real",
			len(messages), strings.Join(got, " / "))
	}
}

// THE REVERT PUTS EVERYTHING BACK, AND VOIDS SESSIONS AGAIN.
func TestRevertingRestoresTheAccountAndSignsEveryoneOut(t *testing.T) {
	h := newChangeHarness(t)
	h.request(t)
	h.confirm(t)
	h.revoker.calls = nil

	revertToken := h.mintedRevertToken(t)
	if err := h.flow.Revert(context.Background(), RevertEmailChangeCommand{
		Token: revertToken, IdempotencyKey: "k-revert",
	}); err != nil {
		t.Fatalf("Revert: %v", err)
	}

	if got := h.user.EmailIndex(); got != oldIndex {
		t.Fatalf("the account's address is %q after a revert, want %q", got, oldIndex)
	}
	if h.addresses.primary != "old@example.test" {
		t.Fatalf("the vault's primary address is %q after a revert; the account's log "+
			"says it moved back and its MAIL still goes to the new address",
			h.addresses.primary)
	}
	if len(h.revoker.calls) != 1 {
		t.Fatalf("a revert made %d revocation calls, want 1. The party this is being "+
			"undone against may still be holding the session they did it from",
			len(h.revoker.calls))
	}
	if r := h.revoker.calls[0].Reason; r != RevokeReasonEmailChangeReverted {
		t.Errorf("the revert's revocation recorded reason %q", r)
	}
	// The address that was moved TO is released outright: nobody is being
	// protected from losing it, and holding it would keep an address the account
	// has repudiated away from whoever else might want it.
	if !h.reservationFor(newIndex).Available(h.clock.Now()) {
		t.Error("the abandoned address is still held after the revert")
	}
}

// CANCELLING KILLS THE LIVE LINK.
//
// Without this the mail already sitting in the new mailbox still completes a
// change the account holder explicitly called off — which is precisely what
// somebody acting on the security warning is trying to prevent.
func TestCancellingVoidsTheOutstandingLink(t *testing.T) {
	h := newChangeHarness(t)
	h.request(t)
	plaintext := h.mintedChangeToken(t)

	if err := h.flow.Cancel(context.Background(), CancelEmailChangeCommand{
		SubjectID: changeSubject, IdempotencyKey: "k-cancel",
	}); err != nil {
		t.Fatalf("Cancel: %v", err)
	}

	if err := h.flow.Confirm(context.Background(), ConfirmEmailChangeCommand{
		Token: plaintext, IdempotencyKey: "k-after-cancel",
	}); err == nil {
		t.Fatal("the link mailed before the cancellation still completed the change. " +
			"Somebody acting on the security warning cancels, and the attacker's mail " +
			"works anyway")
	}
	if got := h.user.EmailIndex(); got != oldIndex {
		t.Errorf("the account moved to %q after the change was cancelled", got)
	}
	if h.addresses.discards == 0 {
		t.Error("the cancelled address was left staged in the vault")
	}
	if !h.reservationFor(newIndex).Available(h.clock.Now()) {
		t.Error("a cancelled change still holds its address away from its real owner")
	}
}

// SUPERSEDING RELEASES THE ADDRESS THAT IS NO LONGER BEING CLAIMED.
//
// Without it a person who mistyped an address once holds it away from its real
// owner until the lease runs out.
func TestASecondRequestReleasesTheFirstAddress(t *testing.T) {
	h := newChangeHarness(t)
	h.request(t)

	if err := h.flow.Request(context.Background(), RequestEmailChangeCommand{
		SubjectID:      changeSubject,
		NewEmail:       "third@example.test",
		IdempotencyKey: "k-request-2",
	}); err != nil {
		t.Fatalf("second Request: %v", err)
	}
	if !h.reservationFor(newIndex).Available(h.clock.Now()) {
		t.Fatal("the superseded address is still claimed; somebody who mistyped an " +
			"address once holds it away from its real owner until the lease runs out")
	}
	if !h.has("identity.EmailChangeCancelled.v1") {
		t.Errorf("appended %v, want the superseded change recorded", h.appended())
	}
}

// ---------------------------------------------------------------------------
// helpers that reach into the token store the way a mailbox would
// ---------------------------------------------------------------------------

func (h *changeHarness) confirm(t *testing.T) {
	t.Helper()
	if err := h.flow.Confirm(context.Background(), ConfirmEmailChangeCommand{
		Token: h.mintedChangeToken(t), IdempotencyKey: "k-confirm",
	}); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
}

// mintedChangeToken issues a change token the way the reactor would and returns
// its plaintext.
//
// The reactor is not exercised here — it has its own tests — but the token has
// to exist and to be of the right purpose, because the purpose binding is one of
// the properties under test.
func (h *changeHarness) mintedChangeToken(t *testing.T) string {
	t.Helper()
	return h.mint(t, PurposeEmailChange, "change-plaintext")
}

func (h *changeHarness) mintedRevertToken(t *testing.T) string {
	t.Helper()
	return h.mint(t, PurposeEmailChangeRevert, "revert-plaintext")
}

func (h *changeHarness) mint(t *testing.T, purpose TokenPurpose, plaintext string) string {
	t.Helper()
	if err := h.tokens.Issue(context.Background(), purpose, changeSubject,
		testDigest(purpose, plaintext), h.clock.Now().Add(48*time.Hour)); err != nil {
		t.Fatalf("issuing a %s token: %v", purpose, err)
	}
	return plaintext
}

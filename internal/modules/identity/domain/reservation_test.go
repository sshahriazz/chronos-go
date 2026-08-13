package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

const (
	idxA  = contract.EmailIndex("a1b2c3")
	lease = 24 * time.Hour
)

func heldReservation(t *testing.T, subject string) *domain.EmailReservation {
	t.Helper()
	r := eventsourcing.NewAggregate(domain.NewReservation)
	if err := r.Reserve(idxA, subject, at.Add(lease), at); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	return r
}

// A free address can be claimed; a held one cannot.
func TestASecondClaimOnAHeldAddressIsRefused(t *testing.T) {
	r := heldReservation(t, "subj_first")

	err := r.Reserve(idxA, "subj_second", at.Add(lease), at.Add(time.Minute))
	if err == nil {
		t.Fatal("two accounts claimed the same address: uniqueness is not enforced")
	}
	if !errors.Is(err, errs.Conflictf("")) {
		t.Errorf("error is %v, want CONFLICT", err)
	}
	if got := r.SubjectID(); got != "subj_first" {
		t.Errorf("the claim moved to %q", got)
	}
}

// The refusal is IDENTICAL whether the holder has proven the address or not.
//
// Distinguishing them tells a caller whether someone has proven control of that
// address — an account-existence oracle, and a better one than a login attempt
// because it needs no password guess (identity.md §7).
func TestARefusalDoesNotRevealWhetherTheAddressWasProven(t *testing.T) {
	unproven := heldReservation(t, "subj_first")

	proven := heldReservation(t, "subj_first")
	if err := proven.Confirm("subj_first", at.Add(time.Minute)); err != nil {
		t.Fatalf("confirm: %v", err)
	}

	errUnproven := unproven.Reserve(idxA, "subj_second", at.Add(lease), at.Add(time.Minute))
	errProven := proven.Reserve(idxA, "subj_second", at.Add(lease), at.Add(time.Minute))

	if errUnproven == nil || errProven == nil {
		t.Fatal("a second claim succeeded")
	}
	if errUnproven.Error() != errProven.Error() {
		t.Fatalf("the two refusals differ:\n  unproven: %v\n  proven:   %v\n"+
			"the difference reports whether a stranger has proven that address",
			errUnproven, errProven)
	}
}

// An UNVERIFIED claim lapses, so a squatter cannot hold an address forever.
//
// This is the whole reason the two-state design exists. Registering with someone
// else's address must not permanently deny it to them — and there is nobody to
// appeal to, because no account was ever proven.
func TestAnUnverifiedClaimLapses(t *testing.T) {
	r := heldReservation(t, "subj_squatter")

	if r.Available(at.Add(lease - time.Second)) {
		t.Fatal("the address was available before the lease ran out")
	}
	if !r.Available(at.Add(lease)) {
		t.Fatal("an unverified claim never lapses: registering with an address you do not " +
			"control denies it to the real owner permanently")
	}

	// And the real owner can now take it.
	if err := r.Reserve(idxA, "subj_owner", at.Add(lease+lease), at.Add(lease)); err != nil {
		t.Fatalf("the owner could not claim the lapsed address: %v", err)
	}
	if got := r.SubjectID(); got != "subj_owner" {
		t.Fatalf("the claim is held by %q after a successful takeover", got)
	}
}

// A VERIFIED claim never lapses.
func TestAVerifiedClaimNeverLapses(t *testing.T) {
	r := heldReservation(t, "subj_owner")
	if err := r.Confirm("subj_owner", at.Add(time.Minute)); err != nil {
		t.Fatalf("confirm: %v", err)
	}

	for _, when := range []time.Time{
		at.Add(lease), at.Add(365 * 24 * time.Hour), at.Add(100 * 365 * 24 * time.Hour),
	} {
		if r.Available(when) {
			t.Fatalf("a confirmed address became available at %v: a stranger can claim an "+
				"address whose owner proved it", when)
		}
	}
}

// Taking over a lapsed claim records the RELEASE as well as the new
// reservation.
//
// A claim that simply vanished when overwritten would leave the earlier
// registrant's disappearance unexplained in the log — and that registrant may
// well write in asking what happened.
func TestATakeoverRecordsTheReleaseOfThePreviousClaim(t *testing.T) {
	r := heldReservation(t, "subj_squatter")
	r.ClearUncommitted()

	if err := r.Reserve(idxA, "subj_owner", at.Add(lease+lease), at.Add(lease)); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	events := r.Uncommitted()
	if len(events) != 2 {
		t.Fatalf("a takeover recorded %d events, want a release followed by a reservation", len(events))
	}
	released, ok := events[0].(*contract.EmailReleased)
	if !ok {
		t.Fatalf("the first event is %T, want EmailReleased", events[0])
	}
	if released.SubjectID != "subj_squatter" {
		t.Errorf("the release names %q, not the previous holder", released.SubjectID)
	}
	if released.Reason != domain.ReleaseExpired {
		t.Errorf("the release reason is %q, want %q", released.Reason, domain.ReleaseExpired)
	}
	if _, ok := events[1].(*contract.EmailReserved); !ok {
		t.Fatalf("the second event is %T, want EmailReserved", events[1])
	}
}

// Re-reserving for the same subject is idempotent and does NOT extend the
// lease.
//
// Extending would let a squatter renew indefinitely by replaying one request,
// which defeats the lapse entirely.
func TestReReservingDoesNotExtendTheLease(t *testing.T) {
	r := heldReservation(t, "subj_squatter")
	original := r.ExpiresAt()
	r.ClearUncommitted()

	// The same registration, retried much later but still inside the lease.
	if err := r.Reserve(idxA, "subj_squatter", at.Add(lease*10), at.Add(lease-time.Minute)); err != nil {
		t.Fatalf("a retried registration failed: %v", err)
	}
	if n := len(r.Uncommitted()); n != 0 {
		t.Errorf("a retried registration recorded %d events", n)
	}
	if !r.ExpiresAt().Equal(original) {
		t.Fatalf("the lease moved from %v to %v: a squatter renews indefinitely by replaying "+
			"one request, and the claim never lapses", original, r.ExpiresAt())
	}
}

// Only the holder may confirm.
//
// Without this, an account whose reservation FAILED could still confirm the
// address — taking it from the holder by presenting a token for an address it
// never proved.
func TestOnlyTheHolderMayConfirm(t *testing.T) {
	r := heldReservation(t, "subj_first")

	if err := r.Confirm("subj_second", at.Add(time.Minute)); err == nil {
		t.Fatal("a non-holder confirmed the address: the account that lost the race takes " +
			"the address anyway")
	}
	if r.Verified() {
		t.Error("the reservation was marked verified by a non-holder")
	}
}

// A lapsed claim cannot be confirmed.
//
// A late verification link must not resurrect a claim, because the address may
// already belong to someone else by then — and taking it back would leave no
// event explaining why.
func TestALapsedClaimCannotBeConfirmed(t *testing.T) {
	r := heldReservation(t, "subj_squatter")

	if err := r.Confirm("subj_squatter", at.Add(lease)); err == nil {
		t.Fatal("a lapsed reservation was confirmed: a verification link that arrives after " +
			"the lease takes the address back from whoever legitimately claimed it")
	}
}

// Confirming twice records one event.
func TestConfirmingTwiceRecordsOneEvent(t *testing.T) {
	r := heldReservation(t, "subj_owner")
	r.ClearUncommitted()

	if err := r.Confirm("subj_owner", at.Add(time.Minute)); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if err := r.Confirm("subj_owner", at.Add(2*time.Minute)); err != nil {
		t.Fatalf("second confirm: %v", err)
	}
	var n int
	for _, e := range r.Uncommitted() {
		if _, ok := e.(*contract.EmailReservationConfirmed); ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("recorded %d confirmations, want 1", n)
	}
}

// A released address is available again.
func TestAReleasedAddressBecomesAvailable(t *testing.T) {
	r := heldReservation(t, "subj_owner")
	if err := r.Confirm("subj_owner", at.Add(time.Minute)); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if err := r.Release("subj_owner", domain.ReleaseErased, at.Add(time.Hour)); err != nil {
		t.Fatalf("release: %v", err)
	}

	if !r.Available(at.Add(time.Hour)) {
		t.Fatal("a released address stayed unavailable: identifier reuse after erasure is " +
			"impossible, and the address is retained for an account that no longer exists")
	}
	// Held, not just Available. A release that cleared the deadline but left the
	// claim in place still reports as available — because the zero deadline has
	// passed — so Available alone cannot tell a freed claim from a broken one.
	if r.Held() {
		t.Fatal("the reservation still reports as held after being released")
	}
	if r.SubjectID() != "" {
		t.Errorf("the released reservation still names %q as its holder", r.SubjectID())
	}

	r.ClearUncommitted()
	if err := r.Reserve(idxA, "subj_new", at.Add(2*time.Hour), at.Add(time.Hour)); err != nil {
		t.Fatalf("the released address could not be claimed: %v", err)
	}
	// Exactly one event. A claim that was not actually dropped takes the takeover
	// branch and records a SECOND release — for a holder that is now the empty
	// string, against an address nobody holds.
	events := r.Uncommitted()
	if len(events) != 1 {
		t.Fatalf("claiming a released address recorded %d events, want 1; the previous claim "+
			"was not dropped, so a spurious release was recorded for an empty holder", len(events))
	}
	if _, ok := events[0].(*contract.EmailReserved); !ok {
		t.Fatalf("the recorded event is %T, want EmailReserved", events[0])
	}
}

// Only the holder may release.
func TestOnlyTheHolderMayRelease(t *testing.T) {
	r := heldReservation(t, "subj_owner")
	if err := r.Release("subj_other", domain.ReleaseChanged, at.Add(time.Minute)); err == nil {
		t.Fatal("a non-holder released someone else's address")
	}
	if !r.Held() {
		t.Error("the claim was dropped by a non-holder")
	}
}

// A release must state a reason the projector can branch on.
func TestAReleaseMustStateAKnownReason(t *testing.T) {
	r := heldReservation(t, "subj_owner")
	for _, reason := range []string{"", "because", "EXPIRED", "expired "} {
		if err := r.Release("subj_owner", reason, at.Add(time.Minute)); err == nil {
			t.Errorf("a release with reason %q was accepted", reason)
		}
	}
}

// A reservation must expire in the future, and needs both identifiers.
func TestAMalformedReservationIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name      string
		index     contract.EmailIndex
		subject   string
		expiresAt time.Time
	}{
		{"no index", "", "subj_1", at.Add(lease)},
		{"no subject", idxA, "", at.Add(lease)},
		{"expiry in the past", idxA, "subj_1", at.Add(-time.Hour)},
		{"expiry now", idxA, "subj_1", at},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := eventsourcing.NewAggregate(domain.NewReservation)
			if err := r.Reserve(tc.index, tc.subject, tc.expiresAt, at); err == nil {
				t.Fatalf("a reservation with %s was accepted", tc.name)
			}
		})
	}
}

// A reservation aggregate refuses to hold a different address.
//
// Unreachable through the repository, since the stream is named from the index —
// and asserted anyway, because reaching it would silently move a claim between
// two addresses.
func TestAReservationRefusesADifferentAddress(t *testing.T) {
	r := heldReservation(t, "subj_owner")
	if err := r.Reserve("someotherindex", "subj_owner", at.Add(lease), at.Add(time.Minute)); err == nil {
		t.Fatal("a reservation accepted a claim for a different address")
	}
}

// Replaying the events reproduces the state.
func TestReplayingAReservationReproducesItsState(t *testing.T) {
	live := heldReservation(t, "subj_squatter")
	if err := live.Reserve(idxA, "subj_owner", at.Add(lease+lease), at.Add(lease)); err != nil {
		t.Fatalf("takeover: %v", err)
	}
	if err := live.Confirm("subj_owner", at.Add(lease+time.Minute)); err != nil {
		t.Fatalf("confirm: %v", err)
	}

	rebuilt := eventsourcing.NewAggregate(domain.NewReservation)
	for _, e := range live.Uncommitted() {
		rebuilt.Apply(e)
	}

	if live.SubjectID() != rebuilt.SubjectID() {
		t.Errorf("subject: live %q, rebuilt %q", live.SubjectID(), rebuilt.SubjectID())
	}
	if live.Verified() != rebuilt.Verified() {
		t.Errorf("verified: live %v, rebuilt %v", live.Verified(), rebuilt.Verified())
	}
	if live.Held() != rebuilt.Held() {
		t.Errorf("held: live %v, rebuilt %v", live.Held(), rebuilt.Held())
	}
	// The deadline must be CLEARED by confirmation, not merely ignored. A
	// rebuilt aggregate that kept a past deadline would report a confirmed
	// address as available.
	if !rebuilt.ExpiresAt().IsZero() {
		t.Errorf("a confirmed reservation rebuilt with a deadline of %v", rebuilt.ExpiresAt())
	}
	if rebuilt.Available(at.Add(100 * lease)) {
		t.Fatal("a rebuilt confirmed reservation reports as available: the deadline survived " +
			"confirmation, so every verified address frees itself once its original lease passes")
	}
}

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

// ---------------------------------------------------------------------------
// The duplicate-registration notice (ADR-055)
// ---------------------------------------------------------------------------

func verifiedReservation(t *testing.T, subject string) *domain.EmailReservation {
	t.Helper()
	r := heldReservation(t, subject)
	if err := r.Confirm(subject, at.Add(time.Minute)); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	r.ClearUncommitted()
	return r
}

// The notice may only be recorded for a claim somebody has PROVEN.
//
// An unverified claim means nobody has shown they can read mail at the address.
// Mailing there is unsolicited mail to a person who never asked for anything
// (NOTIFICATIONS §5), aimed at an address a stranger typed — which is the very
// act being reported.
func TestNoNoticeIsRecordedForAnUnprovenClaim(t *testing.T) {
	t.Parallel()

	free := eventsourcing.NewAggregate(domain.NewReservation)
	unproven := heldReservation(t, "subj_first")
	unproven.ClearUncommitted()

	for name, r := range map[string]*domain.EmailReservation{
		"never claimed":     free,
		"claimed, unproven": unproven,
	} {
		if r.NoticeDuplicateRegistration(at.Add(time.Hour)) {
			t.Errorf("%s: a notice was recorded", name)
		}
		if got := len(r.Uncommitted()); got != 0 {
			t.Errorf("%s: %d events recorded", name, got)
		}
	}
}

// The recorded fact, in full. It names the address's index and the pseudonym of
// the account that HOLDS it — never the address, and never anything about
// whoever made the attempt, who is unauthenticated (ADR-002).
func TestANoticeNamesTheHolderAndNobodyElse(t *testing.T) {
	t.Parallel()

	r := verifiedReservation(t, "subj_owner")
	now := at.Add(time.Hour)

	if !r.NoticeDuplicateRegistration(now) {
		t.Fatal("a verified claim recorded no notice")
	}
	pending := r.Uncommitted()
	if len(pending) != 1 {
		t.Fatalf("%d events recorded, want 1", len(pending))
	}
	notice, ok := pending[0].(*contract.DuplicateRegistrationAttempted)
	if !ok {
		t.Fatalf("recorded %T", pending[0])
	}
	switch {
	case notice.Index != idxA:
		t.Errorf("index is %q, want %q", notice.Index, idxA)
	case notice.SubjectID != "subj_owner":
		t.Errorf("subject is %q; the notice must name the HOLDER", notice.SubjectID)
	case !notice.AttemptedAt.Equal(now):
		t.Errorf("attempted at %s, want %s", notice.AttemptedAt, now)
	case notice.AttemptedAt.Location() != time.UTC:
		t.Errorf("attempted at is in %s; all times are UTC (ADR-008)", notice.AttemptedAt.Location())
	}
}

// The per-address ceiling, which is what stops an unauthenticated caller turning
// this endpoint into a mail bomb AND into an unbounded append to somebody else's
// stream.
//
// Asserted at the boundary in both directions: the last permitted notice must be
// recorded and the next must not, because a ceiling that is off by one in the
// permissive direction reads exactly like one that works.
func TestTheNoticeCeilingIsPerAddressAndPerWindow(t *testing.T) {
	t.Parallel()

	t.Run("hourly", func(t *testing.T) {
		t.Parallel()
		r := verifiedReservation(t, "subj_owner")
		now := at.Add(time.Hour)

		for i := range domain.MaxDuplicateNoticesPerHour {
			if !r.NoticeDuplicateRegistration(now.Add(time.Duration(i) * time.Minute)) {
				t.Fatalf("notice %d of %d was refused", i+1, domain.MaxDuplicateNoticesPerHour)
			}
		}
		if r.NoticeDuplicateRegistration(now.Add(time.Duration(domain.MaxDuplicateNoticesPerHour) * time.Minute)) {
			t.Errorf("a %dth notice was recorded within the hour",
				domain.MaxDuplicateNoticesPerHour+1)
		}
		// And the window really is a window: an hour later the budget is back.
		if !r.NoticeDuplicateRegistration(now.Add(2 * time.Hour)) {
			t.Error("the hourly budget never recovered; the ceiling is a permanent lock")
		}
	})

	t.Run("daily", func(t *testing.T) {
		t.Parallel()
		r := verifiedReservation(t, "subj_owner")
		now := at.Add(time.Hour)

		// Spread across the day so the hourly rule never binds, and the only rule
		// that can refuse the last one is the daily one.
		for i := range domain.MaxDuplicateNoticesPerDay {
			if !r.NoticeDuplicateRegistration(now.Add(time.Duration(i) * time.Hour)) {
				t.Fatalf("notice %d of %d was refused", i+1, domain.MaxDuplicateNoticesPerDay)
			}
		}
		over := now.Add(time.Duration(domain.MaxDuplicateNoticesPerDay) * time.Hour)
		if r.NoticeDuplicateRegistration(over) {
			t.Errorf("a %dth notice was recorded within the day",
				domain.MaxDuplicateNoticesPerDay+1)
		}
		if !r.NoticeDuplicateRegistration(now.Add(25 * time.Hour)) {
			t.Error("the daily budget never recovered")
		}
	})
}

// The ceiling survives a rebuild, which is the whole reason it lives on the
// aggregate instead of in a cache: it is derived from the log, so it cannot be
// degraded by an unreachable Valkey or reset by a FLUSHALL.
func TestTheNoticeCeilingIsRebuiltFromTheLog(t *testing.T) {
	t.Parallel()

	now := at.Add(time.Hour)
	events := []eventsourcing.Event{
		&contract.EmailReserved{Index: idxA, SubjectID: "subj_owner", ExpiresAt: at.Add(lease), ReservedAt: at},
		&contract.EmailReservationConfirmed{Index: idxA, SubjectID: "subj_owner", ConfirmedAt: at},
	}
	for i := range domain.MaxDuplicateNoticesPerHour {
		events = append(events, &contract.DuplicateRegistrationAttempted{
			Index: idxA, SubjectID: "subj_owner",
			AttemptedAt: now.Add(time.Duration(i) * time.Minute),
		})
	}

	rebuilt := eventsourcing.NewAggregate(domain.NewReservation)
	for _, e := range events {
		rebuilt.Apply(e)
	}
	if rebuilt.NoticeDuplicateRegistration(now.Add(4 * time.Minute)) {
		t.Error("a rebuilt reservation had a fresh budget; the ceiling does not survive a reload, " +
			"so restarting the process — or simply loading the aggregate again — resets it")
	}
}

// Releasing the claim must NOT hand back a fresh notice budget.
//
// A lapse is something an attacker only has to wait for, so clearing the history
// on release would sell the whole ceiling for the price of patience.
func TestReleasingTheAddressDoesNotRefreshTheNoticeBudget(t *testing.T) {
	t.Parallel()

	r := verifiedReservation(t, "subj_owner")
	now := at.Add(time.Hour)
	for i := range domain.MaxDuplicateNoticesPerHour {
		if !r.NoticeDuplicateRegistration(now.Add(time.Duration(i) * time.Minute)) {
			t.Fatalf("notice %d was refused", i+1)
		}
	}
	r.Apply(&contract.EmailReleased{Index: idxA, SubjectID: "subj_owner", Reason: domain.ReleaseChanged})
	r.Apply(&contract.EmailReserved{
		Index: idxA, SubjectID: "subj_next", ExpiresAt: now.Add(lease), ReservedAt: now,
	})
	r.Apply(&contract.EmailReservationConfirmed{Index: idxA, SubjectID: "subj_next", ConfirmedAt: now})

	if r.NoticeDuplicateRegistration(now.Add(4 * time.Minute)) {
		t.Error("re-claiming the address reset its notice budget")
	}
}

// The retained history is bounded. An address under sustained attack must not
// grow an unbounded slice every time its aggregate is loaded.
func TestTheNoticeHistoryIsBounded(t *testing.T) {
	t.Parallel()

	r := verifiedReservation(t, "subj_owner")
	for i := range 500 {
		r.Apply(&contract.DuplicateRegistrationAttempted{
			Index: idxA, SubjectID: "subj_owner",
			AttemptedAt: at.Add(time.Duration(i) * time.Minute),
		})
	}
	// Everything ever applied is inside this window, so an unbounded history
	// would answer 500.
	if got := r.NoticesSince(at.Add(-time.Hour)); got > 64 {
		t.Errorf("the aggregate retained %d notices; the history is unbounded", got)
	}
	// And it still refuses, which is what makes the bound safe: pruning must
	// never look like "the ceiling was never reached".
	if r.NoticeDuplicateRegistration(at.Add(500 * time.Minute)) {
		t.Error("a pruned history reported budget it does not have")
	}
}

// ---------------------------------------------------------------------------
// The revert window (identity.md §12)
// ---------------------------------------------------------------------------

func confirmedReservation(t *testing.T, subject string) *domain.EmailReservation {
	t.Helper()
	r := heldReservation(t, subject)
	if err := r.Confirm(subject, at.Add(time.Minute)); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	r.ClearUncommitted()
	return r
}

// A DEMOTED ADDRESS IS STILL UNAVAILABLE TO EVERYONE ELSE.
//
// This is the whole reason the old address is demoted rather than released. In
// the attack the revert window exists to defeat, the party who moved the address
// is an attacker holding a session — and if the release freed the address, that
// attacker could re-register it immediately and leave the revert with nowhere to
// go back to.
func TestADemotedAddressCannotBeTakenDuringTheWindow(t *testing.T) {
	r := confirmedReservation(t, "subj_owner")
	closesAt := at.Add(72 * time.Hour)

	if err := r.Demote("subj_owner", domain.DemoteRevertWindow, closesAt, at.Add(time.Hour)); err != nil {
		t.Fatalf("demote: %v", err)
	}
	if r.Verified() {
		t.Error("a demoted claim is still verified, so it will never lapse and the " +
			"address is held by this account forever")
	}
	if !r.Held() {
		t.Fatal("a demoted claim was released; whoever performed the change can now " +
			"re-register the address and the revert has nowhere to go")
	}
	if r.Available(at.Add(time.Hour)) {
		t.Fatal("the old address is available DURING the revert window; an attacker who " +
			"just moved it can take it and block the revert")
	}
}

// AND IT FREES ITSELF AFTERWARDS, WITH NO SWEEP.
//
// The lapse Reserve already implements is what makes this work: a lapsed
// unverified claim is released before the next is granted, so nothing has to
// remember to release the old address when the window closes.
func TestADemotedAddressLapsesAndIsReclaimable(t *testing.T) {
	r := confirmedReservation(t, "subj_owner")
	closesAt := at.Add(72 * time.Hour)
	if err := r.Demote("subj_owner", domain.DemoteRevertWindow, closesAt, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	r.ClearUncommitted()

	if !r.Available(closesAt) {
		t.Fatal("the address is still unavailable at the instant the window closes; " +
			"nothing else releases it, so it is held forever")
	}
	if err := r.Reserve(idxA, "subj_stranger", closesAt.Add(lease), closesAt); err != nil {
		t.Fatalf("a stranger could not claim the lapsed address: %v", err)
	}
	// The release is RECORDED, so the log says what happened to the previous
	// holder rather than showing a claim that silently changed hands.
	got := r.Uncommitted()
	if len(got) != 2 ||
		got[0].EventType() != "identity.EmailReleased.v1" ||
		got[1].EventType() != "identity.EmailReserved.v1" {
		t.Fatalf("reclaiming recorded %v, want a release then a reservation",
			typesOf(got))
	}
}

// DEMOTING SOMEBODY ELSE'S ADDRESS IS REFUSED.
func TestDemotingAnotherAccountsAddressIsRefused(t *testing.T) {
	r := confirmedReservation(t, "subj_owner")
	if err := r.Demote("subj_other", domain.DemoteRevertWindow, at.Add(72*time.Hour), at); err == nil {
		t.Fatal("one account demoted another's address")
	}
}

// A DEADLINE IN THE PAST IS REFUSED.
//
// It would make the address available the instant it was applied, which is
// exactly the release this method exists to avoid.
func TestDemotingWithAPastDeadlineIsRefused(t *testing.T) {
	r := confirmedReservation(t, "subj_owner")
	for _, deadline := range []time.Time{at.Add(-time.Hour), at} {
		if err := r.Demote("subj_owner", domain.DemoteRevertWindow, deadline, at); err == nil {
			t.Errorf("a demotion expiring at %s was accepted", deadline)
		}
	}
}

// REPEATING A DEMOTION DOES NOT MOVE THE DEADLINE.
//
// A deadline a caller can push out by repeating one request is an address held
// indefinitely — the renewal Reserve refuses, for the same reason.
func TestRepeatingADemotionDoesNotExtendTheWindow(t *testing.T) {
	r := confirmedReservation(t, "subj_owner")
	closesAt := at.Add(72 * time.Hour)
	if err := r.Demote("subj_owner", domain.DemoteRevertWindow, closesAt, at); err != nil {
		t.Fatal(err)
	}
	r.ClearUncommitted()

	if err := r.Demote("subj_owner", domain.DemoteRevertWindow, at.Add(500*time.Hour), at); err != nil {
		t.Fatal(err)
	}
	if got := r.Uncommitted(); len(got) != 0 {
		t.Fatalf("repeating a demotion recorded %v; the window can be pushed out "+
			"indefinitely", typesOf(got))
	}
	if !r.Available(closesAt) {
		t.Fatal("the original deadline was overwritten")
	}
}

// RESTORE RE-VERIFIES, AND ONLY INSIDE THE WINDOW.
func TestRestoringInsideTheWindowAndRefusingAfterIt(t *testing.T) {
	closesAt := at.Add(72 * time.Hour)

	inside := confirmedReservation(t, "subj_owner")
	if err := inside.Demote("subj_owner", domain.DemoteRevertWindow, closesAt, at); err != nil {
		t.Fatal(err)
	}
	inside.ClearUncommitted()
	if err := inside.Restore("subj_owner", at.Add(time.Hour)); err != nil {
		t.Fatalf("restoring inside the window: %v", err)
	}
	if !inside.Verified() {
		t.Fatal("a restored claim is not verified, so it lapses on the old deadline and " +
			"the account loses the address it just took back")
	}
	if inside.Available(closesAt.Add(time.Hour)) {
		t.Error("a restored claim still becomes available when the old window closes")
	}

	after := confirmedReservation(t, "subj_owner")
	if err := after.Demote("subj_owner", domain.DemoteRevertWindow, closesAt, at); err != nil {
		t.Fatal(err)
	}
	if err := after.Restore("subj_owner", closesAt); err == nil {
		t.Fatal("a restore succeeded at the exact instant the window closed; the address " +
			"is available to anybody by then, so this takes it from whoever claimed it")
	}
}

// RESTORING SOMEBODY ELSE'S ADDRESS IS REFUSED.
func TestRestoringAnotherAccountsAddressIsRefused(t *testing.T) {
	r := confirmedReservation(t, "subj_owner")
	if err := r.Demote("subj_owner", domain.DemoteRevertWindow, at.Add(72*time.Hour), at); err != nil {
		t.Fatal(err)
	}
	if err := r.Restore("subj_other", at.Add(time.Hour)); err == nil {
		t.Fatal("one account restored another's address")
	}
}

// typesOf names a slice of recorded events, for failure messages.
func typesOf(es []eventsourcing.Event) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.EventType())
	}
	return out
}

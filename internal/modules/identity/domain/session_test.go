package domain_test

import (
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

const (
	idleWindow     = 30 * time.Minute
	absoluteWindow = 12 * time.Hour
)

func liveSession(t *testing.T) *domain.Session {
	t.Helper()
	s := eventsourcing.NewAggregate(domain.NewSession)
	err := s.Create(
		newID[ids.Session](t), "subj_1", "dev_1", contract.AAL2,
		at.Add(idleWindow), at.Add(absoluteWindow), at, false,
	)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return s
}

// The absolute deadline ends a session that is being actively used.
//
// This is the entire reason for having two deadlines. An attacker holding a
// stolen token keeps it warm, so a fresh idle deadline arrives with every
// request and idle expiry never fires for exactly the session that most needs to
// end. Here the idle deadline is refreshed right up to the moment of the check —
// exactly what a busy session looks like — and the session must still die.
func TestTheAbsoluteDeadlineEndsAnActivelyUsedSession(t *testing.T) {
	s := liveSession(t)

	// A session in constant use: idle deadline always a full window away.
	busyIdle := func(now time.Time) time.Time { return now.Add(idleWindow) }

	justBefore := at.Add(absoluteWindow - time.Second)
	if !s.LiveAt(justBefore, busyIdle(justBefore)) {
		t.Fatal("the session was dead before its absolute deadline")
	}

	deadline := at.Add(absoluteWindow)
	if s.LiveAt(deadline, busyIdle(deadline)) {
		t.Fatal("a session in constant use survived its absolute deadline: a stolen token " +
			"kept warm never expires, which is the failure two deadlines exist to prevent")
	}
	later := at.Add(absoluteWindow + time.Hour)
	if s.LiveAt(later, busyIdle(later)) {
		t.Fatal("the session was live an hour past its absolute deadline")
	}
}

// The idle deadline ends an untouched session, well inside the absolute window.
func TestTheIdleDeadlineEndsAnUntouchedSession(t *testing.T) {
	s := liveSession(t)
	idle := s.InitialIdleDeadline()

	if !s.LiveAt(at.Add(idleWindow-time.Second), idle) {
		t.Fatal("the session was dead before its idle deadline")
	}
	if s.LiveAt(at.Add(idleWindow), idle) {
		t.Fatal("an untouched session survived its idle deadline")
	}
	// And the absolute deadline is nowhere near: this is genuinely idle expiry.
	if !s.Live(at.Add(idleWindow)) {
		t.Fatal("the absolute deadline fired too, so this test proves nothing about idle expiry")
	}
}

// A deadline is exclusive: at exactly the deadline, the session is over.
//
// The off-by-one direction matters. `now.Before(deadline)` and
// `!now.After(deadline)` differ by one nanosecond, which sounds academic until a
// token minted with a deadline equal to a checkpoint is honoured by one code
// path and refused by another.
func TestASessionIsOverAtExactlyItsDeadline(t *testing.T) {
	s := liveSession(t)
	idle := s.InitialIdleDeadline()

	if s.LiveAt(at.Add(idleWindow), idle) {
		t.Error("the session was live at exactly its idle deadline")
	}
	if _, expired := s.ExpiredReason(at.Add(idleWindow), idle); !expired {
		t.Error("ExpiredReason disagrees with LiveAt at exactly the idle deadline")
	}
	if s.Live(at.Add(absoluteWindow)) {
		t.Error("the session was live at exactly its absolute deadline")
	}
}

// Which deadline fired is reported, because they mean different things.
func TestTheExpiryReasonDistinguishesTheTwoDeadlines(t *testing.T) {
	s := liveSession(t)
	idle := s.InitialIdleDeadline()

	absolute, expired := s.ExpiredReason(at.Add(idleWindow), idle)
	if !expired || absolute {
		t.Errorf("idle expiry reported as absolute=%v expired=%v", absolute, expired)
	}

	// Past BOTH deadlines, it must report absolute — that is the one worth
	// surfacing, and calling it idle would bury it among the routine ones.
	past := at.Add(absoluteWindow)
	absolute, expired = s.ExpiredReason(past, past.Add(idleWindow))
	if !expired || !absolute {
		t.Errorf("absolute expiry reported as absolute=%v expired=%v", absolute, expired)
	}

	if _, expired := s.ExpiredReason(at.Add(time.Minute), idle); expired {
		t.Error("a live session was reported as expired")
	}
}

// The log does not hold the current idle deadline, and Live must not pretend it
// does.
//
// The idle deadline moves on every request; recording that movement would make
// every authenticated read a write. So Live answers from the absolute deadline
// alone. A version that also consulted the CREATION-time idle deadline would
// pin every session to its first idle window — firing once, then never again for
// any session that outlives it.
func TestLiveDoesNotConsultTheCreationTimeIdleDeadline(t *testing.T) {
	s := liveSession(t)
	wellPastInitialIdle := at.Add(idleWindow + time.Hour)

	if !s.Live(wellPastInitialIdle) {
		t.Fatal("Live consulted the creation-time idle deadline: every session dies one idle " +
			"window after it was created, no matter how recently it was used")
	}
}

// An idle deadline beyond the absolute one is refused at creation.
//
// Otherwise the idle deadline never fires, and the session has one deadline
// while appearing to have two — which reads as more protection than exists.
func TestAnIdleDeadlineBeyondTheAbsoluteOneIsRefused(t *testing.T) {
	s := eventsourcing.NewAggregate(domain.NewSession)
	err := s.Create(
		newID[ids.Session](t), "subj_1", "dev_1", contract.AAL2,
		at.Add(absoluteWindow+time.Hour), at.Add(absoluteWindow), at, false,
	)
	if err == nil {
		t.Fatal("a session was created whose idle deadline can never be reached: it appears " +
			"to have two deadlines and has one")
	}
}

// A session may only record an assurance level the system can actually
// establish.
//
// AAL0 and AAL3 are both refused, for opposite reasons: nothing authenticated,
// and nothing this system can currently produce (IDENTITY-REVIEW C4). Either
// would lie to every min_aal comparison downstream — AAL3 in the dangerous
// direction, by satisfying a policy no authenticator here can meet.
func TestASessionCannotClaimAnUnreachableAssuranceLevel(t *testing.T) {
	for _, aal := range []contract.AssuranceLevel{contract.AAL0, contract.AAL3, 7, -1} {
		s := eventsourcing.NewAggregate(domain.NewSession)
		err := s.Create(
			newID[ids.Session](t), "subj_1", "dev_1", aal,
			at.Add(idleWindow), at.Add(absoluteWindow), at, false,
		)
		if err == nil {
			t.Errorf("a session recorded AAL%d, which nothing here can establish", aal)
		}
	}
}

// A step-up is proof for ONE operation, not a mode the session enters.
func TestAnElevationCoversOnlyItsOwnScope(t *testing.T) {
	s := liveSession(t)
	now := at.Add(time.Minute)
	if err := s.Elevate(contract.AAL2, "change_password", now.Add(5*time.Minute), now); err != nil {
		t.Fatalf("elevate: %v", err)
	}

	if !s.Elevated("change_password", now) {
		t.Fatal("the elevation did not cover the operation it was granted for")
	}
	if s.Elevated("create_api_key", now) {
		t.Fatal("an elevation for a password change authorised creating an API key: a step-up " +
			"is proof for one dangerous operation, not a mode")
	}
	if s.Elevated("", now) {
		t.Error("an empty scope matched an elevation")
	}
}

// An elevation expires on its own, before the session does.
func TestAnElevationExpiresIndependentlyOfItsSession(t *testing.T) {
	s := liveSession(t)
	now := at.Add(time.Minute)
	if err := s.Elevate(contract.AAL2, "change_password", now.Add(5*time.Minute), now); err != nil {
		t.Fatalf("elevate: %v", err)
	}

	if s.Elevated("change_password", now.Add(5*time.Minute)) {
		t.Fatal("the elevation outlived its own deadline")
	}
	if !s.Live(now.Add(5 * time.Minute)) {
		t.Fatal("the session died with the elevation; they are supposed to be independent")
	}
}

// An elevation may not outlive the session it elevates.
//
// Without this, a step-up taken near the end of a session leaves a window in
// which the elevation is valid and the session is not — and any code that
// consulted only the elevation would honour it.
func TestAnElevationCannotOutliveItsSession(t *testing.T) {
	s := liveSession(t)
	now := at.Add(time.Minute)
	err := s.Elevate(contract.AAL2, "change_password", at.Add(absoluteWindow+time.Hour), now)
	if err == nil {
		t.Fatal("an elevation was granted past the session's absolute deadline: code that " +
			"checks the elevation alone would honour a dead session")
	}
}

// An elevation on a dead session is refused.
func TestADeadSessionCannotBeElevated(t *testing.T) {
	s := liveSession(t)
	if err := s.Revoke("subj_1", "signed out", at.Add(time.Minute)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := s.Elevate(contract.AAL2, "change_password", at.Add(time.Hour), at.Add(2*time.Minute)); err == nil {
		t.Fatal("a revoked session was elevated")
	}
	if s.Elevated("change_password", at.Add(2*time.Minute)) {
		t.Fatal("a revoked session reports an elevation")
	}
}

// Revocation is idempotent and records exactly one event.
//
// "Revoke every session" races with the user signing out on one device. Making
// the second revocation an error turns that race into a partial failure, and the
// caller cannot tell which sessions actually ended.
func TestRevokingTwiceRecordsOneEvent(t *testing.T) {
	s := liveSession(t)
	now := at.Add(time.Minute)

	if err := s.Revoke("subj_1", "signed out", now); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	if err := s.Revoke("op_1", "password reset", now); err != nil {
		t.Fatalf("second revoke returned an error: %v", err)
	}
	if n := countSessionEvents[*contract.SessionRevoked](s); n != 1 {
		t.Fatalf("recorded %d revocations, want 1: each one produces a tombstone the access "+
			"projector must confirm (ADR-045)", n)
	}
	if s.Live(now) {
		t.Error("a revoked session is still live")
	}
}

// An expired session is not revoked.
//
// Recording a revocation for a session nothing can use produces a tombstone with
// a confirmation that will never arrive — and reaching a tombstone's TTL is an
// alert, not routine (ADR-045).
func TestAnExpiredSessionIsNotRevoked(t *testing.T) {
	s := liveSession(t)
	if err := s.Expire(at.Add(absoluteWindow), at.Add(absoluteWindow+idleWindow)); err != nil {
		t.Fatalf("expire: %v", err)
	}
	if err := s.Revoke("subj_1", "signed out", at.Add(absoluteWindow+time.Minute)); err != nil {
		t.Fatalf("revoking an expired session errored: %v", err)
	}
	if n := countSessionEvents[*contract.SessionRevoked](s); n != 0 {
		t.Fatalf("recorded %d revocations for an already-expired session: the access projector "+
			"gets a tombstone whose confirmation never arrives", n)
	}
}

// Expiry is refused before a deadline is reached, so the sweep cannot end a live
// session early.
func TestALiveSessionCannotBeExpired(t *testing.T) {
	s := liveSession(t)
	if err := s.Expire(at.Add(time.Minute), at.Add(idleWindow)); err == nil {
		t.Fatal("a live session was expired: the sweep can end sessions that have not timed out")
	}
}

// A session's state survives a rebuild from its own events.
func TestReplayingASessionReproducesItsState(t *testing.T) {
	live := liveSession(t)
	now := at.Add(time.Minute)
	if err := live.Elevate(contract.AAL2, "change_password", now.Add(5*time.Minute), now); err != nil {
		t.Fatalf("elevate: %v", err)
	}

	rebuilt := eventsourcing.NewAggregate(domain.NewSession)
	for _, e := range live.Uncommitted() {
		rebuilt.Apply(e)
	}

	if live.State() != rebuilt.State() {
		t.Errorf("state: live %v, rebuilt %v", live.State(), rebuilt.State())
	}
	if live.AAL() != rebuilt.AAL() {
		t.Errorf("aal: live %v, rebuilt %v", live.AAL(), rebuilt.AAL())
	}
	if !live.AbsoluteExpiresAt().Equal(rebuilt.AbsoluteExpiresAt()) {
		t.Errorf("absolute deadline: live %v, rebuilt %v",
			live.AbsoluteExpiresAt(), rebuilt.AbsoluteExpiresAt())
	}
	if live.Elevated("change_password", now) != rebuilt.Elevated("change_password", now) {
		t.Error("the elevation did not survive the rebuild: a step-up is forgotten on every " +
			"restart, and the user is re-challenged mid-ceremony")
	}
}

// A session that has never been created is not live, and cannot be revoked.
//
// The zero value must deny. A Session nobody loaded — because the id was
// unknown, or the load silently failed — must not be usable.
func TestTheZeroSessionIsNotLive(t *testing.T) {
	s := eventsourcing.NewAggregate(domain.NewSession)
	if s.Live(at) {
		t.Fatal("a session that was never created reports as live: an unknown token would " +
			"authenticate")
	}
	if err := s.Revoke("subj_1", "x", at); err == nil {
		t.Error("a nonexistent session was revoked")
	}
}

func countSessionEvents[T eventsourcing.Event](s *domain.Session) int {
	var n int
	for _, e := range s.Uncommitted() {
		if _, ok := e.(T); ok {
			n++
		}
	}
	return n
}

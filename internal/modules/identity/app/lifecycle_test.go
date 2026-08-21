package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

// lifeHarness builds the lifecycle use case over the REAL session-revocation
// planner.
//
// The planner is *Authentication itself, not a fake, and that is the point. The
// property this file exists to hold is that a deactivation and its revocations
// reach the log in ONE append; a fake planner would let the test assert the
// shape of its own stub instead of the shape of the write.
type lifeHarness struct {
	*authHarness
	life *Lifecycle
}

func newLifeHarness(t *testing.T) *lifeHarness {
	t.Helper()
	h := newAuthHarness(t)

	life, err := NewLifecycle(LifecycleDeps{
		Clock:    h.clock,
		Subjects: fakeDirectory{user: h.userID, only: h.subjectID},
		Users: loaderFunc[*domain.User](func(_ context.Context, key string) (*domain.User, error) {
			if key != h.userID.String() {
				return eventsourcing.NewAggregate(domain.New), nil
			}
			return h.user, nil
		}),
		Appender:    h.appender,
		Schemas:     identitySchemas(),
		Revocations: h.auth,
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("building the lifecycle use case: %v", err)
	}
	return &lifeHarness{authHarness: h, life: life}
}

func (h *lifeHarness) deactivate(t *testing.T, key string) (DeactivateAccountResult, error) {
	t.Helper()
	return h.life.Deactivate(context.Background(), DeactivateAccountCommand{
		SubjectID: h.subjectID, IdempotencyKey: key,
	})
}

// appendedTypes reports the event types written per append CALL, so a test can
// tell "one atomic write" apart from "two writes that both happened".
func appendedTypes(a *authAppender) [][]string {
	out := make([][]string, 0, len(a.calls))
	for _, call := range a.calls {
		var types []string
		for _, stream := range call {
			for _, e := range stream.Events {
				types = append(types, e.Event.EventType())
			}
		}
		out = append(out, types)
	}
	return out
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

// A nil collaborator is refused at construction, not discovered on the first
// request. Two of these have consequences that no other test in this package
// would show: without a schema registry every event is stored at version 0 and
// the account can never be loaded back, and without a revocation planner the
// account is switched off in the log while every session on it keeps working.
func TestNewLifecycleRefusesAPartialWiring(t *testing.T) {
	t.Parallel()

	full := func() LifecycleDeps {
		return LifecycleDeps{
			Clock:       clock.NewFixed(testNow),
			Subjects:    fakeDirectory{},
			Users:       staticLoader[*domain.User](nil, nil),
			Appender:    &authAppender{journal: new([]string)},
			Schemas:     identitySchemas(),
			Revocations: stubPlanner{},
		}
	}
	for name, break_ := range map[string]func(*LifecycleDeps){
		"no clock":              func(d *LifecycleDeps) { d.Clock = nil },
		"no user directory":     func(d *LifecycleDeps) { d.Subjects = nil },
		"no user loader":        func(d *LifecycleDeps) { d.Users = nil },
		"no appender":           func(d *LifecycleDeps) { d.Appender = nil },
		"no schema registry":    func(d *LifecycleDeps) { d.Schemas = nil },
		"no revocation planner": func(d *LifecycleDeps) { d.Revocations = nil },
		"a negative grace period": func(d *LifecycleDeps) {
			d.GracePeriod = -time.Second
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			deps := full()
			break_(&deps)
			if _, err := NewLifecycle(deps); err == nil {
				t.Fatal("a partially wired lifecycle was accepted")
			}
		})
	}

	t.Run("a zero grace period takes the default", func(t *testing.T) {
		t.Parallel()
		l, err := NewLifecycle(full())
		if err != nil {
			t.Fatalf("building: %v", err)
		}
		if l.grace != DefaultDeletionGracePeriod {
			t.Errorf("grace = %s, want the %s default", l.grace, DefaultDeletionGracePeriod)
		}
	})
}

// ---------------------------------------------------------------------------
// Deactivate
// ---------------------------------------------------------------------------

// The account and every session on it are written in ONE append.
//
// This is the property the whole use case is shaped around. Ask what it would do
// if the feature were removed: split the write into two appends and this fails on
// the call count, naming the two halves — which is the failure that matters,
// because the split version leaves a window in which the account is off in the
// log and its sessions are still resolving. Nothing in the request pipeline reads
// an account's state, so a session that survives a deactivation has full API
// access.
func TestDeactivationAndItsRevocationsAreOneAtomicAppend(t *testing.T) {
	h := newLifeHarness(t)
	first := h.liveSession(t, h.subjectID)
	second := h.liveSession(t, h.subjectID)
	h.live.sessions = []ids.SessionID{first, second}

	res, err := h.deactivate(t, "idem-deactivate")
	if err != nil {
		t.Fatalf("deactivating: %v", err)
	}
	if !res.Changed {
		t.Error("the deactivation reported no change")
	}
	if res.SessionsRevoked != 2 || res.SessionsScanned != 2 {
		t.Errorf("revoked=%d scanned=%d, want 2 and 2", res.SessionsRevoked, res.SessionsScanned)
	}

	calls := appendedTypes(h.appender)
	if len(calls) != 1 {
		t.Fatalf("the deactivation wrote %d appends (%v), want exactly 1 — two writes leave "+
			"a window in which the account is off in the log and its sessions still "+
			"resolve, and nothing in the request pipeline reads an account's state",
			len(calls), calls)
	}
	want := []string{
		(&contract.UserDeactivated{}).EventType(),
		(&contract.SessionRevoked{}).EventType(),
		(&contract.SessionRevoked{}).EventType(),
	}
	got := calls[0]
	if len(got) != len(want) {
		t.Fatalf("the append carries %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("the append carries %v, want %v — the account entry leads, so a reader "+
				"of the log sees the decision before its consequences", got, want)
		}
	}

	// And the account entry carries a PRECONDITION. Without it two concurrent
	// deactivations both write, and so does a deactivation racing any other change
	// to the account.
	accountEntry := h.appender.calls[0][0]
	if accountEntry.Expected == eventsourcing.AnyRevision() {
		t.Error("the account entry expects any revision; two concurrent deactivations would " +
			"then both append")
	}
}

// The session that asked is revoked too.
//
// A deactivation spares nothing. Sparing the caller would leave the account
// switched off everywhere except on the device that switched it off, which is not
// what the person asked for and not what they were told.
func TestDeactivationSparesNoSessionIncludingTheCallersOwn(t *testing.T) {
	h := newLifeHarness(t)
	mine := h.liveSession(t, h.subjectID)
	h.live.sessions = []ids.SessionID{mine}

	if _, err := h.deactivate(t, "idem-spare-nothing"); err != nil {
		t.Fatalf("deactivating: %v", err)
	}

	var revoked []string
	for _, e := range h.appender.events() {
		if r, ok := e.(*contract.SessionRevoked); ok {
			revoked = append(revoked, r.SessionID)
			if r.Reason != RevokeReasonDeactivated {
				t.Errorf("revocation reason is %q, want %q", r.Reason, RevokeReasonDeactivated)
			}
		}
	}
	if len(revoked) != 1 || revoked[0] != mine.String() {
		t.Fatalf("revoked %v, want exactly the caller's own session %s", revoked, mine)
	}
}

// The authorization cache is invalidated BEFORE the append.
//
// The other order leaves a cached allow decision alive for a principal whose
// sessions have just been destroyed, and a retry after a failed append skips the
// invalidation entirely.
func TestDeactivationInvalidatesAuthorizationBeforeItWrites(t *testing.T) {
	h := newLifeHarness(t)
	h.live.sessions = []ids.SessionID{h.liveSession(t, h.subjectID)}

	if _, err := h.deactivate(t, "idem-order"); err != nil {
		t.Fatalf("deactivating: %v", err)
	}
	if len(h.journal) < 2 || h.journal[0] != "epoch" || h.journal[1] != "append" {
		t.Fatalf("journal is %v, want the epoch bump before the append", h.journal)
	}
}

// A retry writes nothing new and STILL sweeps the sessions.
//
// The sweep on the idempotent path is not defensive tidying: a login whose
// ceremony began before the first deactivation committed can mint a session the
// first sweep's work list never saw, and this is the only command that will ever
// look for it.
func TestASecondDeactivationRecordsNothingAndStillSweeps(t *testing.T) {
	h := newLifeHarness(t)
	if _, err := h.deactivate(t, "idem-first"); err != nil {
		t.Fatalf("first deactivation: %v", err)
	}
	h.user.ClearUncommitted()
	h.appender.calls = nil

	// A session that appeared after the first sweep.
	late := h.liveSession(t, h.subjectID)
	h.live.sessions = []ids.SessionID{late}

	res, err := h.deactivate(t, "idem-second")
	if err != nil {
		t.Fatalf("second deactivation: %v", err)
	}
	if res.Changed {
		t.Error("a second deactivation reported a change")
	}
	if res.SessionsRevoked != 1 {
		t.Fatalf("the retry revoked %d sessions, want 1 — a session minted by a login that "+
			"raced the first deactivation would otherwise survive it forever",
			res.SessionsRevoked)
	}
	for _, e := range h.appender.events() {
		if _, ok := e.(*contract.UserDeactivated); ok {
			t.Error("a second deactivation appended another UserDeactivated")
		}
	}
}

// A suspended account is refused, and nothing is written.
//
// Deactivating a suspension would be a downgrade the holder performed on an
// administrative decision.
func TestASuspendedAccountCannotBeDeactivated(t *testing.T) {
	h := newLifeHarness(t)
	mustDo(t, h.user.Suspend("op_1", "abuse", testNow))
	h.user.ClearUncommitted()
	h.live.sessions = []ids.SessionID{h.liveSession(t, h.subjectID)}

	if _, err := h.deactivate(t, "idem-suspended"); err == nil {
		t.Fatal("a suspended account was deactivated")
	}
	if len(h.appender.calls) != 0 {
		t.Errorf("a refused deactivation wrote %d append(s)", len(h.appender.calls))
	}
}

// A lost expected-revision race writes NOTHING — sessions included — and is
// reported as a conflict the caller can retry.
func TestADeactivationThatLosesTheRaceWritesNothing(t *testing.T) {
	h := newLifeHarness(t)
	h.live.sessions = []ids.SessionID{h.liveSession(t, h.subjectID)}
	h.appender.err = fmt.Errorf("%w: someone else wrote first",
		eventsourcing.ErrWrongExpectedRevision)

	_, err := h.deactivate(t, "idem-race")
	if err == nil {
		t.Fatal("a deactivation that lost its precondition reported success")
	}
	if errs.ReasonOf(err) != errs.Conflict {
		t.Errorf("refused with %s, want CONFLICT — the caller is entitled to retry",
			errs.ReasonOf(err))
	}
	// The aggregate keeps its uncommitted event, so a retry re-decides against a
	// reloaded stream rather than believing this one landed.
	if len(h.user.Uncommitted()) == 0 {
		t.Error("the failed deactivation cleared the aggregate's uncommitted events")
	}
}

// An unknown subject is NotFound, and never an internal error.
func TestDeactivateRefusesAnUnknownSubject(t *testing.T) {
	h := newLifeHarness(t)
	_, err := h.life.Deactivate(context.Background(), DeactivateAccountCommand{
		SubjectID: "subj_someone_else", IdempotencyKey: "idem-unknown",
	})
	if errs.ReasonOf(err) != errs.NotFound {
		t.Fatalf("refused with %v, want NOT_FOUND", err)
	}
}

// Both commands refuse a missing idempotency key before anything is loaded.
func TestTheLifecycleCommandsRequireAnIdempotencyKey(t *testing.T) {
	h := newLifeHarness(t)
	if _, err := h.deactivate(t, ""); errs.ReasonOf(err) != errs.ValidationFailed {
		t.Errorf("Deactivate without a key: %v, want VALIDATION_FAILED", err)
	}
	if _, err := h.life.RequestDeletion(context.Background(),
		RequestAccountDeletionCommand{SubjectID: h.subjectID}); errs.ReasonOf(err) != errs.ValidationFailed {
		t.Errorf("RequestDeletion without a key: %v, want VALIDATION_FAILED", err)
	}
	if len(h.appender.calls) != 0 {
		t.Error("a command refused for a missing key still wrote to the log")
	}
}

// ---------------------------------------------------------------------------
// RequestDeletion
// ---------------------------------------------------------------------------

// A deletion request appends one event, revokes nothing, and returns the
// deadline.
//
// The revocation assertion is the interesting half. Every OTHER destructive
// command in this module voids sessions; this one deliberately does not, because
// the grace period exists so the person can change their mind and signing them
// out of an account that still works would teach them the request took effect
// immediately.
func TestRequestDeletionAppendsOneEventAndSignsNobodyOut(t *testing.T) {
	h := newLifeHarness(t)
	h.live.sessions = []ids.SessionID{h.liveSession(t, h.subjectID)}

	res, err := h.life.RequestDeletion(context.Background(), RequestAccountDeletionCommand{
		SubjectID: h.subjectID, IdempotencyKey: "idem-delete",
	})
	if err != nil {
		t.Fatalf("requesting deletion: %v", err)
	}
	if !res.Changed {
		t.Error("the request reported no change")
	}
	want := testNow.Add(DefaultDeletionGracePeriod)
	if !res.ScheduledFor.Equal(want) {
		t.Errorf("scheduled for %s, want %s", res.ScheduledFor, want)
	}

	calls := appendedTypes(h.appender)
	if len(calls) != 1 || len(calls[0]) != 1 ||
		calls[0][0] != (&contract.UserDeletionRequested{}).EventType() {
		t.Fatalf("the request wrote %v, want exactly one UserDeletionRequested", calls)
	}
	for _, e := range h.appender.events() {
		if _, ok := e.(*contract.SessionRevoked); ok {
			t.Error("a deletion request revoked a session; the grace period exists so the " +
				"person can change their mind, and an account that still works must not " +
				"sign them out")
		}
	}
	if len(h.live.asked) != 0 {
		t.Error("a deletion request asked for the account's live sessions at all")
	}
}

// A repeated request records nothing and returns the ORIGINAL deadline.
func TestASecondDeletionRequestKeepsTheFirstDeadline(t *testing.T) {
	h := newLifeHarness(t)
	first, err := h.life.RequestDeletion(context.Background(), RequestAccountDeletionCommand{
		SubjectID: h.subjectID, IdempotencyKey: "idem-delete-1",
	})
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	h.appender.calls = nil
	h.clock.Set(testNow.Add(48 * time.Hour))

	second, err := h.life.RequestDeletion(context.Background(), RequestAccountDeletionCommand{
		SubjectID: h.subjectID, IdempotencyKey: "idem-delete-2",
	})
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	if second.Changed {
		t.Error("a repeated deletion request reported a change")
	}
	if !second.ScheduledFor.Equal(first.ScheduledFor) {
		t.Errorf("the deadline moved from %s to %s; anyone holding the session could then "+
			"push erasure out forever, and the date already mailed would be wrong",
			first.ScheduledFor, second.ScheduledFor)
	}
	if len(h.appender.calls) != 0 {
		t.Error("a repeated deletion request wrote to the log")
	}
}

// The event carries a pseudonym, an actor, and two timestamps — and nothing that
// could identify a person (ADR-002).
func TestTheDeletionRequestEventCarriesNoPersonalData(t *testing.T) {
	h := newLifeHarness(t)
	if _, err := h.life.RequestDeletion(context.Background(), RequestAccountDeletionCommand{
		SubjectID: h.subjectID, IdempotencyKey: "idem-shape",
	}); err != nil {
		t.Fatalf("requesting deletion: %v", err)
	}
	e := eventOf[*contract.UserDeletionRequested](t, h.appender)
	if e.SubjectID != h.subjectID {
		t.Errorf("subject = %q, want %q", e.SubjectID, h.subjectID)
	}
	if e.ActorID != h.subjectID {
		t.Errorf("actor = %q, want the holder's own pseudonym %q — an actor a caller could "+
			"choose would let a request claim to be somebody else's action in a permanent "+
			"log", e.ActorID, h.subjectID)
	}
	if e.ScheduledFor.Before(e.RequestedAt) {
		t.Errorf("the deadline %s precedes the request %s", e.ScheduledFor, e.RequestedAt)
	}
}

// ---------------------------------------------------------------------------
// Stubs used only here
// ---------------------------------------------------------------------------

type stubPlanner struct{}

func (stubPlanner) PlanRevokeAllSessions(
	context.Context, RevokeAllSessionsCommand,
) (SessionRevocationPlan, error) {
	return SessionRevocationPlan{}, nil
}

func (stubPlanner) InvalidateAuthorization(context.Context, string) error { return nil }

var _ SessionRevocationPlanner = stubPlanner{}

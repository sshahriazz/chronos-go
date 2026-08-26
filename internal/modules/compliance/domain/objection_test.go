package domain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/contract"
	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

var objectedAt = time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC)

func newObjection() *domain.Objection {
	return eventsourcing.NewAggregate(domain.NewObjection)
}

func replayObjection(t *testing.T, events ...eventsourcing.Event) *domain.Objection {
	t.Helper()
	o := newObjection()
	for _, e := range events {
		o.Apply(e)
	}
	return o
}

// TestObjectingToOnePurposeLeavesTheOthersStanding.
//
// This is the whole distinction from Article 18 restriction, expressed in the
// aggregate. A restriction is one flag and halts everything but storage; an
// objection is a SET, and stopping one purpose must not touch another the person
// never mentioned.
//
// If this ever fails, objection has collapsed into restriction and one of the
// two should be deleted rather than kept as a synonym for the other.
func TestObjectingToOnePurposeLeavesTheOthersStanding(t *testing.T) {
	o := newObjection()
	if err := o.Object("subj_1", "subj_1", domain.PurposeActivityNotifications,
		objectedAt); err != nil {
		t.Fatalf("objecting: %v", err)
	}
	live := replayObjection(t, o.Uncommitted()...)

	if _, stopped := live.Objected(domain.PurposeActivityNotifications); !stopped {
		t.Fatal("the objection did not survive a replay")
	}
	if _, stopped := live.Objected(domain.PurposeProductUpdates); stopped {
		t.Error("objecting to activity notifications also stopped product updates; a " +
			"per-purpose right that stops everything is Article 18 wearing Article 21's " +
			"name")
	}
}

// TestWithdrawingOnePurposeLeavesTheOtherStopped.
//
// The same property in reverse, and the one the composite primary key in
// `processing_objection_view` also guards. A withdrawal that released
// everything would resume processing the person is still objecting to — and
// they would have no reason to check, having asked for only one thing back.
func TestWithdrawingOnePurposeLeavesTheOtherStopped(t *testing.T) {
	o := newObjection()
	if err := o.Object("subj_1", "subj_1", domain.PurposeActivityNotifications, objectedAt); err != nil {
		t.Fatal(err)
	}
	if err := o.Object("subj_1", "subj_1", domain.PurposeProductUpdates, objectedAt); err != nil {
		t.Fatal(err)
	}
	live := replayObjection(t, o.Uncommitted()...)

	if err := live.Withdraw("subj_1", "subj_1", domain.PurposeProductUpdates,
		objectedAt.Add(time.Hour)); err != nil {
		t.Fatalf("withdrawing: %v", err)
	}
	after := replayObjection(t, append(o.Uncommitted(), live.Uncommitted()...)...)

	if _, stopped := after.Objected(domain.PurposeProductUpdates); stopped {
		t.Error("the withdrawn objection still stands")
	}
	if _, stopped := after.Objected(domain.PurposeActivityNotifications); !stopped {
		t.Error("withdrawing one objection released the other, resuming processing the " +
			"person is still objecting to")
	}
}

// TestObjectingTwiceRecordsOnceAndKeepsTheFirstInstant.
//
// The date is reported to the person — "you objected to this on the 3rd" — and a
// repeated call must not move it. The same rule Restriction and Deferral follow.
func TestObjectingTwiceRecordsOnceAndKeepsTheFirstInstant(t *testing.T) {
	o := newObjection()
	if err := o.Object("subj_1", "subj_1", domain.PurposeActivityNotifications, objectedAt); err != nil {
		t.Fatal(err)
	}
	live := replayObjection(t, o.Uncommitted()...)

	if err := live.Object("subj_1", "subj_1", domain.PurposeActivityNotifications,
		objectedAt.Add(48*time.Hour)); err != nil {
		t.Fatalf("objecting twice: %v", err)
	}
	if n := len(live.Uncommitted()); n != 0 {
		t.Fatalf("a second objection recorded %d events", n)
	}
	when, _ := live.Objected(domain.PurposeActivityNotifications)
	if !when.Equal(objectedAt) {
		t.Errorf("the instant moved to %v; it has been reported to somebody", when)
	}
}

// TestWithdrawingWhatWasNeverObjectedToIsFree.
//
// Asking for a state that already holds. Erroring would make the control fail
// for anybody who clicked it twice, which is the reason Restriction.Lift is
// idempotent too.
func TestWithdrawingWhatWasNeverObjectedToIsFree(t *testing.T) {
	o := newObjection()
	if err := o.Withdraw("subj_1", "subj_1", domain.PurposeProductUpdates, objectedAt); err != nil {
		t.Fatalf("withdrawing nothing errored: %v", err)
	}
	if n := len(o.Uncommitted()); n != 0 {
		t.Errorf("it recorded %d events", n)
	}
}

// TestAnUnenforceablePurposeIsRefused.
//
// An objection to a purpose nothing consults is a PROMISE: the person is told
// the processing stopped, no code anywhere reads the record, and the failure is
// invisible from both sides — no error, no metric, and mail that keeps arriving
// for reasons the recipient now believes were ruled out.
func TestAnUnenforceablePurposeIsRefused(t *testing.T) {
	o := newObjection()
	err := o.Object("subj_1", "subj_1", domain.Purpose("targeted_advertising"), objectedAt)
	if err == nil {
		t.Fatal("an objection to a purpose this system cannot stop was recorded")
	}
	if !strings.Contains(err.Error(), "legitimate interests") {
		t.Errorf("the refusal does not say why the set is narrow: %v", err)
	}
	if len(o.Uncommitted()) != 0 {
		t.Error("it recorded an event anyway")
	}
}

// TestAReplayAppliesAPurposeTheWriteWouldRefuse.
//
// The asymmetry between Apply and Object, and it is the one that keeps a replay
// safe. A purpose retired from the Go constants is still an objection somebody
// made; a projector that skipped it would resume processing they stopped —
// silently, and only for the people who objected earliest.
func TestAReplayAppliesAPurposeTheWriteWouldRefuse(t *testing.T) {
	retired := domain.Purpose("a_purpose_this_build_retired")
	live := replayObjection(t, &contract.ProcessingObjected{
		SubjectID: "subj_1", Purpose: string(retired),
		ActorID: "subj_1", ObjectedAt: objectedAt,
	})

	if _, stopped := live.Objected(retired); !stopped {
		t.Fatal("a replay dropped an objection whose purpose this build no longer " +
			"declares, so processing the person stopped would resume with no event and " +
			"no log line")
	}
	// And it can still be released — the one direction of this right that
	// belongs to the person alone.
	if err := live.Withdraw("subj_1", "subj_1", retired, objectedAt.Add(time.Hour)); err != nil {
		t.Fatalf("withdrawing a retired purpose: %v", err)
	}
	if len(live.Uncommitted()) != 1 {
		t.Error("the withdrawal recorded nothing, so the person cannot release an " +
			"instruction that is still being enforced")
	}
}

// TestTheStandingListIsOrderedByWhenTheObjectionWasMade.
//
// It is rendered to the person as a history. A map iteration order leaking into
// a response would make an otherwise stable list shuffle between polls, which
// reads as the system changing its mind about what somebody asked for.
func TestTheStandingListIsStablyOrdered(t *testing.T) {
	live := replayObjection(t,
		&contract.ProcessingObjected{
			SubjectID: "subj_1", Purpose: string(domain.PurposeProductUpdates),
			ObjectedAt: objectedAt.Add(48 * time.Hour),
		},
		&contract.ProcessingObjected{
			SubjectID: "subj_1", Purpose: string(domain.PurposeActivityNotifications),
			ObjectedAt: objectedAt,
		},
	)

	for range 5 {
		got := live.Purposes()
		if len(got) != 2 {
			t.Fatalf("listed %d purposes, want 2", len(got))
		}
		if got[0] != domain.PurposeActivityNotifications {
			t.Fatalf("the list starts with %q; it is ordered by when the objection was "+
				"made, and the activity one is two days older", got[0])
		}
	}
}

// TestAnObjectionNeedsBothASubjectAndAnActor.
func TestAnObjectionNeedsBothASubjectAndAnActor(t *testing.T) {
	if err := newObjection().Object("", "subj_1",
		domain.PurposeActivityNotifications, objectedAt); err == nil {
		t.Error("an objection with no subject was recorded")
	}
	if err := newObjection().Object("subj_1", "",
		domain.PurposeActivityNotifications, objectedAt); err == nil {
		t.Error("an objection with no actor was recorded")
	}
}

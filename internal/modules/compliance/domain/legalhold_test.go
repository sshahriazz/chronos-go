package domain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/contract"
	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

var heldAt = time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC)

func newHold() *domain.LegalHold {
	return eventsourcing.NewAggregate(domain.NewLegalHold)
}

// replayHold rebuilds from what was recorded, so these assert on the EVENTS
// rather than on the struct the command just mutated.
func replayHold(t *testing.T, events ...eventsourcing.Event) *domain.LegalHold {
	t.Helper()
	h := newHold()
	for _, e := range events {
		h.Apply(e)
	}
	return h
}

// TestASubjectNobodyHeldIsNotHeld is the default, and it is the permissive one
// — which is the opposite of this codebase's usual instinct and deliberate.
//
// A hold is an EXCEPTION to a statutory right. Defaulting to "held" would
// default to withholding a right nobody claimed, and it would do so for every
// subject in the system, silently, because the erasure gate would refuse them
// all.
func TestASubjectNobodyHeldIsNotHeld(t *testing.T) {
	h := newHold()
	if h.Held() {
		t.Error("a subject with no recorded hold reads as held")
	}
	if h.Exists() {
		t.Error("a subject with no recorded hold reads as existing")
	}
}

// TestPlacingAHoldRecordsTheOwnerAndTheMatter.
//
// Both are compliance.md §7's requirement — "a recorded justification and an
// owner" — and both survive a replay, which is what makes them facts rather
// than fields somebody set.
func TestPlacingAHoldRecordsTheOwnerAndTheMatter(t *testing.T) {
	h := newHold()
	if err := h.Place("subj_1", "opr_1", "litigation 2026-4711", heldAt); err != nil {
		t.Fatalf("placing: %v", err)
	}

	pending := h.Uncommitted()
	if len(pending) != 1 {
		t.Fatalf("recorded %d events, want 1", len(pending))
	}
	ev, ok := pending[0].(*contract.LegalHoldPlaced)
	if !ok {
		t.Fatalf("recorded %T", pending[0])
	}
	if ev.PlacedBy != "opr_1" {
		t.Errorf("owner = %q", ev.PlacedBy)
	}
	if ev.Matter != "litigation 2026-4711" {
		t.Errorf("matter = %q", ev.Matter)
	}
	if ev.PlacedAt.Location() != time.UTC {
		t.Errorf("recorded in %v, not UTC", ev.PlacedAt.Location())
	}

	replayed := replayHold(t, pending...)
	if !replayed.Held() {
		t.Fatal("the hold did not survive a replay")
	}
	if replayed.Matter() != "litigation 2026-4711" {
		t.Errorf("matter after replay = %q", replayed.Matter())
	}
	if replayed.PlacedBy() != "opr_1" {
		t.Errorf("owner after replay = %q", replayed.PlacedBy())
	}
}

// TestAHoldNeedsAnOwnerAndAMatter is §7's requirement, refused rather than
// defaulted.
//
// A hold placed by nobody is one nobody can be asked about, and one with no
// matter is one nobody can close — the lift would have nothing to check against.
func TestAHoldNeedsAnOwnerAndAMatter(t *testing.T) {
	cases := []struct {
		name, subject, owner, matter, want string
	}{
		{"no subject", "", "opr_1", "m", "needs a subject"},
		{"no owner", "subj_1", "", "m", "needs an owner"},
		{"no matter", "subj_1", "opr_1", "", "needs a matter"},
		{"a matter longer than the field", "subj_1", "opr_1",
			strings.Repeat("x", domain.MaxMatterLength+1), "at most"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHold()
			err := h.Place(tc.subject, tc.owner, tc.matter, heldAt)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refused for the wrong reason: %v", err)
			}
			if len(h.Uncommitted()) != 0 {
				t.Error("a refused hold still recorded an event")
			}
		})
	}
}

// TestASecondHoldIsRefusedRatherThanAbsorbed is the most important assertion
// here, and it is a refusal where idempotency would be the obvious choice.
//
// One stream per subject means one hold at a time. If a second matter's hold
// were silently absorbed — "already held, record nothing, succeed" — then
// lifting the FIRST matter would release the subject while the second was still
// live. The release would look correct to everybody, because nothing would
// record that two matters ever overlapped.
//
// Refusing surfaces the limitation at the moment somebody hits it, which is
// when the decision to build matter-keyed holds should be taken. Absorbing it
// would defer the discovery to the erasure that should not have run.
func TestASecondHoldIsRefusedRatherThanAbsorbed(t *testing.T) {
	h := newHold()
	if err := h.Place("subj_1", "opr_1", "litigation 2026-4711", heldAt); err != nil {
		t.Fatalf("placing: %v", err)
	}
	held := replayHold(t, h.Uncommitted()...)

	err := held.Place("subj_1", "opr_2", "regulator DPA-88", heldAt.Add(time.Hour))
	if err == nil {
		t.Fatal("a second hold was absorbed. Lifting the first matter would then release " +
			"the subject while the second was still live, and nothing would record that " +
			"two matters overlapped")
	}
	if !strings.Contains(err.Error(), "already held") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
	// And the FIRST matter is named, so whoever hit this knows what to ask
	// about.
	if !strings.Contains(err.Error(), "litigation 2026-4711") {
		t.Errorf("the refusal does not name the standing matter: %v", err)
	}
	if len(held.Uncommitted()) != 0 {
		t.Error("a refused second hold still recorded an event")
	}
}

// TestLiftingIsIdempotentWhilePlacingIsNot is the asymmetry, asserted as a
// pair — because either alone reads as an inconsistency.
//
// The two directions have different costs when they are wrong. A hold placed
// twice and absorbed leaves data unprotected later, under a matter nobody
// tracked. A lift that does nothing leaves data protected that need not be,
// which the next lift fixes.
func TestLiftingIsIdempotentWhilePlacingIsNot(t *testing.T) {
	h := newHold()
	if err := h.Lift("subj_1", "opr_1", heldAt); err != nil {
		t.Fatalf("lifting a hold that does not exist: %v", err)
	}
	if len(h.Uncommitted()) != 0 {
		t.Error("lifting nothing recorded an event")
	}

	if err := h.Place("subj_1", "opr_1", "m-1", heldAt); err != nil {
		t.Fatalf("placing: %v", err)
	}
	held := replayHold(t, h.Uncommitted()...)

	if err := held.Lift("subj_1", "opr_2", heldAt.Add(time.Hour)); err != nil {
		t.Fatalf("lifting: %v", err)
	}
	if len(held.Uncommitted()) != 1 {
		t.Fatalf("lifting a live hold recorded %d events", len(held.Uncommitted()))
	}

	lifted := replayHold(t, append(h.Uncommitted(), held.Uncommitted()...)...)
	if lifted.Held() {
		t.Error("the subject is still held after a lift")
	}
	if lifted.Matter() != "" {
		t.Errorf("the matter survived a lift: %q", lifted.Matter())
	}
}

// TestLiftingNeedsAnOwner.
//
// Somebody decides a matter is closed. A hold that lapsed on its own would be a
// hold with a timer, and §7 gives it none — the whole point is that a human
// judgement releases it.
func TestLiftingNeedsAnOwner(t *testing.T) {
	h := newHold()
	if err := h.Place("subj_1", "opr_1", "m-1", heldAt); err != nil {
		t.Fatalf("placing: %v", err)
	}
	held := replayHold(t, h.Uncommitted()...)

	if err := held.Lift("subj_1", "", heldAt); err == nil {
		t.Fatal("a hold was lifted by nobody")
	}
}

// TestAHoldCanBePlacedAgainAfterBeingLifted.
//
// The refusal is on a LIVE hold, not on the subject ever having been held. A
// matter that closes and a new one that opens are two separate holds, and the
// second must be placeable — otherwise a subject held once could never be held
// again.
func TestAHoldCanBePlacedAgainAfterBeingLifted(t *testing.T) {
	h := newHold()
	if err := h.Place("subj_1", "opr_1", "m-1", heldAt); err != nil {
		t.Fatalf("placing: %v", err)
	}
	first := h.Uncommitted()

	held := replayHold(t, first...)
	if err := held.Lift("subj_1", "opr_1", heldAt.Add(time.Hour)); err != nil {
		t.Fatalf("lifting: %v", err)
	}
	all := append(first, held.Uncommitted()...)

	lifted := replayHold(t, all...)
	if err := lifted.Place("subj_1", "opr_2", "m-2", heldAt.Add(2*time.Hour)); err != nil {
		t.Fatalf("a subject held once could not be held again: %v", err)
	}

	final := replayHold(t, append(all, lifted.Uncommitted()...)...)
	if !final.Held() {
		t.Error("the second hold did not take")
	}
	if final.Matter() != "m-2" {
		t.Errorf("matter = %q, want the SECOND one", final.Matter())
	}
}

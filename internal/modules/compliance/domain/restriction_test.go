package domain_test

import (
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/contract"
	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

var restrictAt = time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)

const (
	restrictSubject = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	restrictActor   = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV"
)

// replay rebuilds an aggregate from what another one recorded.
func replay(t *testing.T, from *domain.Restriction) *domain.Restriction {
	t.Helper()
	r := domain.NewRestriction()
	for _, e := range from.Uncommitted() {
		r.Apply(e)
	}
	return r
}

// replayAll rebuilds from a WHOLE STREAM, which is what a repository does.
//
// It exists because replay() above hides a class of bug: an aggregate rebuilt
// from the last event alone starts at the zero value, so a handler that fails to
// CLEAR a flag looks correct — the flag was never set. Only a replay that
// applies the earlier events first can see it.
func replayAll(t *testing.T, events ...eventsourcing.Event) *domain.Restriction {
	t.Helper()
	r := domain.NewRestriction()
	for _, e := range events {
		r.Apply(e)
	}
	return r
}

// RESTRICTING HALTS PROCESSING AND RECORDS WHEN.
func TestRestrictingRecordsTheInstant(t *testing.T) {
	r := domain.NewRestriction()

	if err := r.Restrict(restrictSubject, restrictActor, restrictAt); err != nil {
		t.Fatal(err)
	}
	events := r.Uncommitted()
	if len(events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(events))
	}
	if _, ok := events[0].(*contract.ProcessingRestricted); !ok {
		t.Fatalf("recorded %T", events[0])
	}

	rebuilt := replay(t, r)
	since, restricted := rebuilt.Restricted()
	if !restricted {
		t.Fatal("the aggregate is not restricted after restricting")
	}
	if !since.Equal(restrictAt) {
		t.Errorf("restricted since %v, want %v", since, restrictAt)
	}
}

// RESTRICTING TWICE KEEPS THE FIRST INSTANT.
//
// The state is binary and already in the state asked for. Moving the date would
// change an answer the person has already been given, for no gain.
func TestRestrictingTwiceKeepsTheFirstInstant(t *testing.T) {
	first := domain.NewRestriction()
	if err := first.Restrict(restrictSubject, restrictActor, restrictAt); err != nil {
		t.Fatal(err)
	}
	r := replay(t, first)

	if err := r.Restrict(restrictSubject, restrictActor, restrictAt.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := len(r.Uncommitted()); got != 0 {
		t.Fatalf("a second restriction recorded %d events", got)
	}
	since, _ := r.Restricted()
	if !since.Equal(restrictAt) {
		t.Errorf("the instant moved to %v", since)
	}
}

// LIFTING RESUMES PROCESSING.
func TestLiftingResumesProcessing(t *testing.T) {
	first := domain.NewRestriction()
	if err := first.Restrict(restrictSubject, restrictActor, restrictAt); err != nil {
		t.Fatal(err)
	}
	r := replay(t, first)

	if err := r.Lift(restrictSubject, restrictActor, restrictAt.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(r.Uncommitted()) != 1 {
		t.Fatalf("lifting recorded %d events, want 1", len(r.Uncommitted()))
	}

	// Replayed from the WHOLE STREAM — restrict, then lift — because that is
	// what the repository does and it is the only ordering that can catch a lift
	// handler which fails to clear the flag. Rebuilding from the lift alone
	// starts at the zero value, where `restricted` is already false and a broken
	// handler looks correct.
	rebuilt := replayAll(t,
		&contract.ProcessingRestricted{
			SubjectID: restrictSubject, ActorID: restrictActor, RestrictedAt: restrictAt,
		},
		&contract.ProcessingRestrictionLifted{
			SubjectID: restrictSubject, ActorID: restrictActor,
			LiftedAt: restrictAt.Add(time.Hour),
		},
	)
	if since, restricted := rebuilt.Restricted(); restricted {
		t.Errorf("the aggregate is still restricted after a full replay through the lift "+
			"(since %v); every notification to this person is suppressed forever", since)
	}
}

// LIFTING NOTHING SUCCEEDS AND RECORDS NOTHING.
//
// The caller asked for a state that already holds. Erroring would make the
// control fail for anybody who used it twice.
func TestLiftingWhenNotRestrictedIsHarmless(t *testing.T) {
	r := domain.NewRestriction()

	if err := r.Lift(restrictSubject, restrictActor, restrictAt); err != nil {
		t.Fatalf("lifting an unrestricted subject failed: %v", err)
	}
	if got := len(r.Uncommitted()); got != 0 {
		t.Errorf("lifting nothing recorded %d events", got)
	}
}

// A SUBJECT CAN BE RESTRICTED AGAIN AFTER LIFTING.
//
// A residual flag would make the second restriction a no-op, so somebody who
// lifted and then re-restricted would believe processing had stopped when it
// had not — and the dispatcher reads a projection built from these events.
func TestASubjectCanBeRestrictedAgain(t *testing.T) {
	first := domain.NewRestriction()
	if err := first.Restrict(restrictSubject, restrictActor, restrictAt); err != nil {
		t.Fatal(err)
	}
	mid := replay(t, first)
	if err := mid.Lift(restrictSubject, restrictActor, restrictAt.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	r := replay(t, mid)

	later := restrictAt.Add(48 * time.Hour)
	if err := r.Restrict(restrictSubject, restrictActor, later); err != nil {
		t.Fatal(err)
	}
	if len(r.Uncommitted()) != 1 {
		t.Fatal("a restriction after a lift recorded nothing; the subject believes " +
			"processing has stopped and it has not")
	}
	rebuilt := replay(t, r)
	since, restricted := rebuilt.Restricted()
	if !restricted || !since.Equal(later) {
		t.Errorf("after re-restricting: restricted=%v since=%v", restricted, since)
	}
}

// BOTH IDENTIFIERS ARE REQUIRED.
func TestARestrictionNeedsASubjectAndAnActor(t *testing.T) {
	for name, call := range map[string]func(*domain.Restriction) error{
		"restrict without a subject": func(r *domain.Restriction) error {
			return r.Restrict("", restrictActor, restrictAt)
		},
		"restrict without an actor": func(r *domain.Restriction) error {
			return r.Restrict(restrictSubject, "", restrictAt)
		},
		"lift without a subject": func(r *domain.Restriction) error {
			return r.Lift("", restrictActor, restrictAt)
		},
		"lift without an actor": func(r *domain.Restriction) error {
			return r.Lift(restrictSubject, "", restrictAt)
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := domain.NewRestriction()
			// Lift needs an existing restriction to reach its own guards.
			if _, ok := map[string]bool{
				"lift without a subject": true, "lift without an actor": true,
			}[name]; ok {
				seed := domain.NewRestriction()
				if err := seed.Restrict(restrictSubject, restrictActor, restrictAt); err != nil {
					t.Fatal(err)
				}
				r = replay(t, seed)
			}
			if err := call(r); err == nil {
				t.Error("accepted")
			}
		})
	}
}

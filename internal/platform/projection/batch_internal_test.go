package projection

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// countingWriter is the shape every production Writer has: Exec QUEUES, and the
// number of statements queued so far is observable.
type countingWriter struct{ n int }

func (w *countingWriter) Exec(string, ...any) { w.n++ }
func (w *countingWriter) Queued() int         { return w.n }

// plainWriter is a Writer that cannot report its position — a test double, or
// any future implementation that does not batch.
type plainWriter struct{}

func (plainWriter) Exec(string, ...any) {}

func envelopes(n int) []Envelope {
	out := make([]Envelope, n)
	for i := range out {
		out[i] = Envelope{
			Type:     fmt.Sprintf("test.Event%d.v1", i),
			Stream:   eventsourcing.StreamID(fmt.Sprintf("agg-%d", i)),
			Revision: eventsourcing.Revision(i),
		}
	}
	return out
}

// A batch failure must name the event whose statement failed — not the event
// that happened to close the batch.
//
// This is the defect the type exists to fix, and it is worth restating why it
// was invisible: Apply returns nil for every event, because db.Writer.Exec only
// QUEUES. The error arrives from the send, after every handler has succeeded, so
// the old code fell back to `last` and reported an event that had done nothing.
// The message then contradicted itself — it named EmailVerificationRequested
// while the statement it quoted was an UpsertUser belonging to a UserRegistered
// several positions earlier — and a reader believes the name.
func TestBatchFailureNamesTheEventThatQueuedTheStatement(t *testing.T) {
	events := envelopes(5)

	// The batch queues its tenant scope before any event is applied, so event 0
	// does not own statement 0. Two statements per event thereafter.
	const scopeStatements, perEvent = 1, 2

	for _, tc := range []struct {
		name  string
		index int
		want  int // index into events, or -1 for "not attributable"
	}{
		{"the scope statement belongs to no event", 0, -1},
		{"the first statement of the first event", scopeStatements, 0},
		{"the second statement of the first event", scopeStatements + 1, 0},
		{"the first statement of the third event", scopeStatements + 2*perEvent, 2},
		{"the last statement of the last event", scopeStatements + 5*perEvent - 1, 4},
		{"the checkpoint statement, after every event", scopeStatements + 5*perEvent, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &countingWriter{}
			for range scopeStatements {
				w.Exec("SELECT set_config(…)")
			}

			blame := attribution{events: events}
			blame.begin(w)
			for i := range events {
				for range perEvent {
					w.Exec("UPSERT …")
				}
				blame.applied(i)
			}
			w.Exec("UPSERT projection_checkpoint …")

			err := fmt.Errorf("postgres: %w", &db.BatchStatementError{
				Index: tc.index, Count: w.Queued(), SQL: "…", Err: errors.New("23505"),
			})
			culprit, known := blame.culprit(err)

			if tc.want < 0 {
				if known {
					t.Errorf("statement %d was attributed to %s with certainty; it belongs to "+
						"the batch itself, and a confident wrong name is the whole defect",
						tc.index, culprit.Type)
				}
				return
			}
			if !known {
				t.Fatalf("statement %d was not attributed, but its owner is known", tc.index)
			}
			if culprit.Type != events[tc.want].Type {
				t.Errorf("statement %d was blamed on %s, want %s",
					tc.index, culprit.Type, events[tc.want].Type)
			}
		})
	}
}

// An error Apply itself returned is unambiguous: nothing was queued for that
// event, so the statement map has nothing to say and must not overrule it.
func TestBatchFailureFromApplyNamesThatEvent(t *testing.T) {
	events := envelopes(5)
	w := &countingWriter{}
	w.Exec("SELECT set_config(…)")

	blame := attribution{events: events}
	blame.begin(w)
	for i := range 2 {
		w.Exec("UPSERT …")
		blame.applied(i)
	}
	blame.applyFailed(2)

	culprit, known := blame.culprit(errors.New("decoding failed"))
	if !known || culprit.Type != events[2].Type {
		t.Errorf("blamed %s (known=%v), want %s", culprit.Type, known, events[2].Type)
	}
}

// A Writer that cannot count degrades to the old behaviour — and says so.
//
// The annotation is the point. Without it this path reports the batch's last
// event as a fact, which is exactly the sentence that cost an hour.
func TestBatchFailureWithoutAStatementCountIsMarkedUncertain(t *testing.T) {
	events := envelopes(3)

	blame := attribution{events: events}
	blame.begin(plainWriter{})
	for i := range events {
		blame.applied(i)
	}

	err := fmt.Errorf("postgres: %w", &db.BatchStatementError{
		Index: 2, Count: 4, SQL: "…", Err: errors.New("23505"),
	})
	culprit, known := blame.culprit(err)
	if known {
		t.Error("an unattributable failure was reported as certain")
	}
	if culprit.Type != events[len(events)-1].Type {
		t.Errorf("the fallback named %s, want the batch's last event %s",
			culprit.Type, events[len(events)-1].Type)
	}
	if !strings.Contains(uncertain(known), "could not be attributed") {
		t.Errorf("the message does not say the attribution is uncertain: %q", uncertain(known))
	}
	if uncertain(true) != "" {
		t.Errorf("a certain attribution must carry no annotation, got %q", uncertain(true))
	}
}

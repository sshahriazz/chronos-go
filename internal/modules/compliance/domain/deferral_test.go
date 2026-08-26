package domain_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/contract"
	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

var deferredAt = time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC)

func newDeferral() *domain.Deferral {
	return eventsourcing.NewAggregate(domain.NewDeferral)
}

func replayDeferral(t *testing.T, events ...eventsourcing.Event) *domain.Deferral {
	t.Helper()
	d := newDeferral()
	for _, e := range events {
		d.Apply(e)
	}
	return d
}

// TestDeferringTwiceRecordsOnceAndKeepsTheFirstInstant is what the whole
// aggregate exists for.
//
// The erasure workflow re-runs its execute step hourly for as long as a hold
// stands — weeks, for a real matter. Every attempt reaches Defer. Article 12(4)
// asks for ONE answer to one request, and a person told weekly that their
// erasure is still deferred is being harassed by a compliance obligation.
//
// The instant is kept for the reason Restriction keeps its: the date has been
// reported to somebody, and a repeated call must not move it.
func TestDeferringTwiceRecordsOnceAndKeepsTheFirstInstant(t *testing.T) {
	d := newDeferral()
	if err := d.Defer("subj_1", deferredAt); err != nil {
		t.Fatalf("deferring: %v", err)
	}
	first := d.Uncommitted()
	if len(first) != 1 {
		t.Fatalf("recorded %d events, want 1", len(first))
	}

	open := replayDeferral(t, first...)
	if err := open.Defer("subj_1", deferredAt.Add(24*time.Hour)); err != nil {
		t.Fatalf("deferring twice: %v", err)
	}
	if n := len(open.Uncommitted()); n != 0 {
		t.Fatalf("a second deferral recorded %d events, so the person would be mailed "+
			"again — every hour, for the length of a legal matter", n)
	}

	when, deferred := open.Deferred()
	if !deferred {
		t.Fatal("the deferral did not survive a replay")
	}
	if !when.Equal(deferredAt) {
		t.Errorf("the instant moved to %v; it has been reported to somebody", when)
	}
}

// TestResumingWhatWasNeverDeferredIsFree is THE common path.
//
// Every erasure of an unheld subject calls Resume. If that recorded an event —
// or errored — the ordinary case would pay for a feature that exists for the
// rare one.
func TestResumingWhatWasNeverDeferredIsFree(t *testing.T) {
	d := newDeferral()
	if err := d.Resume("subj_1", deferredAt); err != nil {
		t.Fatalf("resuming nothing: %v", err)
	}
	if n := len(d.Uncommitted()); n != 0 {
		t.Errorf("resuming a deferral that was never opened recorded %d events", n)
	}
}

// TestResumingClosesTheWindow.
func TestResumingClosesTheWindow(t *testing.T) {
	d := newDeferral()
	if err := d.Defer("subj_1", deferredAt); err != nil {
		t.Fatalf("deferring: %v", err)
	}
	opened := d.Uncommitted()

	open := replayDeferral(t, opened...)
	if err := open.Resume("subj_1", deferredAt.Add(time.Hour)); err != nil {
		t.Fatalf("resuming: %v", err)
	}
	if len(open.Uncommitted()) != 1 {
		t.Fatalf("resuming an open deferral recorded %d events, want 1",
			len(open.Uncommitted()))
	}

	closed := replayDeferral(t, append(opened, open.Uncommitted()...)...)
	if _, deferred := closed.Deferred(); deferred {
		t.Error("the deferral is still open after a resume")
	}

	// And it can be deferred AGAIN — a second hold on the same subject is an
	// ordinary thing, and each deserves its own answer.
	if err := closed.Defer("subj_1", deferredAt.Add(2*time.Hour)); err != nil {
		t.Fatalf("deferring after a resume: %v", err)
	}
	if len(closed.Uncommitted()) != 1 {
		t.Error("a subject deferred once could not be deferred again")
	}
}

// TestTheDeferralEventCarriesNoMatter is the tipping-off guard, asserted on the
// struct rather than on a value.
//
// The hold's own event names the matter. THIS event is what reaches the subject
// — the notification catalogue turns it into their Article 12(4) answer — so a
// matter field on it would put the name of an investigation into the inbox of
// its subject.
//
// A value test would pass on the day the field was added and left empty. This
// fails on the field existing at all.
func TestTheDeferralEventCarriesNoMatter(t *testing.T) {
	forbidden := []string{"matter", "reason", "hold", "case", "justification"}

	for _, ev := range []eventsourcing.Event{
		&contract.ErasureDeferred{},
		&contract.ErasureResumed{},
	} {
		for _, field := range fieldNames(ev) {
			lower := lowerASCII(field)
			for _, bad := range forbidden {
				if lower == bad {
					t.Errorf("%s.%s would put the name of an investigation into the "+
						"inbox of its subject.\n\n"+
						"Article 12(4) asks for the GROUND — 17(3)(e) — which is a legal "+
						"basis and the same sentence for everybody. The matter lives on "+
						"the hold's event and in operator_audit_log, under access "+
						"controls.", ev.EventType(), field)
				}
			}
		}
	}
}

// TestDeferringNeedsASubject.
func TestDeferringNeedsASubject(t *testing.T) {
	if err := newDeferral().Defer("", deferredAt); err == nil {
		t.Error("a deferral was recorded for nobody")
	}
	if err := newDeferral().Resume("", deferredAt); err == nil {
		t.Error("a deferral was resumed for nobody")
	}
}

// TestEveryDeferralInstantIsUTC.
func TestEveryDeferralInstantIsUTC(t *testing.T) {
	local := time.FixedZone("UTC+6", 6*3600)
	when := time.Date(2026, 8, 26, 15, 0, 0, 0, local)

	d := newDeferral()
	if err := d.Defer("subj_1", when); err != nil {
		t.Fatal(err)
	}
	got := d.Uncommitted()[0].(*contract.ErasureDeferred).DeferredAt
	if got.Location() != time.UTC {
		t.Errorf("recorded in %v, not UTC", got.Location())
	}
	if !got.Equal(when) {
		t.Errorf("the instant moved: %v vs %v", got, when)
	}
}

// fieldNames reports the exported field names of an event struct.
func fieldNames(ev any) []string {
	v := reflect.ValueOf(ev)
	for v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}
	t := v.Type()
	out := make([]string, 0, t.NumField())
	for i := range t.NumField() {
		out = append(out, t.Field(i).Name)
	}
	return out
}

// lowerASCII lowercases without pulling in a locale-aware path — the field
// names it sees are Go identifiers.
func lowerASCII(s string) string { return strings.ToLower(s) }

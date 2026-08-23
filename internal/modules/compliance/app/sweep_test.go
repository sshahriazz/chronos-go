package app_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/app"
)

type fakeOverdue struct {
	rows  []app.OverdueRequest
	err   error
	limit int
	calls int
}

func (f *fakeOverdue) ListOverdue(
	_ context.Context, _ time.Time, limit int,
) ([]app.OverdueRequest, error) {
	f.calls++
	f.limit = limit
	if f.err != nil {
		return nil, f.err
	}
	if limit < len(f.rows) {
		return f.rows[:limit], nil
	}
	return f.rows, nil
}

type fakeStarter struct {
	started []string
	err     error
}

func (f *fakeStarter) StartErasure(_ context.Context, subjectID string) error {
	f.started = append(f.started, subjectID)
	return f.err
}

func newSweep(t *testing.T, rows *fakeOverdue, starter *fakeStarter) *app.Sweep {
	t.Helper()
	s, err := app.NewSweep(app.SweepDeps{
		Requests: rows, Starter: starter, Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("NewSweep: %v", err)
	}
	return s
}

func overdue(n int) []app.OverdueRequest {
	out := make([]app.OverdueRequest, 0, n)
	for i := range n {
		out = append(out, app.OverdueRequest{
			SubjectID:    "subj_" + string(rune('a'+i)),
			ScheduledFor: time.Now().Add(-time.Duration(i+1) * time.Hour).UTC(),
		})
	}
	return out
}

// AN OVERDUE REQUEST WITH NO CLOCK GETS ONE.
//
// The failure this exists for: a request whose workflow was never started —
// reactor unregistered for a deployment, group renamed, Temporal off when the
// request came in. Nothing else in the system notices.
func TestAnOverdueRequestIsRestarted(t *testing.T) {
	rows := &fakeOverdue{rows: overdue(3)}
	starter := &fakeStarter{}

	res, err := newSweep(t, rows, starter).SweepOnce(context.Background(), time.Now(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if res.Started != 3 || len(starter.started) != 3 {
		t.Fatalf("started %d clocks, want 3; requests past their deadline stay without one",
			res.Started)
	}
	if res.Scanned != 3 {
		t.Errorf("scanned %d", res.Scanned)
	}
}

// ONE FAILURE DOES NOT STOP THE PASS.
//
// The others are equally overdue. Returning on the first error would let one
// stuck subject hold up everybody else's statutory deadline.
func TestOneFailedRestartDoesNotStopTheRest(t *testing.T) {
	rows := &fakeOverdue{rows: overdue(3)}
	starter := &fakeStarter{err: errors.New("temporal: unavailable")}

	res, err := newSweep(t, rows, starter).SweepOnce(context.Background(), time.Now(), 100)
	if err != nil {
		t.Fatalf("a failing start failed the whole pass: %v", err)
	}
	if len(starter.started) != 3 {
		t.Fatalf("attempted %d starts, want 3; one stuck subject held up the rest",
			len(starter.started))
	}
	if res.Failed != 3 || res.Started != 0 {
		t.Errorf("failed=%d started=%d, want 3/0", res.Failed, res.Started)
	}
}

// A FULL BATCH REPORTS MORE.
//
// The workflow pages on it; without it a backlog is swept one batch per run and
// the rest wait six hours each.
func TestAFullBatchReportsMore(t *testing.T) {
	rows := &fakeOverdue{rows: overdue(5)}

	res, err := newSweep(t, rows, &fakeStarter{}).SweepOnce(context.Background(), time.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	if !res.More {
		t.Fatal("a full batch did not report more; the backlog drains one batch per run")
	}
}

// A SHORT BATCH DOES NOT.
func TestAShortBatchDoesNotReportMore(t *testing.T) {
	rows := &fakeOverdue{rows: overdue(2)}

	res, err := newSweep(t, rows, &fakeStarter{}).SweepOnce(context.Background(), time.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	if res.More {
		t.Error("a short batch reported more; the workflow pages forever")
	}
}

// AN EMPTY WORK LIST IS THE HEALTHY ANSWER.
//
// Every request already has a clock from the reactor. Starting nothing is what
// this looks like when it is working.
func TestNothingOverdueIsASuccess(t *testing.T) {
	starter := &fakeStarter{}

	res, err := newSweep(t, &fakeOverdue{}, starter).SweepOnce(
		context.Background(), time.Now(), 100)
	if err != nil {
		t.Fatalf("an empty work list failed: %v", err)
	}
	if res.Started != 0 || len(starter.started) != 0 {
		t.Error("a clock was started with nothing overdue")
	}
}

// AN UNREADABLE WORK LIST FAILS THE PASS.
//
// Reporting a clean pass would say the backstop ran and found nothing, which is
// exactly what it says when it is working.
func TestAnUnreadableWorkListFailsThePass(t *testing.T) {
	rows := &fakeOverdue{err: errors.New("postgres: down")}

	if _, err := newSweep(t, rows, &fakeStarter{}).SweepOnce(
		context.Background(), time.Now(), 100); err == nil {
		t.Fatal("an unreadable work list reported a clean pass; that is what a working " +
			"backstop reports, so the failure is invisible")
	}
}

// THE BATCH SIZE REACHES THE QUERY, AND MUST BE POSITIVE.
func TestTheSweepBatchIsBounded(t *testing.T) {
	rows := &fakeOverdue{rows: overdue(2)}
	s := newSweep(t, rows, &fakeStarter{})

	if _, err := s.SweepOnce(context.Background(), time.Now(), 0); err == nil {
		t.Error("a zero batch size was accepted")
	}
	if rows.calls != 0 {
		t.Error("the work list was queried with a non-positive limit")
	}
	if _, err := s.SweepOnce(context.Background(), time.Now(), 7); err != nil {
		t.Fatal(err)
	}
	if rows.limit != 7 {
		t.Errorf("queried with limit %d, want 7", rows.limit)
	}
}

// AN INCOMPLETE WIRING IS REFUSED.
func TestTheSweepRefusesAnIncompleteWiring(t *testing.T) {
	log := slog.New(slog.DiscardHandler)

	if _, err := app.NewSweep(app.SweepDeps{Starter: &fakeStarter{}, Log: log}); err == nil {
		t.Error("a sweep with no work list was accepted; it scans nothing and reports a " +
			"clean pass forever")
	}
	if _, err := app.NewSweep(app.SweepDeps{Requests: &fakeOverdue{}, Log: log}); err == nil {
		t.Error("a sweep with no starter was accepted")
	}
	if _, err := app.NewSweep(app.SweepDeps{
		Requests: &fakeOverdue{}, Starter: &fakeStarter{},
	}); err == nil {
		t.Error("a sweep with no logger was accepted")
	}
}

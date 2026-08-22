package app_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/app"
	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
)

// fakeDue is the sweep's work list.
type fakeDue struct {
	rows      []app.DueInvitation
	err       error
	lastLimit int
}

func (f *fakeDue) ListDue(_ context.Context, deadline time.Time, limit int) ([]app.DueInvitation, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.lastLimit = limit
	var out []app.DueInvitation
	for _, r := range f.rows {
		if r.ExpiresAt.After(deadline) {
			continue
		}
		out = append(out, r)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

// fakeExpirer records what it was asked to close.
type fakeExpirer struct {
	called []string
	// outcome maps an invitation id onto what Expire answers: true expired,
	// false stale, error failed.
	outcome map[string]struct {
		expired bool
		err     error
	}
}

func (f *fakeExpirer) Expire(_ context.Context, invitationID string) (bool, error) {
	f.called = append(f.called, invitationID)
	o, ok := f.outcome[invitationID]
	if !ok {
		return true, nil
	}
	return o.expired, o.err
}

func dueRows(n int, at time.Time) []app.DueInvitation {
	out := make([]app.DueInvitation, 0, n)
	for i := range n {
		out = append(out, app.DueInvitation{
			InvitationID: "inv_" + string(rune('A'+i)),
			OrgID:        testOrg,
			WorkspaceID:  inviteWS,
			ExpiresAt:    at.Add(-time.Duration(i+1) * time.Hour),
		})
	}
	return out
}

func sweep(t *testing.T, list app.DueInvitations, e app.Expirer) *app.InvitationSweep {
	t.Helper()
	s, err := app.NewInvitationSweep(list, e, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var sweepNow = time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

// THE SWEEP EXPIRES WHAT HAS RUN OUT.
//
// This is what makes expiry CERTAIN rather than timely. A per-invitation
// workflow that was never started — worker down when the event arrived, Temporal
// unreachable, the reactor parked — leaves a seat held forever by an invitation
// nobody can accept, and nothing else in the system would ever notice.
func TestTheSweepExpiresOverdueInvitations(t *testing.T) {
	list := &fakeDue{rows: dueRows(3, sweepNow)}
	expirer := &fakeExpirer{}
	s := sweep(t, list, expirer)

	result, err := s.Run(context.Background(), sweepNow)
	if err != nil {
		t.Fatalf("sweeping: %v", err)
	}
	if result.Scanned != 3 || result.Expired != 3 {
		t.Fatalf("scanned %d and expired %d, want 3 and 3; every one not expired is a "+
			"seat an organization keeps paying for", result.Scanned, result.Expired)
	}
	if len(expirer.called) != 3 {
		t.Errorf("asked to expire %d invitations", len(expirer.called))
	}
}

// A ROW THAT NO LONGER NEEDS EXPIRING IS STALE, NOT A FAILURE.
//
// The view lags the log by design, and a RESEND moves the deadline past the one
// the row was selected on. Counting that as an error would report a healthy
// system as broken every time somebody pressed resend — and would eventually
// train whoever reads the metric to ignore it.
func TestAResentInvitationIsStaleAndNotAFailure(t *testing.T) {
	rows := dueRows(3, sweepNow)
	expirer := &fakeExpirer{outcome: map[string]struct {
		expired bool
		err     error
	}{
		rows[1].InvitationID: {expired: false}, // resent since the row was read
	}}
	s := sweep(t, &fakeDue{rows: rows}, expirer)

	result, err := s.Run(context.Background(), sweepNow)
	if err != nil {
		t.Fatal(err)
	}
	if result.Stale != 1 {
		t.Errorf("counted %d stale, want 1", result.Stale)
	}
	if result.Failed != 0 {
		t.Errorf("counted %d failed; a lagging row is the mechanism working", result.Failed)
	}
	if result.Expired != 2 {
		t.Errorf("expired %d, want 2", result.Expired)
	}
}

// ONE BAD INVITATION DOES NOT STOP THE BATCH.
//
// Every row in the batch is a seat an organization is paying for, and the whole
// point of the pass is to give those back. Returning on the first failure would
// let one unreadable stream hold every seat behind it.
func TestOneFailureDoesNotStopTheSweep(t *testing.T) {
	rows := dueRows(4, sweepNow)
	expirer := &fakeExpirer{outcome: map[string]struct {
		expired bool
		err     error
	}{
		rows[0].InvitationID: {err: errors.New("kurrentdb: unreadable")},
	}}
	s := sweep(t, &fakeDue{rows: rows}, expirer)

	result, err := s.Run(context.Background(), sweepNow)
	if err != nil {
		t.Fatalf("one unreadable stream failed the whole pass: %v\nEvery seat behind it "+
			"stays held", err)
	}
	if result.Failed != 1 {
		t.Errorf("counted %d failed, want 1", result.Failed)
	}
	if result.Expired != 3 {
		t.Errorf("expired %d of the remaining 3", result.Expired)
	}
	if len(expirer.called) != 4 {
		t.Errorf("stopped after %d of 4", len(expirer.called))
	}
}

// A FAILING WORK LIST FAILS THE PASS.
//
// Nothing was scanned, so reporting a successful pass would say "no invitations
// are overdue" when the truth is "nobody looked" — and the two are
// indistinguishable on a dashboard.
func TestAFailingWorkListFailsThePass(t *testing.T) {
	s := sweep(t, &fakeDue{err: errors.New("postgres: down")}, &fakeExpirer{})

	result, err := s.Run(context.Background(), sweepNow)
	if err == nil {
		t.Fatal("a work list that could not be read was reported as a clean pass; an " +
			"outage then looks exactly like a system with nothing overdue")
	}
	if result.Scanned != 0 {
		t.Error("rows were reported alongside the error")
	}
}

// A FULL BATCH REPORTS THERE IS MORE.
//
// A sweep that silently stopped at its limit reads as "everything is swept"
// while an unbounded number of seats stay held. The caller must be able to loop
// or run again sooner, and it can only do that if told.
func TestAFullBatchReportsMore(t *testing.T) {
	list := &fakeDue{rows: dueRows(app.DefaultSweepBatch+10, sweepNow)}
	s := sweep(t, list, &fakeExpirer{})

	result, err := s.Run(context.Background(), sweepNow)
	if err != nil {
		t.Fatal(err)
	}
	if list.lastLimit != app.DefaultSweepBatch {
		t.Errorf("asked for %d rows, want the batch size %d", list.lastLimit, app.DefaultSweepBatch)
	}
	if !result.More {
		t.Fatal("a full batch did not report More; the caller stops, and every seat past " +
			"the limit stays held until the next scheduled run")
	}

	short := sweep(t, &fakeDue{rows: dueRows(3, sweepNow)}, &fakeExpirer{})
	partial, err := short.Run(context.Background(), sweepNow)
	if err != nil {
		t.Fatal(err)
	}
	if partial.More {
		t.Error("a partial batch reported More, which makes the caller loop forever")
	}
}

// NOTHING OVERDUE IS A CLEAN PASS.
func TestNothingOverdueIsNotAnError(t *testing.T) {
	future := []app.DueInvitation{{
		InvitationID: "inv_future", OrgID: testOrg, WorkspaceID: inviteWS,
		ExpiresAt: sweepNow.Add(24 * time.Hour),
	}}
	expirer := &fakeExpirer{}
	s := sweep(t, &fakeDue{rows: future}, expirer)

	result, err := s.Run(context.Background(), sweepNow)
	if err != nil {
		t.Fatal(err)
	}
	if result.Scanned != 0 || result.Expired != 0 {
		t.Errorf("scanned %d and expired %d for a list with nothing due",
			result.Scanned, result.Expired)
	}
	if len(expirer.called) != 0 {
		t.Fatalf("expired %v, none of which was overdue", expirer.called)
	}
}

// EVERY DEPENDENCY IS REQUIRED.
//
// A sweep with either half missing would run, report success and expire nothing
// — the failure this mechanism exists to prevent, arriving through the wiring.
func TestTheSweepRefusesAnIncompleteWiring(t *testing.T) {
	if _, err := app.NewInvitationSweep(&fakeDue{}, &fakeExpirer{}, nil); err != nil {
		t.Fatalf("precondition: a complete wiring was refused: %v", err)
	}
	for name, build := range map[string]func() error{
		"no work list": func() error {
			_, err := app.NewInvitationSweep(nil, &fakeExpirer{}, nil)
			return err
		},
		"no expirer": func() error {
			_, err := app.NewInvitationSweep(&fakeDue{}, nil, nil)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := build(); err == nil {
				t.Fatalf("constructed with %s", name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Expire, against the real aggregate
// ---------------------------------------------------------------------------

// EXPIRY RETURNS THE SEAT AND KILLS THE LINK.
func TestExpiringReturnsTheSeat(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	h.clock.advance(app.InvitationTTL)

	expired, err := h.settlements.Expire(context.Background(), issued.InvitationID)
	if err != nil {
		t.Fatalf("expiring: %v", err)
	}
	if !expired {
		t.Fatal("nothing was expired for an invitation whose window has closed")
	}
	if len(h.reserver.released) != 1 {
		t.Errorf("released %v, want the seat back", h.reserver.released)
	}
	if _, err := h.accept(issued.Token, acceptor); err == nil {
		t.Fatal("an expired invitation was accepted")
	}
}

// EXPIRY REFUSES TO RUN EARLY, and reports it as nothing-to-do.
//
// The sweep works from a projection. A resend moves the deadline after the row
// was read, and closing the invitation then would kill a link that is live in
// somebody's inbox and take back a seat that is still needed.
func TestExpiringBeforeTheDeadlineDoesNothing(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}

	expired, err := h.settlements.Expire(context.Background(), issued.InvitationID)
	if err != nil {
		t.Fatalf("a live invitation reported an error rather than nothing-to-do: %v", err)
	}
	if expired {
		t.Fatal("a live invitation was expired; its link is in somebody's inbox and the " +
			"seat is still needed")
	}
	if len(h.reserver.released) != 0 {
		t.Errorf("released %v for a live invitation", h.reserver.released)
	}
}

// A SETTLED INVITATION IS NOTHING TO DO, not a conflict.
//
// A sweep that treated "already accepted" as an error would report failures
// proportional to how fast people accept.
func TestExpiringASettledInvitationDoesNothing(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.accept(issued.Token, acceptor); err != nil {
		t.Fatal(err)
	}
	h.clock.advance(app.InvitationTTL)

	expired, err := h.settlements.Expire(context.Background(), issued.InvitationID)
	if err != nil {
		t.Fatalf("an accepted invitation reported an error: %v", err)
	}
	if expired {
		t.Fatal("an ACCEPTED invitation was expired, releasing the seat its new member " +
			"is sitting in")
	}
}

// AN UNKNOWN INVITATION IS NOTHING TO DO.
func TestExpiringAnUnknownInvitationDoesNothing(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})

	expired, err := h.settlements.Expire(context.Background(), "inv_01ARZ3NDEKTSV4RRFFQ69G5FAZ")
	if err != nil {
		t.Fatalf("an unknown invitation reported an error: %v", err)
	}
	if expired {
		t.Fatal("an invitation that does not exist was expired")
	}

	if _, err := h.settlements.Expire(context.Background(), ""); err == nil {
		t.Fatal("an empty invitation id was accepted, which would scan the whole category")
	} else if !strings.Contains(err.Error(), "required") {
		t.Errorf("refused with %v", err)
	}
}

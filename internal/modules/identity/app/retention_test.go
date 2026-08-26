package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeRetentionStore records the order the statements ran in, the cutoffs they
// were given, and lets any one of them be made to fail.
type fakeRetentionStore struct {
	order   []string
	cutoffs map[string]time.Time
	deleted map[string]int64
	fail    map[string]error
}

func newFakeRetentionStore() *fakeRetentionStore {
	return &fakeRetentionStore{
		cutoffs: map[string]time.Time{},
		deleted: map[string]int64{},
		fail:    map[string]error{},
	}
}

func (f *fakeRetentionStore) record(name string) (int64, error) {
	f.order = append(f.order, name)
	if err := f.fail[name]; err != nil {
		return 0, err
	}
	return f.deleted[name], nil
}

func (f *fakeRetentionStore) SweepTOTPReplay(context.Context) (int64, error) {
	return f.record(StatementTOTPReplay)
}

func (f *fakeRetentionStore) SweepTokens(context.Context) (int64, error) {
	return f.record(StatementTokens)
}

func (f *fakeRetentionStore) SweepSessionTokens(context.Context) (int64, error) {
	return f.record(StatementSessionTokens)
}

func (f *fakeRetentionStore) SweepExpiredSessionViews(
	_ context.Context, cutoff time.Time,
) (int64, error) {
	f.cutoffs[StatementSessionViews] = cutoff
	return f.record(StatementSessionViews)
}

func (f *fakeRetentionStore) DeleteReleasedReservations(
	_ context.Context, cutoff time.Time,
) (int64, error) {
	f.cutoffs[StatementReleasedReservations] = cutoff
	return f.record(StatementReleasedReservations)
}

// SweepAPIKeySecrets is the sixth statement. It takes no cutoff, like the other
// three that measure against now() in SQL: an API key secret past its own expiry
// or its rotation retirement protects nothing, so there is no horizon to choose.
func (f *fakeRetentionStore) SweepAPIKeySecrets(_ context.Context) (int64, error) {
	return f.record(StatementAPIKeySecrets)
}

func newTestRetention(t *testing.T, store RetentionStore) *Retention {
	t.Helper()
	r, err := NewRetention(store, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("building retention: %v", err)
	}
	return r
}

var retentionNow = time.Date(2026, 8, 13, 4, 0, 0, 0, time.UTC)

// Every statement must run. This is the test that fails if somebody removes one
// from the list — which is the state all five were in before this job existed:
// authored, generated, indexed for, and called by nothing.
func TestRetentionRunsEveryStatement(t *testing.T) {
	store := newFakeRetentionStore()
	res, err := newTestRetention(t, store).PurgeOnce(context.Background(), retentionNow)
	if err != nil {
		t.Fatalf("purging: %v", err)
	}

	for _, want := range []string{
		StatementTOTPReplay, StatementTokens, StatementSessionTokens,
		StatementSessionViews, StatementReleasedReservations, StatementAPIKeySecrets,
	} {
		if !slices.Contains(store.order, want) {
			t.Errorf("%s never ran, so its table grows unbounded and nothing reports it. "+
				"Ran: %v", want, store.order)
		}
		if !slices.ContainsFunc(res.Outcomes, func(o RetentionOutcome) bool {
			return o.Statement == want
		}) {
			t.Errorf("%s is absent from the result, so a run that skipped it looks identical "+
				"to a run with nothing to delete", want)
		}
	}
	if len(store.order) != 6 {
		t.Errorf("ran %d statements, want 6: %v", len(store.order), store.order)
	}
}

// The one ordering constraint in the pass, and it is not cosmetic.
//
// SweepSessionTokens finds dead secrets by joining session_view, and 00010
// removed the foreign key between them deliberately. So a session_view row
// deleted FIRST does not cascade — it removes the only route by which its token
// digest can ever be found, and the digest is then retained permanently with
// nothing reporting it.
func TestSessionSecretsAreSweptBeforeTheRowsThatFindThem(t *testing.T) {
	store := newFakeRetentionStore()
	if _, err := newTestRetention(t, store).PurgeOnce(context.Background(), retentionNow); err != nil {
		t.Fatalf("purging: %v", err)
	}

	tokens := slices.Index(store.order, StatementSessionTokens)
	views := slices.Index(store.order, StatementSessionViews)
	switch {
	case tokens < 0 || views < 0:
		t.Fatalf("one of the two session statements did not run: %v", store.order)
	case tokens > views:
		t.Errorf("session_view was swept before session_token (%v). SweepSessionTokens joins "+
			"session_view to find dead secrets and there is no foreign key between them, so "+
			"every digest belonging to a deleted row is now unreachable and kept forever",
			store.order)
	}
}

// The horizons must actually reach the statements that take one. A cutoff of
// `now` would delete live sessions; a zero cutoff would delete nothing while
// reporting success.
func TestRetentionAppliesItsHorizons(t *testing.T) {
	store := newFakeRetentionStore()
	if _, err := newTestRetention(t, store).PurgeOnce(context.Background(), retentionNow); err != nil {
		t.Fatalf("purging: %v", err)
	}

	for _, tc := range []struct {
		statement string
		want      time.Time
	}{
		{StatementSessionViews, retentionNow.Add(-SessionViewRetention)},
		{StatementReleasedReservations, retentionNow.Add(-ReleasedReservationRetention)},
	} {
		got, ok := store.cutoffs[tc.statement]
		if !ok {
			t.Errorf("%s was given no cutoff", tc.statement)
			continue
		}
		if !got.Equal(tc.want) {
			t.Errorf("%s cutoff = %s, want %s", tc.statement, got, tc.want)
		}
		if !got.Before(retentionNow) {
			t.Errorf("%s cutoff %s is not in the past, so this deletes rows that are still "+
				"live", tc.statement, got)
		}
	}
}

// The cutoffs are UTC whatever zone the caller's instant carries. Storage is UTC
// everywhere in this system, and a cutoff that arrives in a local zone is a
// horizon nobody reading a log line can compare against the rows it deleted.
func TestTheHorizonsAreComputedInUTC(t *testing.T) {
	store := newFakeRetentionStore()
	local := retentionNow.In(time.FixedZone("well-east", 11*3600))

	if _, err := newTestRetention(t, store).PurgeOnce(context.Background(), local); err != nil {
		t.Fatalf("purging: %v", err)
	}
	for statement, cutoff := range store.cutoffs {
		if cutoff.Location() != time.UTC {
			t.Errorf("%s cutoff is in %s, not UTC", statement, cutoff.Location())
		}
	}
}

// The counts have to be LOGGED as well as returned. The result lives in Temporal
// where somebody has to go and look; the log line is what an alert can be built
// on, and a retention job whose output nobody can see is one nobody notices has
// stopped.
func TestRetentionLogsEveryStatementsCount(t *testing.T) {
	var buf bytes.Buffer
	store := newFakeRetentionStore()
	store.deleted[StatementTOTPReplay] = 11

	r, err := NewRetention(store, slog.New(slog.NewJSONHandler(&buf, nil)))
	if err != nil {
		t.Fatalf("building retention: %v", err)
	}
	if _, err := r.PurgeOnce(context.Background(), retentionNow); err != nil {
		t.Fatalf("purging: %v", err)
	}

	logged := buf.String()
	for _, want := range []string{
		StatementTOTPReplay, StatementTokens, StatementSessionTokens,
		StatementSessionViews, StatementReleasedReservations, StatementAPIKeySecrets,
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("%s does not appear in the log, so an operator cannot tell whether it "+
				"ran. Logged: %s", want, logged)
		}
	}
	if !strings.Contains(logged, `"`+StatementTOTPReplay+`":11`) {
		t.Errorf("the row count for %s was not logged, so the one table that has no TTL "+
			"cannot be watched. Logged: %s", StatementTOTPReplay, logged)
	}
}

// The horizons themselves, spelled out.
//
// The numbers are DUPLICATED from the constants on purpose, which is normally a
// smell. Here it is the point: a horizon is a decision about how long evidence is
// kept — a shortened SessionViewRetention silently deletes the sign-in history an
// account-takeover victim is looking at — and every other test derives its
// expectation from the constant, so a one-character change to either would pass
// the whole suite. Changing a horizon should require changing this test, which is
// where the reasoning is written down.
func TestTheRetentionHorizonsAreWhatWasDecided(t *testing.T) {
	if SessionViewRetention != 90*24*time.Hour {
		t.Errorf("SessionViewRetention = %v, want 90 days. It is chosen against the question "+
			"the security-settings screen answers — which devices signed in, and when — so "+
			"shortening it empties the list somebody reviews after a compromise",
			SessionViewRetention)
	}
	if ReleasedReservationRetention != 30*24*time.Hour {
		t.Errorf("ReleasedReservationRetention = %v, want 30 days. The row is a projection a "+
			"replay would recreate; a month covers the support question attached to it",
			ReleasedReservationRetention)
	}
}

// One broken statement must not stop the others. These tables are unrelated;
// letting one failure abort the pass turns a single broken DELETE into every
// later table growing forever.
//
// It counts against RetentionStatements() rather than a literal, so adding a
// table is not a test edit — and a test edit is a place to get the number wrong
// rather than a place to think. The count moved from five to six when API key
// secrets joined the sweep, and this assertion should not have noticed.
func TestOneFailingStatementDoesNotStopTheOthers(t *testing.T) {
	store := newFakeRetentionStore()
	store.fail[StatementTOTPReplay] = errors.New("relation totp_replay does not exist")
	store.deleted[StatementTokens] = 3
	store.deleted[StatementSessionTokens] = 4

	res, err := newTestRetention(t, store).PurgeOnce(context.Background(), retentionNow)
	if err != nil {
		t.Fatalf("a per-statement failure must not fail the pass: %v", err)
	}
	if want := len(RetentionStatements()); len(store.order) != want {
		t.Fatalf("a failing statement aborted the pass; ran %v of %d", store.order, want)
	}
	if res.Failed != 1 {
		t.Errorf("Failed = %d, want 1", res.Failed)
	}
	if res.Deleted != 7 {
		t.Errorf("Deleted = %d, want 7 (only the statements that succeeded)", res.Deleted)
	}

	var reported bool
	for _, o := range res.Outcomes {
		if o.Statement != StatementTOTPReplay {
			continue
		}
		reported = o.Err != nil
		if o.Deleted != 0 {
			t.Errorf("a failed statement reported %d rows deleted", o.Deleted)
		}
	}
	if !reported {
		t.Error("the failure is absent from the result, so the run reports a clean pass over " +
			"a table that was never swept")
	}
}

// Per-statement counts, not a total. A total of seven is compatible with
// totp_replay never having been touched, and that table is the reason this job
// exists.
func TestRetentionReportsPerStatementCounts(t *testing.T) {
	store := newFakeRetentionStore()
	store.deleted[StatementTOTPReplay] = 11
	store.deleted[StatementSessionViews] = 2

	res, err := newTestRetention(t, store).PurgeOnce(context.Background(), retentionNow)
	if err != nil {
		t.Fatalf("purging: %v", err)
	}

	got := map[string]int64{}
	for _, o := range res.Outcomes {
		got[o.Statement] = o.Deleted
	}
	if got[StatementTOTPReplay] != 11 {
		t.Errorf("totp_replay reported %d rows, want 11", got[StatementTOTPReplay])
	}
	if got[StatementSessionViews] != 2 {
		t.Errorf("session_view reported %d rows, want 2", got[StatementSessionViews])
	}
	if res.Deleted != 13 {
		t.Errorf("Deleted = %d, want 13", res.Deleted)
	}
}

// A zero instant would put both cutoffs in year 1, so both statements would
// delete nothing and report success — retention that has silently stopped,
// wearing the exact signature of retention with nothing to do.
func TestRetentionRefusesAZeroInstant(t *testing.T) {
	store := newFakeRetentionStore()
	if _, err := newTestRetention(t, store).PurgeOnce(context.Background(), time.Time{}); err == nil {
		t.Fatal("a zero instant was accepted; every cutoff would be year 1 and every " +
			"horizon-bearing statement would delete nothing while reporting success")
	}
	if len(store.order) != 0 {
		t.Errorf("statements ran with a zero instant: %v", store.order)
	}
}

// A retention job with no store runs, reports success and deletes nothing —
// indistinguishable from outside this process from one with nothing left to do.
func TestRetentionRefusesToBeBuiltWithoutAStore(t *testing.T) {
	if _, err := NewRetention(nil, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("retention was built with no store")
	}
}

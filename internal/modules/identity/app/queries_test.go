package app

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/page"
)

// ---------------------------------------------------------------------------
// Fakes
//
// The two list fakes implement keyset semantics FOR REAL — sort, then drop
// everything at or before the cursor, then truncate to the limit. A fake that
// merely handed back a slice would make every pagination test below vacuous:
// the skipped-or-repeated-row failure this whole scheme exists to prevent lives
// in the interaction between the cursor and the sort, so a fake that ignores the
// cursor cannot exhibit it.
// ---------------------------------------------------------------------------

type fakeAccounts struct {
	account AccountView
	err     error
	seen    []string
}

func (f *fakeAccounts) Account(_ context.Context, subjectID string) (AccountView, error) {
	f.seen = append(f.seen, subjectID)
	if f.err != nil {
		return AccountView{}, f.err
	}
	return f.account, nil
}

type fakeSessions struct {
	rows   []SessionSummary
	err    error
	calls  int
	limit  int32
	cursor page.Keyset
}

func (f *fakeSessions) Sessions(
	_ context.Context, _ string, after page.Keyset, limit int32,
) ([]SessionSummary, error) {
	f.calls++
	f.limit = limit
	f.cursor = after
	if f.err != nil {
		return nil, f.err
	}

	rows := slices.Clone(f.rows)
	slices.SortFunc(rows, sessionOrder)
	if !after.IsStart() {
		args := after.Args()
		at, id := args[0].(time.Time), args[1].(string)
		rows = slices.DeleteFunc(rows, func(s SessionSummary) bool {
			return !before(s.CreatedAt, s.SessionID.String(), at, id)
		})
	}
	if len(rows) > int(limit) {
		rows = rows[:limit]
	}
	return rows, nil
}

type fakeMethods struct {
	rows []AuthMethod
	err  error
}

func (f *fakeMethods) Methods(context.Context, string) ([]AuthMethod, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.rows, nil
}

type fakeHistory struct {
	rows   []LoginRecord
	err    error
	calls  int
	limit  int32
	cursor page.Keyset
}

func (f *fakeHistory) LoginHistory(
	_ context.Context, _ string, after page.Keyset, limit int32,
) ([]LoginRecord, error) {
	f.calls++
	f.limit = limit
	f.cursor = after
	if f.err != nil {
		return nil, f.err
	}

	rows := slices.Clone(f.rows)
	slices.SortFunc(rows, loginOrder)
	if !after.IsStart() {
		args := after.Args()
		at, id := args[0].(time.Time), args[1].(int64)
		rows = slices.DeleteFunc(rows, func(r LoginRecord) bool {
			return !r.OccurredAt.Before(at) && (!r.OccurredAt.Equal(at) || r.ID >= id)
		})
	}
	if len(rows) > int(limit) {
		rows = rows[:limit]
	}
	return rows, nil
}

// sessionOrder and loginOrder are the ORDER BY the statements declare: the sort
// column descending, then the unique tiebreaker descending.
func sessionOrder(a, b SessionSummary) int {
	if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
		return c
	}
	return strings.Compare(b.SessionID.String(), a.SessionID.String())
}

func loginOrder(a, b LoginRecord) int {
	if c := b.OccurredAt.Compare(a.OccurredAt); c != 0 {
		return c
	}
	return int(b.ID - a.ID)
}

// before reports whether a row sorts strictly AFTER the cursor in a descending
// list — that is, whether the row belongs on a later page.
func before(rowAt time.Time, rowID string, curAt time.Time, curID string) bool {
	if rowAt.Before(curAt) {
		return true
	}
	return rowAt.Equal(curAt) && rowID < curID
}

func newQueries(t *testing.T, deps QueriesDeps) *Queries {
	t.Helper()
	if deps.Accounts == nil {
		deps.Accounts = &fakeAccounts{}
	}
	if deps.Sessions == nil {
		deps.Sessions = &fakeSessions{}
	}
	if deps.Methods == nil {
		deps.Methods = &fakeMethods{}
	}
	if deps.History == nil {
		deps.History = &fakeHistory{}
	}
	q, err := NewQueries(deps)
	if err != nil {
		t.Fatalf("building the read side: %v", err)
	}
	return q
}

func sessionAt(t *testing.T, at time.Time) SessionSummary {
	t.Helper()
	return SessionSummary{
		SessionID:         ids.New[ids.Session](at, ids.Entropy()),
		DeviceID:          "dev",
		AAL:               contract.AAL2,
		CreatedAt:         at,
		AbsoluteExpiresAt: at.Add(24 * time.Hour),
		IdleExpiresAt:     at.Add(time.Hour),
	}
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

func TestNewQueries_RefusesAPartialReadSide(t *testing.T) {
	full := QueriesDeps{
		Accounts: &fakeAccounts{}, Sessions: &fakeSessions{},
		Methods: &fakeMethods{}, History: &fakeHistory{},
	}
	if _, err := NewQueries(full); err != nil {
		t.Fatalf("a complete read side must build: %v", err)
	}

	for _, tc := range []struct {
		name string
		drop func(*QueriesDeps)
	}{
		{"accounts", func(d *QueriesDeps) { d.Accounts = nil }},
		{"sessions", func(d *QueriesDeps) { d.Sessions = nil }},
		{"methods", func(d *QueriesDeps) { d.Methods = nil }},
		{"history", func(d *QueriesDeps) { d.History = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps := full
			tc.drop(&deps)
			if _, err := NewQueries(deps); err == nil {
				t.Fatalf("a read side missing %s built anyway; the nil port would panic on "+
					"the first request to that screen, long after the process reported healthy",
					tc.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GetUser
// ---------------------------------------------------------------------------

func TestGetUser_ReturnsTheAccountAndItsVerificationState(t *testing.T) {
	registered := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	want := AccountView{
		SubjectID:     "subj_abc",
		UserID:        ids.New[ids.User](registered, ids.Entropy()),
		State:         domain.StateActive,
		EmailVerified: true,
		RegisteredAt:  registered,
		ActivatedAt:   registered.Add(time.Hour),
	}
	accounts := &fakeAccounts{account: want}
	q := newQueries(t, QueriesDeps{Accounts: accounts})

	got, err := q.GetUser(context.Background(), "subj_abc")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got != want {
		t.Errorf("GetUser returned %+v, want %+v", got, want)
	}
	if len(accounts.seen) != 1 || accounts.seen[0] != "subj_abc" {
		t.Errorf("the reader was asked for %v, want exactly [subj_abc]: a read side that "+
			"substitutes its own subject answers for the wrong account", accounts.seen)
	}
}

func TestGetUser_UnknownSubjectIsNotFoundAndSaysNothingElse(t *testing.T) {
	q := newQueries(t, QueriesDeps{Accounts: &fakeAccounts{err: ErrNoSuchSubject}})

	_, err := q.GetUser(context.Background(), "subj_missing")
	if err == nil {
		t.Fatal("an unknown subject returned no error")
	}
	if got := errs.ReasonOf(err); got != errs.NotFound {
		t.Fatalf("an unknown subject is %s, want NOT_FOUND", got)
	}
	// The message must not name the subject, and must not hint at WHY there is no
	// account. Once S1-24 checks that the subject is the caller's own, "no such
	// account" and "not your account" must be the same answer — otherwise anyone
	// holding a pseudonym can test it for existence.
	if strings.Contains(err.Error(), "subj_missing") {
		t.Errorf("the not-found error names the subject (%q); a caller can then confirm "+
			"a pseudonym exists by reading the message", err.Error())
	}
}

func TestGetUser_EmptySubjectIsRefusedRatherThanAnswered(t *testing.T) {
	accounts := &fakeAccounts{}
	q := newQueries(t, QueriesDeps{Accounts: accounts})

	if _, err := q.GetUser(context.Background(), ""); errs.ReasonOf(err) != errs.ValidationFailed {
		t.Fatalf("an empty subject gave %v, want VALIDATION_FAILED: an empty subject is a "+
			"caller that lost the authenticated principal, not an account with nothing on it", err)
	}
	if len(accounts.seen) != 0 {
		t.Errorf("the reader was consulted for an empty subject")
	}
}

func TestGetUser_AStorageFailureIsNotReportedAsAMissingAccount(t *testing.T) {
	boom := errors.New("connection reset")
	q := newQueries(t, QueriesDeps{Accounts: &fakeAccounts{err: boom}})

	_, err := q.GetUser(context.Background(), "subj_abc")
	if got := errs.ReasonOf(err); got != errs.Internal {
		t.Fatalf("a storage failure is %s, want INTERNAL: reported as NOT_FOUND it would "+
			"tell every user their account had vanished during an outage", got)
	}
	if !errors.Is(err, boom) {
		t.Errorf("the cause was dropped; %v", err)
	}
}

// ---------------------------------------------------------------------------
// ListSessions — pagination
// ---------------------------------------------------------------------------

func TestListSessions_FirstPageAsksForOneMoreRowThanItReturns(t *testing.T) {
	base := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	rows := []SessionSummary{
		sessionAt(t, base), sessionAt(t, base.Add(-time.Minute)), sessionAt(t, base.Add(-2*time.Minute)),
	}
	sessions := &fakeSessions{rows: rows}
	q := newQueries(t, QueriesDeps{Sessions: sessions})

	got, err := q.ListSessions(context.Background(), "subj_abc", "", 2)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if sessions.limit != 3 {
		t.Errorf("the adapter was asked for %d rows for a page of 2, want 3: without the "+
			"extra row there is nothing to prove another page exists", sessions.limit)
	}
	if !sessions.cursor.IsStart() {
		t.Errorf("an empty page token produced the cursor %v, want the start position",
			sessions.cursor.Columns())
	}
	if len(got.Items) != 2 {
		t.Fatalf("a page of 2 returned %d items; the peeked row reached the caller",
			len(got.Items))
	}
	if got.Next == "" {
		t.Error("a page with more rows behind it returned no token; the client stops early")
	}
}

func TestListSessions_ThePeekedRowIsNeverReturned(t *testing.T) {
	base := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	rows := []SessionSummary{
		sessionAt(t, base), sessionAt(t, base.Add(-time.Minute)), sessionAt(t, base.Add(-2*time.Minute)),
	}
	slices.SortFunc(rows, sessionOrder)
	q := newQueries(t, QueriesDeps{Sessions: &fakeSessions{rows: rows}})

	got, err := q.ListSessions(context.Background(), "subj_abc", "", 2)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	for _, item := range got.Items {
		if item.SessionID == rows[2].SessionID {
			t.Fatalf("the third row was returned on a page of 2; it exists only to prove " +
				"another page follows, and returning it makes every page one row long " +
				"at the boundary")
		}
	}
}

func TestListSessions_TheLastPageReturnsAnEmptyToken(t *testing.T) {
	base := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	q := newQueries(t, QueriesDeps{Sessions: &fakeSessions{rows: []SessionSummary{
		sessionAt(t, base), sessionAt(t, base.Add(-time.Minute)),
	}}})

	got, err := q.ListSessions(context.Background(), "subj_abc", "", 5)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(got.Items) != 2 {
		t.Fatalf("got %d items, want 2", len(got.Items))
	}
	if got.Next != "" {
		t.Errorf("an exhausted list returned the token %q; the client follows it, gets an "+
			"empty page, and the walk never terminates on its own", got.Next)
	}
}

func TestListSessions_AnEmptyListReturnsAnEmptyToken(t *testing.T) {
	q := newQueries(t, QueriesDeps{Sessions: &fakeSessions{}})

	got, err := q.ListSessions(context.Background(), "subj_abc", "", 5)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(got.Items) != 0 || got.Next != "" {
		t.Fatalf("an empty list returned %d items and token %q, want 0 and empty",
			len(got.Items), got.Next)
	}
}

// The property the whole scheme exists for: walking the list page by page visits
// every row exactly once.
//
// Driven with rows that SHARE a created_at, because that is the only shape in
// which the failure appears. With distinct sort values every cursor scheme works,
// including a broken one; with ties, a sort key that did not end in a unique
// column would either return a row on two consecutive pages or drop it between
// them, with no error anywhere.
func TestListSessions_APageBoundaryNeitherSkipsNorRepeatsATiedRow(t *testing.T) {
	base := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	rows := []SessionSummary{
		sessionAt(t, base), sessionAt(t, base), sessionAt(t, base), // three at the same instant
		sessionAt(t, base.Add(-time.Second)), sessionAt(t, base.Add(-time.Second)),
		sessionAt(t, base.Add(-time.Minute)), sessionAt(t, base.Add(-time.Hour)),
	}
	want := slices.Clone(rows)
	slices.SortFunc(want, sessionOrder)

	q := newQueries(t, QueriesDeps{Sessions: &fakeSessions{rows: rows}})

	var walked []SessionSummary
	var token page.Token
	for pages := 0; ; pages++ {
		if pages > len(rows)+2 {
			t.Fatal("the walk did not terminate; the list is handing out a token forever")
		}
		got, err := q.ListSessions(context.Background(), "subj_abc", token, 2)
		if err != nil {
			t.Fatalf("page %d: %v", pages, err)
		}
		walked = append(walked, got.Items...)
		if got.Next == "" {
			break
		}
		token = got.Next
	}

	if len(walked) != len(want) {
		t.Fatalf("the walk visited %d rows, want %d: a boundary either dropped one or "+
			"handed one back twice", len(walked), len(want))
	}
	for i := range want {
		if walked[i].SessionID != want[i].SessionID {
			t.Fatalf("position %d is session %s, want %s: the pages do not reassemble into "+
				"the declared order", i, walked[i].SessionID, want[i].SessionID)
		}
	}
}

func TestListSessions_AnUnreadableTokenIsAnErrorNotAFreshStart(t *testing.T) {
	sessions := &fakeSessions{}
	q := newQueries(t, QueriesDeps{Sessions: sessions})

	for _, tok := range []page.Token{"not base64 at all!!", "aGVsbG8", "AAAA"} {
		t.Run(string(tok), func(t *testing.T) {
			_, err := q.ListSessions(context.Background(), "subj_abc", tok, 2)
			if err == nil {
				t.Fatal("an unreadable token was accepted; a client handed page one for a " +
					"cursor it believes points into the middle of a list walks it forever, " +
					"and nothing in that loop looks like a failure")
			}
			if got := errs.ReasonOf(err); got != errs.ValidationFailed {
				t.Errorf("an unreadable token is %s, want VALIDATION_FAILED", got)
			}
		})
	}
	if sessions.calls != 0 {
		t.Errorf("the adapter was queried %d times for an unreadable token; the refusal "+
			"must happen before any rows are read, or the caller receives page one", sessions.calls)
	}
}

func TestListSessions_ATokenFromTheLoginHistoryIsRefused(t *testing.T) {
	base := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	history := &fakeHistory{rows: []LoginRecord{
		{ID: 3, OccurredAt: base}, {ID: 2, OccurredAt: base.Add(-time.Minute)},
		{ID: 1, OccurredAt: base.Add(-time.Hour)},
	}}
	sessions := &fakeSessions{rows: []SessionSummary{
		sessionAt(t, base), sessionAt(t, base.Add(-time.Minute)), sessionAt(t, base.Add(-time.Hour)),
	}}
	q := newQueries(t, QueriesDeps{Sessions: sessions, History: history})

	historyPage, err := q.ListLoginHistory(context.Background(), "subj_abc", "", 2)
	if err != nil {
		t.Fatalf("ListLoginHistory: %v", err)
	}
	if historyPage.Next == "" {
		t.Fatal("no token to replay; the fixture must leave a page behind")
	}

	before := sessions.calls
	if _, err := q.ListSessions(context.Background(), "subj_abc", historyPage.Next, 2); err == nil {
		t.Fatal("a login-history cursor was accepted by the device list; the two are " +
			"sorted by different columns, so it names a position in a list that does " +
			"not exist and the rows that come back are simply wrong")
	}
	if sessions.calls != before {
		t.Error("the device list queried the adapter with a foreign cursor")
	}

	// And the other direction, which is the one a copy-pasted QueryID would break.
	sessionPage, err := q.ListSessions(context.Background(), "subj_abc", "", 2)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if sessionPage.Next == "" {
		t.Fatal("no session token to replay")
	}
	if _, err := q.ListLoginHistory(context.Background(), "subj_abc", sessionPage.Next, 2); err == nil {
		t.Fatal("a device-list cursor was accepted by the login history")
	}
}

func TestListSessions_ATokenMintedForAnotherSubjectIsRefused(t *testing.T) {
	base := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	q := newQueries(t, QueriesDeps{Sessions: &fakeSessions{rows: []SessionSummary{
		sessionAt(t, base), sessionAt(t, base.Add(-time.Minute)), sessionAt(t, base.Add(-time.Hour)),
	}}})

	mine, err := q.ListSessions(context.Background(), "subj_mine", "", 2)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if mine.Next == "" {
		t.Fatal("no token to replay")
	}

	if _, err := q.ListSessions(context.Background(), "subj_theirs", mine.Next, 2); err == nil {
		t.Fatal("a cursor minted for one subject was accepted for another; the subject is " +
			"a filter value, so the token names a position in a list it was never taken " +
			"from, and this control is meant to hold independently of S1-24's check")
	}
}

func TestListSessions_PageSizeIsResolvedByTheKernelsRules(t *testing.T) {
	base := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		requested int
		wantLimit int32
		wantErr   bool
	}{
		{"unspecified takes the default", 0, page.DefaultSize + 1, false},
		{"over the maximum is capped, not refused", 10_000, page.MaxSize + 1, false},
		{"negative is a caller bug", -1, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sessions := &fakeSessions{rows: []SessionSummary{sessionAt(t, base)}}
			q := newQueries(t, QueriesDeps{Sessions: sessions})

			_, err := q.ListSessions(context.Background(), "subj_abc", "", tc.requested)
			if tc.wantErr {
				if errs.ReasonOf(err) != errs.ValidationFailed {
					t.Fatalf("a page size of %d gave %v, want VALIDATION_FAILED",
						tc.requested, err)
				}
				if sessions.calls != 0 {
					t.Error("a negative page size still reached the adapter")
				}
				return
			}
			if err != nil {
				t.Fatalf("ListSessions: %v", err)
			}
			if sessions.limit != tc.wantLimit {
				t.Errorf("a request for %d asked the adapter for %d rows, want %d",
					tc.requested, sessions.limit, tc.wantLimit)
			}
		})
	}
}

func TestListSessions_EmptySubjectIsRefusedBeforeAnyQuery(t *testing.T) {
	sessions := &fakeSessions{}
	q := newQueries(t, QueriesDeps{Sessions: sessions})

	if _, err := q.ListSessions(context.Background(), "", "", 2); errs.ReasonOf(err) != errs.ValidationFailed {
		t.Fatalf("an empty subject gave %v, want VALIDATION_FAILED", err)
	}
	if sessions.calls != 0 {
		t.Error("an empty subject reached the adapter, where it would filter on '' and " +
			"return an empty device list that looks like a person with no devices")
	}
}

func TestListSessions_AStorageFailureIsInternal(t *testing.T) {
	boom := errors.New("connection reset")
	q := newQueries(t, QueriesDeps{Sessions: &fakeSessions{err: boom}})

	_, err := q.ListSessions(context.Background(), "subj_abc", "", 2)
	if got := errs.ReasonOf(err); got != errs.Internal {
		t.Fatalf("a storage failure is %s, want INTERNAL", got)
	}
	if !errors.Is(err, boom) {
		t.Errorf("the cause was dropped; %v", err)
	}
}

// ---------------------------------------------------------------------------
// ListLoginHistory
// ---------------------------------------------------------------------------

func TestListLoginHistory_APageBoundaryNeitherSkipsNorRepeatsATiedRow(t *testing.T) {
	base := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	// A burst: five attempts recorded in the same instant, which is what a
	// credential-stuffing run actually looks like in this table.
	rows := []LoginRecord{
		{ID: 1, OccurredAt: base}, {ID: 2, OccurredAt: base}, {ID: 3, OccurredAt: base},
		{ID: 4, OccurredAt: base}, {ID: 5, OccurredAt: base},
		{ID: 6, OccurredAt: base.Add(-time.Minute), Succeeded: true},
		{ID: 7, OccurredAt: base.Add(-time.Hour)},
	}
	want := slices.Clone(rows)
	slices.SortFunc(want, loginOrder)

	q := newQueries(t, QueriesDeps{History: &fakeHistory{rows: rows}})

	var walked []LoginRecord
	var token page.Token
	for pages := 0; ; pages++ {
		if pages > len(rows)+2 {
			t.Fatal("the walk did not terminate")
		}
		got, err := q.ListLoginHistory(context.Background(), "subj_abc", token, 2)
		if err != nil {
			t.Fatalf("page %d: %v", pages, err)
		}
		walked = append(walked, got.Items...)
		if got.Next == "" {
			break
		}
		token = got.Next
	}

	if len(walked) != len(want) {
		t.Fatalf("the walk visited %d attempts, want %d: a security screen that drops an "+
			"attempt cannot answer the only question it is asked", len(walked), len(want))
	}
	for i := range want {
		if walked[i].ID != want[i].ID {
			t.Fatalf("position %d is attempt %d, want %d", i, walked[i].ID, want[i].ID)
		}
	}
}

func TestListLoginHistory_FailuresAreReturnedWithTheirReason(t *testing.T) {
	base := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	q := newQueries(t, QueriesDeps{History: &fakeHistory{rows: []LoginRecord{
		{ID: 2, OccurredAt: base, Succeeded: false, Reason: contract.ReasonWrongSecondFactor},
		{ID: 1, OccurredAt: base.Add(-time.Hour), Succeeded: true,
			Methods: []contract.MethodKind{contract.MethodPassword, contract.MethodTOTP},
			AAL:     contract.AAL2},
	}}})

	got, err := q.ListLoginHistory(context.Background(), "subj_abc", "", 10)
	if err != nil {
		t.Fatalf("ListLoginHistory: %v", err)
	}
	if len(got.Items) != 2 {
		t.Fatalf("got %d attempts, want 2: a history of successes only shows a compromised "+
			"account as an ordinary quiet list", len(got.Items))
	}
	if got.Items[0].Succeeded || got.Items[0].Reason != contract.ReasonWrongSecondFactor {
		t.Errorf("the failed attempt came back as %+v; the reason is withheld from the "+
			"failing caller and shown to the account holder afterwards", got.Items[0])
	}
	if got.Items[1].AAL != contract.AAL2 {
		t.Errorf("the successful attempt reports AAL %d, want 2", got.Items[1].AAL)
	}
}

func TestListLoginHistory_UnreadableTokenAndEmptySubjectAreRefused(t *testing.T) {
	history := &fakeHistory{}
	q := newQueries(t, QueriesDeps{History: history})

	if _, err := q.ListLoginHistory(context.Background(), "subj_abc", "@@not-a-token@@", 5); errs.ReasonOf(err) != errs.ValidationFailed {
		t.Errorf("an unreadable token gave %v, want VALIDATION_FAILED", err)
	}
	if _, err := q.ListLoginHistory(context.Background(), "", "", 5); errs.ReasonOf(err) != errs.ValidationFailed {
		t.Errorf("an empty subject gave %v, want VALIDATION_FAILED", err)
	}
	if history.calls != 0 {
		t.Errorf("the adapter was queried %d times for a request that never should have "+
			"reached it", history.calls)
	}
}

func TestListLoginHistory_AStorageFailureIsInternal(t *testing.T) {
	boom := errors.New("connection reset")
	q := newQueries(t, QueriesDeps{History: &fakeHistory{err: boom}})

	if got := errs.ReasonOf(mustErr(q.ListLoginHistory(context.Background(), "subj_abc", "", 5))); got != errs.Internal {
		t.Fatalf("a storage failure is %s, want INTERNAL", got)
	}
}

func mustErr[T any](_ T, err error) error { return err }

// ---------------------------------------------------------------------------
// ListMethods
// ---------------------------------------------------------------------------

func TestListMethods_ReportsUsabilityByTheDomainsRule(t *testing.T) {
	at := time.Date(2026, 4, 1, 8, 0, 0, 0, time.UTC)
	enabled := AuthMethod{
		Method:  domain.Method{ID: ids.New[ids.Credential](at, ids.Entropy()), Kind: contract.MethodPassword, EnabledAt: at},
		AddedAt: at, LastUsedAt: at.Add(time.Hour),
	}
	pending := AuthMethod{
		Method:  domain.Method{ID: ids.New[ids.Credential](at, ids.Entropy()), Kind: contract.MethodTOTP},
		AddedAt: at,
	}
	lockedOut := AuthMethod{
		Method: domain.Method{
			ID: ids.New[ids.Credential](at, ids.Entropy()), Kind: contract.MethodTOTP,
			EnabledAt: at, DisabledAt: at.Add(2 * time.Hour),
		},
		AddedAt: at,
	}

	q := newQueries(t, QueriesDeps{Methods: &fakeMethods{rows: []AuthMethod{enabled, pending, lockedOut}}})

	got, err := q.ListMethods(context.Background(), "subj_abc")
	if err != nil {
		t.Fatalf("ListMethods: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d methods, want 3: a method hidden from this screen is one the "+
			"account holder cannot notice or remove", len(got))
	}
	if !got[0].Usable() {
		t.Error("an enabled, un-disabled method reported itself unusable")
	}
	if got[1].Usable() || !got[1].Pending() {
		t.Error("a provisioned-but-unproven method must be pending and not usable; " +
			"treating provisioning as completion is how an account ends up with a " +
			"second factor that exists only on the server's side")
	}
	if got[2].Usable() {
		t.Error("a locked-out method reported itself usable; the lockout then exists in " +
			"the table and nowhere in the behaviour")
	}
	if !got[0].LastUsedAt.Equal(at.Add(time.Hour)) || !got[1].LastUsedAt.IsZero() {
		t.Errorf("last-used is wrong: %v / %v; a never-used method must say so, or the "+
			"screen cannot answer \"did I enrol that\"", got[0].LastUsedAt, got[1].LastUsedAt)
	}
}

func TestListMethods_EmptySubjectAndFailuresAreRefused(t *testing.T) {
	if _, err := newQueries(t, QueriesDeps{}).ListMethods(context.Background(), ""); errs.ReasonOf(err) != errs.ValidationFailed {
		t.Errorf("an empty subject gave %v, want VALIDATION_FAILED", err)
	}
	boom := errors.New("connection reset")
	_, err := newQueries(t, QueriesDeps{Methods: &fakeMethods{err: boom}}).
		ListMethods(context.Background(), "subj_abc")
	if errs.ReasonOf(err) != errs.Internal {
		t.Errorf("a storage failure gave %v, want INTERNAL", err)
	}
	if !errors.Is(err, boom) {
		t.Errorf("the cause was dropped; %v", err)
	}
}

// ---------------------------------------------------------------------------
// The shapes themselves
// ---------------------------------------------------------------------------

// The result types carry no personal data and no secret, and this test asserts
// the EXACT field set of each one.
//
// Exact rather than a blocklist of suspicious names, deliberately. A blocklist
// passes for the field nobody thought of — `Pepper`, `Sealed`, `Recovery` — and
// the whole risk here is a future edit that widens a SELECT and adds a field to
// carry it. An exact set makes that edit fail this test and require a decision.
func TestResultShapes_CarryNothingThatVerifiesOrIdentifies(t *testing.T) {
	for _, tc := range []struct {
		name  string
		typ   reflect.Type
		want  []string
		notes string
	}{
		{
			name: "AccountView", typ: reflect.TypeFor[AccountView](),
			want: []string{"SubjectID", "UserID", "State", "EmailVerified", "Username",
				"RegisteredAt", "ActivatedAt", "DeactivatedAt", "SuspendedAt",
				"DeletionRequestedAt", "DeletionScheduledFor"},
			notes: "no address and no email index: the address is resolved from the " +
				"SubjectID by the vault, and the index is a lookup key an actor holding " +
				"the blind-index key can confirm a candidate address against. Username " +
				"IS here and is the ONE exception in this list (ADR-051): a public " +
				"handle is published by design, so the vault cannot protect it — " +
				"crypto-shredding does nothing to a value that was published — and " +
				"there is nothing for a pseudonym to stand in for",
		},
		{
			name: "SessionSummary", typ: reflect.TypeFor[SessionSummary](),
			want: []string{"SessionID", "DeviceID", "AAL", "IdleExpiresAt",
				"AbsoluteExpiresAt", "CreatedAt", "LastSeenAt"},
			notes: "no token and no digest: a device list exists so a user can revoke a " +
				"credential, not so it can display one",
		},
		{
			name: "AuthMethod", typ: reflect.TypeFor[AuthMethod](),
			want: []string{"Method", "ID", "Kind", "EnabledAt", "DisabledAt",
				"AddedAt", "LastUsedAt"},
			notes: "no verifier, no sealed TOTP secret, no pepper version, no failure " +
				"count; all four live in the same credential row as the metadata above",
		},
		{
			name: "LoginRecord", typ: reflect.TypeFor[LoginRecord](),
			want: []string{"ID", "Succeeded", "Reason", "Methods", "AAL",
				"DeviceID", "OccurredAt"},
			notes: "no email index: the column exists on login_history_view for " +
				"stuffing detection across accounts and has no place on a screen",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, f := range reflect.VisibleFields(tc.typ) {
				got = append(got, f.Name)
				if f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.Uint8 {
					t.Errorf("%s.%s is a byte slice; every secret in identity is bytes, "+
						"and nothing on these screens is", tc.name, f.Name)
				}
			}
			slices.Sort(got)
			want := slices.Clone(tc.want)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("%s has fields %v, want %v — %s", tc.name, got, want, tc.notes)
			}
		})
	}
}

// The two lists must not share a QueryID.
//
// Asserted directly rather than only through the cross-list replay above,
// because the replay is caught by TWO controls — the query fingerprint and the
// column check — and either one alone makes the other's removal invisible. A
// mutation that gave both lists the same QueryID survived the replay test for
// exactly that reason.
func TestQueryIDs_AreDistinctPerListAndPerSubject(t *testing.T) {
	if sessionsQueryID("subj_a") == loginHistoryQueryID("subj_a") {
		t.Error("the device list and the login history share a QueryID; a cursor is a " +
			"position in one specific filter and sort, and the two are sorted by " +
			"different columns")
	}
	if sessionsQueryID("subj_a") == sessionsQueryID("subj_b") {
		t.Error("two subjects share a session QueryID; the subject is a filter value, so " +
			"a token would name a position in a list it was never taken from")
	}
	if loginHistoryQueryID("subj_a") == loginHistoryQueryID("subj_b") {
		t.Error("two subjects share a login-history QueryID")
	}
}

// The two cursors must name different columns, or one list's token would decode
// cleanly against the other's query on a fingerprint collision.
func TestSortKeys_EndInAUniqueColumn(t *testing.T) {
	for name, columns := range map[string][]string{
		"sessions":      sessionSortColumns,
		"login history": loginHistorySortColumns,
	} {
		t.Run(name, func(t *testing.T) {
			if len(columns) != 2 {
				t.Fatalf("%s sorts by %v; a keyset must name every sort column", name, columns)
			}
			// page.NewKeyset refuses a key whose LAST column is not marked unique.
			// Asserting the refusal here ties this file's declared sort key to the
			// kernel's rule rather than to a comment.
			if _, err := page.NewKeyset(
				page.Key{Column: columns[0], Value: time.Now().UTC()},
				page.Key{Column: columns[1], Value: "x"},
			); err == nil {
				t.Fatal("a keyset whose tail is not marked unique was accepted")
			}
		})
	}
}

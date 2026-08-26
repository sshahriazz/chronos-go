//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	identitypg "github.com/chronos/chronos-go/internal/modules/identity/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/page"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Identity's read side, against the real schema.
//
// Tested here rather than against a fake because the properties that decide
// whether these screens are correct are properties of the SQL and of PostgreSQL's
// own semantics: whether the first page's cursor sentinel actually matches every
// row, whether a row comparison over `(created_at, session_id)` pages a group of
// rows sharing an instant without dropping one, and whether the device list still
// hides a session whose secret has been swept. A stub that accepted the
// statements would demonstrate none of it.
//
// Most tests drive the app service over the real adapter rather than the adapter
// alone. That is deliberate: the cursor is encoded in one layer, bound in the
// other, and compared by PostgreSQL — a test of any single layer would leave the
// two joins between them unexercised, which is exactly where a pagination bug
// lives.

func newReadModel(t *testing.T, pool *pgxpool.Pool) *identitypg.ReadModel {
	t.Helper()
	rm, err := identitypg.NewReadModel(pgadapter.New(pool))
	if err != nil {
		t.Fatalf("building the read model: %v", err)
	}
	return rm
}

func newReadSide(t *testing.T, pool *pgxpool.Pool) *app.Queries {
	t.Helper()
	rm := newReadModel(t, pool)
	// The REAL API key directory, not a stub.
	//
	// Every other port here is the real read model, for the reason this file's
	// header gives: a test of any single layer leaves the joins between them
	// unexercised, and that is where a pagination bug lives. A stubbed key
	// directory would make this harness the one place the read side is built
	// from something that is not what production builds it from.
	//
	// It takes both transaction kinds because its two tables differ:
	// api_key_secret carries no row-level security (the authenticator reads it
	// before any organization is known) while api_key_view and
	// service_account_view do.
	keys, err := identitypg.NewAPIKeys(pgadapter.New(pool), pgadapter.New(pool))
	if err != nil {
		t.Fatalf("building the API key directory: %v", err)
	}

	q, err := app.NewQueries(app.QueriesDeps{
		Accounts: rm, Sessions: rm, Methods: rm, History: rm, Keys: keys,
	})
	if err != nil {
		t.Fatalf("building the read side: %v", err)
	}
	return q
}

// seedReadAccount writes a user_view row with a chosen lifecycle state.
func seedReadAccount(t *testing.T, pool *pgxpool.Pool, label, state string) string {
	t.Helper()
	subjectID := fmt.Sprintf("subj_read_%s_%d", label, time.Now().UnixNano())
	userID := ids.New[ids.User](time.Now().UTC(), sessionEntropy{}).String()
	index := fmt.Sprintf("%064x", time.Now().UnixNano())[:64]

	if _, err := pool.Exec(context.Background(), identitydb.UpsertUser,
		subjectID, userID, index, state, time.Now().UTC()); err != nil {
		t.Fatalf("seeding an account: %v", err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = pool.Exec(ctx, "DELETE FROM session_token WHERE session_id IN "+
			"(SELECT session_id FROM session_view WHERE subject_id = $1)", subjectID)
		_, _ = pool.Exec(ctx, "DELETE FROM login_history_view WHERE subject_id = $1", subjectID)
		_, _ = pool.Exec(ctx, "DELETE FROM credential WHERE subject_id = $1", subjectID)
		_, _ = pool.Exec(ctx, "DELETE FROM user_view WHERE subject_id = $1", subjectID)
	})
	return subjectID
}

// seedLiveSession writes BOTH halves of a session at a chosen created_at.
//
// Both, because the device list joins them — the projected facts and the
// authoritative token row — and a session with only one half is a different test
// (below) rather than a fixture.
func seedLiveSession(
	t *testing.T, pool *pgxpool.Pool, subjectID string, createdAt time.Time,
) ids.SessionID {
	t.Helper()
	ctx := context.Background()
	id := ids.New[ids.Session](time.Now().UTC(), sessionEntropy{})
	if _, err := pool.Exec(ctx, identitydb.UpsertSession,
		id.String(), subjectID, "dev_1", int32(2),
		time.Now().UTC().Add(24*time.Hour), false, createdAt); err != nil {
		t.Fatalf("seeding a session: %v", err)
	}
	if _, err := pool.Exec(ctx, identitydb.IssueSessionToken,
		sessionDigest(7), id.String(), time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("seeding a session token: %v", err)
	}
	return id
}

func seedAttempt(
	t *testing.T, pool *pgxpool.Pool, subjectID string, at time.Time, succeeded bool,
) {
	t.Helper()
	// The table has a CHECK tying the two together: a success carries no reason and
	// a failure must carry one. Seeding otherwise fails at insert time rather than
	// producing the row the test wanted.
	var reason any
	if !succeeded {
		reason = string(contract.ReasonWrongPassword)
	}
	if _, err := pool.Exec(context.Background(), identitydb.RecordLoginAttempt,
		subjectID, nil, succeeded, reason,
		[]string{"password"}, int32(1), "dev_1", at); err != nil {
		t.Fatalf("seeding a login attempt: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetUser
// ---------------------------------------------------------------------------

func TestReadingAnAccountFromTheProjection(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	q := newReadSide(t, pool)

	subject := seedReadAccount(t, pool, "account", "active")
	if _, err := pool.Exec(ctx, identitydb.MarkEmailVerified, subject,
		fmt.Sprintf("%064x", time.Now().UnixNano())[:64]); err != nil {
		t.Fatalf("marking verified: %v", err)
	}

	got, err := q.GetUser(ctx, subject)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.SubjectID != subject {
		t.Errorf("subject is %q, want %q", got.SubjectID, subject)
	}
	if got.State != domain.StateActive {
		t.Errorf("state is %v, want active: the projected string must map to the domain "+
			"type, or an unparsed state would render as a missing account", got.State)
	}
	if !got.EmailVerified {
		t.Error("email_verified came back false after MarkEmailVerified")
	}
	if got.UserID.IsZero() {
		t.Error("the user id did not survive the read")
	}
	if got.RegisteredAt.IsZero() || got.RegisteredAt.Location() != time.UTC {
		t.Errorf("registered_at is %v in %v; storage is UTC and so is every value read "+
			"back from it", got.RegisteredAt, got.RegisteredAt.Location())
	}
}

func TestReadingAnAccountThatIsNotProjectedYet(t *testing.T) {
	rm := newReadModel(t, openPool(t))

	_, err := rm.Account(context.Background(), "subj_read_absent_"+fmt.Sprint(time.Now().UnixNano()))
	if !errors.Is(err, app.ErrNoSuchSubject) {
		t.Fatalf("an unprojected subject gave %v, want ErrNoSuchSubject: any other error "+
			"would surface to the caller as INTERNAL and read as an outage", err)
	}
}

// The database refuses a lifecycle state this application does not write.
//
// This is why the adapter's own parser cannot be provoked from here: the CHECK on
// user_view.state is the first lock, and it holds. The parser is the second lock,
// for the case the constraint cannot cover — a state added to the constraint by a
// newer migration and read by an older binary — and it is exercised by
// TestAccountState in queries_test.go instead.
//
// Asserting the constraint here rather than assuming it: an application-level
// check that duplicates a database constraint is only a second lock if the first
// one exists.
func TestTheDatabaseRefusesAnUnrecognisedLifecycleState(t *testing.T) {
	pool := openPool(t)
	subject := seedReadAccount(t, pool, "badstate", "active")

	_, err := pool.Exec(context.Background(), identitydb.SetUserState, subject, "quarantined")
	if err == nil {
		t.Fatal("user_view accepted the state \"quarantined\"; the CHECK that keeps the " +
			"projection's vocabulary equal to the domain's has gone")
	}
	// And the account still reads back in the state it had, rather than the write
	// having half-applied.
	rm := newReadModel(t, pool)
	got, err := rm.Account(context.Background(), subject)
	if err != nil {
		t.Fatalf("Account: %v", err)
	}
	if got.State != domain.StateActive {
		t.Errorf("state is %v after a refused write, want active", got.State)
	}
}

// ---------------------------------------------------------------------------
// ListSessions
// ---------------------------------------------------------------------------

// The first page's cursor is `timestamptz 'infinity'`, and this is the test that
// says so against a real server.
//
// The statement compares `(created_at, session_id) < ($2, $3)` unconditionally,
// so the first page needs a position strictly above every row rather than a
// second statement. If the sentinel were wrong — a NULL, a zero time, a finite
// "far future" that a clock skew could pass — this returns nothing, and an empty
// device list is indistinguishable from a person who has never signed in.
func TestTheFirstPageOfSessionsMatchesEveryRow(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	q := newReadSide(t, pool)

	subject := seedReadAccount(t, pool, "firstpage", "active")
	now := time.Now().UTC()
	seedLiveSession(t, pool, subject, now)
	seedLiveSession(t, pool, subject, now.Add(-time.Hour))

	got, err := q.ListSessions(ctx, subject, "", 10)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(got.Items) != 2 {
		t.Fatalf("the first page returned %d sessions, want 2: with no cursor the "+
			"comparison must match every row", len(got.Items))
	}
	if got.Next != "" {
		t.Errorf("an exhausted list returned the token %q", got.Next)
	}
	if !got.Items[0].CreatedAt.After(got.Items[1].CreatedAt) {
		t.Errorf("the device list is not newest-first: %v then %v",
			got.Items[0].CreatedAt, got.Items[1].CreatedAt)
	}
}

// Paging a group of sessions that share a created_at.
//
// The tie is the whole point. `session_id` is the unique tail of the sort key,
// and without it the row comparison would either return a tied row on two
// consecutive pages or drop it between them — with no error, no log line, and a
// device list that is quietly missing the device the user is looking for.
func TestPagingSessionsThatShareACreatedAt(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	q := newReadSide(t, pool)

	subject := seedReadAccount(t, pool, "tiedsessions", "active")
	instant := time.Now().UTC().Truncate(time.Microsecond)
	want := map[string]bool{}
	for range 5 {
		want[seedLiveSession(t, pool, subject, instant).String()] = false
	}
	// Two more at a distinct instant, so the walk also crosses a real boundary.
	for range 2 {
		want[seedLiveSession(t, pool, subject, instant.Add(-time.Minute)).String()] = false
	}

	var token page.Token
	seen := 0
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("the walk did not terminate; the list is handing out a token forever")
		}
		got, err := q.ListSessions(ctx, subject, token, 2)
		if err != nil {
			t.Fatalf("page %d: %v", pages, err)
		}
		for _, s := range got.Items {
			id := s.SessionID.String()
			already, known := want[id]
			if !known {
				t.Fatalf("page %d returned session %s, which belongs to nobody in this test", pages, id)
			}
			if already {
				t.Fatalf("session %s was returned on two pages; the boundary fell inside a "+
					"group of rows sharing an instant", id)
			}
			want[id] = true
			seen++
		}
		if got.Next == "" {
			break
		}
		token = got.Next
	}

	if seen != len(want) {
		t.Fatalf("the walk visited %d sessions, want %d", seen, len(want))
	}
	for id, visited := range want {
		if !visited {
			t.Errorf("session %s was skipped entirely", id)
		}
	}
}

// The device list shows a session only when BOTH halves exist and it is still
// usable. Each exclusion below is a different mechanism, so each gets its own row.
func TestTheDeviceListExcludesWhatCannotBeSignedInOn(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	q := newReadSide(t, pool)

	subject := seedReadAccount(t, pool, "excluded", "active")
	now := time.Now().UTC()

	live := seedLiveSession(t, pool, subject, now)

	revoked := seedLiveSession(t, pool, subject, now.Add(-time.Minute))
	if _, err := pool.Exec(ctx, identitydb.RevokeSession, revoked.String()); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	swept := seedLiveSession(t, pool, subject, now.Add(-2*time.Minute))
	if _, err := pool.Exec(ctx,
		"DELETE FROM session_token WHERE session_id = $1", swept.String()); err != nil {
		t.Fatalf("sweeping a token: %v", err)
	}

	expired := ids.New[ids.Session](time.Now().UTC(), sessionEntropy{})
	if _, err := pool.Exec(ctx, identitydb.UpsertSession, expired.String(), subject,
		"dev_1", int32(2), now.Add(-time.Second), false, now.Add(-3*time.Minute)); err != nil {
		t.Fatalf("seeding an expired session: %v", err)
	}
	if _, err := pool.Exec(ctx, identitydb.IssueSessionToken,
		sessionDigest(9), expired.String(), now.Add(time.Hour)); err != nil {
		t.Fatalf("seeding an expired session's token: %v", err)
	}

	other := seedReadAccount(t, pool, "excluded_other", "active")
	theirs := seedLiveSession(t, pool, other, now)

	got, err := q.ListSessions(ctx, subject, "", 50)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(got.Items) != 1 || got.Items[0].SessionID != live {
		ids := make([]string, 0, len(got.Items))
		for _, s := range got.Items {
			ids = append(ids, s.SessionID.String())
		}
		t.Fatalf("the device list returned %v, want only the live session %s "+
			"(revoked %s, token-swept %s, expired %s and another subject's %s must all "+
			"be absent)", ids, live, revoked, swept, expired, theirs)
	}
}

// A next token minted for one subject must not read another subject's list, even
// though the SQL would happily filter on whatever subject is bound.
//
// S1-24 will refuse the request before it arrives. This is the independent half:
// the token itself is bound to the subject, so the two controls fail separately.
func TestASessionTokenIsBoundToItsSubject(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	q := newReadSide(t, pool)

	mine := seedReadAccount(t, pool, "bound_mine", "active")
	theirs := seedReadAccount(t, pool, "bound_theirs", "active")
	now := time.Now().UTC()
	for i := range 3 {
		seedLiveSession(t, pool, mine, now.Add(-time.Duration(i)*time.Minute))
		seedLiveSession(t, pool, theirs, now.Add(-time.Duration(i)*time.Minute))
	}

	first, err := q.ListSessions(ctx, mine, "", 2)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if first.Next == "" {
		t.Fatal("no token to replay")
	}
	if _, err := q.ListSessions(ctx, theirs, first.Next, 2); err == nil {
		t.Fatal("a cursor minted for one subject was accepted for another")
	}
}

// ---------------------------------------------------------------------------
// ListLoginHistory
// ---------------------------------------------------------------------------

func TestPagingLoginHistoryThatSharesAnOccurredAt(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	q := newReadSide(t, pool)

	subject := seedReadAccount(t, pool, "history", "active")
	instant := time.Now().UTC().Truncate(time.Microsecond)
	// A burst at one instant is what a stuffing run actually looks like in this
	// table, and it is the shape that breaks a sort key with no unique tail.
	for range 5 {
		seedAttempt(t, pool, subject, instant, false)
	}
	seedAttempt(t, pool, subject, instant.Add(-time.Minute), true)

	seen := map[int64]bool{}
	var token page.Token
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("the walk did not terminate")
		}
		got, err := q.ListLoginHistory(ctx, subject, token, 2)
		if err != nil {
			t.Fatalf("page %d: %v", pages, err)
		}
		for _, r := range got.Items {
			if seen[r.ID] {
				t.Fatalf("attempt %d was returned on two pages", r.ID)
			}
			seen[r.ID] = true
		}
		if got.Next == "" {
			break
		}
		token = got.Next
	}

	if len(seen) != 6 {
		t.Fatalf("the walk visited %d attempts, want 6: a security screen that drops an "+
			"attempt cannot answer \"was that me?\"", len(seen))
	}
}

func TestLoginHistoryReturnsFailuresAndTheirReason(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	q := newReadSide(t, pool)

	subject := seedReadAccount(t, pool, "history_reason", "active")
	seedAttempt(t, pool, subject, time.Now().UTC(), false)

	got, err := q.ListLoginHistory(ctx, subject, "", 10)
	if err != nil {
		t.Fatalf("ListLoginHistory: %v", err)
	}
	if len(got.Items) != 1 {
		t.Fatalf("got %d attempts, want 1", len(got.Items))
	}
	rec := got.Items[0]
	if rec.Succeeded {
		t.Error("a failed attempt came back as a success")
	}
	if rec.Reason != contract.FailureReason("wrong_password") {
		t.Errorf("reason is %q, want wrong_password", rec.Reason)
	}
	if len(rec.Methods) != 1 || rec.Methods[0] != contract.MethodPassword {
		t.Errorf("methods came back as %v, want [password]", rec.Methods)
	}
	if rec.OccurredAt.Location() != time.UTC {
		t.Errorf("occurred_at is in %v, want UTC", rec.OccurredAt.Location())
	}
}

func TestLoginHistoryIsScopedToOneSubject(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	q := newReadSide(t, pool)

	mine := seedReadAccount(t, pool, "hist_mine", "active")
	theirs := seedReadAccount(t, pool, "hist_theirs", "active")
	seedAttempt(t, pool, mine, time.Now().UTC(), true)
	for range 3 {
		seedAttempt(t, pool, theirs, time.Now().UTC(), false)
	}

	got, err := q.ListLoginHistory(ctx, mine, "", 50)
	if err != nil {
		t.Fatalf("ListLoginHistory: %v", err)
	}
	if len(got.Items) != 1 {
		t.Fatalf("got %d attempts for one subject, want 1: the subject filter is the "+
			"whole tenant boundary on this table", len(got.Items))
	}
}

// ---------------------------------------------------------------------------
// ListMethods
// ---------------------------------------------------------------------------

// The method list reports what exists and whether it works, and reads the
// authoritative credential table to do it.
//
// The verifier in the fixture below is real, non-empty, and distinctive on
// purpose: the statement selects six columns and `verifier` is not among them, so
// the value exists in the row this list reads and cannot reach the result.
func TestListingMethodsReportsUsabilityAndNothingSecret(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	q := newReadSide(t, pool)

	subject := seedReadAccount(t, pool, "methods", "active")
	now := time.Now().UTC()

	usable := newCredentialID()
	if _, err := pool.Exec(ctx, identitydb.UpsertCredential,
		usable.String(), subject, string(contract.MethodPassword),
		"$argon2id$SECRET-VERIFIER-MUST-NOT-ESCAPE", int32(1), now); err != nil {
		t.Fatalf("seeding a usable credential: %v", err)
	}
	pending := newCredentialID()
	if _, err := pool.Exec(ctx, identitydb.UpsertCredential,
		pending.String(), subject, string(contract.MethodTOTP),
		"sealed-totp-secret", int32(1), nil); err != nil {
		t.Fatalf("seeding a pending credential: %v", err)
	}
	if _, err := pool.Exec(ctx, identitydb.TouchCredential, usable.String()); err != nil {
		t.Fatalf("touching: %v", err)
	}

	methods, err := q.ListMethods(ctx, subject)
	if err != nil {
		t.Fatalf("ListMethods: %v", err)
	}
	if len(methods) != 2 {
		t.Fatalf("got %d methods, want 2: a method hidden from this screen is one the "+
			"account holder cannot notice or remove", len(methods))
	}

	byID := map[string]app.AuthMethod{}
	for _, m := range methods {
		byID[m.ID.String()] = m
	}
	if got := byID[usable.String()]; !got.Usable() || got.Kind != contract.MethodPassword {
		t.Errorf("the enabled password came back as %+v, want a usable password", got)
	}
	if got := byID[usable.String()]; got.LastUsedAt.IsZero() {
		t.Error("last-used is zero after TouchCredential; \"when did this last work\" is " +
			"the question this screen exists to answer")
	}
	if got := byID[pending.String()]; got.Usable() || !got.Pending() {
		t.Errorf("the unproven TOTP enrollment came back as %+v, want pending and not "+
			"usable; treating provisioning as completion is how an account ends up with "+
			"a second factor that exists only on the server's side", got)
	}
}

func TestListingMethodsIsScopedToOneSubject(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	q := newReadSide(t, pool)

	mine := seedReadAccount(t, pool, "methods_mine", "active")
	theirs := seedReadAccount(t, pool, "methods_theirs", "active")
	if _, err := pool.Exec(ctx, identitydb.UpsertCredential,
		newCredentialID().String(), theirs, string(contract.MethodPassword),
		"$argon2id$theirs", int32(1), time.Now().UTC()); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	methods, err := q.ListMethods(ctx, mine)
	if err != nil {
		t.Fatalf("ListMethods: %v", err)
	}
	if len(methods) != 0 {
		t.Fatalf("got %d methods for an account with none; another subject's credentials "+
			"are visible", len(methods))
	}
}

// ---------------------------------------------------------------------------
// Cursors the adapter must refuse
// ---------------------------------------------------------------------------

// A cursor of the wrong arity or the wrong types never reaches PostgreSQL.
//
// The dangerous case is not the one that errors — it is a mis-typed cursor that
// still produces rows, because those rows are wrong and nothing says so.
func TestTheAdapterRefusesAMalformedCursor(t *testing.T) {
	ctx := context.Background()
	rm := newReadModel(t, openPool(t))
	subject := "subj_read_cursor"

	wrongArity, err := page.NewKeyset(page.Key{Column: "created_at", Value: "only-one", Unique: true})
	if err != nil {
		t.Fatalf("building a one-column keyset: %v", err)
	}
	if _, err := rm.Sessions(ctx, subject, wrongArity, 10); err == nil {
		t.Error("a one-column cursor was bound to a two-column comparison")
	}

	wrongTypes, err := page.NewKeyset(
		page.Key{Column: "created_at", Value: "not-a-timestamp"},
		page.Key{Column: "session_id", Value: int64(7), Unique: true},
	)
	if err != nil {
		t.Fatalf("building a mis-typed keyset: %v", err)
	}
	if _, err := rm.Sessions(ctx, subject, wrongTypes, 10); err == nil {
		t.Error("a cursor with a string where a timestamp belongs was accepted")
	}

	if _, err := rm.Sessions(ctx, subject, page.Start(), 0); err == nil {
		t.Error("a limit of zero was accepted; LIMIT 0 returns nothing, and an empty page " +
			"reads as \"you have no other devices\"")
	}
	if _, err := rm.LoginHistory(ctx, subject, page.Start(), 0); err == nil {
		t.Error("a login-history limit of zero was accepted")
	}
}

// UserBySubject must return the account it resolved, and must pass an unknown
// subject through unchanged.
//
// Both halves are load-bearing. The method is three lines over a port, so a
// mutation that dropped the resolved id would compile cleanly, wire cleanly, and
// fail at the first email verification with an ids.UserID{} naming a stream that
// does not exist. And flattening the not-found error would turn "no such subject"
// into an outage — or, worse, into an answer that differs from the one an unknown
// token produces, which is an account-existence oracle for anyone holding a
// pseudonym.
//
// Driven against a real row rather than a fake reader: the id has to survive a
// round trip through the column, and a fake would assert the mapping this method
// does not perform.
func TestUserBySubjectResolvesAndDoesNotFlattenAnUnknownSubject(t *testing.T) {
	pool := openPool(t)
	rm := newReadModel(t, pool)
	ctx := context.Background()

	subjectID := seedReadAccount(t, pool, "directory", "active")

	account, err := rm.Account(ctx, subjectID)
	if err != nil {
		t.Fatalf("reading the seeded account: %v", err)
	}

	got, err := rm.UserBySubject(ctx, subjectID)
	if err != nil {
		t.Fatalf("UserBySubject: %v", err)
	}
	if got != account.UserID {
		t.Errorf("UserBySubject returned %v, want %v: the directory drops the account it "+
			"resolved, and every command keyed by user id would name a stream that does "+
			"not exist", got, account.UserID)
	}
	if got.IsZero() {
		t.Error("UserBySubject returned the zero id, which names no stream at all")
	}

	if _, err := rm.UserBySubject(ctx, "subj_no_such_account"); !errors.Is(err, app.ErrNoSuchSubject) {
		t.Errorf("an unknown subject produced %v, want app.ErrNoSuchSubject: the caller "+
			"answers it identically to an unknown token, so a different error here is an "+
			"account-existence oracle", err)
	}
}

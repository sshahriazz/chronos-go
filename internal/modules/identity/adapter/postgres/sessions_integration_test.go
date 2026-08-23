//go:build integration

package postgres_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	identitypg "github.com/chronos/chronos-go/internal/modules/identity/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The session store, against the real schema.
//
// Tested here rather than against a fake because every property that decides
// whether a session is safe is a property of the SQL: whether a token resolves
// only when BOTH halves of a session exist, whether a revoked session stops
// resolving at all, and whether the work list for "sign out everywhere" still
// finds a session whose secret has already been swept. A stub that accepted the
// statements would demonstrate none of it.

func newSessions(t *testing.T, pool *pgxpool.Pool) *identitypg.Sessions {
	t.Helper()
	store, err := identitypg.NewSessions(pgadapter.New(pool))
	if err != nil {
		t.Fatalf("building the session store: %v", err)
	}
	return store
}

// seedAccount writes the user_view row a session's foreign key requires, and
// returns its subject and blind index.
func seedAccount(t *testing.T, pool *pgxpool.Pool, label string) (subjectID string, index contract.EmailIndex) {
	t.Helper()
	subjectID = fmt.Sprintf("subj_sessions_%s_%d", label, time.Now().UnixNano())
	// A REAL prefixed ULID, because the adapter parses it: a label-shaped id would
	// make every lookup fail for a reason no test here is about, and — worse in the
	// other direction — a test that tolerated the failure would never notice the
	// adapter had stopped refusing an unparseable row.
	userID := ids.New[ids.User](time.Now().UTC(), sessionEntropy{}).String()
	index = contract.EmailIndex(fmt.Sprintf("%064x", time.Now().UnixNano())[:64])

	if _, err := pool.Exec(context.Background(), identitydb.UpsertUser,
		subjectID, userID, string(index), "active", time.Now().UTC()); err != nil {
		t.Fatalf("seeding an account: %v", err)
	}
	t.Cleanup(func() {
		// session_view cascades from user_view; session_token does not, so the
		// tokens go first.
		_, _ = pool.Exec(context.Background(),
			"DELETE FROM session_token WHERE session_id IN "+
				"(SELECT session_id FROM session_view WHERE subject_id = $1)", subjectID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM user_view WHERE subject_id = $1", subjectID)
	})
	return subjectID, index
}

// seedSession writes the PROJECTED half, exactly as the projector would.
func seedSession(
	t *testing.T, pool *pgxpool.Pool, subjectID string, absoluteExpiresAt time.Time,
) ids.SessionID {
	t.Helper()
	id := ids.New[ids.Session](time.Now().UTC(), sessionEntropy{})
	if _, err := pool.Exec(context.Background(), identitydb.UpsertSession,
		id.String(), subjectID, "dev_1", int32(2), absoluteExpiresAt, false, time.Now().UTC(),
	); err != nil {
		t.Fatalf("seeding a session: %v", err)
	}
	return id
}

// sessionEntropy is an unlimited byte source. ids.New panics on a short read, so
// it must never run out.
// sessionEntropy is the ULID entropy source for seeded sessions.
//
// crypto/rand, not the clock. The previous version derived every byte from one
// `time.Now().UnixNano()`, which gives two ids generated in the same nanosecond
// the same entropy — and a seeding loop generates several per microsecond. See
// sessionDigest below, where exactly that cost a real failure.
type sessionEntropy struct{}

func (sessionEntropy) Read(p []byte) (int, error) { return rand.Read(p) }

// sessionDigest is a unique 32-byte token digest.
//
// # Why crypto/rand and not the clock
//
// The digest is `session_token`'s PRIMARY KEY, so two seeds that produce the
// same bytes fail the insert. The previous version was
// `seed ^ byte(i) ^ byte(time.Now().UnixNano())` — the LOW BYTE of nanotime,
// which is constant across any two calls less than 256ns apart. A seeding loop
// makes several calls per microsecond, so it collided whenever two iterations
// landed in the same bucket: eight bits of entropy behind a unique constraint.
//
// It failed as `duplicate key value violates unique constraint
// "session_token_pkey"` from inside a helper called `seeding a session token`,
// which reads as a schema problem rather than as the fixture running out of
// distinct values.
//
// The seed is kept so a caller can still make two digests deliberately
// DIFFERENT in a readable way, and is XORed into random bytes rather than
// standing in for them.
func sessionDigest(seed byte) []byte {
	out := make([]byte, 32)
	if _, err := rand.Read(out); err != nil {
		panic("sessionDigest: " + err.Error())
	}
	out[0] ^= seed
	return out
}

// ---------------------------------------------------------------------------
// The login lookup
// ---------------------------------------------------------------------------

func TestAccountByEmailIndex(t *testing.T) {
	pool := openPool(t)
	store := newSessions(t, pool)
	subjectID, index := seedAccount(t, pool, "lookup")

	account, err := store.AccountByEmailIndex(context.Background(), index)
	if err != nil {
		t.Fatalf("resolving a known index: %v", err)
	}
	if account.SubjectID != subjectID {
		t.Errorf("resolved subject %q, want %q", account.SubjectID, subjectID)
	}
	if account.UserID.IsZero() {
		t.Error("resolved no user id")
	}

	// An index nobody claims is ErrNoSuchAccount, never a scan error and never a
	// zero-valued account that a caller might act on.
	_, err = store.AccountByEmailIndex(context.Background(),
		contract.EmailIndex(fmt.Sprintf("%064d", 0)))
	if !errors.Is(err, app.ErrNoSuchAccount) {
		t.Errorf("an unclaimed index gave %v, want ErrNoSuchAccount", err)
	}

	// The empty index is the same answer, and it must not become a query that
	// matches whatever row happens to have an empty column.
	if _, err := store.AccountByEmailIndex(context.Background(), ""); !errors.Is(err, app.ErrNoSuchAccount) {
		t.Errorf("the empty index gave %v, want ErrNoSuchAccount", err)
	}
}

// ---------------------------------------------------------------------------
// Issuing and resolving a bearer token
// ---------------------------------------------------------------------------

// A session resolves only when BOTH halves exist. This is the security property
// migration 00010 exists for, and it is a property of the INNER JOIN.
func TestASessionResolvesOnlyWhenBothHalvesExist(t *testing.T) {
	pool := openPool(t)
	store := newSessions(t, pool)
	subjectID, _ := seedAccount(t, pool, "halves")

	sessionID := ids.New[ids.Session](time.Now().UTC(), sessionEntropy{})
	digest := sessionDigest(1)
	if err := store.Issue(context.Background(), app.NewSessionToken{
		Digest: digest, SessionID: sessionID, IdleExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("issuing a token: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			"DELETE FROM session_token WHERE session_id = $1", sessionID.String())
	})

	// The secret exists and the facts do not: nothing resolves, which is what a
	// projection rebuild looks like from the authenticator's side.
	if resolves(t, pool, digest) {
		t.Error("a token resolved with no projected session; the authenticator would honour " +
			"a session whose subject and assurance level are unknown")
	}

	if _, err := pool.Exec(context.Background(), identitydb.UpsertSession,
		sessionID.String(), subjectID, "dev_1", int32(2),
		time.Now().Add(24*time.Hour), false, time.Now().UTC()); err != nil {
		t.Fatalf("projecting the session: %v", err)
	}
	if !resolves(t, pool, digest) {
		t.Error("a token did not resolve with both halves present")
	}

	// A revoked session stops resolving, without the token row being touched.
	if _, err := pool.Exec(context.Background(), identitydb.RevokeSession, sessionID.String()); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if resolves(t, pool, digest) {
		t.Error("a revoked session still resolves")
	}
}

func resolves(t *testing.T, pool *pgxpool.Pool, digest []byte) bool {
	t.Helper()
	var (
		sessionID, subjectID         string
		deviceID                     *string
		aal                          int32
		idleExpires, absoluteExpires time.Time
		rotation                     bool
		elevatedScope                *string
		elevatedUntil                *time.Time
		createdAt, lastSeenAt        time.Time
	)
	var enrolment string
	err := pool.QueryRow(context.Background(), identitydb.GetSessionByToken, digest, time.Now().UTC()).
		Scan(&sessionID, &subjectID, &deviceID, &aal, &idleExpires, &absoluteExpires,
			&rotation, &elevatedScope, &elevatedUntil, &createdAt, &lastSeenAt, &enrolment)
	if err == nil {
		return true
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return false
	}
	t.Fatalf("resolving a token: %v", err)
	return false
}

// The statement reports whether the ACCOUNT has ever held a proven second
// factor, and this is where that claim is checked against a real database.
//
// It is the input to policy.AALFloor, so a wrong answer here is not a cosmetic
// defect: 'bootstrap' on an account that already has a factor is exactly the
// state in which somebody holding a stolen password may enrol their own. The
// unit tests above the authenticator prove the MAPPING from this column; only
// this one proves the column.
func TestTheResolvedSessionReportsWhetherTheAccountEverHadASecondFactor(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arrange func(t *testing.T, pool *pgxpool.Pool, subjectID string)
		want    string
	}{
		{
			name:    "registered, nothing enrolled",
			arrange: func(*testing.T, *pgxpool.Pool, string) {},
			want:    "bootstrap",
		},
		{
			name: "a password, which is not a second factor",
			arrange: func(t *testing.T, pool *pgxpool.Pool, subjectID string) {
				seedCredential(t, pool, subjectID, "password", true)
			},
			want: "bootstrap",
		},
		{
			name: "an enrolment in progress, not yet proven",
			arrange: func(t *testing.T, pool *pgxpool.Pool, subjectID string) {
				// The row exists with enabled_at NULL. It must NOT read as
				// established, or the account cannot confirm the enrolment it just
				// started and the deadlock returns one step further along.
				seedCredential(t, pool, subjectID, "totp", false)
			},
			want: "bootstrap",
		},
		{
			name: "a recovery-code sheet",
			arrange: func(t *testing.T, pool *pgxpool.Pool, subjectID string) {
				// Excluded for the same reason maybeActivate excludes it: a printed
				// sheet must not satisfy "you must set up a second factor".
				seedCredential(t, pool, subjectID, "recovery_code", true)
			},
			want: "bootstrap",
		},
		{
			name: "a proven authenticator, before the projector has caught up",
			arrange: func(t *testing.T, pool *pgxpool.Pool, subjectID string) {
				// The account is still projected as pending — the credential row is
				// written by the command handler and the activation arrives later —
				// and it already reads as established. That window is precisely where
				// a second enrolment would otherwise be allowed.
				seedCredential(t, pool, subjectID, "totp", true)
			},
			want: "established",
		},
		{
			name: "activated, then the authenticator was removed",
			arrange: func(t *testing.T, pool *pgxpool.Pool, subjectID string) {
				id := seedCredential(t, pool, subjectID, "totp", true)
				setState(t, pool, subjectID, "active")
				if _, err := pool.Exec(context.Background(), identitydb.DeleteCredential, id); err != nil {
					t.Fatalf("removing the authenticator: %v", err)
				}
			},
			want: "established",
		},
		{
			name: "activated, then deactivated, with no credential left",
			arrange: func(t *testing.T, pool *pgxpool.Pool, subjectID string) {
				setState(t, pool, subjectID, "active")
				setState(t, pool, subjectID, "deactivated")
			},
			want: "established",
		},
		{
			name: "activated, then suspended",
			arrange: func(t *testing.T, pool *pgxpool.Pool, subjectID string) {
				setState(t, pool, subjectID, "active")
				setState(t, pool, subjectID, "suspended")
			},
			want: "established",
		},
		{
			name: "re-enrolling clears enabled_at, and the account stays established",
			arrange: func(t *testing.T, pool *pgxpool.Pool, subjectID string) {
				id := seedCredential(t, pool, subjectID, "totp", true)
				setState(t, pool, subjectID, "active")
				// Provision over the same row, exactly as SecondFactors.Provision
				// does: the secret is replaced and enabled_at is cleared. The
				// credential half of the answer flips back; the activation half is
				// what stops the account from reading as a first enrolment.
				if _, err := pool.Exec(context.Background(), identitydb.UpsertCredential,
					id, subjectID, "totp", "sealed:new", int32(1), nil); err != nil {
					t.Fatalf("re-provisioning: %v", err)
				}
			},
			want: "established",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := openPool(t)
			subjectID, _ := seedAccount(t, pool, "enrolment")
			// seedAccount writes the row through UpsertUser, which is the projector's
			// registration statement and never stamps activated_at. The state is
			// corrected to what a registration really produces, so a case that wants
			// an activated account has to go through SetUserState — the same
			// statement the projector uses, and the only one that stamps the column
			// this answer depends on.
			setState(t, pool, subjectID, "pending")
			tc.arrange(t, pool, subjectID)

			digest := sessionDigest(byte(90 + len(tc.name)%9))
			session := seedSession(t, pool, subjectID, time.Now().Add(24*time.Hour))
			if err := newSessions(t, pool).Issue(context.Background(), app.NewSessionToken{
				Digest: digest, SessionID: session, IdleExpiresAt: time.Now().Add(time.Hour),
			}); err != nil {
				t.Fatalf("issuing a token: %v", err)
			}
			t.Cleanup(func() {
				_, _ = pool.Exec(context.Background(),
					"DELETE FROM session_token WHERE token_digest = $1", digest)
			})

			if got := enrolmentOf(t, pool, digest); got != tc.want {
				t.Fatalf("the statement reports enrolment %q, want %q", got, tc.want)
			}
		})
	}
}

// enrolmentOf reads the enrolment column out of a resolved session.
func enrolmentOf(t *testing.T, pool *pgxpool.Pool, digest []byte) string {
	t.Helper()
	var (
		sessionID, subjectID         string
		deviceID                     *string
		aal                          int32
		idleExpires, absoluteExpires time.Time
		rotation                     bool
		elevatedScope                *string
		elevatedUntil                *time.Time
		createdAt, lastSeenAt        time.Time
		enrolment                    string
	)
	if err := pool.QueryRow(
		context.Background(), identitydb.GetSessionByToken, digest, time.Now().UTC(),
	).Scan(&sessionID, &subjectID, &deviceID, &aal, &idleExpires, &absoluteExpires,
		&rotation, &elevatedScope, &elevatedUntil, &createdAt, &lastSeenAt, &enrolment); err != nil {
		t.Fatalf("resolving a token: %v", err)
	}
	return enrolment
}

// setState drives the account through the projector's own state statement, which
// is the one that stamps activated_at.
func setState(t *testing.T, pool *pgxpool.Pool, subjectID, state string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), identitydb.SetUserState, subjectID, state); err != nil {
		t.Fatalf("setting the account state to %s: %v", state, err)
	}
}

// seedCredential writes one credential row, proven or not, and returns its id.
func seedCredential(
	t *testing.T, pool *pgxpool.Pool, subjectID, kind string, proven bool,
) string {
	t.Helper()
	id := ids.New[ids.Credential](time.Now().UTC(), sessionEntropy{}).String()
	var enabledAt any
	if proven {
		enabledAt = time.Now().UTC()
	}
	verifier := "sealed:secret"
	if kind == "password" {
		verifier = "$argon2id$v=19$m=1,t=1,p=1$c2FsdA$ZGlnZXN0"
	}
	if _, err := pool.Exec(context.Background(), identitydb.UpsertCredential,
		id, subjectID, kind, verifier, int32(1), enabledAt); err != nil {
		t.Fatalf("seeding a %s credential: %v", kind, err)
	}
	return id
}

// A digest is a primary key, so issuing the same one twice is refused rather than
// absorbed — the second caller must not end up holding a token for somebody
// else's session.
func TestIssuingTheSameDigestTwiceIsRefused(t *testing.T) {
	pool := openPool(t)
	store := newSessions(t, pool)
	_, _ = seedAccount(t, pool, "dup")

	digest := sessionDigest(2)
	first := ids.New[ids.Session](time.Now().UTC(), sessionEntropy{})
	second := ids.New[ids.Session](time.Now().UTC(), sessionEntropy{})
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			"DELETE FROM session_token WHERE token_digest = $1", digest)
	})

	if err := store.Issue(context.Background(), app.NewSessionToken{
		Digest: digest, SessionID: first, IdleExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("issuing: %v", err)
	}
	if err := store.Issue(context.Background(), app.NewSessionToken{
		Digest: digest, SessionID: second, IdleExpiresAt: time.Now().Add(time.Hour),
	}); err == nil {
		t.Error("the same digest was issued twice; one of the two callers holds a token for " +
			"a session that is not theirs")
	}
}

// The width check refuses a digest that is not a SHA-256, so a caller that hashed
// something else is stopped here rather than by a constraint name.
func TestIssuingRefusesAMalformedToken(t *testing.T) {
	pool := openPool(t)
	store := newSessions(t, pool)

	cases := map[string]app.NewSessionToken{
		"a short digest": {
			Digest:        []byte("too short"),
			SessionID:     ids.New[ids.Session](time.Now().UTC(), sessionEntropy{}),
			IdleExpiresAt: time.Now().Add(time.Hour),
		},
		"no session": {
			Digest:        sessionDigest(3),
			IdleExpiresAt: time.Now().Add(time.Hour),
		},
		"no idle deadline": {
			Digest:    sessionDigest(4),
			SessionID: ids.New[ids.Session](time.Now().UTC(), sessionEntropy{}),
		},
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if err := store.Issue(context.Background(), token); err == nil {
				t.Error("the store accepted it")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The work list for "sign out everywhere"
// ---------------------------------------------------------------------------

// The list finds every live session and excludes the ones that are already over.
// Crucially it does NOT join session_token: a session whose secret was swept must
// still be revocable, because the projected row is what a rebuild replays.
func TestListLiveSessions(t *testing.T) {
	pool := openPool(t)
	store := newSessions(t, pool)
	subjectID, _ := seedAccount(t, pool, "list")

	live := seedSession(t, pool, subjectID, time.Now().Add(24*time.Hour))
	swept := seedSession(t, pool, subjectID, time.Now().Add(24*time.Hour))
	revoked := seedSession(t, pool, subjectID, time.Now().Add(24*time.Hour))
	expired := seedSession(t, pool, subjectID, time.Now().Add(-time.Minute))

	// Only one of them still has a secret; the others model rows the sweep has
	// already cleaned up.
	if err := store.Issue(context.Background(), app.NewSessionToken{
		Digest: sessionDigest(5), SessionID: live, IdleExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("issuing: %v", err)
	}
	if _, err := pool.Exec(context.Background(), identitydb.RevokeSession, revoked.String()); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	got, err := store.List(context.Background(), subjectID, time.Now().UTC())
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	found := map[ids.SessionID]bool{}
	for _, id := range got {
		found[id] = true
	}
	if !found[live] {
		t.Error("the live session is missing from the work list")
	}
	if !found[swept] {
		t.Error("a session whose token row was swept is missing; it would never be revoked, " +
			"and a rebuild would bring it back as live")
	}
	if found[revoked] {
		t.Error("a revoked session is in the work list")
	}
	if found[expired] {
		t.Error("an expired session is in the work list")
	}

	// Another subject's sessions are never in the list.
	otherSubject, _ := seedAccount(t, pool, "list_other")
	other := seedSession(t, pool, otherSubject, time.Now().Add(24*time.Hour))
	got, err = store.List(context.Background(), subjectID, time.Now().UTC())
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	for _, id := range got {
		if id == other {
			t.Error("another subject's session is in the work list")
		}
	}
}

// A session id the application cannot parse stops the whole list rather than
// being skipped.
//
// Skipping would drop that session from a sign-out-everywhere while the call
// still reported success — and the row exists precisely because something wrote
// session_view outside this application, which is the case that most needs to be
// visible.
func TestAnUnreadableSessionIdStopsTheWorkList(t *testing.T) {
	pool := openPool(t)
	store := newSessions(t, pool)
	subjectID, _ := seedAccount(t, pool, "unreadable")

	seedSession(t, pool, subjectID, time.Now().Add(24*time.Hour))
	if _, err := pool.Exec(context.Background(), identitydb.UpsertSession,
		"not-a-session-id", subjectID, "dev_1", int32(2),
		time.Now().Add(24*time.Hour), false, time.Now().UTC()); err != nil {
		t.Fatalf("seeding a malformed session: %v", err)
	}

	got, err := store.List(context.Background(), subjectID, time.Now().UTC())
	if err == nil {
		t.Errorf("the work list returned %d sessions and no error for a row this application "+
			"could not have written; a caller would sign out everything it could parse and "+
			"report success", len(got))
	}
}

// An empty subject or a zero instant is refused rather than answered with an
// empty list: an empty list means "nothing to sign out", and a caller acting on
// that reports a successful sign-out-everywhere that touched nothing.
func TestListLiveSessionsRefusesAnAmbiguousQuestion(t *testing.T) {
	pool := openPool(t)
	store := newSessions(t, pool)

	if _, err := store.List(context.Background(), "", time.Now().UTC()); err == nil {
		t.Error("listing with no subject succeeded")
	}
	if _, err := store.List(context.Background(), "subj_whoever", time.Time{}); err == nil {
		t.Error("listing with no instant succeeded")
	}
}

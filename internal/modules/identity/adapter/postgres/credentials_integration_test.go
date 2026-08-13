//go:build integration

package postgres_test

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	identitypg "github.com/chronos/chronos-go/internal/modules/identity/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The credential store, against the real schema.
//
// Tested here rather than against a fake because every property that matters is
// a property of the SQL and of the constraints around it: which rows the usable
// lookup skips, which unique index refuses a second live password, whether the
// rehash's compare-and-set actually compares, and — the one this whole table
// exists for — whether anything still couples a verifier to the account
// projection. A stub that accepted the statements would demonstrate none of it.
//
// Every test invents its own subject, so they do not interfere, and almost none
// of them seed user_view: the credential table has no foreign key to it any more
// (migration 00009), so writing a credential for a subject with no projected
// account is both legal and the ordinary case while a projector is behind.

func TestStoringAndReadingBackAPasswordVerifier(t *testing.T) {
	ctx := context.Background()
	store := newCredentials(t)

	subject := testSubject(t)
	cred := newCredentialID()
	enabled := time.Now().UTC().Truncate(time.Microsecond)

	if err := store.Store(ctx, app.NewPasswordCredential{
		ID: cred, SubjectID: subject,
		Verifier: "$argon2id$fixture$one", PepperVersion: 3, EnabledAt: enabled,
	}); err != nil {
		t.Fatalf("storing: %v", err)
	}

	got, err := store.Find(ctx, subject)
	if err != nil {
		t.Fatalf("finding: %v", err)
	}
	if got.ID != cred {
		t.Errorf("credential id is %s, want %s: the verifier is sealed against this id, "+
			"so the wrong one means it can never be opened", got.ID, cred)
	}
	if got.Verifier != "$argon2id$fixture$one" {
		t.Errorf("verifier read back as %q", got.Verifier)
	}
	if got.PepperVersion != 3 {
		t.Errorf("pepper version is %d, want 3: at the wrong version the rotation job "+
			"visits the wrong rows", got.PepperVersion)
	}
	if got.SubjectID != subject {
		t.Errorf("subject is %q, want %q", got.SubjectID, subject)
	}
	if got.Failures != 0 {
		t.Errorf("a fresh credential starts with %d failures", got.Failures)
	}
	if got.EnabledAt.Location() != time.UTC {
		t.Errorf("enabled_at came back as %v, not UTC", got.EnabledAt.Location())
	}
	if !got.EnabledAt.Equal(enabled) {
		t.Errorf("enabled_at is %v, want %v", got.EnabledAt, enabled)
	}
}

// The invariant the whole table exists for: nothing couples a verifier to the
// account PROJECTION, so a rebuild cannot take the verifiers with it.
//
// What this asserts is the removal of the foreign key that 00008 gave this table
// and 00009 dropped. With that key in place a credential could not exist without
// a projected account at all, and — the actual disaster — emptying user_view for
// a rebuild would cascade into every password verifier in the system, none of
// which any replay can restore because verifiers are in no event.
//
// The rebuild statement itself is deliberately NOT run here: as chronos_app it
// fails with "permission denied" (00008 grants these tables SELECT/INSERT/
// UPDATE/DELETE and not TRUNCATE), and a test that ran it as the owner would be
// exercising a role the application never uses.
func TestACredentialIsNotCoupledToTheAccountProjection(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	q := identitydb.New(pool)
	store := newCredentialsOn(t, pool)

	subject := testSubject(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	// No user_view row for this subject: mid-rebuild, the projection is empty
	// while the credential table is untouched, and this is what the world looks
	// like from here.
	if _, err := q.GetUserBySubject(ctx, subject); err == nil {
		t.Fatal("the subject is already projected, so this test proves nothing")
	}
	if err := store.Store(ctx, app.NewPasswordCredential{
		ID: newCredentialID(), SubjectID: subject,
		Verifier: "$argon2id$fixture$survivor", PepperVersion: 1, EnabledAt: now,
	}); err != nil {
		t.Fatalf("a credential could not be stored for an unprojected subject, so the "+
			"projection and the verifiers are coupled again: %v", err)
	}

	got, err := store.Find(ctx, subject)
	if err != nil {
		t.Fatalf("finding: %v", err)
	}
	if got.Verifier != "$argon2id$fixture$survivor" {
		t.Errorf("verifier is %q", got.Verifier)
	}

	// And it stays readable once the projection catches up, which is the other
	// half of the ordering: the handler writes the verifier before the projector
	// has seen the event that creates the account.
	if err := q.UpsertUser(ctx, identitydb.UpsertUserParams{
		SubjectID: subject, UserID: "usr_" + subject, EmailIndex: testIndex(t),
		State: "active", RegisteredAt: pgtype.Timestamptz{Time: now, Valid: true},
	}); err != nil {
		t.Fatalf("projecting the account: %v", err)
	}
	if _, err := store.Find(ctx, subject); err != nil {
		t.Fatalf("finding after the projection caught up: %v", err)
	}
}

func TestAnUnknownSubjectHasNoUsablePassword(t *testing.T) {
	store := newCredentials(t)
	if _, err := store.Find(context.Background(), testSubject(t)); !errors.Is(err, app.ErrNoPasswordCredential) {
		t.Fatalf("got %v, want ErrNoPasswordCredential", err)
	}
}

func TestADisabledCredentialIsNotUsable(t *testing.T) {
	ctx := context.Background()
	store := newCredentials(t)

	subject := testSubject(t)
	cred := newCredentialID()
	mustStore(t, store, subject, cred, "$argon2id$fixture$disabled", 1)

	if err := store.Disable(ctx, cred); err != nil {
		t.Fatalf("disabling: %v", err)
	}

	// If the lookup returns it, the lockout exists in the table and nowhere in
	// the behaviour: the caller verifies against it and the login succeeds.
	if _, err := store.Find(ctx, subject); !errors.Is(err, app.ErrNoPasswordCredential) {
		t.Fatalf("a disabled credential is still returned as usable: err = %v", err)
	}
}

// A credential row that was never enabled must not be usable either, and the
// guard has to live in the SQL rather than only in the adapter's validation.
//
// The row is written through the generated statement directly, because the
// adapter refuses to create one — which is the point: the adapter is not the
// only writer this table will ever have (an enrolment that is provisioned but
// not yet proven produces exactly this shape), and a lookup that trusted the
// caller would hand out a credential nobody has finished binding.
func TestACredentialThatWasNeverEnabledIsNotUsable(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	subject := testSubject(t)

	if err := identitydb.New(pool).UpsertCredential(ctx, identitydb.UpsertCredentialParams{
		CredentialID: newCredentialID().String(), SubjectID: subject, Kind: "password",
		Verifier:      pgtype.Text{String: "$argon2id$fixture$pending", Valid: true},
		PepperVersion: pgtype.Int4{Int32: 1, Valid: true},
		EnabledAt:     pgtype.Timestamptz{}, // NULL: provisioned, not yet usable.
	}); err != nil {
		t.Fatalf("seeding an unenabled credential: %v", err)
	}

	if _, err := newCredentialsOn(t, pool).Find(ctx, subject); !errors.Is(err, app.ErrNoPasswordCredential) {
		t.Fatalf("got %v, want ErrNoPasswordCredential: a credential nobody enabled was "+
			"returned as usable", err)
	}
}

func TestDisablingTwiceSucceeds(t *testing.T) {
	ctx := context.Background()
	store := newCredentials(t)
	cred := newCredentialID()
	mustStore(t, store, testSubject(t), cred, "$argon2id$fixture$idem", 1)

	if err := store.Disable(ctx, cred); err != nil {
		t.Fatalf("first disable: %v", err)
	}
	// The credential is already unusable, which is what the caller asked for. An
	// error here puts a retry loop around a lockout that has succeeded.
	if err := store.Disable(ctx, cred); err != nil {
		t.Fatalf("second disable: %v", err)
	}
}

func TestASecondUsablePasswordIsRefused(t *testing.T) {
	ctx := context.Background()
	store := newCredentials(t)
	subject := testSubject(t)

	first := newCredentialID()
	mustStore(t, store, subject, first, "$argon2id$fixture$first", 1)

	// A retried registration mints a fresh credential id, so this is the shape
	// the collision actually takes. Replacing the stored verifier would bind the
	// account to a verifier sealed against a DIFFERENT credential id, which
	// opens for nobody.
	err := store.Store(ctx, app.NewPasswordCredential{
		ID: newCredentialID(), SubjectID: subject,
		Verifier: "$argon2id$fixture$second", PepperVersion: 1,
		EnabledAt: time.Now().UTC(),
	})
	if !errors.Is(err, app.ErrPasswordAlreadySet) {
		t.Fatalf("got %v, want ErrPasswordAlreadySet", err)
	}

	got, err := store.Find(ctx, subject)
	if err != nil {
		t.Fatalf("finding: %v", err)
	}
	if got.Verifier != "$argon2id$fixture$first" {
		t.Errorf("the refused write still changed the stored verifier to %q", got.Verifier)
	}
}

func TestStoringTheSameCredentialTwiceIsIdempotent(t *testing.T) {
	ctx := context.Background()
	store := newCredentials(t)
	subject, cred := testSubject(t), newCredentialID()
	enabled := time.Now().UTC().Truncate(time.Microsecond)

	// A handler that crashed between appending PasswordSet and writing the
	// verifier retries the whole command with the id the event already names.
	for i := range 2 {
		if err := store.Store(ctx, app.NewPasswordCredential{
			ID: cred, SubjectID: subject,
			Verifier: "$argon2id$fixture$retry", PepperVersion: 2, EnabledAt: enabled,
		}); err != nil {
			t.Fatalf("store %d: %v", i, err)
		}
	}
	if _, err := store.Find(ctx, subject); err != nil {
		t.Fatalf("finding after a retry: %v", err)
	}
}

func TestRebindingAfterALockoutIsAllowed(t *testing.T) {
	ctx := context.Background()
	store := newCredentials(t)
	subject := testSubject(t)

	first := newCredentialID()
	mustStore(t, store, subject, first, "$argon2id$fixture$old", 1)
	if err := store.Disable(ctx, first); err != nil {
		t.Fatalf("disabling: %v", err)
	}

	// The uniqueness rule is over USABLE credentials only. If it covered
	// disabled ones too, a locked-out authenticator would permanently prevent
	// setting a new password — the lockout would have no exit.
	second := newCredentialID()
	mustStore(t, store, subject, second, "$argon2id$fixture$new", 1)

	got, err := store.Find(ctx, subject)
	if err != nil {
		t.Fatalf("finding: %v", err)
	}
	if got.ID != second {
		t.Errorf("usable credential is %s, want the newly bound %s", got.ID, second)
	}
}

func TestRehashReplacesTheVerifierItVerifiedAgainst(t *testing.T) {
	ctx := context.Background()
	store := newCredentials(t)
	subject, cred := testSubject(t), newCredentialID()
	mustStore(t, store, subject, cred, "$argon2id$fixture$v1", 1)

	if err := store.Rehash(ctx, cred, "$argon2id$fixture$v1", "$argon2id$fixture$v2", 2); err != nil {
		t.Fatalf("rehashing: %v", err)
	}

	got, err := store.Find(ctx, subject)
	if err != nil {
		t.Fatalf("finding: %v", err)
	}
	if got.Verifier != "$argon2id$fixture$v2" {
		t.Errorf("verifier is %q after a rehash, want the replacement", got.Verifier)
	}
	if got.PepperVersion != 2 {
		t.Errorf("pepper version is %d after a rehash, want 2: the row still looks due for "+
			"rotation and the job will keep visiting it", got.PepperVersion)
	}
}

func TestRehashRefusesToOverwriteAVerifierThatMoved(t *testing.T) {
	ctx := context.Background()
	store := newCredentials(t)
	subject, cred := testSubject(t), newCredentialID()
	mustStore(t, store, subject, cred, "$argon2id$fixture$current", 1)

	// The login read "$stale", the user changed their password mid-flight, and
	// the rehash lands afterwards. Without the compare-and-set it would restore a
	// re-encoding of the old password — possibly the one the user was replacing
	// because it had been compromised.
	err := store.Rehash(ctx, cred, "$argon2id$fixture$stale", "$argon2id$fixture$rehashed", 2)
	if !errors.Is(err, app.ErrCredentialMoved) {
		t.Fatalf("got %v, want ErrCredentialMoved", err)
	}

	got, findErr := store.Find(ctx, subject)
	if findErr != nil {
		t.Fatalf("finding: %v", findErr)
	}
	if got.Verifier != "$argon2id$fixture$current" {
		t.Errorf("a rehash against a stale verifier overwrote the current one with %q — "+
			"the password the user just changed is back", got.Verifier)
	}
	if got.PepperVersion != 1 {
		t.Errorf("pepper version moved to %d on a write that matched no row", got.PepperVersion)
	}
}

func TestRehashRefusesADisabledCredential(t *testing.T) {
	ctx := context.Background()
	store := newCredentials(t)
	subject, cred := testSubject(t), newCredentialID()
	mustStore(t, store, subject, cred, "$argon2id$fixture$locked", 1)

	if err := store.Disable(ctx, cred); err != nil {
		t.Fatalf("disabling: %v", err)
	}

	// A fresh verifier on a locked-out row leaves the lockout intact and the row
	// looking maintained, so the next reader sees a current verifier on a
	// credential nothing will ever accept.
	err := store.Rehash(ctx, cred, "$argon2id$fixture$locked", "$argon2id$fixture$revived", 2)
	if !errors.Is(err, app.ErrCredentialMoved) {
		t.Fatalf("got %v, want ErrCredentialMoved: a disabled credential was rehashed", err)
	}
}

func TestRehashOfAnUnknownCredentialIsRefused(t *testing.T) {
	err := newCredentials(t).Rehash(context.Background(),
		newCredentialID(), "$argon2id$fixture$a", "$argon2id$fixture$b", 1)
	if !errors.Is(err, app.ErrCredentialMoved) {
		t.Fatalf("got %v, want ErrCredentialMoved", err)
	}
}

func TestFailuresAreConsecutiveAndClearedBySuccess(t *testing.T) {
	ctx := context.Background()
	store := newCredentials(t)
	subject, cred := testSubject(t), newCredentialID()
	mustStore(t, store, subject, cred, "$argon2id$fixture$failures", 1)

	for want := int32(1); want <= 3; want++ {
		got, err := store.RecordFailure(ctx, cred)
		if err != nil {
			t.Fatalf("recording failure %d: %v", want, err)
		}
		if got != want {
			t.Fatalf("failure count is %d, want %d: a count that does not advance never "+
				"reaches the ceiling and the lockout never fires", got, want)
		}
	}

	if err := store.RecordSuccess(ctx, cred); err != nil {
		t.Fatalf("recording success: %v", err)
	}

	// Consecutive, not lifetime. Without the reset, an account that has ever
	// failed enough times is locked out for good however many successes follow.
	got, err := store.Find(ctx, subject)
	if err != nil {
		t.Fatalf("finding: %v", err)
	}
	if got.Failures != 0 {
		t.Errorf("failure count is %d after a success, want 0", got.Failures)
	}

	// And the counter resumes from zero rather than from where it left off.
	next, err := store.RecordFailure(ctx, cred)
	if err != nil {
		t.Fatalf("recording a failure after a success: %v", err)
	}
	if next != 1 {
		t.Errorf("the first failure after a success counted as %d", next)
	}
}

func TestBookkeepingAgainstAVanishedCredential(t *testing.T) {
	ctx := context.Background()
	store := newCredentials(t)
	cred := newCredentialID()

	if _, err := store.RecordFailure(ctx, cred); !errors.Is(err, app.ErrCredentialNotFound) {
		t.Errorf("RecordFailure: got %v, want ErrCredentialNotFound — a count against a row "+
			"that does not exist is a count nothing enforces", err)
	}
	if err := store.RecordSuccess(ctx, cred); !errors.Is(err, app.ErrCredentialNotFound) {
		t.Errorf("RecordSuccess: got %v, want ErrCredentialNotFound", err)
	}
}

// The refusals below are cheap and each names a way a stored credential is
// silently unusable rather than loudly wrong.
func TestAnUnusableCredentialIsRefusedRatherThanStored(t *testing.T) {
	ctx := context.Background()
	store := newCredentials(t)
	now := time.Now().UTC()

	cases := map[string]app.NewPasswordCredential{
		// enabled_at NULL is skipped by the usable lookup, so the account is
		// passwordless with a password sitting in the table.
		"no enabled-at": {ID: newCredentialID(), SubjectID: testSubject(t),
			Verifier: "$argon2id$fixture$x", PepperVersion: 1},
		// pepper_version 0 is invisible to `pepper_version < n`, so the rotation
		// job never visits the row and destroying the old key locks the user out.
		"no pepper version": {ID: newCredentialID(), SubjectID: testSubject(t),
			Verifier: "$argon2id$fixture$x", EnabledAt: now},
		// The verifier is what the id is sealed against; without an id it opens
		// from any row.
		"no credential id": {SubjectID: testSubject(t),
			Verifier: "$argon2id$fixture$x", PepperVersion: 1, EnabledAt: now},
		"no verifier": {ID: newCredentialID(), SubjectID: testSubject(t),
			PepperVersion: 1, EnabledAt: now},
		"no subject": {ID: newCredentialID(),
			Verifier: "$argon2id$fixture$x", PepperVersion: 1, EnabledAt: now},
	}
	for name, cred := range cases {
		t.Run(name, func(t *testing.T) {
			if err := store.Store(ctx, cred); err == nil {
				t.Fatal("stored a credential that can never be used")
			}
		})
	}
}

func TestAnUnconditionalRehashIsRefused(t *testing.T) {
	ctx := context.Background()
	store := newCredentials(t)
	subject, cred := testSubject(t), newCredentialID()
	mustStore(t, store, subject, cred, "$argon2id$fixture$guarded", 1)

	// An empty expected value would make the statement's comparison trivially
	// unsatisfiable or, worse under a future edit, absent — which is the exact
	// write the guard exists to prevent.
	if err := store.Rehash(ctx, cred, "", "$argon2id$fixture$new", 2); err == nil {
		t.Error("a rehash with no expected verifier was accepted")
	}
	if err := store.Rehash(ctx, cred, "$argon2id$fixture$guarded", "$argon2id$fixture$guarded", 2); err == nil {
		t.Error("a rehash that replaces a verifier with itself was accepted")
	}
	if err := store.Rehash(ctx, cred, "$argon2id$fixture$guarded", "$argon2id$fixture$new", 0); err == nil {
		t.Error("a rehash to pepper version 0 was accepted; the rotation job would never " +
			"find the row again")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newCredentials(t *testing.T) *identitypg.Credentials {
	t.Helper()
	return newCredentialsOn(t, openPool(t))
}

func newCredentialsOn(t *testing.T, pool *pgxpool.Pool) *identitypg.Credentials {
	t.Helper()
	store, err := identitypg.NewCredentials(pgadapter.New(pool))
	if err != nil {
		t.Fatalf("building the credential store: %v", err)
	}
	return store
}

func openPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), credentialDSN())
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// credentialDSN connects as chronos_app, never the owner: the owner bypasses
// RLS, and a test that runs as one proves nothing about what the application
// can see. Identity's tables carry no RLS, but the role still decides which
// grants apply — and 00008 grants these tables to chronos_app explicitly.
func credentialDSN() string {
	if v := os.Getenv("APP_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://chronos_app:chronos_app_dev_password@localhost:5432/chronos?sslmode=disable"
}

func mustStore(
	t *testing.T, store *identitypg.Credentials,
	subject string, cred ids.CredentialID, verifier string, pepper int32,
) {
	t.Helper()
	if err := store.Store(context.Background(), app.NewPasswordCredential{
		ID: cred, SubjectID: subject, Verifier: verifier,
		PepperVersion: pepper, EnabledAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("storing: %v", err)
	}
}

func newCredentialID() ids.CredentialID {
	return ids.New[ids.Credential](time.Now(), ids.Entropy())
}

// testSubject returns a pseudonym no other test or run uses. A pseudonym, never
// an address: no column in this table may hold personal data (compliance.md §1).
func testSubject(t *testing.T) string {
	t.Helper()
	return "subj_test_" + randomHex(t, 16)
}

// testIndex is shaped like a real keyed email index — 64 hex characters —
// because the column is UNIQUE and a short value would exercise a narrower index
// entry than production ever sees.
func testIndex(t *testing.T) string {
	t.Helper()
	return randomHex(t, 32)
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(ids.Entropy(), b); err != nil {
		t.Fatalf("entropy: %v", err)
	}
	return hex.EncodeToString(b)
}

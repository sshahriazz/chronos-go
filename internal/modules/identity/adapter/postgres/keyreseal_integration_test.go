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
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The re-sealing store, against the real schema.
//
// Tested here rather than against a fake because every property that matters is a
// property of the SQL: whether the cursor actually steps past a row, whether the
// LEFT JOIN really does return a credential whose account projection is missing,
// whether the compare-and-set compares BOTH the value and the version, and —
// the one an operator's decision rests on — whether the work list and the done
// check select the same rows. A stub that accepted the statements would
// demonstrate none of it.

// ---------------------------------------------------------------------------
// The work list
// ---------------------------------------------------------------------------

// The list returns rows below the version, in credential-id order, and resumes
// strictly after the cursor.
func TestResealWorkList_IsOrderedAndResumesAfterTheCursor(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	store := newResealStore(t, pool)

	fence, from := resealFence(t)
	seeded, _ := seedSealedCredentials(t, pool, app.KindTOTP, 1, 4, from)

	first, err := store.ListToReseal(ctx, app.KindTOTP, 2, fence, 2)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(first) != 2 {
		t.Fatalf("%d rows, want the page limit of 2", len(first))
	}
	if first[0].ID != seeded[0] || first[1].ID != seeded[1] {
		t.Fatalf("the page is not in credential-id order: %s then %s",
			first[0].ID, first[1].ID)
	}

	second, err := store.ListToReseal(ctx, app.KindTOTP, 2, first[1].ID.String(), 10)
	if err != nil {
		t.Fatalf("listing after the cursor: %v", err)
	}
	if len(second) != 2 {
		t.Fatalf("%d rows after the cursor, want the remaining 2", len(second))
	}
	if second[0].ID != seeded[2] {
		t.Errorf("the second page starts at %s, want %s; without a strict cursor a row "+
			"that could not be re-sealed comes back at the head of every page and the job "+
			"never advances", second[0].ID, seeded[2])
	}
}

// A row at or above the bound is not in the work list, and a kind that is not
// asked for is not in it either.
//
// The kind filter is the correction this query exists for: it once hardcoded
// `kind = 'password'`, so TOTP rows were invisible and the job reported zero
// outstanding while every second factor still depended on the old key.
func TestResealWorkList_FiltersByVersionAndByKind(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	store := newResealStore(t, pool)

	fence, from := resealFence(t)
	totpIDs, _ := seedSealedCredentials(t, pool, app.KindTOTP, 1, 1, from)
	currentIDs, _ := seedSealedCredentials(t, pool, app.KindTOTP, 5, 1, from.Add(time.Minute))
	pwIDs, _ := seedSealedCredentials(t, pool, app.KindPassword, 1, 1, from.Add(2*time.Minute))
	totp, current, password := totpIDs[0], currentIDs[0], pwIDs[0]

	got, err := store.ListToReseal(ctx, app.KindTOTP, 5, fence, 100)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(got) != 1 || got[0].ID != totp {
		t.Fatalf("the TOTP work list returned %d rows; it must contain only the row below "+
			"version 5 and only of kind totp", len(got))
	}
	for _, r := range got {
		if r.ID == current {
			t.Error("a row already at the current version is in the work list")
		}
		if r.ID == password {
			t.Error("a password row is in the TOTP work list; the two key sets have " +
				"unrelated version sequences and must never be compared")
		}
	}

	// And the password kind sees its own row, at its own bound.
	pw, err := store.ListToReseal(ctx, app.KindPassword, 2, fence, 100)
	if err != nil {
		t.Fatalf("listing passwords: %v", err)
	}
	if len(pw) != 1 || pw[0].ID != password {
		t.Fatalf("the password work list returned %d rows, want exactly the one seeded", len(pw))
	}
}

// The work list carries the USER ID, which the credential row does not have.
//
// A password verifier is sealed with the user id as additional data, so without
// it the row cannot be opened at all — and the only place the id exists is
// user_view.
func TestResealWorkList_CarriesTheUserIDForAPasswordRow(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	store := newResealStore(t, pool)

	fence, from := resealFence(t)
	_, subjects := seedSealedCredentials(t, pool, app.KindPassword, 1, 1, from)
	subject := subjects[0]

	got, err := store.ListToReseal(ctx, app.KindPassword, 2, fence, 10)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("%d rows", len(got))
	}
	if got[0].UserID.IsZero() {
		t.Fatal("the work list did not resolve the user id; a password verifier is sealed " +
			"against it, so without it the row can never be opened and never re-sealed")
	}
	if got[0].SubjectID != subject {
		t.Errorf("subject %q, want %q", got[0].SubjectID, subject)
	}
}

// A credential whose account projection is MISSING still appears, with a zero
// user id.
//
// Migration 00009 dropped the foreign key precisely so a projection rebuild
// cannot cascade into authoritative credential rows, which means this state is
// legal. Under an INNER JOIN those rows would vanish from the work list while
// still counting in the done check, and the job would loop on an empty page
// forever with nothing explaining why.
func TestResealWorkList_StillReturnsACredentialWhoseAccountRowIsGone(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	store := newResealStore(t, pool)

	fence, from := resealFence(t)
	cred := seedOrphanCredential(t, pool, app.KindPassword, 1, from)

	got, err := store.ListToReseal(ctx, app.KindPassword, 2, fence, 10)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	var found *app.SealedCredential
	for i := range got {
		if got[i].ID == cred {
			found = &got[i]
		}
	}
	if found == nil {
		t.Fatal("a credential with no user_view row is invisible to the work list while " +
			"still counting in the done check; the rotation would stall with no explanation")
	}
	if !found.UserID.IsZero() {
		t.Errorf("a user id was invented for a subject with no account row: %s", found.UserID)
	}
}

// Inputs that would silently select nothing are refused rather than returning a
// clean empty page — and a clean empty page is what an operator reads as "safe
// to destroy the old key".
func TestResealWorkList_RefusesInputsThatSelectNothing(t *testing.T) {
	ctx := context.Background()
	store := newResealStore(t, openPool(t))

	tests := []struct {
		name  string
		kind  string
		below int32
		limit int
	}{
		{"no kind", "", 2, 10},
		{"version zero, invisible to `pepper_version < n`", app.KindTOTP, 0, 10},
		{"a negative version", app.KindTOTP, -1, 10},
		{"a zero page", app.KindTOTP, 2, 0},
		{"a page above the cap", app.KindTOTP, 2, 100_000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := store.ListToReseal(ctx, tt.kind, tt.below, "", tt.limit); err == nil {
				t.Fatal("an input that can only ever return an empty page was accepted")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The done check
// ---------------------------------------------------------------------------

// The count and the work list must select the SAME rows, ignoring the cursor.
//
// A job whose completion test differs from the operator's own query is a job
// that can report finished while `SELECT count(*) ... WHERE pepper_version < n`
// still returns rows — and the difference between those two answers is a
// destroyed key that rows still need.
func TestResealDoneCheck_AgreesWithTheWorkListAndIgnoresTheCursor(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	store := newResealStore(t, pool)

	baseline, err := store.CountToReseal(ctx, app.KindTOTP, 2)
	if err != nil {
		t.Fatalf("counting the baseline: %v", err)
	}

	_, from := resealFence(t)
	seeded, _ := seedSealedCredentials(t, pool, app.KindTOTP, 1, 3, from)

	before, err := store.CountToReseal(ctx, app.KindTOTP, 2)
	if err != nil {
		t.Fatalf("counting: %v", err)
	}
	// A DELTA, not an absolute: the schema is shared with every other test that
	// has ever run against it, and an absolute count would be asserting facts
	// about their leftovers rather than about this statement.
	if before-baseline != 3 {
		t.Fatalf("the count moved by %d, want the 3 rows seeded", before-baseline)
	}

	// Walk past every row. The PAGE is now empty and the COUNT is unchanged,
	// which is the whole reason the two are separate statements.
	page, err := store.ListToReseal(ctx, app.KindTOTP, 2, seeded[len(seeded)-1].String(), 10)
	if err != nil {
		t.Fatalf("listing past the end: %v", err)
	}
	after, err := store.CountToReseal(ctx, app.KindTOTP, 2)
	if err != nil {
		t.Fatalf("counting again: %v", err)
	}
	if len(page) != 0 {
		t.Fatalf("%d rows after the last cursor", len(page))
	}
	if after != before {
		t.Errorf("the done check moved from %d to %d because of a cursor; it must answer "+
			"'is anything left ANYWHERE', not 'is anything left after here'", before, after)
	}
}

// A DISABLED credential still counts, and must therefore still be re-sealable.
//
// This is the reason ResealCredential does not carry RehashCredential's
// `disabled_at IS NULL` guard. The operator's done check counts disabled rows,
// so a job that skipped them would leave the count permanently above zero and
// one locked-out authenticator would pin a retired key for the life of the
// deployment.
func TestResealDoneCheck_CountsDisabledRowsAndTheWriteCanStillMoveThem(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	store := newResealStore(t, pool)

	fence, from := resealFence(t)
	seeded, _ := seedSealedCredentials(t, pool, app.KindTOTP, 1, 1, from)
	cred := seeded[0]
	if _, err := pool.Exec(ctx, identitydb.DisableCredential, cred.String()); err != nil {
		t.Fatalf("disabling: %v", err)
	}

	got, err := store.ListToReseal(ctx, app.KindTOTP, 2, fence, 10)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(got) != 1 || got[0].ID != cred {
		t.Fatalf("%d rows; a disabled credential is still sealed under the old key and the "+
			"done check still counts it, so the work list has to see it too", len(got))
	}

	before, err := store.CountToReseal(ctx, app.KindTOTP, 2)
	if err != nil {
		t.Fatalf("counting: %v", err)
	}
	if err := store.Reseal(ctx, cred, got[0].Sealed, "totp$v2$resealed", 2); err != nil {
		t.Fatalf("re-sealing a disabled credential: %v; one locked-out authenticator would "+
			"pin the old key forever", err)
	}
	after, err := store.CountToReseal(ctx, app.KindTOTP, 2)
	if err != nil {
		t.Fatalf("counting again: %v", err)
	}
	if before-after != 1 {
		t.Fatalf("the done check moved by %d after re-sealing a disabled row; it must fall "+
			"by exactly one, or that row pins the retired key forever", before-after)
	}
}

func TestResealDoneCheck_RefusesInputsThatWouldReportAFalseZero(t *testing.T) {
	ctx := context.Background()
	store := newResealStore(t, openPool(t))

	if _, err := store.CountToReseal(ctx, "", 2); err == nil {
		t.Error("a count with no kind was accepted; zero is what licenses destroying a key")
	}
	if _, err := store.CountToReseal(ctx, app.KindTOTP, 0); err == nil {
		t.Error("a count bounded at version 0 was accepted; it returns zero for every table")
	}
}

// ---------------------------------------------------------------------------
// The compare-and-set
// ---------------------------------------------------------------------------

// The happy path: the value and the version both move, and the row leaves the
// work list.
func TestResealWrite_MovesTheValueAndTheVersion(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	store := newResealStore(t, pool)

	fence, from := resealFence(t)
	seeded, _ := seedSealedCredentials(t, pool, app.KindTOTP, 1, 1, from)
	cred := seeded[0]

	if err := store.Reseal(ctx, cred, "sealed$v1$0", "sealed$v2$moved", 2); err != nil {
		t.Fatalf("re-sealing: %v", err)
	}

	var verifier string
	var version int32
	if err := pool.QueryRow(ctx,
		"SELECT verifier, pepper_version FROM credential WHERE credential_id = $1",
		cred.String()).Scan(&verifier, &version); err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if verifier != "sealed$v2$moved" || version != 2 {
		t.Fatalf("the row holds %q at version %d", verifier, version)
	}
	left, err := store.ListToReseal(ctx, app.KindTOTP, 2, fence, 10)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("%d rows still in the work list; a re-sealed row must leave it or the "+
			"job re-seals it on every pass forever", len(left))
	}
}

// LOSING the compare-and-set is ErrCredentialMoved, not a database error and not
// a silent success.
//
// This is the race the statement exists for: between the job reading a value and
// writing it back, a login-time rehash, a password change or a TOTP
// re-enrollment may have replaced it — all of which wrote under the CURRENT key,
// so losing is the rotation succeeding by another route.
func TestResealWrite_ALostRaceIsErrCredentialMovedAndOverwritesNothing(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	store := newResealStore(t, pool)

	_, from := resealFence(t)
	seeded, _ := seedSealedCredentials(t, pool, app.KindPassword, 1, 1, from)
	cred := seeded[0]

	// Somebody else won: the row now holds a different value at a newer version.
	if _, err := pool.Exec(ctx,
		"UPDATE credential SET verifier = $2, pepper_version = 2 WHERE credential_id = $1",
		cred.String(), "$argon2id$fixture$changed"); err != nil {
		t.Fatalf("simulating the winner: %v", err)
	}

	err := store.Reseal(ctx, cred, "sealed$v1$0", "$argon2id$fixture$reseal", 2)
	if !errors.Is(err, app.ErrCredentialMoved) {
		t.Fatalf("a lost race gave %v, want ErrCredentialMoved", err)
	}

	var verifier string
	if err := pool.QueryRow(ctx,
		"SELECT verifier FROM credential WHERE credential_id = $1", cred.String(),
	).Scan(&verifier); err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if verifier != "$argon2id$fixture$changed" {
		t.Fatalf("the winner's value was overwritten with %q; a stale re-seal must never "+
			"undo a password change", verifier)
	}
}

// A row already AT or ABOVE the target version cannot be rewritten, even when
// the expected value still matches.
//
// Without the `pepper_version < $new` guard, a row whose column disagrees with
// its verifier — which the schema explicitly permits — would be given fresh
// ciphertext at an unchanged version on every pass forever, and the done check
// would never fall.
func TestResealWrite_RefusesToRewriteARowAtTheSameVersion(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	store := newResealStore(t, pool)

	_, from := resealFence(t)
	seeded, _ := seedSealedCredentials(t, pool, app.KindTOTP, 2, 1, from)
	cred := seeded[0]

	// The expected value MATCHES, so only the version guard can refuse this. That
	// is the point: nothing else stands between a job and a row rewritten at the
	// version it already had, on every pass, forever.
	err := store.Reseal(ctx, cred, "sealed$v2$0", "sealed$v2$rewritten", 2)
	if !errors.Is(err, app.ErrCredentialMoved) {
		t.Fatalf("rewriting a row at the target version gave %v, want ErrCredentialMoved", err)
	}

	var verifier string
	if err := pool.QueryRow(ctx,
		"SELECT verifier FROM credential WHERE credential_id = $1", cred.String(),
	).Scan(&verifier); err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if verifier != "sealed$v2$0" {
		t.Fatalf("the row was rewritten at an unchanged version, to %q", verifier)
	}
}

// Inputs that would turn the compare-and-set into an unconditional write, or
// destroy the only copy of a secret, are refused before they reach the database.
func TestResealWrite_RefusesInputsThatWouldDestroyASecret(t *testing.T) {
	ctx := context.Background()
	store := newResealStore(t, openPool(t))
	cred := newCredentialID()

	tests := []struct {
		name                  string
		cred                  ids.CredentialID
		expected, replacement string
		version               int32
	}{
		{"no credential id", ids.CredentialID{}, "a", "b", 2},
		{"no expected value, making the write unconditional", cred, "", "b", 2},
		{"an empty replacement", cred, "a", "", 2},
		{"a replacement identical to the stored value", cred, "a", "a", 2},
		{"version zero, invisible to the rotation job forever", cred, "a", "b", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := store.Reseal(ctx, tt.cred, tt.expected, tt.replacement, tt.version); err == nil {
				t.Fatal("the write was accepted")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newResealStore(t *testing.T, pool *pgxpool.Pool) *identitypg.ResealStore {
	t.Helper()
	s, err := identitypg.NewResealStore(pgadapter.New(pool))
	if err != nil {
		t.Fatalf("building the re-sealing store: %v", err)
	}
	return s
}

// seedResealAccount writes a user_view row, so the work list's LEFT JOIN has a
// user id to resolve.
func seedResealAccount(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	subject := testSubject(t)
	userID := ids.New[ids.User](time.Now().UTC(), ids.Entropy()).String()

	if _, err := pool.Exec(ctx, identitydb.UpsertUser,
		subject, userID, testIndex(t), "active", time.Now().UTC()); err != nil {
		t.Fatalf("seeding an account: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, "DELETE FROM credential WHERE subject_id = $1", subject)
		_, _ = pool.Exec(bg, "DELETE FROM user_view WHERE subject_id = $1", subject)
	})
	return subject
}

// resealFenceHorizon is how far ahead of wall time the fence is minted.
//
// A fence at time.Now() was the original design and it is NOT enough, which took
// a reproducible failure to establish. credential_id is a ULID minted from the
// APPLICATION's clock, and in local that clock is movable and forward-only
// (ADR-054): internal/adapter/identityit pushes it past every TOTP step boundary
// it needs, so the credentials that suite leaves behind carry ids MINUTES INTO
// THE FUTURE. Against a wall-clock fence those rows sort after it, they match
// `pepper_version < n` like any other, and every page assertion in this file
// fails by however many accounts that suite happened to create — reproducibly in
// a combined `go test -tags=integration ./...`, and alone for as long as it takes
// wall time to catch up. The symptom ("9 rows after the cursor, want 2") names
// nothing that would lead anyone here.
//
// Thirty days is chosen for the gap between two magnitudes rather than tuned:
// the advances are TOTP steps and token lifetimes, tens of minutes at most, and
// nothing anywhere moves a clock by days. Rows seeded above it are still deleted
// by seedResealAccount's cleanup, so nothing accumulates.
const resealFenceHorizon = 30 * 24 * time.Hour

// resealFence returns a cursor that every row seeded from now on sorts AFTER,
// and every row written by anything else sorts BEFORE.
//
// It is what makes these tests assertable against a shared database. credential_id
// is a ULID and the work list is ordered by it, so a ULID minted beyond every
// other writer's reach separates "rows this test created" from "rows some other
// suite left behind" — without it, every assertion about page contents would be
// at the mercy of whatever else has ever run against this schema.
func resealFence(t *testing.T) (string, time.Time) {
	t.Helper()
	at := time.Now().Add(resealFenceHorizon)
	return ids.New[ids.Credential](at, ids.Entropy()).String(), at.Add(time.Second)
}

// seedSealedCredentials writes n credentials of one kind at one version, each on
// its OWN account, with monotonically increasing ids.
//
// One account per credential is forced by the schema rather than chosen:
// credential_one_usable_per_kind_idx is unique on (subject_id, kind) wherever
// disabled_at IS NULL, so a subject can hold exactly one non-disabled credential
// of a kind. Re-sealing cares about none of that — neither the work list nor the
// done check filters on enabled_at or disabled_at, because a row is sealed under
// the old key whether or not anyone can currently use it.
//
// The ids are spaced in time so the ULID prefix orders them: the work list is
// sorted by credential_id and every cursor assertion here depends on that order.
//
// It writes through the generated upsert rather than raw SQL, so a schema change
// that breaks the write path breaks this too.
func seedSealedCredentials(
	t *testing.T, pool *pgxpool.Pool, kind string, version int32, n int, from time.Time,
) ([]ids.CredentialID, []string) {
	t.Helper()
	ctx := context.Background()

	credIDs := make([]ids.CredentialID, 0, n)
	subjects := make([]string, 0, n)
	for i := range n {
		subject := seedResealAccount(t, pool)
		id := ids.New[ids.Credential](from.Add(time.Duration(i)*time.Second), ids.Entropy())
		if _, err := pool.Exec(ctx, identitydb.UpsertCredential,
			id.String(), subject, kind,
			fmt.Sprintf("sealed$v%d$%d", version, i), version, nil,
		); err != nil {
			t.Fatalf("seeding a credential: %v", err)
		}
		credIDs = append(credIDs, id)
		subjects = append(subjects, subject)
	}
	return credIDs, subjects
}

// seedOrphanCredential writes a credential for a subject that has NO user_view
// row — the state a projection rebuild leaves behind, and legal since migration
// 00009 dropped the foreign key.
func seedOrphanCredential(
	t *testing.T, pool *pgxpool.Pool, kind string, version int32, at time.Time,
) ids.CredentialID {
	t.Helper()
	ctx := context.Background()
	subject := "subj_reseal_orphan_" + randomHex(t, 12)
	id := ids.New[ids.Credential](at, ids.Entropy())

	if _, err := pool.Exec(ctx, identitydb.UpsertCredential,
		id.String(), subject, kind, "sealed$v1$orphan", version, nil,
	); err != nil {
		t.Fatalf("seeding an orphan credential: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			"DELETE FROM credential WHERE subject_id = $1", subject)
	})
	return id
}

package app_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// fakeResealStore is an in-memory `credential` table.
//
// It models the two properties the real statements have and that the job's
// correctness rests on: the work list is filtered by version and resumed by
// cursor, and the write is a COMPARE-AND-SET that affects nothing when the stored
// value has moved. A fake that accepted every write would let a lost race look
// identical to a successful one, which is the single behaviour these tests exist
// to pin.
type fakeResealStore struct {
	rows []app.SealedCredential
	// version is the stored pepper_version, keyed by credential id.
	version map[string]int32

	listErr  error
	countErr error
	writeErr error

	// listCalls records (kind, below, after, limit) per call, so a test can
	// assert the cursor actually advanced rather than assuming it.
	listCalls []listCall
	writes    int
}

type listCall struct {
	kind  string
	below int32
	after string
	limit int
}

func (f *fakeResealStore) ListToReseal(
	_ context.Context, kind string, below int32, after string, limit int,
) ([]app.SealedCredential, error) {
	f.listCalls = append(f.listCalls, listCall{kind, below, after, limit})
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []app.SealedCredential
	for _, r := range f.rows {
		id := r.ID.String()
		if f.version[id] >= below || id <= after {
			continue
		}
		out = append(out, r)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

func (f *fakeResealStore) CountToReseal(_ context.Context, _ string, below int32) (int64, error) {
	if f.countErr != nil {
		return 0, f.countErr
	}
	var n int64
	for _, r := range f.rows {
		if f.version[r.ID.String()] < below {
			n++
		}
	}
	return n, nil
}

func (f *fakeResealStore) Reseal(
	_ context.Context, cred ids.CredentialID, expected, replacement string, version int32,
) error {
	f.writes++
	if f.writeErr != nil {
		return f.writeErr
	}
	id := cred.String()
	for i, r := range f.rows {
		if r.ID != cred {
			continue
		}
		// The compare-and-set, both halves: the stored value must still be the
		// one that was opened, and the row must still be below the new version.
		if r.Sealed != expected || f.version[id] >= version {
			return app.ErrCredentialMoved
		}
		f.rows[i].Sealed = replacement
		f.version[id] = version
		return nil
	}
	return app.ErrCredentialMoved
}

// fakeResealer re-seals by relabelling, so a test can see which key version a
// value ended up under without any crypto.
type fakeResealer struct {
	kind    string
	version int32
	// errs maps a credential id to the error Reseal should return for it.
	errs map[string]error
	// echo makes Reseal return its input unchanged, which a real AEAD never can.
	echo bool
	// empty makes Reseal return "" with no error.
	empty bool
}

func (f fakeResealer) Kind() string          { return f.kind }
func (f fakeResealer) CurrentVersion() int32 { return f.version }

func (f fakeResealer) Reseal(sealed string, cred app.SealedCredential) (string, error) {
	if err := f.errs[cred.ID.String()]; err != nil {
		return "", err
	}
	switch {
	case f.echo:
		return sealed, nil
	case f.empty:
		return "", nil
	}
	return fmt.Sprintf("v%d:%s", f.version, strings.SplitN(sealed, ":", 2)[1]), nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func credID(t *testing.T, n int) ids.CredentialID {
	t.Helper()
	// Monotonic in n so the ORDER BY credential_id the cursor relies on is
	// reproducible: the fake sorts by nothing, it filters by `id > after`, and a
	// random id would make that assertion meaningless.
	return ids.New[ids.Credential](time.Unix(int64(1_700_000_000+n), 0), ids.Entropy())
}

func userID(t *testing.T) ids.UserID {
	t.Helper()
	return ids.New[ids.User](time.Now(), ids.Entropy())
}

// storeWith builds a table of n rows of one kind, all sealed at version 1.
func storeWith(t *testing.T, kind string, n int) (*fakeResealStore, []ids.CredentialID) {
	t.Helper()
	s := &fakeResealStore{version: map[string]int32{}}
	ids := make([]ids.CredentialID, 0, n)
	for i := range n {
		id := credID(t, i)
		row := app.SealedCredential{
			ID: id, SubjectID: fmt.Sprintf("sub_%d", i), Sealed: "v1:secret",
		}
		if kind == app.KindPassword {
			row.UserID = userID(t)
		}
		s.rows = append(s.rows, row)
		s.version[id.String()] = 1
		ids = append(ids, id)
	}
	return s, ids
}

func newJob(t *testing.T, store app.ResealableCredentials, r ...app.Resealer) *app.KeyReseal {
	t.Helper()
	j, err := app.NewKeyReseal(store, slog.New(slog.DiscardHandler), r...)
	if err != nil {
		t.Fatalf("building the re-sealing job: %v", err)
	}
	return j
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

// A job wired with no store or no resealer runs to completion and reports a
// clean pass while moving nothing — and a clean pass is what an operator reads
// as "safe to destroy the old key". Refusing at construction is the only place
// the mistake is still recoverable.
func TestNewKeyReseal_RefusesAJobThatCouldNeverMoveARow(t *testing.T) {
	t.Parallel()

	store := &fakeResealStore{version: map[string]int32{}}
	good := fakeResealer{kind: app.KindTOTP, version: 2}

	tests := []struct {
		name      string
		store     app.ResealableCredentials
		resealers []app.Resealer
	}{
		{"no store", nil, []app.Resealer{good}},
		{"no resealer at all", store, nil},
		{"a nil resealer", store, []app.Resealer{nil}},
		{"a resealer with no kind", store, []app.Resealer{fakeResealer{version: 2}}},
		{
			"a resealer at version 0, invisible to `pepper_version < n`",
			store, []app.Resealer{fakeResealer{kind: app.KindTOTP}},
		},
		{
			"two resealers for one kind, one of them silently unused",
			store, []app.Resealer{good, fakeResealer{kind: app.KindTOTP, version: 3}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := app.NewKeyReseal(tt.store, nil, tt.resealers...); err == nil {
				t.Fatal("a job was built that would report a clean pass while re-sealing " +
					"nothing, which is exactly what gets an in-use key destroyed")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The happy path, and the done check
// ---------------------------------------------------------------------------

func TestResealOnce_MovesEveryRowAndTheDoneCheckFalls(t *testing.T) {
	t.Parallel()

	store, _ := storeWith(t, app.KindTOTP, 3)
	job := newJob(t, store, fakeResealer{kind: app.KindTOTP, version: 2})

	pass, err := job.ResealOnce(t.Context(), app.KindTOTP, "", 10)
	if err != nil {
		t.Fatalf("re-sealing: %v", err)
	}
	if pass.Resealed != 3 || pass.Scanned != 3 {
		t.Errorf("scanned %d, re-sealed %d; want 3 and 3", pass.Scanned, pass.Resealed)
	}
	if pass.Remaining != 0 || !pass.Done() {
		t.Errorf("remaining %d, done %v; the rotation is complete and the job must say so",
			pass.Remaining, pass.Done())
	}
	for _, row := range store.rows {
		if store.version[row.ID.String()] != 2 {
			t.Errorf("credential %s is still at version %d",
				row.ID, store.version[row.ID.String()])
		}
		if row.Sealed != "v2:secret" {
			t.Errorf("credential %s holds %q, which is not what the current key sealed",
				row.ID, row.Sealed)
		}
	}
}

// Both kinds go through the SAME job, and each is bounded by its OWN version
// sequence. The bug this replaces was a work list that could see only passwords:
// it reported zero rows outstanding while every TOTP secret still depended on
// the key an operator was being told was safe to destroy.
func TestResealOnce_EachKindUsesItsOwnKeyVersion(t *testing.T) {
	t.Parallel()

	store, _ := storeWith(t, app.KindTOTP, 2)
	job := newJob(t, store,
		fakeResealer{kind: app.KindPassword, version: 7},
		fakeResealer{kind: app.KindTOTP, version: 2},
	)

	if got := job.Kinds(); len(got) != 2 || got[0] != app.KindPassword || got[1] != app.KindTOTP {
		t.Fatalf("kinds are %v; they must be stable and sorted, because the caller is a "+
			"workflow whose replay depends on the order", got)
	}

	pass, err := job.ResealOnce(t.Context(), app.KindTOTP, "", 10)
	if err != nil {
		t.Fatalf("re-sealing: %v", err)
	}
	if pass.Version != 2 {
		t.Errorf("the TOTP pass ran at version %d; the password resealer's version must "+
			"not bound it — the two key sets are unrelated", pass.Version)
	}
	if got := store.listCalls[0].below; got != 2 {
		t.Errorf("the work list was bounded at version %d, not the TOTP resealer's 2", got)
	}
}

// An unknown kind is named, not skipped. A silently ignored kind is how TOTP
// secrets went unseen in the first place.
func TestResealOnce_RefusesAKindNothingIsWiredFor(t *testing.T) {
	t.Parallel()

	store, _ := storeWith(t, app.KindTOTP, 1)
	job := newJob(t, store, fakeResealer{kind: app.KindTOTP, version: 2})

	if _, err := job.ResealOnce(t.Context(), app.KindPassword, "", 10); err == nil {
		t.Fatal("a kind with no resealer was accepted; its rows would stay at an old key " +
			"version with nothing reporting it")
	}
}

// ---------------------------------------------------------------------------
// Concurrency: the lost compare-and-set
// ---------------------------------------------------------------------------

// A lost CAS is a SKIP, never a failure.
//
// The re-sealing job races the login-time rehash, a password change and a TOTP
// re-enrollment. Every one of those writes a value sealed under the CURRENT key,
// so losing to them is the rotation succeeding by another route. Counting it as
// a failure would make every busy deployment report a broken rotation, and would
// hide real failures in the noise.
func TestResealOnce_ALostCompareAndSetIsASkipAndNotAFailure(t *testing.T) {
	t.Parallel()

	store, credIDs := storeWith(t, app.KindTOTP, 3)
	// Somebody else got there first for the middle row: it already holds a value
	// at the current version, which is exactly what a login-time rehash leaves.
	store.rows[1].Sealed = "v2:secret"
	store.version[credIDs[1].String()] = 2

	job := newJob(t, store, fakeResealer{kind: app.KindTOTP, version: 2})
	pass, err := job.ResealOnce(t.Context(), app.KindTOTP, "", 10)
	if err != nil {
		t.Fatalf("re-sealing: %v", err)
	}
	if pass.Failed != 0 {
		t.Errorf("failed %d; losing the compare-and-set is the normal outcome of a live "+
			"system and must never be reported as a failure", pass.Failed)
	}
	if pass.Resealed != 2 {
		t.Errorf("re-sealed %d, want the 2 rows that were genuinely behind", pass.Resealed)
	}
	if pass.Remaining != 0 || !pass.Done() {
		t.Errorf("remaining %d: the row somebody else re-sealed still counts as done",
			pass.Remaining)
	}
}

// The same, driven through the store's error rather than through its state, so
// the branch is exercised even if the fake's CAS logic changes.
func TestResealOnce_ErrCredentialMovedFromTheStoreIsASkip(t *testing.T) {
	t.Parallel()

	store, _ := storeWith(t, app.KindTOTP, 2)
	store.writeErr = app.ErrCredentialMoved

	job := newJob(t, store, fakeResealer{kind: app.KindTOTP, version: 2})
	pass, err := job.ResealOnce(t.Context(), app.KindTOTP, "", 10)
	if err != nil {
		t.Fatalf("re-sealing: %v", err)
	}
	if pass.Skipped != 2 || pass.Failed != 0 || pass.Resealed != 0 {
		t.Errorf("skipped %d, failed %d, re-sealed %d; every row lost its race and every "+
			"one of them must be a skip", pass.Skipped, pass.Failed, pass.Resealed)
	}
}

// ---------------------------------------------------------------------------
// Unopenable rows
// ---------------------------------------------------------------------------

// A row that cannot be OPENED is a categorically different event from a
// transient failure, and the two must not be collapsed.
//
// A failure is retried and costs a delay. An unopenable secret is an account
// that loses its password or its second factor the moment the old key is
// destroyed — unrecoverably, because the plaintext exists nowhere else.
func TestResealOnce_AnUnopenableRowIsReportedApartFromAFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		kind string
		err  error
	}{
		{"a password verifier", app.KindPassword, app.ErrVerifierUnreadable},
		{"a TOTP secret", app.KindTOTP, app.ErrSecretUnreadable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store, credIDs := storeWith(t, tt.kind, 3)
			job := newJob(t, store, fakeResealer{
				kind: tt.kind, version: 2,
				errs: map[string]error{
					credIDs[1].String(): fmt.Errorf("no key: %w", tt.err),
				},
			})

			pass, err := job.ResealOnce(t.Context(), tt.kind, "", 10)
			if err != nil {
				t.Fatalf("re-sealing: %v", err)
			}
			if pass.Unopenable != 1 {
				t.Errorf("unopenable %d, want 1; a secret that cannot be opened must be "+
					"reported distinctly or nobody learns the account is about to lose "+
					"its factor", pass.Unopenable)
			}
			if pass.Failed != 0 || pass.Skipped != 0 {
				t.Errorf("failed %d, skipped %d; an unopenable row is neither",
					pass.Failed, pass.Skipped)
			}
			if pass.Resealed != 2 {
				t.Errorf("re-sealed %d; one bad row must not stop the batch", pass.Resealed)
			}
			// The row is LEFT ALONE. A job that invented a replacement would
			// silently swap out a password the user knows, or an authenticator
			// they still hold, and the row would look healthy afterwards.
			if store.rows[1].Sealed != "v1:secret" {
				t.Errorf("the unopenable row now holds %q; it must be untouched",
					store.rows[1].Sealed)
			}
			if pass.Remaining != 1 || pass.Done() {
				t.Errorf("remaining %d, done %v; the old key is still in use",
					pass.Remaining, pass.Done())
			}
		})
	}
}

// A value already at the current version is skipped rather than rewritten.
//
// Without this, a row whose pepper_version column disagrees with its verifier —
// which the schema explicitly permits — would be given fresh ciphertext at an
// unchanged version on every pass, forever.
func TestResealOnce_ARowAlreadyAtTheCurrentVersionIsSkippedNotRewritten(t *testing.T) {
	t.Parallel()

	store, credIDs := storeWith(t, app.KindTOTP, 2)
	job := newJob(t, store, fakeResealer{
		kind: app.KindTOTP, version: 2,
		errs: map[string]error{credIDs[0].String(): app.ErrAlreadyCurrent},
	})

	pass, err := job.ResealOnce(t.Context(), app.KindTOTP, "", 10)
	if err != nil {
		t.Fatalf("re-sealing: %v", err)
	}
	if pass.Skipped != 1 || pass.Failed != 0 || pass.Unopenable != 0 {
		t.Errorf("skipped %d, failed %d, unopenable %d; already-current is a no-op",
			pass.Skipped, pass.Failed, pass.Unopenable)
	}
	if store.writes != 1 {
		t.Errorf("%d writes; the already-current row must not reach the database at all",
			store.writes)
	}
}

// A resealer that returns its input unchanged, or an empty string, has not
// re-sealed anything. Writing either would stamp a new key version onto a value
// the new key cannot open — a lockout written by the job meant to prevent one.
func TestResealOnce_RefusesToWriteAValueThatWasNotActuallyResealed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		resealer fakeResealer
	}{
		{"byte-identical output, which a random GCM nonce makes impossible",
			fakeResealer{kind: app.KindTOTP, version: 2, echo: true}},
		{"an empty replacement",
			fakeResealer{kind: app.KindTOTP, version: 2, empty: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store, _ := storeWith(t, app.KindTOTP, 2)
			job := newJob(t, store, tt.resealer)

			pass, err := job.ResealOnce(t.Context(), app.KindTOTP, "", 10)
			if err != nil {
				t.Fatalf("re-sealing: %v", err)
			}
			if pass.Failed != 2 || pass.Resealed != 0 {
				t.Errorf("failed %d, re-sealed %d; nothing was re-sealed",
					pass.Failed, pass.Resealed)
			}
			if store.writes != 0 {
				t.Errorf("%d writes reached the database; none should have", store.writes)
			}
		})
	}
}

// A password row with no user_view row cannot be bound and must be reported.
//
// Migration 00009 dropped the foreign key that used to make this impossible, so
// the state is real. Skipping it silently would leave a row counting against the
// done check with nothing explaining why.
func TestResealOnce_APasswordRowWithNoUserIDIsAFailureNotASilentSkip(t *testing.T) {
	t.Parallel()

	store, _ := storeWith(t, app.KindPassword, 2)
	store.rows[0].UserID = ids.UserID{}

	job := newJob(t, store, fakeResealer{kind: app.KindPassword, version: 2})
	pass, err := job.ResealOnce(t.Context(), app.KindPassword, "", 10)
	if err != nil {
		t.Fatalf("re-sealing: %v", err)
	}
	if pass.Failed != 1 || pass.Resealed != 1 {
		t.Errorf("failed %d, re-sealed %d; the unbound row is a failure and the other "+
			"row still gets re-sealed", pass.Failed, pass.Resealed)
	}
	if pass.Remaining != 1 {
		t.Errorf("remaining %d; the unbound row still holds the old key alive", pass.Remaining)
	}
}

// A TOTP row needs no user id, and demanding one would strand every TOTP secret.
func TestResealOnce_ATOTPRowNeedsNoUserID(t *testing.T) {
	t.Parallel()

	store, _ := storeWith(t, app.KindTOTP, 2) // built without user ids
	job := newJob(t, store, fakeResealer{kind: app.KindTOTP, version: 2})

	pass, err := job.ResealOnce(t.Context(), app.KindTOTP, "", 10)
	if err != nil {
		t.Fatalf("re-sealing: %v", err)
	}
	if pass.Resealed != 2 || pass.Failed != 0 {
		t.Errorf("re-sealed %d, failed %d; a TOTP secret binds to the subject, not the user",
			pass.Resealed, pass.Failed)
	}
}

// ---------------------------------------------------------------------------
// Progress, completion and bounded work
// ---------------------------------------------------------------------------

// An empty PAGE is not completion, and the count is what says so.
//
// This is the exact trap the separate COUNT statement exists to remove: when
// every remaining row is behind the cursor because it could not be re-sealed,
// the page comes back empty and looks precisely like a finished rotation.
func TestResealOnce_AnEmptyPageIsNotDoneWhenRowsRemain(t *testing.T) {
	t.Parallel()

	store, credIDs := storeWith(t, app.KindTOTP, 2)
	job := newJob(t, store, fakeResealer{kind: app.KindTOTP, version: 2})

	// Resume past both rows: nothing is after the cursor, but both are still at
	// the old version.
	pass, err := job.ResealOnce(t.Context(), app.KindTOTP, credIDs[1].String(), 10)
	if err != nil {
		t.Fatalf("re-sealing: %v", err)
	}
	if pass.Scanned != 0 || pass.More {
		t.Fatalf("the page was not empty: scanned %d, more %v", pass.Scanned, pass.More)
	}
	if pass.Remaining != 2 {
		t.Errorf("remaining %d, want 2", pass.Remaining)
	}
	if pass.Done() {
		t.Fatal("an empty page was reported as a completed rotation; this is the answer " +
			"that gets an in-use key destroyed")
	}
}

// The cursor advances over a row that could NOT be re-sealed.
//
// Without that, one unopenable secret pins the job to the first page forever:
// the row keeps its old version, matches the work list again, and comes back at
// the head of every subsequent page while each pass reports that it scanned work.
func TestResealOnce_TheCursorStepsOverARowItCouldNotFix(t *testing.T) {
	t.Parallel()

	store, credIDs := storeWith(t, app.KindTOTP, 3)
	job := newJob(t, store, fakeResealer{
		kind: app.KindTOTP, version: 2,
		// The FIRST row is the poison pill, which is the case that actually
		// blocks: a failure later in the page is stepped over anyway.
		errs: map[string]error{credIDs[0].String(): app.ErrSecretUnreadable},
	})

	first, err := job.ResealOnce(t.Context(), app.KindTOTP, "", 1)
	if err != nil {
		t.Fatalf("first pass: %v", err)
	}
	if first.Cursor != credIDs[0].String() {
		t.Fatalf("cursor is %q; it must advance to the row that was looked at, whatever "+
			"the outcome was", first.Cursor)
	}
	if !first.More {
		t.Fatal("the page filled, so the caller must be told to loop")
	}

	second, err := job.ResealOnce(t.Context(), app.KindTOTP, first.Cursor, 1)
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if second.Resealed != 1 {
		t.Errorf("re-sealed %d on the second pass; the unopenable row blocked progress",
			second.Resealed)
	}
	if got := store.listCalls[1].after; got != credIDs[0].String() {
		t.Errorf("the second work list resumed after %q, not the first pass's cursor", got)
	}
}

// A full page reports More. A caller that stopped there would report success
// over a backlog it never looked at.
func TestResealOnce_AFullPageReportsThereIsMore(t *testing.T) {
	t.Parallel()

	store, _ := storeWith(t, app.KindTOTP, 5)
	job := newJob(t, store, fakeResealer{kind: app.KindTOTP, version: 2})

	pass, err := job.ResealOnce(t.Context(), app.KindTOTP, "", 2)
	if err != nil {
		t.Fatalf("re-sealing: %v", err)
	}
	if !pass.More {
		t.Error("a full page did not report More, so the caller stops with work remaining")
	}
	if pass.Remaining != 3 {
		t.Errorf("remaining %d, want 3", pass.Remaining)
	}
	if pass.Done() {
		t.Error("a truncated pass was reported as a completed rotation")
	}
}

// A limit of zero moves nothing and would report a clean pass forever.
func TestResealOnce_RefusesANonPositiveLimit(t *testing.T) {
	t.Parallel()

	store, _ := storeWith(t, app.KindTOTP, 1)
	job := newJob(t, store, fakeResealer{kind: app.KindTOTP, version: 2})

	for _, limit := range []int{0, -1} {
		if _, err := job.ResealOnce(t.Context(), app.KindTOTP, "", limit); err == nil {
			t.Errorf("a limit of %d was accepted; it moves no rows and never will", limit)
		}
	}
}

// ---------------------------------------------------------------------------
// Failure isolation
// ---------------------------------------------------------------------------

// An unreadable work list is the one thing that fails the whole pass: nothing
// is known, so the caller must retry rather than record a result.
func TestResealOnce_AnUnreadableWorkListFailsThePass(t *testing.T) {
	t.Parallel()

	store, _ := storeWith(t, app.KindTOTP, 2)
	store.listErr = errors.New("connection reset")

	job := newJob(t, store, fakeResealer{kind: app.KindTOTP, version: 2})
	if _, err := job.ResealOnce(t.Context(), app.KindTOTP, "", 10); err == nil {
		t.Fatal("a pass that could not read its work list reported success")
	}
}

// A failed COUNT must never read as zero.
//
// Zero is the value that licenses destroying a key, so "the count could not be
// taken" and "there is nothing left" have to be different answers.
func TestResealOnce_AFailedDoneCheckIsAnErrorAndNotAZero(t *testing.T) {
	t.Parallel()

	store, _ := storeWith(t, app.KindTOTP, 2)
	store.countErr = errors.New("statement timeout")

	job := newJob(t, store, fakeResealer{kind: app.KindTOTP, version: 2})
	pass, err := job.ResealOnce(t.Context(), app.KindTOTP, "", 10)
	if err == nil {
		t.Fatal("a pass whose done check failed reported success; a missing count must " +
			"never be read as 'nothing left'")
	}
	if pass.Done() {
		t.Error("Done() is true on a pass whose count never came back")
	}
	// The writes still happened, and the partial result is still reported.
	if pass.Resealed != 2 {
		t.Errorf("re-sealed %d; the work that did happen must still be reported", pass.Resealed)
	}
}

// A write that fails for a non-CAS reason is a counted failure, and the rest of
// the batch still runs.
func TestResealOnce_AWriteFailureDoesNotStopTheBatch(t *testing.T) {
	t.Parallel()

	store, _ := storeWith(t, app.KindTOTP, 3)
	store.writeErr = errors.New("deadlock detected")

	job := newJob(t, store, fakeResealer{kind: app.KindTOTP, version: 2})
	pass, err := job.ResealOnce(t.Context(), app.KindTOTP, "", 10)
	if err != nil {
		t.Fatalf("re-sealing: %v", err)
	}
	if pass.Failed != 3 {
		t.Errorf("failed %d, want 3; every row was attempted", pass.Failed)
	}
	if pass.Scanned != 3 {
		t.Errorf("scanned %d; the batch must not stop at the first failure", pass.Scanned)
	}
}

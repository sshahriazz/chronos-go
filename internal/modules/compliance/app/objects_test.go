package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/compliance/app"
	"github.com/chronos/chronos-go/internal/platform/blob"
)

type fakeObjectStore struct {
	byPrefix map[string][]blob.Key
	listErr  error
	delErr   error

	listed  []string
	deleted []blob.Key
	limits  []int
}

func (f *fakeObjectStore) ListPrefix(
	_ context.Context, prefix string, limit int,
) ([]blob.Key, error) {
	f.listed = append(f.listed, prefix)
	f.limits = append(f.limits, limit)
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.byPrefix[prefix], nil
}

func (f *fakeObjectStore) Delete(_ context.Context, key blob.Key) error {
	if f.delErr != nil {
		return f.delErr
	}
	f.deleted = append(f.deleted, key)
	return nil
}

func onePrefix(subjectID string) []string { return []string{"avatar-" + subjectID} }

func newObjects(t *testing.T, store *fakeObjectStore, prefixes app.SubjectPrefixes) *app.Objects {
	t.Helper()
	o, err := app.NewObjects(app.ObjectsDeps{Store: store, Prefixes: prefixes})
	if err != nil {
		t.Fatalf("NewObjects: %v", err)
	}
	return o
}

// EVERY OBJECT UNDER THE SUBJECT'S PREFIX GOES, NOT JUST THE CURRENT ONE.
//
// This is the whole reason erasure enumerates a prefix instead of reading the
// projection. Objects are immutable — a new avatar is a new key plus a new event
// — so every SUPERSEDED avatar is still there under a key no row has named since,
// and every granted-but-abandoned upload is there under a key no row ever named.
// Both are photographs of a person who asked to be forgotten.
func TestEveryObjectUnderTheSubjectsPrefixIsDeleted(t *testing.T) {
	store := &fakeObjectStore{byPrefix: map[string][]blob.Key{
		"avatar-subj_1": {"avatar-subj_1/current", "avatar-subj_1/superseded", "avatar-subj_1/abandoned"},
	}}

	deleted, err := newObjects(t, store, onePrefix).ErasePrefixes(
		context.Background(), "subj_1")
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 3 {
		t.Fatalf("deleted %d objects, want 3; the ones a projection does not name are "+
			"still personal data and still servable", deleted)
	}
	if len(store.deleted) != 3 {
		t.Errorf("the store saw %d deletes", len(store.deleted))
	}
}

// EVERY REGISTERED PREFIX IS TRAVERSED.
//
// The list is the extension point: a module that stores objects and is not in it
// erases incompletely, and the symptom is nothing at all.
func TestEveryRegisteredPrefixIsTraversed(t *testing.T) {
	store := &fakeObjectStore{byPrefix: map[string][]blob.Key{
		"a-subj_1": {"a-subj_1/x"},
		"b-subj_1": {"b-subj_1/y"},
	}}
	two := func(s string) []string { return []string{"a-" + s, "b-" + s} }

	deleted, err := newObjects(t, store, two).ErasePrefixes(context.Background(), "subj_1")
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 2 {
		t.Fatalf("deleted %d, want 2 — one module's objects were skipped", deleted)
	}
	if len(store.listed) != 2 {
		t.Errorf("listed %v, want both prefixes", store.listed)
	}
}

// AN EMPTY PREFIX LIST IS A FAILURE, NOT A FAST SUCCESS.
//
// A traversal that visits nothing completes instantly and is indistinguishable
// from one that found nothing to delete. Since the list is hand-maintained at
// the composition root, "somebody forgot to add their module" has to be loud.
func TestAnEmptyPrefixListIsRefused(t *testing.T) {
	store := &fakeObjectStore{}
	none := func(string) []string { return nil }

	if _, err := newObjects(t, store, none).ErasePrefixes(
		context.Background(), "subj_1"); err == nil {
		t.Fatal("an erasure with no registered prefixes reported success; a module that " +
			"forgot to register erases nothing and nobody finds out")
	}
	if len(store.listed) != 0 {
		t.Error("the store was consulted with no prefixes")
	}
}

// TOO MANY OBJECTS FAILS THE ERASURE AND DELETES NOTHING FURTHER.
//
// A partial deletion reported as success is indistinguishable afterwards from a
// complete one — the worst available outcome, and the one this whole path exists
// to prevent.
func TestTooManyObjectsRefusesRatherThanPartiallyDeleting(t *testing.T) {
	store := &fakeObjectStore{listErr: blob.ErrTooManyObjects}

	_, err := newObjects(t, store, onePrefix).ErasePrefixes(context.Background(), "subj_1")
	if err == nil {
		t.Fatal("an oversized prefix was treated as success")
	}
	if !errors.Is(err, blob.ErrTooManyObjects) {
		t.Errorf("returned %v, which does not carry ErrTooManyObjects; the operator cannot "+
			"tell a bucket problem from a subject with too many objects", err)
	}
	if len(store.deleted) != 0 {
		t.Error("objects were deleted despite the refusal")
	}
}

// THE LIMIT REACHES THE STORE.
//
// A limit the caller never passes is a bound that does not exist.
func TestTheObjectLimitIsPassedThrough(t *testing.T) {
	store := &fakeObjectStore{}
	if _, err := newObjects(t, store, onePrefix).ErasePrefixes(
		context.Background(), "subj_1"); err != nil {
		t.Fatal(err)
	}
	if len(store.limits) != 1 || store.limits[0] != app.MaxObjectsPerSubject {
		t.Errorf("listed with limit %v, want %d", store.limits, app.MaxObjectsPerSubject)
	}
}

// A FAILED DELETE FAILS THE ERASURE.
//
// Continuing past it would leave an object behind under a subject the log
// records as erased.
func TestAFailedDeleteFailsTheErasure(t *testing.T) {
	store := &fakeObjectStore{
		byPrefix: map[string][]blob.Key{"avatar-subj_1": {"avatar-subj_1/x"}},
		delErr:   errors.New("seaweedfs: connection refused"),
	}

	if _, err := newObjects(t, store, onePrefix).ErasePrefixes(
		context.Background(), "subj_1"); err == nil {
		t.Fatal("a failed delete was reported as a successful erasure")
	}
}

// A SUBJECT WITH NO OBJECTS SUCCEEDS.
//
// Most people never upload an avatar, so this is the ordinary case rather than
// an edge one.
func TestASubjectWithNoObjectsSucceeds(t *testing.T) {
	store := &fakeObjectStore{}

	deleted, err := newObjects(t, store, onePrefix).ErasePrefixes(
		context.Background(), "subj_1")
	if err != nil {
		t.Fatalf("a subject with no objects failed: %v", err)
	}
	if deleted != 0 {
		t.Errorf("deleted %d", deleted)
	}
}

// AN EMPTY SUBJECT IS REFUSED BEFORE ANYTHING IS LISTED.
//
// A prefix built from an empty subject is a prefix somebody else's objects could
// share.
func TestErasingObjectsNeedsASubject(t *testing.T) {
	store := &fakeObjectStore{}

	if _, err := newObjects(t, store, onePrefix).ErasePrefixes(
		context.Background(), ""); err == nil {
		t.Fatal("an empty subject was accepted")
	}
	if len(store.listed) != 0 {
		t.Error("the store was listed for an empty subject")
	}
}

// AN INCOMPLETE WIRING IS REFUSED.
func TestObjectsRefusesAnIncompleteWiring(t *testing.T) {
	if _, err := app.NewObjects(app.ObjectsDeps{Prefixes: onePrefix}); err == nil {
		t.Error("an object eraser with no store was accepted")
	}
	if _, err := app.NewObjects(app.ObjectsDeps{Store: &fakeObjectStore{}}); err == nil {
		t.Error("an object eraser with no prefix list was accepted")
	}
}

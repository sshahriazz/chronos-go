package app_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"sync"
	"time"

	"github.com/chronos/chronos-go/internal/modules/profile/app"
	"github.com/chronos/chronos-go/internal/modules/profile/contract"
	"github.com/chronos/chronos-go/internal/modules/profile/domain"
	"github.com/chronos/chronos-go/internal/platform/blob"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

const (
	subject      = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	otherSubject = "subj_01BX5ZZKBKACTAV9WEVGEMMVRZ"
)

// ---------------------------------------------------------------------------
// Fakes
//
// Deliberately in-memory and deliberately dumb: these exist so a use-case test
// can drive a branch, not so it can assert on infrastructure. The real
// behaviour of each port is covered by its adapter's own tests and, end to end,
// by internal/adapter/profileit.
// ---------------------------------------------------------------------------

// fakeRepo is one profile stream, plus the optimistic-concurrency precondition
// that makes two concurrent saves collide.
type fakeRepo struct {
	mu       sync.Mutex
	events   []eventsourcing.Event
	saves    int
	loadErr  error
	saveErr  error
	conflict bool
}

func (r *fakeRepo) Load(context.Context, string) (*domain.Profile, error) {
	if r.loadErr != nil {
		return nil, r.loadErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p := eventsourcing.NewAggregate(domain.NewProfile)
	for _, e := range r.events {
		p.Apply(e)
	}
	return p, nil
}

func (r *fakeRepo) Save(
	_ context.Context, _ string, agg *domain.Profile, _ string, _ eventsourcing.Metadata,
) (eventsourcing.AppendResult, error) {
	if r.saveErr != nil {
		return eventsourcing.AppendResult{}, r.saveErr
	}
	if r.conflict {
		return eventsourcing.AppendResult{}, fmt.Errorf(
			"fake: %w", eventsourcing.ErrWrongExpectedRevision)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, agg.Uncommitted()...)
	r.saves++
	agg.ClearUncommitted()
	return eventsourcing.AppendResult{}, nil
}

// recorded returns the single event this repository holds.
func (r *fakeRepo) recorded() []*contract.ProfileUpdated {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*contract.ProfileUpdated, 0, len(r.events))
	for _, e := range r.events {
		if u, ok := e.(*contract.ProfileUpdated); ok {
			out = append(out, u)
		}
	}
	return out
}

// fakeVault is the PII vault, and it enforces the vault's own rules: it refuses
// what pii.Validate refuses, so a test cannot pass here and fail in production.
type fakeVault struct {
	mu      sync.Mutex
	values  map[pii.Field]string
	erased  bool
	absent  bool
	putErr  error
	readErr error
	puts    int
}

func newFakeVault() *fakeVault { return &fakeVault{values: map[pii.Field]string{}} }

func (v *fakeVault) PutAll(_ context.Context, id pii.SubjectID, values map[pii.Field]string) error {
	if v.putErr != nil {
		return v.putErr
	}
	if id == "" {
		return errors.New("fake vault: a subject id is required")
	}
	for f, val := range values {
		if err := pii.Validate(f, val); err != nil {
			return err
		}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	maps.Copy(v.values, values)
	v.puts++
	return nil
}

func (v *fakeVault) Profile(_ context.Context, id pii.SubjectID) (pii.Profile, error) {
	switch {
	case v.readErr != nil:
		return pii.Profile{}, v.readErr
	case v.erased:
		return pii.Profile{}, pii.ErrErased
	case v.absent:
		return pii.Profile{}, pii.ErrNoSubject
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return pii.Profile{SubjectID: id, Fields: maps.Clone(v.values)}, nil
}

// fakeStore is the object store. Objects are put there by a test, never by the
// code under test, which is exactly the shape of the real thing: the bytes
// arrive from the browser.
type fakeStore struct {
	mu        sync.Mutex
	objects   map[blob.Key]blob.Object
	grantErr  error
	verifyErr error
	signErr   error
	granted   []blob.UploadRequest
}

func newFakeStore() *fakeStore {
	return &fakeStore{objects: map[blob.Key]blob.Object{}}
}

func (s *fakeStore) GrantUpload(_ context.Context, req blob.UploadRequest) (blob.Grant, error) {
	if s.grantErr != nil {
		return blob.Grant{}, s.grantErr
	}
	key, err := blob.NewKey(req.Prefix)
	if err != nil {
		return blob.Grant{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.granted = append(s.granted, req)
	return blob.Grant{
		URL:      "https://objects.example/bucket",
		Fields:   map[string]string{"key": key.String(), "Content-Type": req.ContentType},
		Key:      key,
		Expires:  time.Date(2026, 8, 21, 10, 10, 0, 0, time.UTC),
		MaxBytes: req.MaxBytes,
	}, nil
}

func (s *fakeStore) Verify(_ context.Context, key blob.Key) (blob.Object, error) {
	if s.verifyErr != nil {
		return blob.Object{}, s.verifyErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	obj, ok := s.objects[key]
	if !ok {
		return blob.Object{}, fmt.Errorf("%w: %s", blob.ErrNotFound, key)
	}
	return obj, nil
}

func (s *fakeStore) GrantDownload(_ context.Context, key blob.Key, _ time.Duration) (string, error) {
	if s.signErr != nil {
		return "", s.signErr
	}
	return "https://objects.example/bucket/" + key.String() + "?signed", nil
}

// put places an object as if a browser had uploaded it.
func (s *fakeStore) put(key string, contentType string, size int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[blob.Key(key)] = blob.Object{
		Key: blob.Key(key), ContentType: contentType, Size: size,
	}
}

// fakeReader is the projection. It is fed by hand rather than by a projector,
// because a use-case test is not the place to assert that the projector works
// — internal/adapter/profileit does that against a real one.
type fakeReader struct {
	view app.View
	err  error
}

func (r *fakeReader) View(context.Context, string) (app.View, error) {
	if r.err != nil {
		return app.View{}, r.err
	}
	return r.view, nil
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

type harness struct {
	repo    *fakeRepo
	vault   *fakeVault
	store   *fakeStore
	reader  *fakeReader
	queries *app.Queries
	updates *app.Updates
	avatars *app.Avatars
}

func newHarness(t interface{ Fatalf(string, ...any) }) *harness {
	h := &harness{
		repo: &fakeRepo{}, vault: newFakeVault(), store: newFakeStore(), reader: &fakeReader{},
	}

	var err error
	h.queries, err = app.NewQueries(app.QueriesDeps{
		Reader: h.reader, Vault: h.vault, Avatars: h.store,
		Now: func() time.Time { return time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewQueries: %v", err)
	}
	h.updates, err = app.NewUpdates(app.UpdatesDeps{
		Repo: h.repo, Vault: h.vault, Avatars: h.store, Queries: h.queries,
	})
	if err != nil {
		t.Fatalf("NewUpdates: %v", err)
	}
	h.avatars, err = app.NewAvatars(app.AvatarsDeps{Store: h.store})
	if err != nil {
		t.Fatalf("NewAvatars: %v", err)
	}
	return h
}

func ptr[T any](v T) *T { return &v }

// renderEvent produces a readable dump of an event's payload for an assertion
// that nothing personal is in it.
//
// Reflection over the STRUCT rather than a hand-written list of fields, so a
// field added later is covered without anybody remembering to extend the
// assertion — which is the failure mode a hand-written list has.
func renderEvent(e *contract.ProfileUpdated) string {
	return fmt.Sprintf("%#v|%+v", *e, deref(e))
}

func deref(e *contract.ProfileUpdated) map[string]any {
	out := map[string]any{"SubjectID": e.SubjectID, "UpdatedAt": e.UpdatedAt}
	v := reflect.ValueOf(*e)
	typ := v.Type()
	for i := range typ.NumField() {
		f := v.Field(i)
		if f.Kind() == reflect.Pointer && !f.IsNil() {
			out[typ.Field(i).Name] = f.Elem().Interface()
			continue
		}
		out[typ.Field(i).Name] = f.Interface()
	}
	return out
}

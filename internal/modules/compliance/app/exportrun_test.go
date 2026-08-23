package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/modules/compliance"
	"github.com/chronos/chronos-go/internal/modules/compliance/app"
	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
	"github.com/chronos/chronos-go/internal/platform/blob"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

var runAt = time.Date(2026, 8, 23, 10, 0, 0, 0, time.UTC)

// ---------------------------------------------------------------------------
// Doubles
// ---------------------------------------------------------------------------

type fakeProfile struct {
	fields map[string]string
	err    error
}

func (f fakeProfile) Profile(context.Context, string) (map[string]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.fields, nil
}

type fakeLister struct {
	pages []blob.Page
	err   error
	calls []string
}

func (f *fakeLister) ListPage(
	_ context.Context, prefix, after string, _ int,
) (blob.Page, error) {
	f.calls = append(f.calls, prefix+"|"+after)
	if f.err != nil {
		return blob.Page{}, f.err
	}
	i := len(f.calls) - 1
	if i >= len(f.pages) {
		return blob.Page{}, nil
	}
	return f.pages[i], nil
}

// recordingStore records what was written, and can be made to fail.
type recordingStore struct {
	put      [][]byte
	putErr   error
	grantErr error
}

func (s *recordingStore) Put(_ context.Context, _ blob.Key, body []byte, _ string) error {
	if s.putErr != nil {
		return s.putErr
	}
	s.put = append(s.put, body)
	return nil
}

func (s *recordingStore) GrantDownload(
	context.Context, blob.Key, time.Duration,
) (string, error) {
	if s.grantErr != nil {
		return "", s.grantErr
	}
	return "https://example.test/signed", nil
}

type fakeRestricted struct {
	restricted bool
	err        error
}

func (f fakeRestricted) Restricted(context.Context, string) (bool, error) {
	return f.restricted, f.err
}

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

// memoryStore is an EventStore that actually persists, so a retried Request
// finds the stream the first one wrote — which is the property under test.
type memoryStore struct {
	streams map[string][]eventsourcing.RecordedEvent
	codec   *eventcodec.JSON
}

func newMemoryStore() *memoryStore {
	codec := eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry())
	compliance.RegisterEvents(codec)
	return &memoryStore{
		streams: map[string][]eventsourcing.RecordedEvent{},
		codec:   codec,
	}
}

func (m *memoryStore) Append(
	_ context.Context, stream eventsourcing.StreamID,
	_ eventsourcing.ExpectedRevision, events []eventsourcing.PendingEvent,
) (eventsourcing.AppendResult, error) {
	key := stream.String()
	for _, e := range events {
		payload, err := m.codec.Marshal(e.Event)
		if err != nil {
			return eventsourcing.AppendResult{}, err
		}
		meta, err := m.codec.MarshalMetadata(e.Meta)
		if err != nil {
			return eventsourcing.AppendResult{}, err
		}
		m.streams[key] = append(m.streams[key], eventsourcing.RecordedEvent{
			ID:       e.ID,
			Type:     e.Event.EventType(),
			Stream:   stream,
			Revision: eventsourcing.Revision(len(m.streams[key])),
			Payload:  payload,
			Metadata: meta,
		})
	}
	return eventsourcing.AppendResult{
		Revision: eventsourcing.Revision(len(m.streams[key]) - 1),
		Position: eventsourcing.Position{Commit: 1, Prepare: 1},
	}, nil
}

func (m *memoryStore) ReadStream(
	_ context.Context, stream eventsourcing.StreamID, from eventsourcing.Revision,
) ([]eventsourcing.RecordedEvent, error) {
	events, ok := m.streams[stream.String()]
	if !ok {
		return nil, eventsourcing.ErrStreamNotFound
	}
	if int(from) >= len(events) {
		return nil, nil
	}
	return events[from:], nil
}

// types names every event the store holds, in commit order.
func (m *memoryStore) types() []string {
	var out []string
	for _, events := range m.streams {
		for _, e := range events {
			out = append(out, e.Type)
		}
	}
	return out
}

type runHarness struct {
	runs   *app.ExportRuns
	store  *recordingStore
	lister *fakeLister
	events *memoryStore
}

func newRunHarness(t *testing.T, restricted fakeRestricted) *runHarness {
	t.Helper()

	events := newMemoryStore()
	store := &recordingStore{}
	lister := &fakeLister{}

	runs, err := app.NewExportRuns(app.ExportRunsDeps{
		Exports: eventsourcing.NewRepository[*domain.Export](
			events, events.codec, nil,
			domain.ExportCategory, domain.NewExport),
		Profile:      fakeProfile{fields: map[string]string{"email": "a@b.test"}},
		Objects:      lister,
		Prefixes:     app.SubjectPrefixes(func(s string) []string { return []string{"px" + s} }),
		Store:        store,
		Prefix:       func(s string) string { return "px" + s },
		Restrictions: restricted,
		Now:          func() time.Time { return runAt },
	})
	if err != nil {
		t.Fatalf("NewExportRuns: %v", err)
	}
	return &runHarness{runs: runs, store: store, lister: lister, events: events}
}

// ---------------------------------------------------------------------------
// The properties
// ---------------------------------------------------------------------------

// THE EXPORT ID IS DERIVED FROM THE IDEMPOTENCY KEY.
//
// One person pressing a button twice must poll ONE export. A random id would
// give the retry its own stream, its own workflow, its own bundle and its own
// "your export is ready" mail — and the client, which never saw the first
// answer, would have no way to find the first request again.
func TestTheExportIDIsDerivedFromTheIdempotencyKey(t *testing.T) {
	h := newRunHarness(t, fakeRestricted{})
	ctx := context.Background()

	first, err := h.runs.Request(ctx, app.RequestExportCommand{
		SubjectID: "subj_1", IdempotencyKey: "k-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.runs.Request(ctx, app.RequestExportCommand{
		SubjectID: "subj_1", IdempotencyKey: "k-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("one key produced two export ids, %q and %q. A retried request starts a "+
			"second workflow and the client cannot find the first", first, second)
	}

	// A DIFFERENT key is a different request. Without this the derivation would
	// be a constant and every export in the system would share one stream.
	other, err := h.runs.Request(ctx, app.RequestExportCommand{
		SubjectID: "subj_1", IdempotencyKey: "k-2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if other == first {
		t.Fatal("two different keys produced one export id; every request shares a stream")
	}
}

// ARTICLE 18 STOPS AN EXPORT, PERMANENTLY.
//
// compliance.md §6: a restricted subject is not processed, and building an
// export is processing. The refusal must also be PERMANENT — a restricted
// subject will still be restricted on the hundredth attempt, so retrying it like
// an outage burns the workflow's whole schedule to reach the same answer.
func TestARestrictedSubjectsExportIsRefusedPermanently(t *testing.T) {
	h := newRunHarness(t, fakeRestricted{restricted: true})
	ctx := context.Background()

	id, err := h.runs.Request(ctx, app.RequestExportCommand{
		SubjectID: "subj_1", IdempotencyKey: "k-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = h.runs.Begin(ctx, id)
	if err == nil {
		t.Fatal("an export ran for a subject under Article 18 restriction; building it is " +
			"exactly the processing the restriction halts")
	}
	var permanent *app.PermanentExportError
	if !errors.As(err, &permanent) {
		t.Fatalf("the refusal is %v, which the workflow will RETRY for an hour before "+
			"telling the person something a first attempt already knew", err)
	}
	if permanent.Permanent() != "processing_restricted" {
		t.Errorf("the refusal reports reason %q", permanent.Permanent())
	}
}

// AN UNREADABLE RESTRICTION FAILS CLOSED.
//
// The one lookup where a wrong "no" resumes processing for somebody who asked it
// to stop. An unreadable answer is not an absent restriction (ADR-010), and the
// alternative is that a Postgres blip exports the data of a person who invoked
// Article 18.
func TestAnUnreadableRestrictionRefusesTheExport(t *testing.T) {
	h := newRunHarness(t, fakeRestricted{err: errors.New("postgres is down")})
	ctx := context.Background()

	id, err := h.runs.Request(ctx, app.RequestExportCommand{
		SubjectID: "subj_1", IdempotencyKey: "k-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.runs.Begin(ctx, id); err == nil {
		t.Fatal("an export ran while the restriction could not be read. A blip in the read " +
			"model exports the data of somebody who asked us to stop processing it")
	}
	// NOT permanent: an outage is worth retrying, unlike a restriction.
	var permanent *app.PermanentExportError
	if errors.As(err, &permanent) {
		t.Error("an unreadable restriction was treated as permanent; a transient outage " +
			"would permanently fail a request the person is entitled to")
	}
}

// THE COMPLETION IS RECORDED ONLY AFTER THE OBJECT EXISTS.
//
// The reverse order announces a fetchable export — and mails the subject about
// it — while the manifest is still only an intention. The poll then hands them a
// signed URL for an object that is not there.
func TestTheCompletionIsRecordedAfterTheObjectIsWritten(t *testing.T) {
	h := newRunHarness(t, fakeRestricted{})
	h.store.putErr = errors.New("s3 is down")
	ctx := context.Background()

	id, err := h.runs.Request(ctx, app.RequestExportCommand{
		SubjectID: "subj_1", IdempotencyKey: "k-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.runs.WriteManifest(ctx, id, nil); err == nil {
		t.Fatal("the manifest reported success while the store refused to store it")
	}
	for _, e := range h.events.types() {
		if e == "compliance.DataExportCompleted.v1" {
			t.Fatal("the export was recorded COMPLETE while the manifest failed to write. " +
				"The subject is mailed that their data is ready and the poll hands them a " +
				"signed URL for an object that does not exist")
		}
	}
}

// A LISTING PAGE IS PASSED THROUGH WITH ITS CURSOR.
func TestListObjectsReturnsThePageAndItsCursor(t *testing.T) {
	h := newRunHarness(t, fakeRestricted{})
	h.lister.pages = []blob.Page{{
		Objects: []blob.Object{{Key: "pxsubj_1/a", Size: 12}},
		Cursor:  "next",
	}}

	page, err := h.runs.ListObjects(context.Background(), "pxsubj_1", "")
	if err != nil {
		t.Fatal(err)
	}
	if page.Cursor != "next" {
		t.Fatalf("the cursor came back as %q; without it the workflow stops at the first "+
			"page and the bundle is missing everything after it", page.Cursor)
	}
	if len(page.Objects) != 1 || page.Objects[0].Key != "pxsubj_1/a" {
		t.Fatalf("the page came back as %v", page.Objects)
	}
}

// AN EMPTY PREFIX IS REFUSED, PERMANENTLY.
//
// It would list the WHOLE BUCKET, which here means putting another tenant's
// objects into somebody's data export.
func TestAnEmptyExportPrefixIsRefused(t *testing.T) {
	h := newRunHarness(t, fakeRestricted{})
	if _, err := h.runs.ListObjects(context.Background(), "", ""); err == nil {
		t.Fatal("an empty prefix was listed; every object in the bucket is now in one " +
			"person's export")
	}
	if len(h.lister.calls) != 0 {
		t.Error("the refused listing still reached the store")
	}
}

// A FAILURE AFTER A COMPLETION IS SWALLOWED, NOT PROPAGATED.
//
// The aggregate refuses it, and this must translate that refusal into success:
// the bundle is fetchable, so telling the subject it failed would be a lie — and
// returning an error would make the workflow retry recording a failure it must
// never record.
func TestAFailureAfterACompletionIsNotAnError(t *testing.T) {
	h := newRunHarness(t, fakeRestricted{})
	ctx := context.Background()

	id, err := h.runs.Request(ctx, app.RequestExportCommand{
		SubjectID: "subj_1", IdempotencyKey: "k-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.runs.WriteManifest(ctx, id, nil); err != nil {
		t.Fatal(err)
	}
	if err := h.runs.Fail(ctx, id, "source_unreadable"); err != nil {
		t.Fatalf("a late failure on a completed export returned %v; the workflow will "+
			"retry it, and the subject's fetchable bundle is reported as failed if it "+
			"ever succeeds", err)
	}
}

// EVERY DEPENDENCY IS REQUIRED.
func TestExportRunsRefusesAPartialWiring(t *testing.T) {
	store := newMemoryStore()
	full := func() app.ExportRunsDeps {
		return app.ExportRunsDeps{
			Exports: eventsourcing.NewRepository[*domain.Export](
				store, store.codec, nil,
				domain.ExportCategory, domain.NewExport),
			Profile:      fakeProfile{},
			Objects:      &fakeLister{},
			Prefixes:     app.SubjectPrefixes(func(string) []string { return nil }),
			Store:        &recordingStore{},
			Prefix:       func(string) string { return "p" },
			Restrictions: fakeRestricted{},
			Now:          func() time.Time { return runAt },
		}
	}
	for name, break_ := range map[string]func(*app.ExportRunsDeps){
		"no repository": func(d *app.ExportRunsDeps) { d.Exports = nil },
		"no profile":    func(d *app.ExportRunsDeps) { d.Profile = nil },
		"no lister":     func(d *app.ExportRunsDeps) { d.Objects = nil },
		"no prefixes":   func(d *app.ExportRunsDeps) { d.Prefixes = nil },
		"no store":      func(d *app.ExportRunsDeps) { d.Store = nil },
		"no manifest":   func(d *app.ExportRunsDeps) { d.Prefix = nil },
		// Without it every export runs for a restricted subject, which is the one
		// failure here that silently violates a right rather than failing loudly.
		"no restrictions": func(d *app.ExportRunsDeps) { d.Restrictions = nil },
		"no clock":        func(d *app.ExportRunsDeps) { d.Now = nil },
	} {
		t.Run(name, func(t *testing.T) {
			deps := full()
			break_(&deps)
			if _, err := app.NewExportRuns(deps); err == nil {
				t.Fatalf("a runner was built with %s", name)
			}
		})
	}
}

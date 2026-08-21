package app_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/modules/notification/app"
	"github.com/chronos/chronos-go/internal/modules/notification/contract"
	"github.com/chronos/chronos-go/internal/modules/notification/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/notify"
	"github.com/chronos/chronos-go/internal/platform/page"
)

const (
	testOrg      = "org_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	testOtherOrg = "org_01ARZ3NDEKTSV4RRFFQ69G5FBB"
	testSubject  = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	testOther    = "subj_01ARZ3NDEKTSV4RRFFQ69G5FZZ"
	testEndpoint = "https://updates.push.services.mozilla.com/wpush/v2/gAAAAABm7Qk"
)

func testCodec(t *testing.T) eventsourcing.Codec {
	t.Helper()
	c := eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry())
	eventcodec.Register[contract.NotificationCreated](c)
	eventcodec.Register[contract.NotificationRead](c)
	eventcodec.Register[contract.PushSubscribed](c)
	eventcodec.Register[contract.PushSubscriptionExpired](c)
	eventcodec.Register[contract.PushSent](c)
	eventcodec.Register[contract.ChannelPreferenceSet](c)
	return c
}

// ---------------------------------------------------------------------------
// memStore is an in-memory event store with REAL optimistic concurrency.
//
// It exists rather than a hand-stubbed repository because the property under
// test — two concurrent preference saves must not tear — is a property of the
// expected-revision precondition, and a stub that always accepts would assert
// nothing about it. Every revision check here behaves as KurrentDB's does:
// NoStream requires absence, an exact revision requires that exact last event,
// StreamExists requires presence, and AnyRevision checks nothing.
// ---------------------------------------------------------------------------

type memStore struct {
	codec eventsourcing.Codec

	mu      sync.Mutex
	streams map[eventsourcing.StreamID][]eventsourcing.RecordedEvent

	// appends records every AppendToMany call as one entry, so a test can assert
	// that a batch was ONE atomic operation rather than several.
	appends [][]eventsourcing.StreamAppend

	// failNext makes the next append fail, for the error paths.
	failNext error

	// beforeAppend runs while the lock is NOT held, immediately before the
	// revision check. It is how a test interleaves two commands deterministically.
	beforeAppend func(eventsourcing.StreamID)
}

func newMemStore(t *testing.T) *memStore {
	t.Helper()
	return &memStore{
		codec:   testCodec(t),
		streams: map[eventsourcing.StreamID][]eventsourcing.RecordedEvent{},
	}
}

var (
	_ eventsourcing.EventStore    = (*memStore)(nil)
	_ eventsourcing.MultiAppender = (*memStore)(nil)
)

func (s *memStore) ReadStream(
	_ context.Context, stream eventsourcing.StreamID, from eventsourcing.Revision,
) ([]eventsourcing.RecordedEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	recorded, ok := s.streams[stream]
	if !ok {
		return nil, eventsourcing.ErrStreamNotFound
	}
	if int(from) >= len(recorded) {
		return nil, nil
	}
	out := make([]eventsourcing.RecordedEvent, len(recorded[from:]))
	copy(out, recorded[from:])
	return out, nil
}

func (s *memStore) Append(
	_ context.Context,
	stream eventsourcing.StreamID,
	expected eventsourcing.ExpectedRevision,
	events []eventsourcing.PendingEvent,
) (eventsourcing.AppendResult, error) {
	if s.beforeAppend != nil {
		s.beforeAppend(stream)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failNext != nil {
		err := s.failNext
		s.failNext = nil
		return eventsourcing.AppendResult{}, err
	}
	return s.appendLocked(stream, expected, events)
}

func (s *memStore) AppendToMany(
	_ context.Context, appends []eventsourcing.StreamAppend,
) ([]eventsourcing.AppendResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appends = append(s.appends, appends)
	if s.failNext != nil {
		err := s.failNext
		s.failNext = nil
		return nil, err
	}

	// Atomic: every precondition is checked before anything is written, so a
	// failure leaves the store exactly as it was — which is what the running
	// server does (internal/adapter/kurrentdb/multiappend_integration_test.go).
	for _, a := range appends {
		if err := s.checkLocked(a.Stream, a.Expected); err != nil {
			return nil, err
		}
	}
	out := make([]eventsourcing.AppendResult, 0, len(appends))
	for _, a := range appends {
		res, err := s.appendLocked(a.Stream, a.Expected, a.Events)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (s *memStore) checkLocked(
	stream eventsourcing.StreamID, expected eventsourcing.ExpectedRevision,
) error {
	have := eventsourcing.Revision(len(s.streams[stream])) - 1
	switch {
	case expected.IsAny():
		return nil
	case expected.IsNoStream():
		if have >= 0 {
			return fmt.Errorf("%w: %s exists", eventsourcing.ErrWrongExpectedRevision, stream)
		}
	case expected.IsStreamExists():
		if have < 0 {
			return fmt.Errorf("%w: %s does not exist", eventsourcing.ErrWrongExpectedRevision, stream)
		}
	default:
		if want, ok := expected.Exact(); ok && want != have {
			return fmt.Errorf("%w: %s is at %d, expected %d",
				eventsourcing.ErrWrongExpectedRevision, stream, have, want)
		}
	}
	return nil
}

func (s *memStore) appendLocked(
	stream eventsourcing.StreamID,
	expected eventsourcing.ExpectedRevision,
	events []eventsourcing.PendingEvent,
) (eventsourcing.AppendResult, error) {
	if err := s.checkLocked(stream, expected); err != nil {
		return eventsourcing.AppendResult{}, err
	}
	for _, e := range events {
		payload, err := s.codec.Marshal(e.Event)
		if err != nil {
			return eventsourcing.AppendResult{}, err
		}
		meta, err := s.codec.MarshalMetadata(e.Meta)
		if err != nil {
			return eventsourcing.AppendResult{}, err
		}
		s.streams[stream] = append(s.streams[stream], eventsourcing.RecordedEvent{
			ID:       e.ID,
			Type:     e.Event.EventType(),
			Stream:   stream,
			Revision: eventsourcing.Revision(len(s.streams[stream])),
			Payload:  payload,
			Metadata: meta,
		})
	}
	return eventsourcing.AppendResult{
		Revision: eventsourcing.Revision(len(s.streams[stream])) - 1,
	}, nil
}

// events decodes everything on one stream, so a test asserts against FACTS
// rather than against the arguments it passed in.
func (s *memStore) events(t *testing.T, stream eventsourcing.StreamID) []eventsourcing.Event {
	t.Helper()
	s.mu.Lock()
	recorded := append([]eventsourcing.RecordedEvent(nil), s.streams[stream]...)
	s.mu.Unlock()

	out := make([]eventsourcing.Event, 0, len(recorded))
	for _, r := range recorded {
		e, err := s.codec.Unmarshal(r.Type, r.Payload)
		if err != nil {
			t.Fatalf("decoding %s: %v", r.Type, err)
		}
		out = append(out, e)
	}
	return out
}

func (s *memStore) eventIDs(stream eventsourcing.StreamID) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.streams[stream]))
	for _, r := range s.streams[stream] {
		out = append(out, r.ID.String())
	}
	return out
}

func (s *memStore) streamCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.streams)
}

func (s *memStore) preferenceRepo() *eventsourcing.Repository[*domain.Preferences] {
	return eventsourcing.NewRepository(s, s.codec, nil, domain.Category, domain.NewPreferences)
}

// ---------------------------------------------------------------------------
// Read-model fakes
// ---------------------------------------------------------------------------

// fakeFeed answers ownership and paging questions from an in-memory list.
//
// It enforces the SAME scope the real statements do — org_id and subject_id —
// because a fake that answered for any subject would make every ownership
// assertion below vacuous.
type fakeFeed struct {
	items map[string][]app.FeedItem // key: org + "\x00" + subject
	err   error

	mu    sync.Mutex
	calls int
}

func newFakeFeed() *fakeFeed { return &fakeFeed{items: map[string][]app.FeedItem{}} }

func feedKey(orgID, subjectID string) string { return orgID + "\x00" + subjectID }

func (f *fakeFeed) add(orgID, subjectID string, items ...app.FeedItem) {
	k := feedKey(orgID, subjectID)
	f.items[k] = append(f.items[k], items...)
}

func (f *fakeFeed) Feed(
	_ context.Context, orgID, subjectID string, after page.Keyset, limit int32,
) ([]app.FeedItem, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	all := f.items[feedKey(orgID, subjectID)]

	start := 0
	if !after.IsStart() {
		args := after.Args()
		cursorID, _ := args[1].(string)
		for i, item := range all {
			if item.NotificationID.String() == cursorID {
				start = i + 1
				break
			}
		}
	}
	rest := all[min(start, len(all)):]
	if int(limit) < len(rest) {
		rest = rest[:limit]
	}
	return append([]app.FeedItem(nil), rest...), nil
}

func (f *fakeFeed) UnreadCount(_ context.Context, orgID, subjectID string) (int64, error) {
	if f.err != nil {
		return 0, f.err
	}
	var n int64
	for _, item := range f.items[feedKey(orgID, subjectID)] {
		if item.ReadAt.IsZero() {
			n++
		}
	}
	return n, nil
}

func (f *fakeFeed) OwnedBy(
	_ context.Context, orgID, subjectID string, notificationIDs []string,
) ([]app.OwnedItem, error) {
	if f.err != nil {
		return nil, f.err
	}
	want := make(map[string]struct{}, len(notificationIDs))
	for _, id := range notificationIDs {
		want[id] = struct{}{}
	}
	var out []app.OwnedItem
	for _, item := range f.items[feedKey(orgID, subjectID)] {
		if _, ok := want[item.NotificationID.String()]; ok {
			out = append(out, app.OwnedItem{
				NotificationID: item.NotificationID,
				AlreadyRead:    !item.ReadAt.IsZero(),
			})
		}
	}
	return out, nil
}

// fakePrefs returns only what was explicitly stored, exactly as the real
// statement does — the defaults are the use case's job to fill.
type fakePrefs struct {
	mu     sync.Mutex
	stored map[string]map[notify.Channel]bool // key: org + "\x00" + subject
	err    error
}

func newFakePrefs() *fakePrefs {
	return &fakePrefs{stored: map[string]map[notify.Channel]bool{}}
}

func (p *fakePrefs) set(orgID, subjectID string, ch notify.Channel, enabled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	k := feedKey(orgID, subjectID)
	if p.stored[k] == nil {
		p.stored[k] = map[notify.Channel]bool{}
	}
	p.stored[k][ch] = enabled
}

func (p *fakePrefs) ChannelPreferences(
	_ context.Context, orgID, subjectID string,
) ([]app.ChannelPreference, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return nil, p.err
	}
	var out []app.ChannelPreference
	for ch, enabled := range p.stored[feedKey(orgID, subjectID)] {
		out = append(out, app.ChannelPreference{Channel: ch, Enabled: enabled})
	}
	return out, nil
}

// applyEvents plays the preference events a command produced into the fake
// projection, exactly as the real projector's upsert does.
//
// It exists so a test can assert on the SETTINGS SCREEN after a save without a
// database, and it is deliberately the same one-row-per-event upsert: any other
// shape here would be testing a projector this repository does not have.
func (p *fakePrefs) applyEvents(events []eventsourcing.Event) {
	for _, e := range events {
		if set, ok := e.(*contract.ChannelPreferenceSet); ok {
			p.set(set.OrgID, set.SubjectID, notify.Channel(set.Channel), set.Enabled)
		}
	}
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

var testClock = fixedClock{t: time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

func newNotificationID(t *testing.T, seed string) ids.NotificationID {
	t.Helper()
	var body [16]byte
	copy(body[:], seed)
	return ids.FromUUID[ids.Notification](body)
}

func feedItem(t *testing.T, seed string, readAt time.Time) app.FeedItem {
	t.Helper()
	return app.FeedItem{
		NotificationID: newNotificationID(t, seed),
		Template:       "identity.totp_disabled",
		Class:          notify.Security,
		OccurredAt:     testClock.t,
		ReadAt:         readAt,
	}
}

// seedNotification puts one notification into BOTH the log and the projection,
// exactly as the in-app transport and its projector do.
//
// Both halves matter. Seeding only the projection would make MarkRead fail on
// its StreamExists precondition, and a test asserting a refusal would then pass
// because the stream was missing rather than because the caller does not own
// it — which is the wrong reason, and the reason would survive deleting the
// ownership check entirely.
func seedNotification(
	t *testing.T, store *memStore, feed *fakeFeed, orgID, subjectID, seed string, readAt time.Time,
) app.FeedItem {
	t.Helper()
	item := feedItem(t, seed, readAt)
	stream := eventsourcing.MustStreamID(domain.Category, item.NotificationID.String())
	if _, err := store.Append(context.Background(), stream, eventsourcing.NoStream(),
		[]eventsourcing.PendingEvent{{
			ID: eventsourcing.DeriveEventID("seed:"+seed, 0),
			Event: &contract.NotificationCreated{
				NotificationID: item.NotificationID.String(),
				SubjectID:      subjectID,
				Template:       item.Template,
				Class:          item.Class.String(),
				OrgID:          orgID,
				OccurredAt:     item.OccurredAt,
			},
			Meta: eventsourcing.Metadata{
				SchemaVersion: 1, OccurredAt: item.OccurredAt,
				OrgID: orgID, SubjectIDs: []string{subjectID},
			},
		}}); err != nil {
		t.Fatalf("seeding %s: %v", stream, err)
	}
	feed.add(orgID, subjectID, item)
	return item
}

func preferenceStream(orgID, subjectID string) eventsourcing.StreamID {
	return eventsourcing.MustStreamID(domain.Category, domain.PreferenceStreamKey(orgID, subjectID))
}

// zeroTime is "never read". Named rather than written inline, because
// `time.Time{}` in a table row reads as an omission and this one is the
// assertion.
var zeroTime = time.Time{}

// newQueries builds a Queries over the two fakes, failing the test rather than
// returning an error.
//
// Its constructor refuses a nil dependency, so a test that ignored the error
// would nil-panic several lines later at the call site rather than here, where
// the cause is visible.
func newQueries(t *testing.T, feed *fakeFeed, prefs *fakePrefs) *app.Queries {
	t.Helper()
	q, err := app.NewQueries(app.QueriesDeps{Feed: feed, Preferences: prefs})
	if err != nil {
		t.Fatalf("building Queries: %v", err)
	}
	return q
}

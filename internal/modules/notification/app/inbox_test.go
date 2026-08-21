package app_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/notification/app"
	"github.com/chronos/chronos-go/internal/modules/notification/contract"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

func newInbox(t *testing.T, feed *fakeFeed, store *memStore) *app.Inbox {
	t.Helper()
	in, err := app.NewInbox(app.InboxDeps{Feed: feed, Appends: store, Clock: testClock})
	if err != nil {
		t.Fatalf("NewInbox: %v", err)
	}
	return in
}

// A feed reader is REQUIRED, and the refusal is the whole ownership control.
//
// Without it MarkRead would accept any notification id a caller could produce,
// which is somebody else's alert dismissed from somebody else's screen.
func TestNewInboxRefusesWithoutAFeedReader(t *testing.T) {
	t.Parallel()

	if _, err := app.NewInbox(app.InboxDeps{Appends: newMemStore(t)}); err == nil {
		t.Fatal("an inbox was built with no way to establish that a notification " +
			"belongs to the caller")
	}
	if _, err := app.NewInbox(app.InboxDeps{Feed: newFakeFeed()}); err == nil {
		t.Fatal("an inbox was built with no event store")
	}
}

// ---------------------------------------------------------------------------
// THE containment test: an id is a stream name, not a capability
// ---------------------------------------------------------------------------

// A notification belonging to somebody else is refused, and refused
// IDENTICALLY to one that does not exist.
//
// This is the assertion a mutation has to get past. Deleting the OwnedBy call —
// or softening it to "skip what you do not own" — lets any caller append a read
// event to any notification's stream, which dismisses the alert on the victim's
// screen. The projector's `AND subject_id = $3` is the independent second half;
// this is the half that produces a clean refusal.
func TestMarkReadRefusesANotificationBelongingToAnotherSubject(t *testing.T) {
	t.Parallel()

	feed := newFakeFeed()
	store := newMemStore(t)
	seedNotification(t, store, feed, testOrg, testSubject, "mine", zeroTime)
	// Seeded into the LOG as well, so the refusal below can only come from the
	// ownership check: a notification that did not exist would be refused by the
	// StreamExists precondition even with that check deleted.
	theirs := seedNotification(t, store, feed, testOrg, testOther, "theirs", zeroTime)

	before := store.streamCount()
	_, err := newInbox(t, feed, store).MarkRead(context.Background(), app.MarkReadCommand{
		OrgID: testOrg, SubjectID: testSubject,
		NotificationIDs: []ids.NotificationID{theirs.NotificationID},
		IdempotencyKey:  "cmd-1",
	})
	if errs.ReasonOf(err) != errs.NotFound {
		t.Fatalf("marking another subject's notification read returned %v (reason %s), "+
			"want NOT_FOUND", err, errs.ReasonOf(err))
	}
	if len(store.appends) != 0 || store.streamCount() != before {
		t.Error("an event was appended for a notification the caller does not own")
	}
}

// Absent, invisible and not-yours must be one answer, or the endpoint becomes an
// existence oracle for any id a caller can produce.
func TestMarkReadAnswersAbsentAndForeignIdenticallly(t *testing.T) {
	t.Parallel()

	feed := newFakeFeed()
	store := newMemStore(t)
	theirs := seedNotification(t, store, feed, testOrg, testOther, "theirs", zeroTime)
	seedNotification(t, store, feed, testOrg, testSubject, "mine", zeroTime)

	inbox := newInbox(t, feed, store)
	run := func(id ids.NotificationID) error {
		_, err := inbox.MarkRead(context.Background(), app.MarkReadCommand{
			OrgID: testOrg, SubjectID: testSubject,
			NotificationIDs: []ids.NotificationID{id},
			IdempotencyKey:  "cmd-1",
		})
		return err
	}

	foreign := run(theirs.NotificationID)
	absent := run(newNotificationID(t, "never-existed"))

	if foreign == nil || absent == nil {
		t.Fatalf("both must be refused: foreign=%v absent=%v", foreign, absent)
	}
	if foreign.Error() != absent.Error() {
		t.Fatalf("a foreign notification says %q and an absent one says %q; a caller "+
			"who can tell them apart can test notification ids for existence",
			foreign, absent)
	}
}

// One unknown id fails the WHOLE batch. Skipping it would let a client discover
// which of a hundred guessed ids exist by counting how many came back marked.
func TestMarkReadRefusesTheWholeBatchWhenOneIDIsNotTheCallers(t *testing.T) {
	t.Parallel()

	feed := newFakeFeed()
	store := newMemStore(t)
	mine := seedNotification(t, store, feed, testOrg, testSubject, "mine", zeroTime)

	_, err := newInbox(t, feed, store).MarkRead(context.Background(), app.MarkReadCommand{
		OrgID: testOrg, SubjectID: testSubject,
		NotificationIDs: []ids.NotificationID{
			mine.NotificationID,
			newNotificationID(t, "guessed"),
		},
		IdempotencyKey: "cmd-1",
	})
	if errs.ReasonOf(err) != errs.NotFound {
		t.Fatalf("got %v, want NOT_FOUND", err)
	}
	if len(store.appends) != 0 {
		t.Error("the owned half of a refused batch was still marked read, which is an " +
			"existence oracle assembled out of partial successes")
	}
}

// The organization is part of the scope, not decoration: the same subject in a
// different organization must not reach these rows.
func TestMarkReadIsScopedToTheOrganization(t *testing.T) {
	t.Parallel()

	feed := newFakeFeed()
	store := newMemStore(t)
	item := seedNotification(t, store, feed, testOrg, testSubject, "mine", zeroTime)

	_, err := newInbox(t, feed, store).MarkRead(context.Background(), app.MarkReadCommand{
		OrgID: testOtherOrg, SubjectID: testSubject,
		NotificationIDs: []ids.NotificationID{item.NotificationID},
		IdempotencyKey:  "cmd-1",
	})
	if errs.ReasonOf(err) != errs.NotFound {
		t.Fatalf("a notification was reachable from another organization: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The happy path, and its atomicity
// ---------------------------------------------------------------------------

// A batch is ONE atomic append across every item's stream.
//
// Two appends would still satisfy every per-stream assertion, which is exactly
// why this counts the CALLS: a client whose call failed halfway would otherwise
// have to reconcile a partly-dismissed screen, and the obvious client-side fix
// — retry the batch — is what produces duplicates.
func TestMarkReadAppendsOnceAcrossEveryStream(t *testing.T) {
	t.Parallel()

	feed := newFakeFeed()
	store := newMemStore(t)
	first := seedNotification(t, store, feed, testOrg, testSubject, "one", zeroTime)
	second := seedNotification(t, store, feed, testOrg, testSubject, "two", zeroTime)

	got, err := newInbox(t, feed, store).MarkRead(context.Background(), app.MarkReadCommand{
		OrgID: testOrg, SubjectID: testSubject,
		NotificationIDs: []ids.NotificationID{first.NotificationID, second.NotificationID},
		IdempotencyKey:  "cmd-1",
	})
	if err != nil {
		t.Fatalf("MarkRead: %v", err)
	}
	if got.Marked != 2 {
		t.Errorf("Marked = %d, want 2", got.Marked)
	}
	if len(store.appends) != 1 {
		t.Fatalf("AppendToMany called %d times, want exactly 1 — a batch must be atomic",
			len(store.appends))
	}
	if n := len(store.appends[0]); n != 2 {
		t.Fatalf("the atomic append covered %d streams, want 2", n)
	}

	for _, item := range []ids.NotificationID{first.NotificationID, second.NotificationID} {
		stream := eventsourcing.MustStreamID("notification", item.String())
		events := store.events(t, stream)
		// The seeded Created event, then the Read this command appended.
		if len(events) != 2 {
			t.Fatalf("%s carries %d events, want 2", stream, len(events))
		}
		read, ok := events[1].(*contract.NotificationRead)
		if !ok {
			t.Fatalf("%s carries %T, want *contract.NotificationRead", stream, events[1])
		}
		// The subject on the event is what the projector matches on. Writing the
		// wrong one here would make the read invisible to the projection.
		if read.SubjectID != testSubject {
			t.Errorf("the read event names subject %q, want the caller's %q",
				read.SubjectID, testSubject)
		}
		if !read.ReadAt.Equal(testClock.t) {
			t.Errorf("ReadAt = %v, want the injected clock's %v", read.ReadAt, testClock.t)
		}
	}
}

// A notification the caller has already read is excluded from the append and not
// counted. Two devices dismissing one item is the normal case, not a conflict.
func TestMarkReadSkipsWhatIsAlreadyRead(t *testing.T) {
	t.Parallel()

	feed := newFakeFeed()
	store := newMemStore(t)
	unread := seedNotification(t, store, feed, testOrg, testSubject, "unread", zeroTime)
	already := seedNotification(t, store, feed, testOrg, testSubject, "already", testClock.t)

	got, err := newInbox(t, feed, store).MarkRead(context.Background(), app.MarkReadCommand{
		OrgID: testOrg, SubjectID: testSubject,
		NotificationIDs: []ids.NotificationID{unread.NotificationID, already.NotificationID},
		IdempotencyKey:  "cmd-1",
	})
	if err != nil {
		t.Fatalf("MarkRead: %v", err)
	}
	if got.Marked != 1 {
		t.Errorf("Marked = %d, want 1 — an item already read did not move", got.Marked)
	}
	if n := len(store.appends[0]); n != 1 {
		t.Errorf("the append covered %d streams, want 1", n)
	}
}

// Everything already read appends NOTHING and is not an error: the caller wanted
// them read, and they are read.
func TestMarkReadOnAnAlreadyReadBatchAppendsNothing(t *testing.T) {
	t.Parallel()

	feed := newFakeFeed()
	store := newMemStore(t)
	item := seedNotification(t, store, feed, testOrg, testSubject, "already", testClock.t)

	got, err := newInbox(t, feed, store).MarkRead(context.Background(), app.MarkReadCommand{
		OrgID: testOrg, SubjectID: testSubject,
		NotificationIDs: []ids.NotificationID{item.NotificationID},
		IdempotencyKey:  "cmd-1",
	})
	if err != nil {
		t.Fatalf("MarkRead: %v", err)
	}
	if got.Marked != 0 {
		t.Errorf("Marked = %d, want 0", got.Marked)
	}
	if len(store.appends) != 0 {
		t.Error("an append was made for a batch in which nothing changed")
	}
}

// ---------------------------------------------------------------------------
// Idempotency
// ---------------------------------------------------------------------------

// The same command run twice derives the SAME event ids, which is what lets the
// store collapse a redelivery instead of writing a second read event.
//
// It only holds because the ownership statement is ORDERED: an unordered result
// would index the same notification differently on the second attempt.
func TestMarkReadDerivesTheSameEventIDsOnARetry(t *testing.T) {
	t.Parallel()

	ids0 := markReadEventIDs(t, "cmd-1")
	ids1 := markReadEventIDs(t, "cmd-1")
	if !slices.Equal(ids0, ids1) {
		t.Fatalf("a retry derived %v then %v; the store cannot collapse the duplicate "+
			"and the same notification is recorded as read twice", ids0, ids1)
	}

	other := markReadEventIDs(t, "cmd-2")
	if slices.Equal(ids0, other) {
		t.Fatal("two different commands derived the same event ids")
	}
}

func markReadEventIDs(t *testing.T, key string) []string {
	t.Helper()
	feed := newFakeFeed()
	store := newMemStore(t)
	first := seedNotification(t, store, feed, testOrg, testSubject, "one", zeroTime)
	second := seedNotification(t, store, feed, testOrg, testSubject, "two", zeroTime)

	if _, err := newInbox(t, feed, store).MarkRead(context.Background(), app.MarkReadCommand{
		OrgID: testOrg, SubjectID: testSubject,
		NotificationIDs: []ids.NotificationID{first.NotificationID, second.NotificationID},
		IdempotencyKey:  key,
	}); err != nil {
		t.Fatalf("MarkRead: %v", err)
	}

	var out []string
	for _, item := range []ids.NotificationID{first.NotificationID, second.NotificationID} {
		out = append(out, store.eventIDs(eventsourcing.MustStreamID("notification", item.String()))...)
	}
	slices.Sort(out)
	return out
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

func TestMarkReadRefusals(t *testing.T) {
	t.Parallel()

	item := feedItem(t, "mine", zeroTime)

	for name, cmd := range map[string]app.MarkReadCommand{
		"no organization": {
			SubjectID:       testSubject,
			NotificationIDs: []ids.NotificationID{item.NotificationID},
			IdempotencyKey:  "cmd-1",
		},
		"no subject": {
			OrgID:           testOrg,
			NotificationIDs: []ids.NotificationID{item.NotificationID},
			IdempotencyKey:  "cmd-1",
		},
		"no ids": {
			OrgID: testOrg, SubjectID: testSubject, IdempotencyKey: "cmd-1",
		},
		"no idempotency key": {
			OrgID: testOrg, SubjectID: testSubject,
			NotificationIDs: []ids.NotificationID{item.NotificationID},
		},
		"the same id twice": {
			OrgID: testOrg, SubjectID: testSubject,
			NotificationIDs: []ids.NotificationID{item.NotificationID, item.NotificationID},
			IdempotencyKey:  "cmd-1",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			feed := newFakeFeed()
			store := newMemStore(t)
			seedNotification(t, store, feed, testOrg, testSubject, "mine", zeroTime)

			_, err := newInbox(t, feed, store).MarkRead(context.Background(), cmd)
			if errs.ReasonOf(err) != errs.ValidationFailed {
				t.Fatalf("got %v (reason %s), want VALIDATION_FAILED", err, errs.ReasonOf(err))
			}
			if len(store.appends) != 0 {
				t.Error("a refused command still appended")
			}
		})
	}
}

func TestMarkReadRefusesAnOversizedBatch(t *testing.T) {
	t.Parallel()

	feed := newFakeFeed()
	store := newMemStore(t)
	batch := make([]ids.NotificationID, 0, app.MaxMarkReadBatch+1)
	for i := range app.MaxMarkReadBatch + 1 {
		seed := string(rune('a'+i%26)) + string(rune('a'+i/26))
		batch = append(batch, seedNotification(
			t, store, feed, testOrg, testSubject, seed, zeroTime).NotificationID)
	}

	_, err := newInbox(t, feed, store).MarkRead(context.Background(), app.MarkReadCommand{
		OrgID: testOrg, SubjectID: testSubject,
		NotificationIDs: batch, IdempotencyKey: "cmd-1",
	})
	if errs.ReasonOf(err) != errs.ValidationFailed {
		t.Fatalf("a batch of %d was accepted: %v", len(batch), err)
	}
	if len(store.appends) != 0 {
		t.Error("an oversized batch still appended")
	}
}

// A store failure is reported as INTERNAL and is not mistaken for "not yours".
func TestMarkReadReportsAStoreFailureAsInternal(t *testing.T) {
	t.Parallel()

	feed := newFakeFeed()
	store := newMemStore(t)
	item := seedNotification(t, store, feed, testOrg, testSubject, "mine", zeroTime)
	store.failNext = errors.New("the log is unreachable")

	_, err := newInbox(t, feed, store).MarkRead(context.Background(), app.MarkReadCommand{
		OrgID: testOrg, SubjectID: testSubject,
		NotificationIDs: []ids.NotificationID{item.NotificationID},
		IdempotencyKey:  "cmd-1",
	})
	if errs.ReasonOf(err) != errs.Internal {
		t.Fatalf("got %v (reason %s), want INTERNAL — an outage reported as NOT_FOUND "+
			"tells a person their notification does not exist", err, errs.ReasonOf(err))
	}
}

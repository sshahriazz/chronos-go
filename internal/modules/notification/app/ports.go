// Package app holds notification's client-facing use cases and the ports they
// need.
//
// # What this module's app layer is, and what it is not
//
// notification is pure delivery: it never decides whether something happened,
// only how someone is told (notification.md). Its reactors and transports —
// mail, web push, the in-app feed — already existed and are driven by the event
// log. What did not exist is the other direction: the person reading their own
// feed, dismissing an item, enrolling a browser, and switching a channel off.
// That is this package.
//
// # Two rules the whole package is shaped by
//
//  1. NOTHING HERE WRITES A PROJECTION. `notification_feed`,
//     `push_subscription` and `notification_preference` are read models, filled
//     by projectors from the log (ADR-019). Every state change below is an
//     append to KurrentDB; the tables follow. A handler that wrote a row would
//     put state in PostgreSQL that no replay reproduces and that the next
//     rebuild deletes.
//
//  2. THE SUBJECT IS ALWAYS THE CALLER'S. Every method takes a subjectID, and
//     every one of them is called with the pseudonym the authn gate read out of
//     the session. This layer does not authorize — it answers for whatever
//     subject it is handed — so the API layer's obligation is to hand it the
//     caller's own and nothing else. The consequence for errors is honoured
//     throughout: "not yours" and "does not exist" produce the identical answer,
//     because a caller able to tell them apart can test ids for existence
//     (ADR-036).
//
// Ports are declared here, by the consumer, and satisfied in adapter/
// (CONVENTIONS §1.1).
package app

import (
	"context"
	"time"

	"github.com/chronos/chronos-go/internal/modules/notification/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/notify"
	"github.com/chronos/chronos-go/internal/platform/page"
)

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

// FeedItem is one entry in a person's in-app list.
//
// It carries the TEMPLATE and its data, never rendered text, and it carries no
// personal data at all: the recipient's name and address live in the PII vault
// and are resolved by whoever renders (ADR-002, compliance.md §1). That is what
// makes erasure the destruction of a key rather than a sweep across every
// projection that ever copied an address — and it is a property of this STRUCT,
// not of the query, because a struct with no field for an address cannot acquire
// one by a statement being edited.
type FeedItem struct {
	NotificationID ids.NotificationID

	// Template names the wording, e.g. "identity.totp_disabled".
	Template string

	// Class is what decides whether any preference could have suppressed this.
	//
	// A stored string this build does not recognise becomes the zero Class
	// rather than an error. Refusing would fail the whole page because one row
	// was written by a newer build — an empty inbox during a rolling deploy —
	// and the class drives presentation rather than any decision, so degrading
	// costs one row's styling and refusing costs the screen.
	Class notify.Class

	// Data is template input. Free of personal data by the same rule the event
	// it came from obeys.
	Data map[string]any

	// WorkspaceID is empty for an organization-level fact.
	WorkspaceID string

	// OccurredAt is the underlying event's own instant, in UTC — not when the
	// row was written. It is the first half of the sort key, which is why it is
	// here rather than merely useful: a caller cannot page this list without the
	// server having ordered by it.
	OccurredAt time.Time

	// ReadAt is zero while unread, and is the FIRST read rather than the most
	// recent: reading something twice does not move when you first saw it, and
	// email arbitration asks exactly that question (ADR-026).
	ReadAt time.Time
}

// OwnedItem is the answer to "is this notification the caller's, and has it
// already been read".
//
// Two fields rather than one, because "already read" is what makes
// MarkNotificationsRead able to report how many items it actually moved without
// asking the projection again after the append — which it could not do anyway,
// the projection being eventually consistent.
type OwnedItem struct {
	NotificationID ids.NotificationID
	AlreadyRead    bool
}

// ChannelPreference is one channel switched on or off.
type ChannelPreference = domain.Setting

// PreferenceView is the settings screen: the toggles, and what they reach.
//
// Governed and AlwaysDelivered are computed from the dispatcher's own predicate
// (domain.GovernedClasses). They are returned rather than left to the client
// because a screen showing three switches and nothing else implies they govern
// everything, and they deliberately do not: a person may switch off product mail
// and may never switch off the message telling them their second factor was
// removed (NOTIFICATIONS §3).
type PreferenceView struct {
	Channels        []ChannelPreference
	Governed        []notify.Class
	AlwaysDelivered []notify.Class
}

// MarkReadResult is what one dismissal did.
type MarkReadResult struct {
	// Marked counts the items this call moved from unread to read. Items that
	// were already read are NOT counted and are NOT an error: the caller wanted
	// them read, and they are read.
	Marked int
}

// RegisterPushResult names the subscription that now exists.
type RegisterPushResult struct {
	SubscriptionID ids.PushSubscriptionID

	// Created is false when the same browser was already registered in this
	// organization. Not an error: a permission prompt answered twice is the
	// normal case, and it collapses onto the existing subscription rather than
	// creating a second one that would push to that device twice.
	Created bool
}

// RemovePushResult names the subscription that was retired.
type RemovePushResult struct {
	SubscriptionID ids.PushSubscriptionID
}

// ---------------------------------------------------------------------------
// Read ports
// ---------------------------------------------------------------------------

// FeedReader reads a person's own in-app list.
//
// READ-ONLY, by definition rather than by discipline: the feed is a projection,
// and a port that could write it would put a second writer on a rebuildable
// table (CONVENTIONS §8).
//
// Every method takes orgID and subjectID together and neither is optional.
// orgID is the row-level-security scope; subjectID is the whole tenant boundary
// beneath it. Passing them explicitly rather than reading either from the
// context is deliberate — a caller cannot forget a parameter the compiler
// requires, and it can very easily forget to populate a context.
type FeedReader interface {
	// Feed returns at most limit items strictly after the cursor, newest first.
	// limit is one MORE than the page size: the extra row proves another page
	// follows and is trimmed by page.Of before anything reaches a caller.
	Feed(ctx context.Context, orgID, subjectID string, after page.Keyset, limit int32) ([]FeedItem, error)

	// UnreadCount is the badge.
	UnreadCount(ctx context.Context, orgID, subjectID string) (int64, error)

	// OwnedBy filters a set of notification ids down to the ones that belong to
	// this subject in this organization.
	//
	// It is the check that makes marking-read safe. A notification id is a
	// STREAM NAME, and a stream name is not a capability: without this, an id
	// obtained by any means could be used to append a read event about somebody
	// else's notification and dismiss the alert on their screen. Ids the caller
	// does not own simply do not come back, so "not yours" and "no such
	// notification" are one answer.
	OwnedBy(ctx context.Context, orgID, subjectID string, notificationIDs []string) ([]OwnedItem, error)
}

// PreferenceReader reads a person's own channel toggles.
//
// It returns ONLY the channels they explicitly switched. Absence means enabled,
// and the use case fills the gaps: a reader that invented defaults would make
// "never opened the settings screen" and "turned it back on" indistinguishable,
// and the two are different facts.
type PreferenceReader interface {
	ChannelPreferences(ctx context.Context, orgID, subjectID string) ([]ChannelPreference, error)
}

// ---------------------------------------------------------------------------
// Write ports
// ---------------------------------------------------------------------------

// Appender writes events to one stream.
//
// Narrowed to Append from eventsourcing.EventStore, so a use case holding it
// cannot read a stream it has no business reading.
type Appender interface {
	Append(
		ctx context.Context,
		stream eventsourcing.StreamID,
		expected eventsourcing.ExpectedRevision,
		events []eventsourcing.PendingEvent,
	) (eventsourcing.AppendResult, error)
}

// MultiAppender writes to several streams in ONE atomic operation.
//
// Marking a batch of notifications read touches one stream per notification, and
// this is what makes the batch all-or-nothing: verified against the running
// server, failing one stream's precondition rolls every other stream's events
// back (internal/adapter/kurrentdb/multiappend_integration_test.go). Without it
// a client whose call failed halfway would have to reconcile a partly-dismissed
// screen, and the obvious client-side fix — retry the whole batch — is exactly
// what produces duplicates.
type MultiAppender interface {
	AppendToMany(
		ctx context.Context, appends []eventsourcing.StreamAppend,
	) ([]eventsourcing.AppendResult, error)
}

// PreferenceRepository is the write side of the settings screen.
//
// Satisfied by eventsourcing.Repository[*domain.Preferences]; declared here so
// the use case can be driven without a store, and narrowed to the two methods it
// calls.
type PreferenceRepository interface {
	// Load rebuilds one person's toggles for one organization. A stream that
	// does not exist yields an empty aggregate rather than an error, which here
	// means "they have never changed anything", which reads as all-enabled.
	Load(ctx context.Context, key string) (*domain.Preferences, error)

	// Save appends what the aggregate recorded, under the expected-revision
	// precondition it was loaded at — which is what turns two concurrent saves
	// into one CONFLICT rather than a lost update.
	Save(
		ctx context.Context,
		key string,
		agg *domain.Preferences,
		idempotencyKey string,
		meta eventsourcing.Metadata,
	) (eventsourcing.AppendResult, error)
}

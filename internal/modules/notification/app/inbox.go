package app

import (
	"context"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/notification/contract"
	"github.com/chronos/chronos-go/internal/modules/notification/domain"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// MarkReadCommand dismisses a batch of the caller's own notifications.
type MarkReadCommand struct {
	// OrgID scopes the read model the ownership check runs against.
	OrgID string

	// SubjectID is the CALLER'S pseudonym, taken from the session by the API
	// layer. Nothing in the request may set it.
	SubjectID string

	// NotificationIDs are the items to mark. Bounded by the schema at 100; the
	// bound is repeated here because this layer is reachable without the schema.
	NotificationIDs []ids.NotificationID

	// IdempotencyKey derives every event id in the batch, so a retry produces
	// byte-identical ids and the store collapses it rather than appending twice.
	IdempotencyKey string
}

// Inbox is the write half of a person's own feed.
//
// One use case with one method, because there is exactly one thing a person does
// TO their feed: mark items read. Deleting is deliberately absent — a feed item
// is a projection of an event that happened, and offering deletion would offer
// to make a security alert disappear, which is the opposite of what the feed is
// for. Retention removes old items on a schedule instead.
type Inbox struct {
	feed    FeedReader
	appends MultiAppender
	clock   clock.Clock
}

// InboxDeps is what the use case needs.
type InboxDeps struct {
	// Feed answers the ownership question. Required: without it there is no way
	// to establish that a notification id belongs to the caller, and an id is
	// not a capability.
	Feed FeedReader

	// Appends writes the read events, atomically across every item's stream.
	Appends MultiAppender

	Clock clock.Clock
}

// NewInbox builds the use case, refusing a partial one.
func NewInbox(deps InboxDeps) (*Inbox, error) {
	switch {
	case deps.Feed == nil:
		// Refused rather than tolerated. Without the reader there is no
		// ownership check, and marking read would accept any notification id a
		// caller could produce — which is somebody else's alert dismissed from
		// somebody else's screen.
		return nil, fmt.Errorf("notification/app: the inbox needs a feed reader to establish " +
			"that a notification belongs to the caller")
	case deps.Appends == nil:
		return nil, fmt.Errorf("notification/app: the inbox needs an event store")
	}
	if deps.Clock == nil {
		deps.Clock = clock.System{}
	}
	return &Inbox{feed: deps.Feed, appends: deps.Appends, clock: deps.Clock}, nil
}

// MaxMarkReadBatch bounds one dismissal.
//
// One request must not become an unbounded append to the log. A hundred is a
// screenful several times over, and the client pages anyway.
const MaxMarkReadBatch = 100

// MarkRead dismisses items the caller has seen.
//
// # The ownership check, and why it is here rather than only in the projector
//
// A notification id is a STREAM NAME. Appending `notification.Read.v1` to a
// stream requires nothing but knowing the name, so without a check this call
// would let anyone dismiss anyone's alert — the in-app half of an account
// takeover covering its tracks. The check reads the CALLER'S OWN feed, which is
// scoped by row-level security to their organization and filtered to their
// subject, and refuses the whole batch if any id is not in it.
//
// The projector matches on `(notification_id, subject_id)` as well, so a forged
// event still updates nothing. The two are independent on purpose: this one
// produces a clean refusal for a caller who made a mistake, and that one holds
// for an event that never came through this path at all.
//
// # Why the whole batch is refused
//
// One unknown id fails the call rather than being skipped. Skipping would let a
// client discover which of a hundred guessed ids exist by counting how many were
// marked — an existence oracle assembled out of successes.
//
// The refusal is NOT_FOUND with no detail, and it is the same answer for an id
// that does not exist, an id in another organization, and an id belonging to
// somebody else. A caller able to tell those apart can test ids for existence
// (ADR-036).
//
// # Why already-read items are not an error
//
// Marking something already read is the caller getting what they asked for, and
// two devices dismissing the same item is the normal case, not a conflict. They
// are excluded from the append — appending would record a change that changes
// nothing, and the projector's COALESCE would ignore it anyway — and are not
// counted in Marked.
func (i *Inbox) MarkRead(ctx context.Context, cmd MarkReadCommand) (MarkReadResult, error) {
	if err := requireScope(cmd.OrgID, cmd.SubjectID, "marking notifications read"); err != nil {
		return MarkReadResult{}, err
	}
	switch {
	case len(cmd.NotificationIDs) == 0:
		return MarkReadResult{}, errs.ValidationFailedf("no notifications were named")
	case len(cmd.NotificationIDs) > MaxMarkReadBatch:
		return MarkReadResult{}, errs.ValidationFailedf(
			"%d notifications is more than the %d one request may mark",
			len(cmd.NotificationIDs), MaxMarkReadBatch)
	case cmd.IdempotencyKey == "":
		// Refused rather than substituted. A key minted here would make every
		// retry look like a new command, which is the exact failure the header
		// exists to prevent, with the added insult of looking handled.
		return MarkReadResult{}, errs.ValidationFailedf("an idempotency key is required")
	}

	wanted := make([]string, 0, len(cmd.NotificationIDs))
	seen := make(map[string]struct{}, len(cmd.NotificationIDs))
	for _, id := range cmd.NotificationIDs {
		s := id.String()
		if s == "" {
			return MarkReadResult{}, errs.ValidationFailedf("a notification id is empty")
		}
		if _, dup := seen[s]; dup {
			// Two entries for one id would produce two appends to one stream in
			// one atomic operation, which the store refuses outright. Naming it
			// here is clearer than a revision conflict from three layers down.
			return MarkReadResult{}, errs.ValidationFailedf(
				"notification %s appears twice in one request", s)
		}
		seen[s] = struct{}{}
		wanted = append(wanted, s)
	}

	owned, err := i.feed.OwnedBy(ctx, cmd.OrgID, cmd.SubjectID, wanted)
	if err != nil {
		return MarkReadResult{}, errs.Internalf("checking notification ownership").Wrap(err)
	}
	if len(owned) != len(wanted) {
		// Deliberately says nothing about WHICH, or about why. See the doc
		// comment: absent, invisible and not-yours are one answer.
		return MarkReadResult{}, errs.NotFoundf("no such notification")
	}

	now := i.clock.Now().UTC()
	appends := make([]eventsourcing.StreamAppend, 0, len(owned))
	for _, item := range owned {
		if item.AlreadyRead {
			continue
		}
		stream, err := eventsourcing.NewStreamID(domain.Category, item.NotificationID.String())
		if err != nil {
			return MarkReadResult{}, errs.Internalf("notification stream id").Wrap(err)
		}
		// The sequence number is the index within THIS command, so a retry with
		// the same key derives byte-identical ids and the store collapses the
		// duplicate rather than appending twice. That only holds because
		// FeedItemsOwnedBy is ORDERED: an unordered result would index the same
		// notification differently on a retry and defeat the whole mechanism.
		appends = append(appends, eventsourcing.StreamAppend{
			Stream: stream,
			// StreamExists, not AnyRevision: a read event on a stream with no
			// created event is a fact about nothing. The feed row the ownership
			// check just returned proves the stream exists, so this precondition
			// costs nothing and refuses the one case that would be corrupt.
			Expected: eventsourcing.StreamExists(),
			Events: []eventsourcing.PendingEvent{{
				ID: eventsourcing.DeriveEventID(cmd.IdempotencyKey, len(appends)),
				Event: &contract.NotificationRead{
					NotificationID: item.NotificationID.String(),
					SubjectID:      cmd.SubjectID,
					ReadAt:         now,
				},
				Meta: i.meta(ctx, cmd, now),
			}},
		})
	}

	if len(appends) == 0 {
		// Everything was already read. Not an error, and nothing to append.
		return MarkReadResult{Marked: 0}, nil
	}

	// ATOMIC across every stream: either the whole screenful is dismissed or
	// none of it is, so a client never has to reconcile a half-dismissed list.
	if _, err := i.appends.AppendToMany(ctx, appends); err != nil {
		return MarkReadResult{}, errs.Internalf("recording notifications as read").Wrap(err)
	}
	return MarkReadResult{Marked: len(appends)}, nil
}

func (i *Inbox) meta(ctx context.Context, cmd MarkReadCommand, now time.Time) eventsourcing.Metadata {
	trace := eventsourcing.TraceFrom(ctx)
	return eventsourcing.Metadata{
		SchemaVersion: 1,
		OccurredAt:    now,
		OrgID:         cmd.OrgID,
		SubjectIDs:    []string{cmd.SubjectID},
		// The reader IS the actor here, and saying so explicitly matters for the
		// audiences a later notification might resolve: "the person this is
		// about" and "the person who did it" are different questions that happen
		// to have one answer on this path.
		ActorID:       cmd.SubjectID,
		CorrelationID: rootCorrelation(trace.CorrelationID, cmd.IdempotencyKey),
		CausationID:   rootCausation(trace.CausationID, cmd.IdempotencyKey),
	}
}

// rootCorrelation and rootCausation fill the causation chain for a write that
// has no ambient one.
//
// eventsourcing.Repository does this for aggregate saves; this path appends
// directly, so it does it here rather than leaving both fields empty. An empty
// correlation id is not neutral — it GROUPS every such event together, so a log
// search for one request returns every request that also forgot.
//
// The fallback is the command's idempotency key, which is deterministic: a
// retried command produces the same chain rather than a second one.
func rootCorrelation(fromContext, idempotencyKey string) string {
	if fromContext != "" {
		return fromContext
	}
	return eventsourcing.DeriveEventID(idempotencyKey, 0).String()
}

func rootCausation(fromContext, idempotencyKey string) string {
	if fromContext != "" {
		return fromContext
	}
	return idempotencyKey
}

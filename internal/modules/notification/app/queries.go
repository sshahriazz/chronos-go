package app

import (
	"context"
	"fmt"
	"slices"

	"github.com/chronos/chronos-go/internal/modules/notification/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/notify"
	"github.com/chronos/chronos-go/internal/platform/page"
)

// ---------------------------------------------------------------------------
// Cursors
// ---------------------------------------------------------------------------

// feedSortColumns is the sort key, in ORDER BY order.
//
// It ENDS IN THE PRIMARY KEY. `occurred_at` alone can tie — two notifications
// raised by one command share an instant — and a sort key that can tie loses or
// repeats rows at a page boundary with no error and no log line. page.NewKeyset
// refuses a cursor whose last column is not marked unique, which is the loud
// half of the same rule.
var feedSortColumns = []string{"occurred_at", "notification_id"}

// feedQueryID names the query a feed cursor belongs to.
//
// It binds the ORGANIZATION and the SUBJECT as well as the sort, because both
// are filter values and a cursor is a position in one specific filter. A token
// minted for one person is therefore a decode failure against another, and one
// minted in one organization is a decode failure in the next — independently of
// the checks that already refuse such a request, so the two controls fail
// separately rather than together.
//
// The QueryID is hashed into the token rather than stored in it, so neither the
// pseudonym nor the organization travels in a cursor that ends up in an access
// log.
func feedQueryID(orgID, subjectID string) page.QueryID {
	return page.QueryID("notification.feed:org=" + orgID + ":subject=" + subjectID +
		":occurred_at desc,notification_id desc")
}

// feedCursor is the position of a feed row.
//
// Called on the LAST row of a trimmed page, never on the peeked one — page.Of
// enforces that ordering, and keying the peeked row would resume one row late
// and skip it.
//
// The error is folded into a zero Keyset because page.Of's signature takes no
// error, and a zero Keyset is not silently harmless: Encode refuses to write a
// token for the start position, so a failure surfaces as an error from
// ListNotifications rather than as a token that lies about where it points.
func feedCursor(f FeedItem) page.Keyset {
	k, err := page.NewKeyset(
		page.Key{Column: feedSortColumns[0], Value: f.OccurredAt.UTC()},
		page.Key{Column: feedSortColumns[1], Value: f.NotificationID.String(), Unique: true},
	)
	if err != nil {
		return page.Keyset{}
	}
	return k
}

// resumeAt decodes a request's page token for one specific query.
//
// Every failure is an ERROR and none of them is "start from the beginning". A
// client handed page one for a token it believes points into the middle of a
// list walks that list forever, and nothing in that loop looks like a failure —
// no error, no empty page, no log line (platform/page).
func resumeAt(tok page.Token, q page.QueryID) (page.Keyset, error) {
	cursor, err := page.Resume(tok, q)
	if err != nil {
		return page.Keyset{}, errs.ValidationFailedf(
			"this page token cannot be used for this list; restart from the first page").Wrap(err)
	}
	if cursor.IsStart() {
		return cursor, nil
	}
	if got := cursor.Columns(); !slices.Equal(got, feedSortColumns) {
		// A second lock on the same door: page.Decode already refuses a token
		// whose query fingerprint does not match, so a mismatched column list can
		// only arrive through a collision in a 64-bit hash. It costs a slice
		// compare and turns that from "the wrong rows, silently" into a refusal.
		return page.Keyset{}, errs.ValidationFailedf(
			"this page token names the columns %v, but this list is sorted by %v",
			got, feedSortColumns)
	}
	return cursor, nil
}

// pageSize resolves a requested page size.
//
// Over the maximum is CAPPED rather than refused, which is page.Clamp's decision:
// a client asking for too much still gets a correct answer plus a token, so
// capping costs it a round trip where refusing costs it the feature. A negative
// size is a caller bug — the wire type is unsigned — and is refused.
func pageSize(requested int) (page.Size, error) {
	size, err := page.Clamp(requested)
	if err != nil {
		return 0, errs.ValidationFailedf("page size: %v", err).Wrap(err)
	}
	return size, nil
}

// ---------------------------------------------------------------------------
// The read side
// ---------------------------------------------------------------------------

// Queries is notification's read side: the inbox, the badge and the settings
// screen.
//
// It WRITES NOTHING, and that is structural rather than conventional — every
// port it holds is a read, so there is no write for a bug to reach.
//
// THIS TYPE DOES NOT AUTHORIZE. It answers for whatever (organization, subject)
// pair it is handed; the API layer supplies the caller's own pseudonym from the
// session and never from the request. What it does guarantee is that neither
// argument can be omitted: an empty one is refused rather than filtered on,
// because a filter on an empty subject returns an empty list, which looks
// exactly like an account with no notifications.
type Queries struct {
	feed  FeedReader
	prefs PreferenceReader
}

// QueriesDeps is what the read side needs.
type QueriesDeps struct {
	Feed        FeedReader
	Preferences PreferenceReader
}

// NewQueries builds the read side, refusing a partial one.
//
// A nil port would panic on the first request to the screen that uses it, after
// the composition root has reported a healthy start — the failure mode
// compile-time wiring exists to avoid.
func NewQueries(deps QueriesDeps) (*Queries, error) {
	switch {
	case deps.Feed == nil:
		return nil, fmt.Errorf("notification/app: the read side needs a feed reader")
	case deps.Preferences == nil:
		return nil, fmt.Errorf("notification/app: the read side needs a preference reader")
	}
	return &Queries{feed: deps.Feed, prefs: deps.Preferences}, nil
}

// ListNotifications returns one page of a person's own feed, newest first.
//
// Keyset paginated over (occurred_at DESC, notification_id DESC). Offsets are
// banned: a notification arriving between two requests shifts every later OFFSET
// page, so somebody walking their inbox would silently miss items — and on this
// screen a missed item is a security alert nobody read.
func (q *Queries) ListNotifications(
	ctx context.Context, orgID, subjectID string, pageToken page.Token, pageSizeRequested int,
) (page.Page[FeedItem], error) {
	if err := requireScope(orgID, subjectID, "listing notifications"); err != nil {
		return page.Page[FeedItem]{}, err
	}
	size, err := pageSize(pageSizeRequested)
	if err != nil {
		return page.Page[FeedItem]{}, err
	}
	queryID := feedQueryID(orgID, subjectID)
	cursor, err := resumeAt(pageToken, queryID)
	if err != nil {
		return page.Page[FeedItem]{}, err
	}

	// Limit(), not size: one extra row is asked for and page.Of trims it. That
	// extra row is how "is there another page" is answered without a COUNT(*)
	// whose answer was true a moment ago.
	rows, err := q.feed.Feed(ctx, orgID, subjectID, cursor, size.Limit())
	if err != nil {
		return page.Page[FeedItem]{}, errs.Internalf("listing notifications").Wrap(err)
	}

	out, err := page.Of(rows, size, queryID, feedCursor)
	if err != nil {
		return page.Page[FeedItem]{}, errs.Internalf("building a notification page token").Wrap(err)
	}
	return out, nil
}

// UnreadCount is the badge for one organization.
func (q *Queries) UnreadCount(ctx context.Context, orgID, subjectID string) (int64, error) {
	if err := requireScope(orgID, subjectID, "counting unread notifications"); err != nil {
		return 0, err
	}
	n, err := q.feed.UnreadCount(ctx, orgID, subjectID)
	if err != nil {
		return 0, errs.Internalf("counting unread notifications").Wrap(err)
	}
	return n, nil
}

// GetPreferences returns a person's own channel toggles, and what those toggles
// reach.
//
// ABSENCE MEANS ENABLED. The reader returns only the channels this person
// actually switched; everything else is filled in as enabled here, so somebody
// who has never opened the settings screen sees three switches that are all on
// and receives everything — and a failure to write a default row can never
// silence anyone.
//
// An unknown channel in the table is IGNORED rather than reported. It can only
// come from a build that knew a channel this one does not, and rendering an
// unnamed switch on a settings screen is worse than omitting it. It is not a
// silent security gap: the dispatcher looks preferences up by channel, so a row
// this build cannot name is a row this build never consults either.
func (q *Queries) GetPreferences(
	ctx context.Context, orgID, subjectID string,
) (PreferenceView, error) {
	if err := requireScope(orgID, subjectID, "reading notification preferences"); err != nil {
		return PreferenceView{}, err
	}
	stored, err := q.prefs.ChannelPreferences(ctx, orgID, subjectID)
	if err != nil {
		return PreferenceView{}, errs.Internalf("reading notification preferences").Wrap(err)
	}

	explicit := make(map[notify.Channel]bool, len(stored))
	for _, s := range stored {
		if domain.IsGovernable(s.Channel) {
			explicit[s.Channel] = s.Enabled
		}
	}

	channels := make([]ChannelPreference, 0, len(domain.Governable()))
	for _, ch := range domain.Governable() {
		enabled, ok := explicit[ch]
		if !ok {
			enabled = true
		}
		channels = append(channels, ChannelPreference{Channel: ch, Enabled: enabled})
	}

	return PreferenceView{
		Channels: channels,
		// Both lists are computed from the same predicate the dispatcher applies
		// at delivery time, never from a list written out here. See
		// domain.GovernedClasses.
		Governed:        domain.GovernedClasses(),
		AlwaysDelivered: domain.AlwaysDeliveredClasses(),
	}, nil
}

// requireScope refuses a read that names no organization or no subject.
//
// Refused rather than answered with an empty list, because both would filter on
// an empty string and return nothing — and nothing is indistinguishable from a
// person who has no notifications. An empty subject here means the authenticated
// principal was not propagated, which is a bug that must look like one.
func requireScope(orgID, subjectID, what string) error {
	switch {
	case orgID == "":
		return errs.ValidationFailedf("%s needs an organization", what)
	case subjectID == "":
		return errs.ValidationFailedf("%s needs a subject", what)
	}
	return nil
}

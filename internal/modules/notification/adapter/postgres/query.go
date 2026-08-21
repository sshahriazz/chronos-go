package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	notificationdb "github.com/chronos/chronos-go/gen/sqlc/notification"
	"github.com/chronos/chronos-go/internal/modules/notification/app"
	jsoncodec "github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/notify"
	"github.com/chronos/chronos-go/internal/platform/page"
	"github.com/jackc/pgx/v5/pgtype"
)

// ReadModel answers the questions a person asks about their OWN notifications:
// what is in my inbox, how many are unread, is this item mine, and what have I
// switched off.
//
// It NEVER writes. Not "does not currently write" — every statement it issues is
// a SELECT, which is what keeps `notification_feed`, `push_subscription` and
// `notification_preference` reconstructable by replaying the log from position
// zero (ADR-019).
//
// # The transaction, and where the tenant scope comes from
//
// Every read runs inside `db.TX.InTenantTx`, which opens a transaction and
// applies `SET LOCAL app.org_id` before any statement runs (ADR-011). There is
// no bypass: RLS then restricts every one of these tables to that organization,
// under a role that is neither owner nor superuser.
//
// The scope is built HERE, from the organization the use case passed in, because
// the org-context gate that will eventually put it in the context does not exist
// yet — `organization` is unbuilt, and cmd/api leaves gate 1 deliberately nil.
// Building it here rather than in the handler keeps the rule "a handler never
// implements a gate" intact, and it is a strictly smaller claim than the gate
// will make: the gate establishes that the caller BELONGS to the organization,
// while this only establishes that every statement is scoped to it. The
// membership half is carried in the meantime by the subject filter in each
// statement — a caller naming an organization they have nothing to do with gets
// their own rows in it, of which there are none.
//
// When gate 1 lands, this constructor takes the tenant from the context instead
// and the org_id request field is deprecated; nothing else here changes.
type ReadModel struct{ tx db.TX }

// NewReadModel builds the adapter.
func NewReadModel(tx db.TX) (*ReadModel, error) {
	if tx == nil {
		return nil, errors.New("notification/postgres: a tenant transaction is required; " +
			"these tables are RLS-protected and an unscoped read returns nothing at all")
	}
	return &ReadModel{tx: tx}, nil
}

var (
	_ app.FeedReader       = (*ReadModel)(nil)
	_ app.PreferenceReader = (*ReadModel)(nil)
)

// inOrg runs fn inside a transaction scoped to one organization.
func (r *ReadModel) inOrg(
	ctx context.Context, orgID string, fn func(context.Context, db.Querier) error,
) error {
	if orgID == "" {
		// Refused rather than run unscoped. `SET LOCAL app.org_id = ''` matches
		// no policy, so every statement would return nothing — an empty inbox
		// that looks exactly like a person with no notifications.
		return errors.New("notification/postgres: a read needs an organization scope")
	}
	return r.tx.InTenantTx(db.WithTenant(ctx, db.Tenant{OrgID: orgID}), fn)
}

// beforeEverything is the cursor value for the FIRST page.
//
// ListFeedPage compares `(occurred_at, notification_id) < ($3, $4)`, so the
// first page needs a position strictly above every row rather than a second
// statement without the comparison. `timestamptz 'infinity'` is exactly that:
// every stored timestamp is finite, so the row comparison short-circuits on the
// first component and the tiebreaker is never consulted — which is why the
// second argument can be empty.
//
// The alternative — `($3 IS NULL OR (…) < (…))` — was rejected because the OR
// makes the predicate non-sargable, and the index that exists to serve this
// exact ORDER BY would stop being used on the one page every client asks for.
var beforeEverything = pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true}

// Feed returns one page of a subject's own in-app list, newest first.
func (r *ReadModel) Feed(
	ctx context.Context, orgID, subjectID string, after page.Keyset, limit int32,
) ([]app.FeedItem, error) {
	if subjectID == "" {
		return nil, errors.New("notification/postgres: listing a feed needs a subject")
	}
	if limit <= 0 {
		// Refused rather than passed through. `LIMIT 0` returns nothing, and an
		// empty page reads as "your inbox is empty" — a caller that miscounted
		// its page size would be told the list had ended.
		return nil, fmt.Errorf("notification/postgres: a feed page limit of %d returns nothing", limit)
	}

	occurredBefore, idBefore, err := feedCursorArgs(after)
	if err != nil {
		return nil, err
	}

	var out []app.FeedItem
	err = r.inOrg(ctx, orgID, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Query(ctx, notificationdb.ListFeedPage,
			orgID, subjectID, occurredBefore, idBefore, limit)
		if err != nil {
			return fmt.Errorf("notification/postgres: listing a feed: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var (
				notificationID string
				subject        string
				org            string
				workspace      string
				template       string
				class          string
				data           []byte
				occurredAt     pgtype.Timestamptz
				readAt         pgtype.Timestamptz
			)
			if err := rows.Scan(&notificationID, &subject, &org, &workspace,
				&template, &class, &data, &occurredAt, &readAt); err != nil {
				return fmt.Errorf("notification/postgres: reading a feed item: %w", err)
			}
			id, err := ids.Parse[ids.Notification](notificationID)
			if err != nil {
				// Refused, not skipped. Skipping would drop an item from the
				// list somebody dismisses from, and the item they cannot see is
				// the item they cannot mark read.
				return fmt.Errorf("notification/postgres: notification id %q is unreadable: %w",
					notificationID, err)
			}
			out = append(out, app.FeedItem{
				NotificationID: id,
				Template:       template,
				Class:          parseClass(class),
				Data:           decodeData(data),
				WorkspaceID:    workspace,
				OccurredAt:     utc(occurredAt),
				ReadAt:         utc(readAt),
			})
		}
		if err := rows.Err(); err != nil {
			// A truncated page would end the list early and, worse, would end it
			// with a next token pointing past rows the caller never saw.
			return fmt.Errorf("notification/postgres: reading a feed page: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UnreadCount is the badge.
func (r *ReadModel) UnreadCount(ctx context.Context, orgID, subjectID string) (int64, error) {
	if subjectID == "" {
		return 0, errors.New("notification/postgres: counting unread needs a subject")
	}
	var n int64
	err := r.inOrg(ctx, orgID, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx, notificationdb.CountUnread, orgID, subjectID).Scan(&n)
	})
	if err != nil {
		return 0, fmt.Errorf("notification/postgres: counting unread notifications: %w", err)
	}
	return n, nil
}

// OwnedBy filters notification ids down to the ones belonging to this subject in
// this organization.
//
// Ids the caller does not own are simply absent from the result. There is no
// error and no distinction between "not yours", "another organization" and "no
// such notification": the statement's WHERE clause makes all three the same
// answer, which is what stops the check being an existence oracle (ADR-036).
func (r *ReadModel) OwnedBy(
	ctx context.Context, orgID, subjectID string, notificationIDs []string,
) ([]app.OwnedItem, error) {
	if subjectID == "" {
		return nil, errors.New("notification/postgres: an ownership check needs a subject")
	}
	if len(notificationIDs) == 0 {
		return nil, nil
	}

	var out []app.OwnedItem
	err := r.inOrg(ctx, orgID, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Query(ctx, notificationdb.FeedItemsOwnedBy, orgID, subjectID, notificationIDs)
		if err != nil {
			return fmt.Errorf("notification/postgres: checking notification ownership: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var (
				notificationID string
				alreadyRead    bool
			)
			if err := rows.Scan(&notificationID, &alreadyRead); err != nil {
				return fmt.Errorf("notification/postgres: reading an ownership row: %w", err)
			}
			id, err := ids.Parse[ids.Notification](notificationID)
			if err != nil {
				return fmt.Errorf("notification/postgres: notification id %q is unreadable: %w",
					notificationID, err)
			}
			out = append(out, app.OwnedItem{NotificationID: id, AlreadyRead: alreadyRead})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ChannelPreferences returns only the channels this person explicitly switched.
//
// The gaps are NOT filled here. Absence means enabled, and inventing a default
// row in the adapter would make "never opened the settings screen" and "turned
// it back on" indistinguishable to everything above — two different facts, and
// only one of them is a decision somebody made.
func (r *ReadModel) ChannelPreferences(
	ctx context.Context, orgID, subjectID string,
) ([]app.ChannelPreference, error) {
	if subjectID == "" {
		return nil, errors.New("notification/postgres: reading preferences needs a subject")
	}

	var out []app.ChannelPreference
	err := r.inOrg(ctx, orgID, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Query(ctx, notificationdb.ListChannelPreferences, orgID, subjectID)
		if err != nil {
			return fmt.Errorf("notification/postgres: reading preferences: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var (
				channel   string
				enabled   bool
				updatedAt pgtype.Timestamptz
			)
			if err := rows.Scan(&channel, &enabled, &updatedAt); err != nil {
				return fmt.Errorf("notification/postgres: reading a preference: %w", err)
			}
			out = append(out, app.ChannelPreference{
				Channel: notify.Channel(channel), Enabled: enabled,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// feedCursorArgs turns a keyset into the two bind values ListFeedPage expects.
func feedCursorArgs(after page.Keyset) (pgtype.Timestamptz, string, error) {
	if after.IsStart() {
		return beforeEverything, "", nil
	}
	args := after.Args()
	if len(args) != 2 {
		return pgtype.Timestamptz{}, "", fmt.Errorf(
			"notification/postgres: a feed cursor has %d columns, want 2", len(args))
	}
	occurredAt, ok := args[0].(time.Time)
	if !ok {
		return pgtype.Timestamptz{}, "", fmt.Errorf(
			"notification/postgres: a feed cursor's occurred_at is %T, want a timestamp", args[0])
	}
	notificationID, ok := args[1].(string)
	if !ok {
		return pgtype.Timestamptz{}, "", fmt.Errorf(
			"notification/postgres: a feed cursor's notification_id is %T, want a string", args[1])
	}
	return pgtype.Timestamptz{Time: occurredAt.UTC(), Valid: true}, notificationID, nil
}

// parseClass maps the stored label back to the class.
//
// An unrecognised label becomes the zero Class rather than an error, and the
// choice is deliberate: the stored string comes from notify.Class.String(), so
// an unknown one means a newer build wrote it. Refusing would fail the whole
// page — an empty inbox during a rolling deploy — and the class drives
// presentation rather than any decision this system takes, so degrading costs
// one row's styling.
//
// It is not a route around the class rule. Suppression is decided at DELIVERY
// time from the class on the notification, never from this string, so a row that
// reads as unspecified here cannot make a security alert suppressible.
func parseClass(s string) notify.Class {
	for _, c := range []notify.Class{
		notify.Security, notify.Transactional, notify.Activity, notify.Product, notify.Operator,
	} {
		if c.String() == s {
			return c
		}
	}
	return 0
}

// decodeData turns the stored jsonb into template input.
//
// A decode failure yields an EMPTY map rather than an error. The column is
// `jsonb NOT NULL DEFAULT '{}'`, so unparseable content is not reachable through
// any writer this system has; if it ever becomes reachable, an item rendered
// with no placeholders is a better outcome than an inbox that will not load.
func decodeData(raw []byte) map[string]any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	out, err := jsoncodec.Unmarshal[map[string]any](raw)
	if err != nil || out == nil {
		return map[string]any{}
	}
	return out
}

// utc renders a nullable timestamp. NULL becomes the zero time, which every
// caller reads as "never".
func utc(t pgtype.Timestamptz) time.Time {
	if !t.Valid {
		return time.Time{}
	}
	return t.Time.UTC()
}

-- Queries for the notification feed.
--
-- The :exec queries here are QUEUED by the feed projector into a single
-- pipelined round trip rather than executed one at a time, so it uses the
-- exported constants rather than the generated methods. Authoring them here
-- still buys what sqlc is for: the SQL is checked against the real schema, so a
-- renamed column fails at generate time instead of at 3am.

-- name: UpsertFeedItem :exec
-- Upsert, not insert: a projector is replayed on restart and on rebuild, so the
-- same event WILL arrive twice. read_at is deliberately untouched — a replay
-- must not mark a read notification unread again.
INSERT INTO notification_feed
    (notification_id, subject_id, org_id, workspace_id, template, class, data, occurred_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (notification_id) DO UPDATE SET
    template    = EXCLUDED.template,
    class       = EXCLUDED.class,
    data        = EXCLUDED.data,
    occurred_at = EXCLUDED.occurred_at;

-- name: MarkFeedItemRead :exec
-- COALESCE keeps the FIRST read time: reading something twice does not move
-- when you first saw it, and arbitration asks exactly that (ADR-026).
--
-- Matched on the SUBJECT as well as the id, and that second predicate is a
-- containment control rather than a filter. The id names the stream a
-- notification.Read.v1 event was appended to, and a stream name is not a
-- capability: an event carrying somebody else's notification id would otherwise
-- dismiss the alert on THEIR screen. The API refuses such an id before it
-- appends, and this refuses it again after — the two fail independently, and
-- only this one survives a forged or replayed event.
UPDATE notification_feed
SET read_at = COALESCE(read_at, $2)
WHERE notification_id = $1 AND subject_id = $3;

-- name: TruncateFeed :exec
-- TRUNCATE, not DELETE: a rebuild runs in an unscoped system transaction where
-- RLS hides every row, so DELETE would remove none (ADR-019).
TRUNCATE TABLE notification_feed;

-- name: WasReadWithin :one
-- Arbitration: was this seen in-app already? A missing row means unread, which
-- is the safe answer — it sends the email rather than suppressing it.
SELECT read_at IS NOT NULL AND read_at > now() - sqlc.arg(read_window)::interval
FROM notification_feed
WHERE subject_id = $1 AND notification_id = $2;

-- name: ListFeed :many
-- The in-app list, newest first. Leading with org_id matches the RLS predicate,
-- which is in every query whether or not it was written there.
SELECT notification_id, subject_id, org_id, workspace_id, template, class,
       data, occurred_at, read_at
FROM notification_feed
WHERE org_id = sqlc.arg(org_id) AND subject_id = sqlc.arg(subject_id)
ORDER BY occurred_at DESC, notification_id DESC
LIMIT sqlc.arg(page_size);

-- name: CountUnread :one
SELECT count(*) FROM notification_feed
WHERE org_id = sqlc.arg(org_id) AND subject_id = sqlc.arg(subject_id) AND read_at IS NULL;

-- name: ListFeedPage :many
-- One page of the in-app list, newest first.
--
-- Keyset pagination over (occurred_at, notification_id), ending in the PRIMARY
-- KEY so the tiebreak column is unique: an ordering that can tie loses or
-- repeats rows at a page boundary, silently (platform/page).
--
-- The comparison is unconditional rather than `$3 IS NULL OR (…)`. The OR makes
-- the predicate non-sargable and the index that exists to serve this exact
-- ORDER BY would stop being used on the one page every client asks for; the
-- first page passes 'infinity'::timestamptz instead, which is strictly above
-- every stored row.
--
-- Leading with org_id matches the RLS predicate and the composite index, and
-- subject_id is the whole tenant scope beneath it: the caller may read their own
-- feed and nobody else's.
SELECT notification_id, subject_id, org_id, workspace_id, template, class,
       data, occurred_at, read_at
FROM notification_feed
WHERE org_id = $1
  AND subject_id = $2
  AND (occurred_at, notification_id) < ($3::timestamptz, $4::text)
ORDER BY occurred_at DESC, notification_id DESC
LIMIT $5;

-- name: FeedItemsOwnedBy :many
-- Of these notification ids, which belong to this subject in this organization.
--
-- Asked before MarkNotificationsRead appends anything. A notification id is a
-- stream name, and a stream name is not a capability — without this an id
-- obtained by any means could be used to append a read event about somebody
-- else's notification. Ids the caller does not own simply do not come back, so
-- "not yours" and "no such notification" are one answer.
--
-- ORDERED, and the ordering is load-bearing rather than cosmetic: the caller
-- derives one event id per row from the row's INDEX in this result, so an
-- unordered result would give a retried command different ids from the first
-- attempt and the store's duplicate collapse would not fire.
SELECT notification_id, read_at IS NOT NULL AS already_read
FROM notification_feed
WHERE org_id = $1
  AND subject_id = $2
  AND notification_id = ANY($3::text[])
ORDER BY notification_id;

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
UPDATE notification_feed
SET read_at = COALESCE(read_at, $2)
WHERE notification_id = $1;

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

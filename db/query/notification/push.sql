-- Queries for push subscriptions and per-user channel preferences.

-- name: UpsertPushSubscription :exec
-- Conflict on (org_id, endpoint), not the id: the same browser re-subscribing
-- produces the same endpoint with a fresh id, and inserting both would push to
-- that device twice for every notification. Re-subscribing also revives an
-- expired row — the person granted permission again.
--
-- Scoped to the ORGANIZATION because one person belongs to several, and their
-- browser has one endpoint across all of them. Conflicting globally made the
-- upsert read a row RLS hides, so the second organization's subscribe failed
-- outright and that person received no push there (migration 00006).
INSERT INTO push_subscription
    (subscription_id, subject_id, org_id, endpoint, p256dh, auth, user_agent, subscribed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (org_id, endpoint) DO UPDATE SET
    subscription_id = EXCLUDED.subscription_id,
    p256dh          = EXCLUDED.p256dh,
    auth            = EXCLUDED.auth,
    user_agent      = EXCLUDED.user_agent,
    subscribed_at   = EXCLUDED.subscribed_at,
    expired_at      = NULL,
    expired_reason  = NULL;

-- name: ExpirePushSubscription :exec
-- Marked expired, not deleted: "why did I stop getting push?" is a real support
-- question and a deleted row cannot answer it.
UPDATE push_subscription
SET expired_at     = COALESCE(expired_at, $2),
    expired_reason = COALESCE(expired_reason, $3)
WHERE subscription_id = $1;

-- name: TruncatePushSubscriptions :exec
TRUNCATE TABLE push_subscription;

-- name: ListActivePushSubscriptions :many
SELECT subscription_id, subject_id, endpoint, p256dh, auth
FROM push_subscription
WHERE subject_id = $1 AND expired_at IS NULL;

-- name: IsChannelEnabled :one
-- ABSENCE MEANS ENABLED: someone who has never opened the settings screen still
-- receives their notifications, so a missing row must not read as "off".
SELECT enabled FROM notification_preference
WHERE subject_id = $1 AND channel = $2;

-- name: ListChannelPreferences :many
-- Every channel this person has explicitly switched, for one organization.
--
-- Only rows they actually changed come back. ABSENCE MEANS ENABLED, so the
-- caller fills the gaps rather than this statement inventing defaults: a
-- statement that emitted a default would make "never opened the settings
-- screen" and "turned it back on" indistinguishable in the read model.
SELECT channel, enabled, updated_at
FROM notification_preference
WHERE org_id = $1 AND subject_id = $2
ORDER BY channel;

-- name: UpsertChannelPreference :exec
-- Upsert, not insert: a projector is replayed on restart and on rebuild, so the
-- same event WILL arrive twice.
--
-- LAST WRITER WINS, and the ordering is the STREAM's rather than the clock's.
-- A person's preference changes all live on one stream, so two settings screens
-- saving at once are already totally ordered by the time this runs — which is
-- what stops a torn result where one channel takes the first save and another
-- takes the second.
INSERT INTO notification_preference (subject_id, org_id, channel, enabled, updated_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (org_id, subject_id, channel) DO UPDATE SET
    enabled    = EXCLUDED.enabled,
    updated_at = EXCLUDED.updated_at;

-- name: TruncateChannelPreferences :exec
-- TRUNCATE, not DELETE: a rebuild runs in an unscoped system transaction where
-- RLS hides every row, so DELETE would remove none (ADR-019).
TRUNCATE TABLE notification_preference;

-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- notification_feed — the in-app list and unread counts
-- ---------------------------------------------------------------------------
-- A PROJECTION (notification.md §11). Nothing writes it except its projector,
-- and it is reconstructable by replaying notification.Created.v1 from position
-- zero — which is what lets the feed's shape change without a data migration.
--
-- It stores the TEMPLATE and its data, never rendered text. Wording is resolved
-- at read time in the reader's locale and timezone, so changing a translation
-- changes history's presentation without rewriting history (ADR-008, ADR-029).
--
-- No personal-data column, by rule: subject_id is a pseudonym and the vault
-- resolves it at read time. That is what makes erasure a key deletion rather
-- than a migration (compliance.md §1).
CREATE TABLE notification_feed (
    notification_id text        PRIMARY KEY,
    subject_id      text        NOT NULL,
    org_id          text        NOT NULL,
    workspace_id    text        NOT NULL DEFAULT '',
    template        text        NOT NULL,
    class           text        NOT NULL,
    data            jsonb       NOT NULL DEFAULT '{}'::jsonb,
    occurred_at     timestamptz NOT NULL,
    read_at         timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- The feed query is "this subject's notifications, newest first", and the
-- unread badge is the same predicate with read_at IS NULL. Leading with org_id
-- matches the RLS predicate, which is in every query whether or not it was
-- written there (ADR-013).
CREATE INDEX notification_feed_subject_idx
    ON notification_feed (org_id, subject_id, occurred_at DESC, notification_id);

-- A partial index: unread rows are a small and shrinking fraction, and the
-- badge count is read on every page load.
CREATE INDEX notification_feed_unread_idx
    ON notification_feed (org_id, subject_id)
    WHERE read_at IS NULL;

ALTER TABLE notification_feed ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_feed FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON notification_feed
    USING (org_id = current_setting('app.org_id', true))
    WITH CHECK (org_id = current_setting('app.org_id', true));

-- TRUNCATE, because a rebuild empties the table from an UNSCOPED system
-- transaction, which under RLS can see no rows and would DELETE none (ADR-019).
GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON notification_feed TO chronos_app;

-- ---------------------------------------------------------------------------
-- push_subscription — active browser endpoints
-- ---------------------------------------------------------------------------
-- One row per browser profile per device, not per user: one person commonly has
-- several (notification.md §4).
--
-- The keys are transport credentials, not personal data, but they identify a
-- device and are treated as sensitive: they are never logged, and the endpoint
-- is redacted before it reaches a log line.
CREATE TABLE push_subscription (
    subscription_id text        PRIMARY KEY,
    subject_id      text        NOT NULL,
    org_id          text        NOT NULL,
    endpoint        text        NOT NULL,
    p256dh          text        NOT NULL,
    auth            text        NOT NULL,
    user_agent      text        NOT NULL DEFAULT '',
    subscribed_at   timestamptz NOT NULL,
    expired_at      timestamptz,
    expired_reason  text
);

-- Sends read "this subject's live endpoints"; expired rows are kept for
-- support questions rather than deleted, so the index excludes them.
CREATE INDEX push_subscription_active_idx
    ON push_subscription (org_id, subject_id)
    WHERE expired_at IS NULL;

-- The same browser re-subscribing produces the same endpoint. Without this a
-- device accumulates a row per permission prompt and receives duplicates.
CREATE UNIQUE INDEX push_subscription_endpoint_idx
    ON push_subscription (endpoint);

ALTER TABLE push_subscription ENABLE ROW LEVEL SECURITY;
ALTER TABLE push_subscription FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON push_subscription
    USING (org_id = current_setting('app.org_id', true))
    WITH CHECK (org_id = current_setting('app.org_id', true));

GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON push_subscription TO chronos_app;

-- ---------------------------------------------------------------------------
-- notification_preference — each person's own channel toggles
-- ---------------------------------------------------------------------------
-- Every user controls their own three channels. Nobody else can set them: not
-- an administrator, not the operator.
--
-- ABSENCE MEANS ENABLED. A person who has never opened the settings screen
-- still receives their notifications, and a row appears only when they turn
-- something off — so a failure to write a default cannot silence anyone.
--
-- These toggles reach Activity and Product notifications only. Security and
-- Transactional ignore them entirely, enforced in the dispatcher before this
-- table is ever consulted: someone who takes over an account must not be able
-- to switch off the alert that reveals the takeover (notification.md §6).
CREATE TABLE notification_preference (
    subject_id text NOT NULL,
    org_id     text NOT NULL,
    channel    text NOT NULL,
    enabled    boolean NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, subject_id, channel)
);

ALTER TABLE notification_preference ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_preference FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON notification_preference
    USING (org_id = current_setting('app.org_id', true))
    WITH CHECK (org_id = current_setting('app.org_id', true));

GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON notification_preference TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS notification_preference;
DROP TABLE IF EXISTS push_subscription;
DROP TABLE IF EXISTS notification_feed;
-- +goose StatementEnd

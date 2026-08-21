-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- profile_view — what a person has configured about how they are presented
-- ---------------------------------------------------------------------------
-- A PROJECTION, built from `profile.ProfileUpdated.v1` and nothing else. It is
-- reconstructable by replaying from position zero, which is what lets its shape
-- change without a data migration (ADR-019).
--
-- # It holds no personal data, and the omissions are the design
--
-- The display name, the locale and the timezone are personal data
-- (internal/platform/pii declares all three, and says why locale and timezone
-- count even though they read as preferences). They live in the PII vault and
-- ONLY there, resolved at read time — which is also where
-- internal/platform/notify resolves them from when it renders mail, so there is
-- exactly one answer to "what is this person's timezone" rather than two that
-- can drift.
--
-- What is stored instead is the FACT that each is set. A boolean answers "has
-- this person configured a locale?" for support and for the profile screen
-- without decrypting anything, and it survives erasure honestly: the key is
-- destroyed, the value becomes unreadable, and this row still records that
-- something was once configured without saying what.
--
-- That is what keeps erasure a key deletion instead of a migration across every
-- table that ever touched a user (ADR-002, compliance.md §1). The one
-- deliberate cleartext exception in this system remains the username, and it
-- stays in identity where ADR-051 put it — it is deliberately NOT duplicated
-- here.
--
-- # The avatar is a reference, never bytes
--
-- `avatar_object_key` names an object in the blob store. It is opaque: a
-- per-subject digest prefix and a random name, with no business meaning in it
-- (ADR-013). No image is stored in this database, in an event, or in a request
-- body. The content type and size are what the object store REPORTED when the
-- upload was confirmed, not what the uploader claimed.
--
-- # No org_id, and no row-level security
--
-- A profile is global to a person, exactly as their account is: one display
-- name, one avatar, one timezone, whatever organizations they belong to. It is
-- therefore not tenant-scoped, and it carries no `org_id` for RLS to key on —
-- the same shape, and the same reasoning, as identity's `user_view` (00008).
-- Access is by pseudonym: every statement against this table is filtered by the
-- caller's own `subject_id`, which the authn gate supplies and no request can
-- name.
CREATE TABLE profile_view (
    subject_id text PRIMARY KEY,

    -- Whether each vault-held field currently holds a value. Not the value.
    display_name_set boolean NOT NULL DEFAULT false,
    locale_set       boolean NOT NULL DEFAULT false,
    timezone_set     boolean NOT NULL DEFAULT false,

    -- The avatar reference. Empty means the person has none, which is also the
    -- state a removal leaves behind.
    avatar_object_key   text   NOT NULL DEFAULT '',
    avatar_content_type text   NOT NULL DEFAULT '',
    avatar_size_bytes   bigint NOT NULL DEFAULT 0,

    updated_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),

    -- An avatar is all three columns or none of them. A key with no content
    -- type produces a download URL for an object nothing can describe, and a
    -- size of zero with a key set means the projection recorded a confirmation
    -- that could not have passed verification.
    CONSTRAINT profile_view_avatar_complete CHECK (
        (avatar_object_key = '' AND avatar_content_type = '' AND avatar_size_bytes = 0)
        OR (avatar_object_key <> '' AND avatar_content_type <> '' AND avatar_size_bytes > 0)
    )
);

COMMENT ON TABLE profile_view IS
    'Profile projection. No personal data: pseudonym, set-flags and an opaque avatar object key only.';

-- Answers "which objects are still referenced by a live profile", which is the
-- question a sweep of abandoned uploads has to ask before deleting anything.
-- Partial, because the overwhelming majority of rows have no avatar.
CREATE INDEX profile_view_avatar_idx
    ON profile_view (avatar_object_key)
    WHERE avatar_object_key <> '';

-- TRUNCATE, because a rebuild empties the table from an UNSCOPED system
-- transaction. This table has no row security, so DELETE would in fact work
-- here — but `Projection.Reset` is one TRUNCATE for every projection in the
-- system, and granting it is what stops this one being the exception that
-- fails at 3am during a rebuild (ADR-019, migration 00012).
GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON profile_view TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS profile_view;
-- +goose StatementEnd

-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- processing_restriction_view — Article 18, as a lookup
-- ---------------------------------------------------------------------------
-- One row per RESTRICTED subject. A row's presence is the restriction; lifting
-- deletes it.
--
-- # Why presence rather than a boolean column
--
-- This table is read on the notification path, once per tenant-facing send, to
-- answer "may this person be contacted". The overwhelmingly common answer is
-- "yes" — almost nobody is under restriction — and a table holding only the
-- exceptions makes that answer a miss on a small index rather than a hit on a
-- row per account.
--
-- It also makes the failure direction right. A row that should have been deleted
-- keeps somebody restricted, which is over-restriction: they are not contacted
-- when they could be, and they will say so. A boolean that failed to be set
-- would under-restrict silently, which nobody notices.
--
-- # No org_id, and no row security
--
-- A restriction is a fact about a PERSON, not about their membership of any
-- organization — the same shape as `user_view` and `profile_view`. Isolation is
-- by pseudonym: every statement here is filtered by a subject the caller cannot
-- name, because the caller is a dispatcher acting on an event's own metadata.
CREATE TABLE processing_restriction_view (
    -- The pseudonym, never a person (ADR-002).
    subject_id text PRIMARY KEY,

    -- When processing was halted. Shown to the subject so the answer to "since
    -- when have you stopped?" is a fact rather than a recollection.
    restricted_at timestamptz NOT NULL,

    -- Who invoked it: normally the subject, an operator when the request
    -- arrived out of band. A pseudonym in both cases.
    actor_id text NOT NULL
);

COMMENT ON TABLE processing_restriction_view IS
    'Article 18 restrictions. A row IS the restriction; lifting deletes it. Read once per tenant-facing notification.';

GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON processing_restriction_view TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS processing_restriction_view;
-- +goose StatementEnd

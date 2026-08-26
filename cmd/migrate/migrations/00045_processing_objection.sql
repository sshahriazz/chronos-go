-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- processing_objection_view — Article 21, as a lookup
-- ---------------------------------------------------------------------------
-- One row per (subject, purpose) a person has objected to. A row's presence is
-- the objection; withdrawing deletes it.
--
-- # Why this is a separate table from processing_restriction_view
--
-- The temptation is a `purpose` column on the restriction table with a
-- sentinel meaning "everything", and it would be wrong in a way that outlives
-- the schema. Article 18 restriction and Article 21 objection are different
-- rights with different lifetimes: a restriction is total and temporary, held
-- while a dispute about the data runs and lifted when it is settled; an
-- objection is per-purpose and open-ended, and only the person who made it may
-- release it. A subject can hold both at once, and lifting the restriction must
-- not release the objection — which one table with a sentinel row makes very
-- easy to get wrong with a single DELETE.
--
-- # Presence rather than a boolean, for processing_restriction_view's reason
--
-- This is read on the notification path. The overwhelmingly common answer is
-- "no objection", and a table holding only the exceptions makes that a miss on
-- a small index rather than a hit on a row per account per purpose.
--
-- The failure direction is right as well. A row that should have been deleted
-- keeps a purpose stopped, which the person notices and reports. A boolean that
-- failed to be set would resume processing somebody objected to, silently.
--
-- # No org_id, and no row security
--
-- An objection is a fact about a PERSON, not about their membership of any
-- organization — the shape `processing_restriction_view`, `user_view` and
-- `profile_view` all have. Isolation is by pseudonym: the caller is a
-- notification dispatcher acting on a subject taken from an event's own
-- metadata, never one a request named.
CREATE TABLE processing_objection_view (
    -- The pseudonym, never a person (ADR-002).
    subject_id text NOT NULL,

    -- Which processing was stopped. One of domain.Purposes().
    --
    -- # No CHECK constraint, and that is deliberate rather than an omission
    --
    -- A CHECK cannot read a Go constant, so it would be a second copy of the
    -- purpose list that drifts from the first (00029's comment is the record of
    -- exactly that happening to identity_token.purpose). Here the copy would be
    -- worse than there: this table is written by a PROJECTOR replaying the log,
    -- and a constraint narrower than the log would make a replay fail on an
    -- event that was legitimately appended under an earlier build — turning a
    -- retired purpose into an unreplayable projection.
    --
    -- The aggregate refuses an unknown purpose at the WRITE, which is where the
    -- validation belongs and where it cannot break a rebuild.
    purpose text NOT NULL,

    -- When the objection was made. Shown to the subject, so the answer to
    -- "since when?" is a fact rather than a recollection.
    objected_at timestamptz NOT NULL,

    -- Who objected: the subject. A pseudonym. Carried for the same reason
    -- processing_restriction_view carries it — so an operator-assisted request,
    -- if one ever exists, is distinguishable from a self-service one.
    actor_id text NOT NULL,

    -- One objection per purpose per person. The composite key is what makes
    -- withdrawing one purpose leave the others standing.
    PRIMARY KEY (subject_id, purpose)
);

COMMENT ON TABLE processing_objection_view IS
    'Article 21 objections, one row per (subject, purpose). A row IS the objection; withdrawing deletes it. Read on the notification path for Activity and Product class messages only.';

GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON processing_objection_view TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS processing_objection_view;
-- +goose StatementEnd

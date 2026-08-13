-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- email_reservation_view — the lapse sweep's work list
-- ---------------------------------------------------------------------------
-- A PROJECTION, and it deliberately does NOT enforce anything.
--
-- Uniqueness is enforced by the reservation STREAM: two concurrent
-- registrations for one address contend on the same KurrentDB stream and
-- exactly one append wins (ADR-044). A projection cannot do that job — it is by
-- definition behind the log, so both registrations would read "free".
--
-- So why does this table exist at all? Because one question cannot be answered
-- from the log: "which unverified reservations have lapsed?" Answering it by
-- replay would mean scanning every reservation stream in the system on every
-- sweep. The lapse is what stops someone registering with an address they do not
-- control and holding it forever, so the sweep has to be cheap enough to run
-- often.
--
-- The sweep reads this table, then loads each aggregate and issues the release
-- against the STREAM — so a stale row costs a wasted load, never a wrong
-- release. The decision stays where it can be made correctly.

CREATE TABLE email_reservation_view (
    -- The keyed HMAC of the address. Not the address: it is not in this
    -- database, and this index is what names the stream.
    email_index text PRIMARY KEY,

    subject_id text NOT NULL,

    -- Verified claims never lapse. Unverified ones lapse at expires_at.
    verified boolean NOT NULL DEFAULT false,

    -- NULL once confirmed — cleared rather than left in the past, so a
    -- confirmed reservation cannot be swept by a query that only compares
    -- against now().
    expires_at timestamptz,

    reserved_at timestamptz NOT NULL,
    released_at timestamptz,

    CONSTRAINT reservation_unverified_has_a_deadline CHECK (
        verified OR released_at IS NOT NULL OR expires_at IS NOT NULL
    )
);

COMMENT ON TABLE email_reservation_view IS
    'PROJECTION. The lapse sweep''s work list; enforces nothing — the stream does that.';

-- The sweep's query: unverified, unreleased, past deadline.
CREATE INDEX email_reservation_lapsed_idx
    ON email_reservation_view (expires_at)
    WHERE NOT verified AND released_at IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON email_reservation_view TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS email_reservation_view;
-- +goose StatementEnd

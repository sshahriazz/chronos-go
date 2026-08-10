-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- reactor_processed — redelivery filter for reactors
-- ---------------------------------------------------------------------------
-- A persistent subscription is at-least-once: a restart, a lost ack or a slow
-- handler all produce redelivery. Without this table a reactor sends the same
-- email every time that happens.
--
-- It is a FILTER, not a guarantee. A crash between performing the effect and
-- recording it here still yields a duplicate, which is why React must be
-- idempotent regardless and why reactors that start Temporal workflows key them
-- by event id (ADR-017, ADR-019).
--
-- NOT tenant-scoped and carrying no RLS: a reactor consumes $all across every
-- tenant, and the row holds only two opaque identifiers — no personal data,
-- nothing that identifies a subject (ADR-002).
CREATE TABLE reactor_processed (
    reactor      text        NOT NULL,
    event_id     uuid        NOT NULL,
    processed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (reactor, event_id)
);

COMMENT ON TABLE reactor_processed IS
    'One row per (reactor, event) already handled. Filters at-least-once redelivery.';

-- Retention sweeps delete by age; without this they scan the whole table.
CREATE INDEX reactor_processed_age_idx ON reactor_processed (processed_at);

GRANT SELECT, INSERT, DELETE ON reactor_processed TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS reactor_processed;
-- +goose StatementEnd

-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- stripe_webhook_event — the idempotency boundary for incoming webhooks
-- ---------------------------------------------------------------------------
-- billing.md §4 step 2. Stripe retries by design, so the same event arrives
-- more than once; this table is what makes the second arrival a no-op instead
-- of a second state change.
--
-- # Why not the existing `reactor_dedup` table
--
-- That one is keyed by ids.EventID, which is a prefixed ULID this system mints.
-- A Stripe event id is `evt_...` and is Stripe's, so it cannot go there without
-- pretending to be something it is not.
--
-- # Why the raw payload is kept
--
-- Two reasons, and neither is nostalgia. It is the only record of what Stripe
-- actually SENT, which is the first thing anybody wants when a charge and our
-- state disagree. And it is what a replay would use if the reconciliation job
-- ever needs to re-apply a window of history — Stripe stops retrying after
-- about three days, so after that this row is the only copy.
--
-- # No row security
--
-- Not tenant-scoped, deliberately: an event arrives before anything has decided
-- which organization it concerns, and the mapping lives in Stripe's metadata
-- rather than in the request. It is operational data, like the reactor
-- checkpoints, and is reachable only by the process that ingests webhooks.
CREATE TABLE stripe_webhook_event (
    -- Stripe's own id. The whole point of the table.
    event_id text PRIMARY KEY,

    event_type text NOT NULL,

    -- Exactly what Stripe sent. NOT re-serialized: the signature covers those
    -- bytes, and a round trip through a JSON encoder produces different ones.
    payload jsonb NOT NULL,

    received_at  timestamptz NOT NULL DEFAULT now(),

    -- NULL until the event has been applied. The gap between received and
    -- processed is what a retry looks at: a row that exists but is unprocessed
    -- means an earlier attempt failed partway, and processing again is safe
    -- because applying a subscription's current state is convergent.
    processed_at timestamptz,

    -- The last failure, for the case where an event keeps failing and somebody
    -- has to find out why without reading the whole log.
    last_error text NOT NULL DEFAULT ''
);

COMMENT ON TABLE stripe_webhook_event IS
    'Raw Stripe webhooks, keyed by Stripe event id. The idempotency boundary for billing.';

-- Answers "what has arrived and not been applied", which is the query an
-- operator runs when Stripe and our state disagree. Partial, because the
-- overwhelming majority of rows are processed.
CREATE INDEX stripe_webhook_event_unprocessed_idx
    ON stripe_webhook_event (received_at)
    WHERE processed_at IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON stripe_webhook_event TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS stripe_webhook_event;
-- +goose StatementEnd

-- Queries for Stripe webhook ingestion.

-- name: RecordWebhookEvent :one
-- Claim an event, or report that it was already claimed.
--
-- ON CONFLICT DO NOTHING with a RETURNING is the whole idempotency mechanism:
-- the first delivery inserts and gets a row back, and every later one gets
-- nothing. Checking first and inserting after would leave a window in which two
-- concurrent deliveries both see "not seen" and both apply the change.
INSERT INTO stripe_webhook_event (event_id, event_type, payload)
VALUES ($1, $2, $3)
ON CONFLICT (event_id) DO NOTHING
RETURNING event_id;

-- name: WebhookEventProcessed :one
-- Has this event already been APPLIED, as opposed to merely received?
--
-- A row that exists with a NULL processed_at is an earlier attempt that failed
-- partway. Retrying it is safe, because applying a subscription's current state
-- is convergent — so this asks about processing rather than existence.
SELECT processed_at IS NOT NULL FROM stripe_webhook_event WHERE event_id = $1;

-- name: MarkWebhookEventProcessed :exec
UPDATE stripe_webhook_event
SET processed_at = now(), last_error = ''
WHERE event_id = $1;

-- name: MarkWebhookEventFailed :exec
-- Records why, without marking it processed, so a retry still applies it.
UPDATE stripe_webhook_event
SET last_error = $2
WHERE event_id = $1;

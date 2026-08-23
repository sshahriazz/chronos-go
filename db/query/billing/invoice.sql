-- Queries for the invoice projection.
--
-- Every write here is an UPSERT, because Stripe sends several events per invoice
-- — created, finalized, paid — and each one carries the WHOLE object after a
-- re-fetch. There is no incremental update to make: the handler is convergent by
-- construction, so applying an out-of-order or duplicated event reaches the same
-- row.

-- name: UpsertInvoice :exec
-- Record an invoice's current state.
--
-- # Why created_at is preserved and everything else overwritten
--
-- created_at is Stripe's creation instant and is immutable — a redelivery must
-- not move an invoice in the customer's history. Everything else is the CURRENT
-- state of a mutable object: a draft becomes open becomes paid, a number appears
-- at finalization, and the hosted URLs appear with it.
--
-- # Why the ordering guard is on created_at and not on a version
--
-- Stripe does not version invoices and does not guarantee webhook ordering. What
-- makes overwriting safe anyway is the RE-FETCH: the handler asks Stripe for the
-- object before writing, so two deliveries in either order write the same state,
-- and a stale event writes what is currently true rather than what was true when
-- it fired.
INSERT INTO invoice_view (
    invoice_id, org_id, stripe_subscription_id, number, status,
    amount_due, amount_paid, currency,
    period_start, period_end, hosted_url, pdf_url,
    created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
ON CONFLICT (invoice_id) DO UPDATE SET
    stripe_subscription_id = EXCLUDED.stripe_subscription_id,
    number                 = EXCLUDED.number,
    status                 = EXCLUDED.status,
    amount_due             = EXCLUDED.amount_due,
    amount_paid            = EXCLUDED.amount_paid,
    currency               = EXCLUDED.currency,
    period_start           = EXCLUDED.period_start,
    period_end             = EXCLUDED.period_end,
    hosted_url             = EXCLUDED.hosted_url,
    pdf_url                = EXCLUDED.pdf_url,
    updated_at             = EXCLUDED.updated_at;

-- name: ListInvoices :many
-- One page of an organization's billing history, newest first.
--
-- Keyset paging on `(created_at, invoice_id)` DESC, because an offset shifts
-- under a concurrent webhook and silently skips a row — and the row it skips is
-- an invoice somebody is looking for. The id breaks ties: Stripe can create
-- several invoices in the same second.
--
-- The cursor comparison is a ROW comparison rather than an OR-chain, so it uses
-- the index directly.
SELECT invoice_id, number, status, amount_due, amount_paid, currency,
       period_start, period_end, hosted_url, pdf_url, created_at
FROM invoice_view
WHERE org_id = $1
  -- Both cursor parameters are CAST, and the second one is not decoration.
  -- Inside a row comparison sqlc infers $3 from its left-hand neighbour rather
  -- than from `invoice_id`, and generates a timestamptz for a text column — a
  -- parameter struct nothing can fill correctly. The cast puts the type in the
  -- statement, where it is also what a reader would expect to see.
  AND ($2::timestamptz IS NULL OR (created_at, invoice_id) < ($2::timestamptz, $3::text))
ORDER BY created_at DESC, invoice_id DESC
LIMIT $4;

-- name: TruncateInvoices :exec
-- TRUNCATE, because a rebuild empties the table from an UNSCOPED system
-- transaction where RLS hides every row, so DELETE would remove none (ADR-019).
TRUNCATE TABLE invoice_view;

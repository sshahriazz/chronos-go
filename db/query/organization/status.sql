-- Queries for the organization status projection.
--
-- Every one is keyed by org_id and runs inside a tenant-scoped transaction, so
-- the RLS predicate and the WHERE clause say the same thing. That redundancy is
-- deliberate: the policy is what holds when somebody forgets the predicate.

-- name: UpsertOrgStatus :exec
-- Upsert, not insert: a projector is replayed on restart and on rebuild, so the
-- same event WILL arrive twice.
--
-- created_at is untouched on conflict — a replay must not move when the
-- organization first appeared.
INSERT INTO org_status_view
    (org_id, status, trial_ends_at, stripe_subscription_id, updated_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (org_id) DO UPDATE SET
    status                 = EXCLUDED.status,
    trial_ends_at          = EXCLUDED.trial_ends_at,
    stripe_subscription_id = EXCLUDED.stripe_subscription_id,
    updated_at             = EXCLUDED.updated_at;

-- name: SetOrgStatus :exec
-- Move the status without touching the Stripe columns.
--
-- Separate from the upsert because most lifecycle events change ONLY the
-- status, and folding them into one statement would mean every handler
-- restating the subscription id it is not changing — which is how a projector
-- blanks a column it never meant to touch.
UPDATE org_status_view
SET status = $2, updated_at = $3
WHERE org_id = $1;

-- name: ClearOrgTrialEnd :exec
-- Drop the trial deadline once the organization is no longer trialing, so the
-- due-trials index stops naming it.
UPDATE org_status_view
SET trial_ends_at = NULL, updated_at = $2
WHERE org_id = $1;

-- name: GetOrgStatus :one
-- The read gate 3 performs on every request.
--
-- Returns the status alone. Anything else added here is read once per request
-- for every request in the system, which is the cost this projection's shape
-- exists to avoid.
SELECT status FROM org_status_view WHERE org_id = $1;

-- name: GetOrgStatusRow :one
-- The fuller row, for the billing screen and for reconciliation.
SELECT org_id, status, trial_ends_at, stripe_subscription_id, updated_at
FROM org_status_view
WHERE org_id = $1;

-- name: TruncateOrgStatus :exec
-- TRUNCATE, not DELETE: a rebuild runs in an unscoped system transaction where
-- RLS hides every row, so DELETE would remove none (ADR-019).
TRUNCATE TABLE org_status_view;

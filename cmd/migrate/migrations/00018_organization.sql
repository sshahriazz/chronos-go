-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- org_status_view — the subscription state that gates an entire tenant
-- ---------------------------------------------------------------------------
-- A PROJECTION, built from organization's lifecycle events and nothing else.
-- Reconstructable by replaying from position zero (ADR-019).
--
-- # Why it is this small
--
-- organization.md §10 calls it "the most performance-critical projection in the
-- system — gate 3 consults it on EVERY request. It is tiny, cacheable, and
-- invalidated by event rather than TTL." So it holds the one fact gate 3 needs
-- and nothing a screen wants: no name, no slug, no settings. Those belong to
-- organization_view, which is read once per page rather than once per request.
--
-- Keeping them apart is not premature optimisation. A row that a screen also
-- reads acquires columns that screens want, and every added column widens the
-- thing every request in the system already reads.
--
-- # Row security, on the hot path, deliberately
--
-- It would be tempting to leave RLS off here: the gate reads one row by primary
-- key, and a SET LOCAL per request is real cost. That is exactly the carve-out
-- ADR-011 exists to refuse. A tenant-scoped table without row security is one
-- forgotten predicate away from answering with another organization's status —
-- and the answer to "may this tenant act" is the last one that should be
-- reachable across a tenant boundary. The cache is what removes the per-request
-- read, not the absence of a policy.
CREATE TABLE org_status_view (
    org_id text PRIMARY KEY,

    -- The lifecycle status, as the domain spells it: provisioning, trialing,
    -- active, past_due, suspended, closed. Text rather than an enum because an
    -- enum change is a migration and a status set that cannot change cheaply is
    -- one people work around.
    status text NOT NULL,

    -- When the trial ends, for the "3 days left" banner and for reconciliation
    -- to notice a trial that should have ended and did not. NULL once the
    -- organization is no longer trialing.
    trial_ends_at timestamptz,

    -- Stripe's subscription, which every webhook names. The mapping has to live
    -- on our side, and this is the row every webhook lookup starts from.
    stripe_subscription_id text NOT NULL DEFAULT '',

    updated_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE org_status_view IS
    'Subscription status per organization. Read by gate 3 on every request; keep it small.';

ALTER TABLE org_status_view ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_status_view FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON org_status_view
    USING (org_id = current_setting('app.org_id', true))
    WITH CHECK (org_id = current_setting('app.org_id', true));

-- Answers "which trials are due to end", which the reconciliation job asks to
-- catch a Stripe webhook that never arrived (billing.md §5 case 15). Partial,
-- because only trialing rows have a deadline worth scanning.
CREATE INDEX org_status_view_trial_ends_idx
    ON org_status_view (trial_ends_at)
    WHERE status = 'trialing';

-- Answers "which organization does this Stripe subscription belong to", which
-- is the first question every webhook asks. Partial for the same reason: an org
-- with no subscription yet is not reachable from a webhook.
CREATE INDEX org_status_view_subscription_idx
    ON org_status_view (stripe_subscription_id)
    WHERE stripe_subscription_id <> '';

-- TRUNCATE, because a rebuild empties the table from an UNSCOPED system
-- transaction where RLS hides every row, so DELETE would remove none (ADR-019).
GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON org_status_view TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS org_status_view;
-- +goose StatementEnd

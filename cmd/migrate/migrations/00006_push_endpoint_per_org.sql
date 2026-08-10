-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- push_subscription: the endpoint is unique PER ORGANIZATION, not globally
-- ---------------------------------------------------------------------------
-- 00004 made the endpoint globally unique, reasoning that the same browser
-- re-subscribing yields the same endpoint and two rows would push twice. That
-- part is right. What it missed is that a person belongs to several
-- organizations (workspace.md §2), and their browser produces ONE endpoint
-- across all of them.
--
-- The consequence was not a duplicate row. It was an outright failure, because
-- the upsert conflicts on a row RLS hides:
--
--     ERROR: new row violates row-level security policy (USING expression)
--            for table "push_subscription"
--
-- ON CONFLICT DO UPDATE has to read the conflicting row to update it, and the
-- row belongs to the other organization. So the second organization's
-- subscribe failed and that person silently received no web push there at all.
--
-- Verified against the running database before this migration was written; the
-- regression test lives in internal/modules/notification/adapter/postgres.
--
-- Scoping the index to org_id also removes a cross-tenant signal: under the old
-- index, the shape of the error told a caller whether an endpoint already
-- existed in some other tenant.
DROP INDEX IF EXISTS push_subscription_endpoint_idx;

CREATE UNIQUE INDEX push_subscription_endpoint_idx
    ON push_subscription (org_id, endpoint);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- The old index cannot be recreated unconditionally: rows that are legitimate
-- under the new rule — one person, one browser, two organizations — violate it.
-- Down therefore drops to a NON-unique index rather than failing or, worse,
-- silently deleting somebody's subscription to make the constraint fit.
DROP INDEX IF EXISTS push_subscription_endpoint_idx;

CREATE INDEX push_subscription_endpoint_idx
    ON push_subscription (endpoint);

-- +goose StatementEnd

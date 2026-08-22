-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- quota_reservation — the concurrency-safe core of gate 4
-- ---------------------------------------------------------------------------
-- entitlement.md §4. A plain check-then-act is a race: two admins inviting the
-- last seat both read `49 < 50` and both proceed. A reservation is what closes
-- that window, and it closes it by being a ROW, taken under the same lock as the
-- count it guards.
--
-- # Why Postgres and not Valkey (review D12)
--
-- A standing invariant of this system is that Valkey must survive FLUSHALL. A
-- reservation cannot: flushing would destroy every in-flight one and let two
-- requests take the last seat. The reservation IS the correctness mechanism, so
-- it lives in the durable store. Valkey still serves the read-side CHECK as a
-- hot cache — only RESERVE touches Postgres, and only on operations that
-- actually consume a limit.
--
-- # Why committed reservations stay
--
-- A committed row is the USAGE record: three committed `workspaces.count` rows
-- for an organization means three workspaces. Counting from the projection
-- instead would mean counting a table that lags the log, which reopens the
-- window this table exists to close.
CREATE TABLE quota_reservation (
    reservation_id text PRIMARY KEY,

    org_id    text NOT NULL,
    limit_key text NOT NULL,

    -- NULL while held, set when the handler committed it. A held reservation
    -- counts against the limit exactly as a committed one does — that is the
    -- point — but only a held one can expire.
    committed_at timestamptz,

    -- Mandatory, and only meaningful while held. A process that dies between
    -- reserving and committing must not leak a seat forever.
    expires_at timestamptz NOT NULL,

    -- What consumed it, for reporting and for the operator question "which
    -- workspace is using this seat".
    subject_ref text NOT NULL DEFAULT '',

    created_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE quota_reservation IS
    'Quota reservations and committed usage. Held rows expire; committed rows are the usage record.';

ALTER TABLE quota_reservation ENABLE ROW LEVEL SECURITY;
ALTER TABLE quota_reservation FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON quota_reservation
    USING (org_id = current_setting('app.org_id', true))
    WITH CHECK (org_id = current_setting('app.org_id', true));

-- The counting query: everything live for one organization and one limit.
-- Leading with (org_id, limit_key) matches both the RLS predicate and the WHERE.
--
-- NO partial predicate, deliberately. The obvious one is
-- `WHERE committed_at IS NOT NULL OR expires_at > now()`, and PostgreSQL refuses
-- it: `functions in index predicate must be marked IMMUTABLE`. It is right to —
-- `now()` changes, so the set of rows the index covers would drift away from the
-- rows it was built over, and the index would quietly stop matching reality.
-- The time comparison belongs in the query, where it is evaluated per statement.
CREATE INDEX quota_reservation_live_idx
    ON quota_reservation (org_id, limit_key, expires_at);

-- The sweep: which HELD reservations have lapsed. Partial, because a committed
-- row never expires and the overwhelming majority of rows are committed.
CREATE INDEX quota_reservation_expiry_idx
    ON quota_reservation (expires_at)
    WHERE committed_at IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON quota_reservation TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS quota_reservation;
-- +goose StatementEnd

-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- Projection checkpoints
-- ---------------------------------------------------------------------------
-- The position each projector has consumed to. Updated in the SAME transaction
-- as the rows it describes — that atomicity is what makes replay idempotent and
-- restart safe (ADR-019).
--
-- Deliberately NOT tenant-scoped: a projector consumes $all across every
-- tenant, so this table is system-owned and carries no RLS.
CREATE TABLE projection_checkpoint (
    name              text        PRIMARY KEY,
    commit_position   bigint      NOT NULL DEFAULT 0,
    prepare_position  bigint      NOT NULL DEFAULT 0,
    events_processed  bigint      NOT NULL DEFAULT 0,
    last_event_at     timestamptz,
    updated_at        timestamptz NOT NULL DEFAULT now(),
    -- Informational only: real mutual exclusion is a Postgres advisory lock,
    -- because a projector is a single writer (ARCHITECTURE §3.3).
    holder            text,
    CONSTRAINT positions_non_negative
        CHECK (commit_position >= 0 AND prepare_position >= 0)
);

COMMENT ON TABLE projection_checkpoint IS
    'One row per projector. Written in the same transaction as projected rows.';

-- ---------------------------------------------------------------------------
-- tenant_probe — a real tenant-scoped table proving the isolation rules
-- ---------------------------------------------------------------------------
CREATE TABLE tenant_probe (
    id            text        PRIMARY KEY,
    org_id        text        NOT NULL,
    workspace_id  text        NOT NULL,
    residency     text        NOT NULL DEFAULT 'eu',
    label         text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- Composite indexes lead with org_id: it is in the predicate of every query,
-- including the RLS policy itself (ADR-013).
CREATE INDEX tenant_probe_org_created_idx
    ON tenant_probe (org_id, created_at DESC, id);

ALTER TABLE tenant_probe ENABLE ROW LEVEL SECURITY;
-- FORCE is the load-bearing word: without it the table OWNER is exempt. Note it
-- still does not constrain a SUPERUSER, which bypasses RLS entirely — hence the
-- startup privilege check in adapter/postgres (ADR-011, ADR-015).
ALTER TABLE tenant_probe FORCE ROW LEVEL SECURITY;

-- Both columns are checked. org_id alone would let a leaked workspace_id from
-- another tenant resolve; workspace_id alone would trust a forged value
-- (ADR-020).
CREATE POLICY tenant_isolation ON tenant_probe
    USING (
        org_id = current_setting('app.org_id', true)
        AND workspace_id = current_setting('app.workspace_id', true)
    )
    WITH CHECK (
        org_id = current_setting('app.org_id', true)
        AND workspace_id = current_setting('app.workspace_id', true)
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_probe TO chronos_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON projection_checkpoint TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS tenant_probe;
DROP TABLE IF EXISTS projection_checkpoint;
-- +goose StatementEnd

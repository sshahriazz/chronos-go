-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- projection_probe — a real projected read model
-- ---------------------------------------------------------------------------
-- Its purpose is to prove, against the running system rather than in a comment,
-- that the projector pipeline holds:
--
--   * events appended to KurrentDB reach Postgres,
--   * the checkpoint commits in the same transaction as the rows,
--   * a rebuild from position zero reproduces the same rows exactly,
--   * every row is written under the RLS policy of the event's own tenant.
--
-- It carries the same shape a real read model does — org_id + workspace_id,
-- FORCE RLS, both columns in the policy — because a proof against a weaker
-- table would prove nothing about the tables that matter.
CREATE TABLE projection_probe (
    id            text        PRIMARY KEY,
    org_id        text        NOT NULL,
    workspace_id  text        NOT NULL,
    name          text        NOT NULL,
    revision      bigint      NOT NULL,
    updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX projection_probe_org_idx ON projection_probe (org_id, workspace_id, id);

ALTER TABLE projection_probe ENABLE ROW LEVEL SECURITY;
ALTER TABLE projection_probe FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON projection_probe
    USING (
        org_id = current_setting('app.org_id', true)
        AND workspace_id = current_setting('app.workspace_id', true)
    )
    WITH CHECK (
        org_id = current_setting('app.org_id', true)
        AND workspace_id = current_setting('app.workspace_id', true)
    );

-- TRUNCATE, not just DELETE. A rebuild empties the table from an UNSCOPED
-- system transaction, which under RLS can see no rows and would therefore
-- delete none — leaving a "rebuilt" projection still full of its old contents.
-- TRUNCATE is a table-level operation and is not filtered by row security, so
-- it is the only correct way for a projector to reset itself.
GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON projection_probe TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS projection_probe;
-- +goose StatementEnd

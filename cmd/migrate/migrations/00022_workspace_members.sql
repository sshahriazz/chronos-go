-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- workspace_member_view — who is in which workspace
-- ---------------------------------------------------------------------------
-- One row per (workspace, person). Distinct from `org_member_index`, which is
-- one row per (organization, person) and answers a different question.
--
-- Both are needed and neither derives the other cheaply. The seat rule is
-- "per person per ORGANIZATION" (workspace.md §2), so joining asks "is this
-- person already anywhere in this organization" — a question `org_member_index`
-- answers with a single indexed lookup. Removing asks "how many memberships do
-- they have LEFT", which needs the per-workspace rows and is what this table is
-- for. Answering the first from this table would work; answering the second from
-- `org_member_index` cannot, because a count of one row is one whatever the
-- truth is.
--
-- # Row security, unlike org_member_index
--
-- `org_member_index` carries none because gate 1 reads it BEFORE any tenant
-- scope exists — resolving the scope is what it is doing. This table is read
-- after gate 1, inside the tenant transaction every query runs in (ADR-011), so
-- the ordinary policy applies and a workspace of another organization is
-- invisible rather than merely unmatched.
CREATE TABLE workspace_member_view (
    workspace_id text NOT NULL,

    -- Denormalised from the workspace so the seat count is one indexed lookup
    -- rather than a join, and so the row security policy has a column to key
    -- on. It is immutable in the domain: a workspace never moves organization.
    org_id text NOT NULL,

    -- The pseudonym, never a person (ADR-002). Resolving it to a name is the
    -- vault's job at read time.
    subject_id text NOT NULL,

    -- `admin`, `member` or `guest`. Text rather than an enum for the reason
    -- org_member_index gives: an enum change is a migration, and a role set that
    -- cannot grow cheaply is one people work around.
    role text NOT NULL,

    joined_at timestamptz NOT NULL,

    PRIMARY KEY (workspace_id, subject_id)
);

COMMENT ON TABLE workspace_member_view IS
    'Membership per (workspace, subject). Counts here decide when a seat is taken and returned.';

ALTER TABLE workspace_member_view ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_member_view FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON workspace_member_view
    USING (org_id = current_setting('app.org_id', true))
    WITH CHECK (org_id = current_setting('app.org_id', true));

-- Answers "how many workspaces of this organization is this person in", which
-- is the question both halves of the seat rule turn on.
CREATE INDEX workspace_member_view_org_subject_idx
    ON workspace_member_view (org_id, subject_id);

GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON workspace_member_view TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS workspace_member_view;
-- +goose StatementEnd

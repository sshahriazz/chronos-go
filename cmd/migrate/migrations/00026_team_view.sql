-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- team_view — the teams in a workspace
-- ---------------------------------------------------------------------------
-- What a team screen renders, and what the deletion path enumerates members
-- from. It is NOT authority: every decision about a team — may this person
-- manage it, is it already deleted — is taken against the aggregate, because a
-- projection lags and a decision taken from one can be taken twice with two
-- different answers.
--
-- # Deleted rows are KEPT
--
-- access.md §7.5 requires that a team id is never reused, because grants target
-- `team:x#member` and a reused id would silently inherit the deleted team's
-- access. A DELETE here would make the id look free to anything that checked
-- this table, so deletion is a status change and the row stays.
--
-- It is also what makes "this team is gone" answerable at all. A missing row and
-- a team that never existed are the same thing to a reader; a row marked deleted
-- is a fact.
CREATE TABLE team_view (
    team_id text PRIMARY KEY,

    workspace_id text NOT NULL,
    org_id       text NOT NULL,

    name text NOT NULL,

    -- `active` or `deleted`. Text rather than an enum for the reason every other
    -- status column here gives: an enum change is a migration, and a value set
    -- that cannot grow cheaply is one people work around.
    status text NOT NULL,

    created_by text NOT NULL,
    created_at timestamptz NOT NULL,

    -- NULL while active. Set on deletion, so "when did this team go" is
    -- answerable without reading the log.
    deleted_at timestamptz,

    CONSTRAINT team_view_status CHECK (status IN ('active', 'deleted'))
);

COMMENT ON TABLE team_view IS
    'Teams per workspace. Screens and enumeration only; the aggregate is authority. Deleted rows are kept, because team ids are never reused.';

ALTER TABLE team_view ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_view FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON team_view
    USING (org_id = current_setting('app.org_id', true))
    WITH CHECK (org_id = current_setting('app.org_id', true));

-- The team list, and the only ordering a person reading it wants.
CREATE INDEX team_view_workspace_idx ON team_view (workspace_id, status, name);

GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON team_view TO chronos_app;

-- ---------------------------------------------------------------------------
-- team_member_view — who is in which team
-- ---------------------------------------------------------------------------
-- One row per (team, person). Its own table rather than an array on team_view,
-- because access.md §6 measured a thousand-member team and an array is neither
-- indexable by member nor writable by one projector without rewriting the whole
-- team on every join.
--
-- Two questions turn on it: "who is in this team", which is the screen, and
-- "which teams is this person in", which is what removing somebody from a
-- WORKSPACE has to ask — a team member must be a workspace member
-- (workspace.md §6), so losing the second has to lose the first.
CREATE TABLE team_member_view (
    team_id text NOT NULL,

    -- Denormalised so the row security policy has a column to key on and so
    -- "which teams is this person in HERE" is one indexed lookup.
    workspace_id text NOT NULL,
    org_id       text NOT NULL,

    -- The pseudonym, never a person (ADR-002).
    subject_id text NOT NULL,

    added_at timestamptz NOT NULL,

    PRIMARY KEY (team_id, subject_id)
);

COMMENT ON TABLE team_member_view IS
    'Membership per (team, subject). A team member must also be a workspace member.';

ALTER TABLE team_member_view ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_member_view FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON team_member_view
    USING (org_id = current_setting('app.org_id', true))
    WITH CHECK (org_id = current_setting('app.org_id', true));

-- "Which teams is this person in, in this workspace" — what a workspace removal
-- asks, and what a team screen asks in reverse.
CREATE INDEX team_member_view_subject_idx
    ON team_member_view (workspace_id, subject_id);

GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON team_member_view TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS team_member_view;
DROP TABLE IF EXISTS team_view;
-- +goose StatementEnd

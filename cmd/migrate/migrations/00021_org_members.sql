-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- org_member_index — who belongs to which organization
-- ---------------------------------------------------------------------------
-- workspace.md §9 names this table and says what makes it worth its own
-- projection: "`org_member_index` is what makes 'one person, one seat'
-- computable — a unique `(org_id, user_id)` regardless of how many workspaces
-- they belong to."
--
-- It has a second job before that one, and that is why it exists now: gate 1
-- answers "which organization is this request in", and it has to VERIFY the
-- answer rather than trust a header. This is the table it verifies against.
--
-- # Why not org_status_view
--
-- That one is read on every request by gate 3 and is deliberately tiny
-- (organization.md §10). Membership is a different question, asked once per
-- request by a different gate, and a row a second gate also reads acquires
-- columns that gate wants.
--
-- # No row security, deliberately
--
-- Gate 1 reads this BEFORE any tenant scope exists — resolving the scope is
-- precisely what it is doing. A policy keyed on `app.org_id` would hide every
-- row from the one caller who legitimately has not set it yet. Containment here
-- is the query: every statement filters by the caller's own subject_id, which
-- the authn gate supplies and no request can name.
CREATE TABLE org_member_index (
    org_id     text NOT NULL,
    subject_id text NOT NULL,

    -- `owner` or `admin` today; `member` and `guest` arrive with invitations.
    -- Text rather than an enum because an enum change is a migration, and a role
    -- set that cannot grow cheaply is one people work around.
    role text NOT NULL,

    joined_at timestamptz NOT NULL,

    -- One row per person per organization, which is the uniqueness the seat
    -- model depends on: five workspaces, one seat.
    PRIMARY KEY (org_id, subject_id)
);

COMMENT ON TABLE org_member_index IS
    'Membership per (org, subject). Gate 1 verifies against it; seat counting will too.';

-- Answers "which organizations does this person belong to", which is what gate 1
-- asks when no organization was named.
CREATE INDEX org_member_index_subject_idx ON org_member_index (subject_id);

GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON org_member_index TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS org_member_index;
-- +goose StatementEnd

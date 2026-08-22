-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- invitation_view — outstanding and settled invitations
-- ---------------------------------------------------------------------------
-- workspace.md §9 names this table and its index: `(workspace_id, status,
-- expires_at)`. Three questions turn on it, and each wants a different part of
-- that key:
--
--   * "who is outstanding in this workspace" — the admin screen
--   * "which invitations are due to expire" — the reconciliation sweep that
--     catches a Temporal workflow that never fired
--   * "what did this person issue" — an inviter removed from the organization
--     takes their outstanding invitations with them
--
-- # Nothing here is authority
--
-- The accept, decline, revoke and resend paths all read the AGGREGATE, never
-- this table. A projection is behind the log by construction, so a decision
-- taken from one can be taken twice with two different answers — and every
-- decision on those paths spends a seat or a credential. This is for screens and
-- for sweeps.
CREATE TABLE invitation_view (
    invitation_id text PRIMARY KEY,

    workspace_id text NOT NULL,
    org_id       text NOT NULL,

    -- The invitee's pseudonym. The ADDRESS is not here and is not anywhere in
    -- Postgres outside the vault: an admin screen listing invitations resolves
    -- it at read time, under the same key destruction erases (ADR-002).
    subject_id text NOT NULL,

    -- The keyed blind index, so "is there already an invitation to this address"
    -- is answerable without holding the address.
    email_index text NOT NULL,

    -- Who issued it. An inviter removed from the organization takes their
    -- outstanding invitations with them (workspace.md §5), and this is the
    -- column that reactor reads.
    invited_by text NOT NULL,

    role   text NOT NULL,
    status text NOT NULL,

    -- Moves on a resend, which extends the window. It is the sweep's key, so it
    -- has to reflect the CURRENT deadline rather than the original.
    expires_at timestamptz NOT NULL,

    issued_at timestamptz NOT NULL,

    -- NULL while pending. Set on every terminal transition, so "how long did
    -- this sit before somebody acted" is answerable without joining the log.
    settled_at timestamptz,

    CONSTRAINT invitation_view_status CHECK (
        status IN ('pending', 'accepted', 'revoked', 'expired', 'declined', 'undeliverable')
    )
);

COMMENT ON TABLE invitation_view IS
    'Invitations per workspace. Screens and sweeps only; the aggregate is authority.';

ALTER TABLE invitation_view ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitation_view FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON invitation_view
    USING (org_id = current_setting('app.org_id', true))
    WITH CHECK (org_id = current_setting('app.org_id', true));

-- The admin screen, and the expiry sweep. Exactly the key workspace.md §9 names.
CREATE INDEX invitation_view_workspace_idx
    ON invitation_view (workspace_id, status, expires_at);

-- "What did this person issue", for the reactor that revokes an inviter's
-- outstanding invitations when they leave the organization. Scoped by org
-- because that is how the question is asked.
CREATE INDEX invitation_view_inviter_idx
    ON invitation_view (org_id, invited_by, status);

-- "Is there already an invitation to this address in this organization",
-- answered without holding the address. A second invitation to one address
-- supersedes the first (workspace.md §5) rather than taking a second seat.
CREATE INDEX invitation_view_address_idx
    ON invitation_view (org_id, email_index, status);

GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON invitation_view TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS invitation_view;
-- +goose StatementEnd

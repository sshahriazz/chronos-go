-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- service_account_view — a non-human principal, owned by an organization
-- ---------------------------------------------------------------------------
-- identity.md §10. A PROJECTION, rebuildable from `identity.ServiceAccount*`
-- events, holding no secret and nothing that moves per request — so it is on
-- the projected side of migration 00010's rule and its whole contents can be
-- truncated and replayed.
--
-- # Why this is not a column on user_view
--
-- The operator plane refused the same shape for the same reason and said it
-- more sharply than we would have (operator.md §3): a boolean that grants
-- something is exactly the field an injection bug sets. An
-- `is_service_account` column on `user_view` would put every human account one
-- flipped bit away from being a machine principal that survives its owner's
-- departure — and nothing in the schema, the types or the tests would object,
-- because the row would still be a perfectly ordinary account row.
--
-- A separate table with its own identifier space (`svc_…`, ids.ServiceAccount)
-- makes the wrong principal fail to PARSE rather than fail to be noticed.
--
-- # Why it carries no subject pseudonym
--
-- Everything else in this schema names a person by `subject_id`, because the
-- vault resolves the pseudonym to personal data at read time (ADR-002). A
-- service account has no mailbox, no address, no name it chose for itself and
-- nothing to shred, so a pseudonym here would be indirection to an empty vault
-- entry. `service_account_id` is therefore both the row's identity and the
-- principal id that appears in events, in OpenFGA tuples and in the
-- `api_key_view.owner_id` column.
CREATE TABLE service_account_view (
    service_account_id text PRIMARY KEY,

    -- The organization that owns it, fixed at creation. There is no command
    -- that changes it: a principal that could move between organizations would
    -- carry one customer's automation into another customer's data, which is
    -- the cross-tenant failure identity.md §10 (review D2) describes for keys
    -- and which applies at least as hard to the principal a key acts as.
    org_id text NOT NULL,

    -- A machine-readable label: lower-case snake, bounded, chosen by an admin.
    --
    -- The CHECK is an ADR-002 control and not a formatting preference. This
    -- value is in the event log in cleartext and the log is append-only, so
    -- free text here — "alice's deploy bot" — would put a person's name into a
    -- record erasure can never reach. `deploy_bot` cannot hold a sentence.
    -- domain.ServiceAccount.Create refuses the same shape one layer up; this is
    -- the copy that holds when a future writer reaches the table another way.
    name text NOT NULL,

    -- The pseudonym of the admin who created it. A person, always: the creating
    -- RPC requires AAL2 and no machine credential can ever reach AAL2, so a
    -- service account cannot create another one.
    created_by text NOT NULL,

    created_at timestamptz NOT NULL,

    CONSTRAINT service_account_name_shape CHECK (
        name ~ '^[a-z][a-z0-9_]*$' AND length(name) BETWEEN 1 AND 64
    )
);

COMMENT ON TABLE service_account_view IS
    'PROJECTION. A non-human principal owned by an organization (identity.md §10). Holds no credential — an API key is a separate aggregate. Not a flag on user_view, deliberately.';

COMMENT ON COLUMN service_account_view.name IS
    'Lower-case snake by CHECK, because this value is in an append-only event log and free text is where personal data arrives (ADR-002).';

ALTER TABLE service_account_view ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_account_view FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON service_account_view
    USING (org_id = current_setting('app.org_id', true))
    WITH CHECK (org_id = current_setting('app.org_id', true));

-- One name per organization, and nothing weaker.
--
-- Two service accounts called `deploy_bot` in one organization is a screen an
-- admin cannot act on: the revocation they meant to perform is a coin flip. The
-- index is PER ORG rather than global, because the name is a label inside a
-- tenant and a global constraint would let one customer's choice of name refuse
-- another's — a cross-tenant information leak dressed as a conflict.
CREATE UNIQUE INDEX service_account_view_name_idx
    ON service_account_view (org_id, name);

-- The management screen, newest first, in keyset order so pagination over
-- (created_at DESC, service_account_id DESC) never skips or repeats a row at a
-- page boundary (platform/page).
CREATE INDEX service_account_view_org_idx
    ON service_account_view (org_id, created_at DESC, service_account_id DESC);

GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON service_account_view TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS service_account_view;
-- +goose StatementEnd

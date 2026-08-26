-- +goose Up
-- +goose StatementBegin

-- ===========================================================================
-- The operator plane (ADR-024, operator.md)
-- ===========================================================================
--
-- This migration creates the only tables in this database that are NOT
-- tenant-scoped, and the only database role besides chronos_app that can log
-- in. Both facts are the point, and both are what make the isolation real
-- rather than asserted.
--
-- # Why there is no ROW LEVEL SECURITY here
--
-- Every other table in this schema carries RLS because every row belongs to
-- exactly one tenant, and a query that forgets its scope is a cross-tenant
-- breach. Operator tables have no tenant: an operator account belongs to us, an
-- audit entry belongs to the action, and `operator_customer_list` is a view
-- ACROSS tenants by definition. A policy keyed on `app.workspace_id` would
-- either match nothing or be a policy that always passes, and the second is
-- worse than none because it looks like protection.
--
-- What replaces RLS here is the GRANT table at the bottom. The tenant plane is
-- kept out of these tables by not being granted them, and the operator plane is
-- kept out of tenant tables by the same mechanism in the other direction. That
-- is the "structural, not procedural" minimisation operator.md §4 asks for: the
-- bad query does not fail, it cannot be written.
--
-- # Why the projections here are NOT built by cmd/projector
--
-- cmd/projector connects as chronos_app, and chronos_app must not be able to
-- write these tables — otherwise the grant that keeps the tenant plane out is a
-- grant the tenant plane holds. So `cmd/operator` runs its own catch-up
-- subscriptions as chronos_operator. One more responsibility on a binary that
-- has to be running anyway, in exchange for an isolation boundary that a
-- misconfigured DSN cannot cross.
-- ---------------------------------------------------------------------------


-- ---------------------------------------------------------------------------
-- The role
-- ---------------------------------------------------------------------------
-- Created HERE rather than in infra/postgres/init/ because init runs once, on
-- an empty volume only. Every environment that already exists would never get
-- this role, and "works on a fresh nuke, missing everywhere else" is the
-- failure mode that makes a security boundary untrustworthy.
--
-- Idempotent because migrations are append-only but roles are cluster objects:
-- the same cluster can host a re-created database, and CREATE ROLE would then
-- fail on a role the previous database left behind.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chronos_operator') THEN
        CREATE ROLE chronos_operator LOGIN PASSWORD 'chronos_operator_dev_password';
    END IF;
END
$$;

GRANT CONNECT ON DATABASE chronos TO chronos_operator;
GRANT USAGE ON SCHEMA public TO chronos_operator;

-- The DEFAULT PRIVILEGES that infra/postgres/init/02-app-role.sql set up hand
-- chronos_app every future table, which is right for the ninety-odd tenant
-- tables and wrong for the six below. Each one is revoked explicitly after
-- creation; see the block at the end.
--
-- No matching default is granted to chronos_operator, deliberately. A future
-- tenant table must NOT become readable by the operator plane just because
-- somebody added it — the operator plane's grants are enumerated, one line per
-- table, so extending them is a decision somebody writes down.


-- ---------------------------------------------------------------------------
-- operator_account — projection of the `operator-` streams
-- ---------------------------------------------------------------------------
-- Rebuildable from the log. Holds no key material and no personal data: an
-- operator's address lives in the vault under subject_id, resolved at display
-- time exactly as a tenant's is.
CREATE TABLE operator_account (
    operator_id text PRIMARY KEY,

    -- The vault pseudonym for this employee. UNIQUE because one person is one
    -- operator: two operator accounts sharing a pseudonym would make "who did
    -- this" ambiguous in the audit log, which is the one question it exists to
    -- answer.
    subject_id text NOT NULL UNIQUE,

    -- The IdP binding sign-in resolves against. UNIQUE TOGETHER, so one
    -- Workspace identity maps to at most one operator account — the property
    -- that stops a second, quieter account being provisioned for the same
    -- employee.
    issuer           text NOT NULL,
    provider_subject text NOT NULL,

    -- One of the four roles in operator.md §3. Not a foreign key to a roles
    -- table: the set is closed, it is enumerated in Go, and a row somebody
    -- could INSERT into a lookup table is a role somebody could invent.
    role text NOT NULL,

    -- Offboarding. Set, never cleared — re-granting access is a new
    -- provisioning by a second person, which is an audited act, and a column
    -- that can be un-set is a column that turns offboarding into a toggle.
    disabled_at timestamptz,

    provisioned_at timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT operator_account_binding_unique UNIQUE (issuer, provider_subject),
    CONSTRAINT operator_account_role_known CHECK (
        role IN ('support', 'billing_ops', 'catalogue_admin', 'operator_admin')
    )
);

COMMENT ON TABLE operator_account IS
    'Operators (ADR-024, operator.md §3). Projection of the operator- streams. No personal data: the employee address is in the vault under subject_id.';


-- ---------------------------------------------------------------------------
-- operator_credential — WebAuthn material for operators
-- ---------------------------------------------------------------------------
-- NOT rebuildable from the log, for the same reason passkey_credential is not:
-- a public key never enters an event. The event records that a credential was
-- enrolled and its id; the material lives here.
--
-- It deliberately does NOT reference operator_account. That is migration 00033's
-- lesson applied before it can bite: a foreign key from an authoritative table
-- to a PROJECTION means rebuilding the projection either deletes the
-- authoritative rows (ON DELETE CASCADE) or is refused outright (TRUNCATE on a
-- referenced table). Here it would mean rebuilding operator_account destroys
-- every operator's authenticator, which is a lockout of the entire back office.
CREATE TABLE operator_credential (
    -- Unique across the whole table, not per operator — WebAuthn L3 §7.1
    -- step 27, and the primary key so the uniqueness is the table's shape
    -- rather than an index somebody could drop.
    credential_id text PRIMARY KEY,

    operator_id text NOT NULL,

    public_key bytea NOT NULL,
    sign_count bigint NOT NULL DEFAULT 0,

    aaguid          bytea,
    transports      text[],
    backup_eligible boolean NOT NULL DEFAULT false,
    backup_state    boolean NOT NULL DEFAULT false,

    label text,

    created_at      timestamptz NOT NULL DEFAULT now(),
    last_used_at    timestamptz,
    clone_warned_at timestamptz,

    CONSTRAINT operator_credential_id_len CHECK (length(credential_id) BETWEEN 1 AND 1024),
    CONSTRAINT operator_credential_key_present CHECK (octet_length(public_key) > 0),
    CONSTRAINT operator_credential_count_unsigned CHECK (sign_count >= 0)
);

CREATE INDEX operator_credential_operator_idx
    ON operator_credential (operator_id, created_at DESC);

COMMENT ON TABLE operator_credential IS
    'WebAuthn credentials for operators. Authoritative, NOT rebuildable — a public key never enters an event. Intentionally no FK to operator_account: see migration 00033.';


-- ---------------------------------------------------------------------------
-- operator_session — the bearer tokens, in two stages
-- ---------------------------------------------------------------------------
-- Authoritative, like session_token. Holds a DIGEST, never a token: the
-- plaintext is returned to one caller and never stored, so a dump of this table
-- does not authenticate anybody.
--
-- # The two stages are the whole sign-in design
--
-- operator.md §3 requires SSO **and** mandatory WebAuthn. Two separate proofs
-- means an intermediate state, and the safe way to represent it is a token that
-- exists but authorizes nothing except the step that completes it. A single
-- boolean "mfa_done" on a full session would mean the window between the two
-- proofs is a live session with a flag — and every future endpoint would have
-- to remember to read the flag.
CREATE TABLE operator_session (
    token_digest bytea PRIMARY KEY,

    session_id  text NOT NULL UNIQUE,
    operator_id text NOT NULL,

    -- 'sso_only' may call the WebAuthn pair and nothing else. 'live' may call
    -- what the operator's role permits. There is no third value and no
    -- transition back.
    stage text NOT NULL,

    -- ABSOLUTE, and never moved. operator.md §3: "sessions are short and
    -- non-extendable; no remember me". There is deliberately no idle deadline —
    -- an idle timeout that renews on activity IS extension, and the pair of
    -- them is how a session that was supposed to last thirty minutes lasts a
    -- working day.
    expires_at timestamptz NOT NULL,

    -- Set by sign-out. Distinct from expiry so the audit trail can tell an
    -- ended session from a lapsed one.
    ended_at timestamptz,

    -- The origin, for the IP restriction operator.md §3 requires and for the
    -- anomaly detection §5 describes.
    from_ip inet,

    -- Which authenticator completed the sign-in, for "a credential we have not
    -- seen before" alerting. NULL while the session is still sso_only.
    credential_id text,

    created_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT operator_session_stage_known CHECK (stage IN ('sso_only', 'live')),
    CONSTRAINT operator_session_digest_len CHECK (octet_length(token_digest) = 32)
);

CREATE INDEX operator_session_operator_idx ON operator_session (operator_id, created_at DESC);

-- Sweeping dead sessions. Partial, so it indexes only what the sweep scans.
CREATE INDEX operator_session_expiry_idx ON operator_session (expires_at)
    WHERE ended_at IS NULL;

COMMENT ON COLUMN operator_session.expires_at IS
    'Absolute and never moved. Non-extendable by design (operator.md §3) — there is deliberately no idle deadline, because an idle timeout that renews on activity is extension.';


-- ---------------------------------------------------------------------------
-- operator_ceremony — short-lived state for a sign-in in progress
-- ---------------------------------------------------------------------------
-- The OIDC state/nonce/PKCE verifier, and the WebAuthn challenge. Authoritative
-- and short-lived; every row has a deadline and the sweep removes it.
--
-- In Postgres rather than in Valkey deliberately. A ceremony is single-use, and
-- single use means the consume must be atomic against a concurrent replay —
-- `UPDATE … WHERE consumed_at IS NULL RETURNING` gives that in one statement.
-- The equivalent in a cache is a compare-and-delete that has to be right; here
-- the database is the thing that is right.
CREATE TABLE operator_ceremony (
    ceremony_id text PRIMARY KEY,

    -- 'oidc', 'webauthn_login' or 'webauthn_enrol'.
    kind text NOT NULL,

    -- NULL for 'oidc': who is signing in is not known until the IdP answers,
    -- and a ceremony that named an operator before the answer would be a
    -- ceremony an unauthenticated caller could aim at a chosen account.
    operator_id text,

    -- The ceremony's own serialized state. Opaque here on purpose: what an OIDC
    -- ceremony carries and what a WebAuthn one carries have nothing in common,
    -- and columns for the union of both would be mostly NULL and would invite a
    -- query that reads the wrong half.
    payload bytea NOT NULL,

    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT operator_ceremony_kind_known CHECK (
        kind IN ('oidc', 'webauthn_login', 'webauthn_enrol')
    )
);

CREATE INDEX operator_ceremony_expiry_idx ON operator_ceremony (expires_at)
    WHERE consumed_at IS NULL;


-- ---------------------------------------------------------------------------
-- operator_audit_log — every operator action, reads included
-- ---------------------------------------------------------------------------
-- Projection of the operatoraudit- streams. Rebuildable, which matters more
-- here than elsewhere: an audit table that could only be corrected by UPDATE
-- would be an audit table somebody could correct.
CREATE TABLE operator_audit_log (
    entry_id text PRIMARY KEY,

    operator_id         text NOT NULL,
    operator_subject_id text NOT NULL,

    -- 'signed_in', 'signed_out', 'viewed_customer', 'viewed_personal_data'.
    action text NOT NULL,

    -- The full RPC name. The audit's unit is the action, and the action is the
    -- method.
    method text NOT NULL,

    -- The tenant, when the action named one. NULL on a list view, which is an
    -- aggregate over many tenants — naming one of them would be false.
    org_id text,

    -- The person whose data was resolved, on a personal-data read. A pseudonym,
    -- so this row stays non-identifying after their erasure.
    target_subject_id text,

    -- Which vault fields were resolved. Names only, never values.
    fields text[],

    -- The operator's recorded justification, on a personal-data read. The one
    -- free-text column in the operator plane; see the event's own comment for
    -- why it is here and what it costs.
    reason text,

    from_ip inet,

    occurred_at timestamptz NOT NULL,

    CONSTRAINT operator_audit_action_known CHECK (
        action IN ('signed_in', 'signed_out', 'viewed_customer', 'viewed_personal_data')
    ),
    -- The invariant the domain also enforces, asserted here so a projection bug
    -- cannot land an unjustified personal-data read.
    CONSTRAINT operator_audit_personal_data_justified CHECK (
        action <> 'viewed_personal_data'
        OR (target_subject_id IS NOT NULL AND reason IS NOT NULL AND length(reason) > 0)
    )
);

-- "What did this operator do", the anomaly-detection query.
CREATE INDEX operator_audit_operator_idx ON operator_audit_log (operator_id, occurred_at DESC);

-- "Who looked at us", the query operator.md §5 promises tenants. Partial,
-- because an entry with no org is not part of any tenant's history.
CREATE INDEX operator_audit_org_idx ON operator_audit_log (org_id, occurred_at DESC)
    WHERE org_id IS NOT NULL;

COMMENT ON TABLE operator_audit_log IS
    'Every operator action, reads included (operator.md §5). Under GDPR looking is processing. Stores SubjectID pseudonyms only, so entries survive erasure as non-identifying facts.';


-- ---------------------------------------------------------------------------
-- operator_customer_list — the customer directory
-- ---------------------------------------------------------------------------
-- Projection of organization and billing events, with a REDUCED field set.
--
-- # The columns that are absent are the design
--
-- operator.md §4: "the operator read models are built to contain only what
-- operators may see, so there is no query that COULD return customer content —
-- the columns do not exist in the projection". Every column below is org-level:
-- a status, a plan, a count, an instant. There is no member list, no email, no
-- workspace name, no content of any kind, and TestOperatorProjectionsHoldNoPersonalData
-- asserts that against the live schema so a later migration cannot quietly add
-- one.
--
-- org_name is the one column worth defending. It is tenant-provided business
-- data rather than vault data, it is what makes a directory usable at all, and
-- an operator who cannot see who a customer is cannot answer their ticket. It
-- is also the column to revisit first if the minimisation rule is ever
-- tightened, because a sole trader's company name can be their own.
CREATE TABLE operator_customer_list (
    org_id text PRIMARY KEY,

    slug     text NOT NULL,
    org_name text NOT NULL,

    -- organization.md's lifecycle: active, past_due, suspended, closed.
    lifecycle_state text NOT NULL,

    plan_id         text,
    plan_version_id text,

    -- Stripe's subscription status, mirrored. Nullable: an org on a cardless
    -- trial has no subscription yet.
    subscription_status text,
    trial_ends_at       timestamptz,

    -- Coarse aggregates only (operator.md §2: "minimal activity").
    workspace_count integer NOT NULL DEFAULT 0,
    member_count    integer NOT NULL DEFAULT 0,
    last_active_at  timestamptz,

    signup_source text,

    -- Support context: "is this org suspended, why, and since when".
    suspended_at      timestamptz,
    suspension_reason text,

    org_created_at timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT operator_customer_counts_unsigned CHECK (
        workspace_count >= 0 AND member_count >= 0
    )
);

CREATE INDEX operator_customer_state_idx ON operator_customer_list (lifecycle_state, org_created_at DESC);
CREATE INDEX operator_customer_name_idx ON operator_customer_list (lower(org_name));

COMMENT ON TABLE operator_customer_list IS
    'The customer directory (operator.md §9). Org-level columns only — minimisation is structural, and TestOperatorProjectionsHoldNoPersonalData asserts it against this schema.';


-- ---------------------------------------------------------------------------
-- The grants, in both directions
-- ---------------------------------------------------------------------------
-- This block is the isolation. Everything above is just tables.

-- The operator plane gets exactly these six, enumerated.
GRANT SELECT, INSERT, UPDATE, DELETE ON operator_account       TO chronos_operator;
GRANT SELECT, INSERT, UPDATE, DELETE ON operator_credential    TO chronos_operator;
GRANT SELECT, INSERT, UPDATE, DELETE ON operator_session       TO chronos_operator;
GRANT SELECT, INSERT, UPDATE, DELETE ON operator_ceremony      TO chronos_operator;
GRANT SELECT, INSERT, UPDATE, DELETE ON operator_audit_log     TO chronos_operator;
GRANT SELECT, INSERT, UPDATE, DELETE ON operator_customer_list TO chronos_operator;

-- TRUNCATE on the two PROJECTIONS only, because a rebuild truncates and the
-- other four are authoritative. Withholding it from operator_credential is what
-- makes "a rebuild cannot destroy the back office's authenticators" a property
-- of the grant rather than of the code that happens not to try.
GRANT TRUNCATE ON operator_account       TO chronos_operator;
GRANT TRUNCATE ON operator_audit_log     TO chronos_operator;
GRANT TRUNCATE ON operator_customer_list TO chronos_operator;

-- Its projectors need to record where they are. Shared with the tenant plane's,
-- keyed by projection name; the alternative is a second checkpoint table whose
-- only difference is who writes it.
GRANT SELECT, INSERT, UPDATE ON projection_checkpoint TO chronos_operator;

-- And the other direction: chronos_app is REVOKED from all six.
--
-- Necessary because infra/postgres/init/02-app-role.sql sets DEFAULT PRIVILEGES
-- granting chronos_app every future table — which is right for tenant tables
-- and is exactly wrong here. Without these revokes, "the operator plane is
-- separate" would be true of the Go packages and false of the database, and the
-- database is where the data is.
REVOKE ALL ON operator_account       FROM chronos_app;
REVOKE ALL ON operator_credential    FROM chronos_app;
REVOKE ALL ON operator_session       FROM chronos_app;
REVOKE ALL ON operator_ceremony      FROM chronos_app;
REVOKE ALL ON operator_audit_log     FROM chronos_app;
REVOKE ALL ON operator_customer_list FROM chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS operator_customer_list;
DROP TABLE IF EXISTS operator_audit_log;
DROP TABLE IF EXISTS operator_ceremony;
DROP TABLE IF EXISTS operator_session;
DROP TABLE IF EXISTS operator_credential;
DROP TABLE IF EXISTS operator_account;

-- The role is left in place. Dropping it would fail on any object it still
-- owns or is granted, and a Down that sometimes fails is worse than one that
-- leaves a login role with no grants — which is what this is.
REVOKE ALL ON projection_checkpoint FROM chronos_operator;
-- +goose StatementEnd

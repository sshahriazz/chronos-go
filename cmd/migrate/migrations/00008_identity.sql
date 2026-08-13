-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- identity — accounts, credentials, sessions
-- ---------------------------------------------------------------------------
-- NONE of these tables are tenant-scoped, and none carry RLS. A user exists
-- before they belong to any organization — registration happens with no org in
-- context at all — so there is no workspace_id to SET LOCAL and a policy here
-- could never be satisfied. They are reached through db.SystemTX only, the same
-- path the PII vault uses (ADR-011, ADR-013).
--
-- That is a second access path, and it has to be audited as one: an identity
-- query that accidentally went through InTenantTx would fail, but one that
-- reaches these tables from a tenant-scoped handler is not stopped by anything
-- here. The boundary is the transaction helper, not the row.
--
-- NO PERSONAL DATA. No email, no name, no IP, no device label, no user agent.
-- Every table below holds a subject_id pseudonym and the vault resolves it at
-- read time (compliance.md §1). The one apparent exception is email_index,
-- which is a keyed HMAC and not reversible without a key that is not in this
-- database.

-- ---------------------------------------------------------------------------
-- user_view — the account projection
-- ---------------------------------------------------------------------------
-- Rebuildable from the log by replaying identity.User* events.
CREATE TABLE user_view (
    subject_id text PRIMARY KEY,
    user_id    text NOT NULL UNIQUE,

    -- Keyed HMAC of the normalized address (ADR-044). UNIQUE, and the constraint
    -- is a backstop rather than the mechanism: uniqueness is enforced at write
    -- time by the reservation stream, because a projection is by definition
    -- behind the log and two concurrent registrations would both read "free".
    --
    -- If this ever fires, the reservation mechanism has failed and the projector
    -- stops — which is the correct direction for that failure.
    email_index text NOT NULL UNIQUE,

    state          text        NOT NULL,
    email_verified boolean     NOT NULL DEFAULT false,
    registered_at  timestamptz NOT NULL,
    activated_at   timestamptz,
    deactivated_at timestamptz,
    suspended_at   timestamptz,

    CONSTRAINT user_view_state CHECK (
        state IN ('pending', 'active', 'deactivated', 'suspended')
    )
);

COMMENT ON TABLE user_view IS
    'Account projection. No personal data: subject_id and a keyed email index only.';

CREATE INDEX user_view_state_idx ON user_view (state);

-- ---------------------------------------------------------------------------
-- credential — authentication methods
-- ---------------------------------------------------------------------------
-- NOT rebuildable from the log, deliberately, and it is the one identity table
-- that is not.
--
-- The password verifier and the TOTP secret cannot go into events: an event is
-- permanent and readable by anyone who can replay, so a verifier there would
-- survive the user changing their password, survive erasure of everything else,
-- and be offline-crackable forever. The log records THAT a password was set;
-- this table holds what verifies it (identity.md §4).
--
-- The consequence is that a rebuild from position zero reconstructs every other
-- identity table and not this one. That is understood and accepted: losing this
-- table means every user resets their password, which is recoverable. Putting
-- its contents in the log is not.
CREATE TABLE credential (
    credential_id text PRIMARY KEY,
    subject_id    text NOT NULL REFERENCES user_view (subject_id) ON DELETE CASCADE,

    kind text NOT NULL,

    -- For a password: the full PHC-shaped verifier, including the Argon2id
    -- parameters, the salt and the GCM-sealed digest. For TOTP: NULL, because
    -- the secret lives in the vault under the subject's key.
    verifier text,

    -- Pepper key version, duplicated from inside the verifier so the rotation
    -- job can find rows at an old version without parsing every row.
    --
    -- Written by the same statement that writes the verifier, never separately.
    -- A generated column would be better — the two could not then disagree — but
    -- generating it means parsing a PHC-shaped string in SQL, and a parser
    -- split across Go and Postgres is worse than one duplicated integer.
    --
    -- If they ever DO disagree, the verifier wins: it is what the hasher reads.
    -- This column only decides which rows the rotation job visits, so a stale
    -- value means a row is re-hashed unnecessarily or missed by one pass.
    pepper_version integer,

    enabled_at  timestamptz,
    disabled_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,

    failures integer NOT NULL DEFAULT 0,

    CONSTRAINT credential_kind CHECK (
        kind IN ('password', 'totp', 'recovery_code', 'passkey', 'federated')
    ),

    -- A password credential without a verifier cannot verify anything, and its
    -- presence would satisfy the "at least one usable method" invariant while
    -- being unusable — locking the account out with no error anywhere.
    CONSTRAINT password_has_a_verifier CHECK (
        kind <> 'password' OR verifier IS NOT NULL
    )
);

COMMENT ON TABLE credential IS
    'Authentication methods. NOT rebuildable from the log: verifiers never enter events.';

-- One usable password and one usable TOTP per account.
--
-- A partial unique index rather than a table constraint, because DISABLED
-- credentials may accumulate — a rebound authenticator leaves the old row — and
-- only the usable ones are constrained.
CREATE UNIQUE INDEX credential_one_usable_per_kind_idx
    ON credential (subject_id, kind)
    WHERE disabled_at IS NULL AND kind IN ('password', 'totp', 'recovery_code');

CREATE INDEX credential_subject_idx ON credential (subject_id);
CREATE INDEX credential_pepper_version_idx ON credential (pepper_version)
    WHERE kind = 'password';

-- ---------------------------------------------------------------------------
-- recovery_code — single-use fallback codes
-- ---------------------------------------------------------------------------
-- Digests only. SHA-256 rather than Argon2id: a recovery code is generated by
-- crypto/rand, so there is no candidate list to search and a slow hash would buy
-- nothing (see internal/modules/identity/adapter/token).
CREATE TABLE recovery_code (
    subject_id    text  NOT NULL REFERENCES user_view (subject_id) ON DELETE CASCADE,
    credential_id text  NOT NULL REFERENCES credential (credential_id) ON DELETE CASCADE,
    digest        bytea NOT NULL,

    consumed_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (subject_id, digest),

    CONSTRAINT recovery_code_digest_len CHECK (octet_length(digest) = 32)
);

COMMENT ON TABLE recovery_code IS
    'Single-use recovery codes, stored as SHA-256 digests. Consumed, never deleted.';

-- Counting what remains is the common read: the low-codes-remaining warning.
CREATE INDEX recovery_code_unused_idx
    ON recovery_code (subject_id) WHERE consumed_at IS NULL;

-- ---------------------------------------------------------------------------
-- totp_replay — RFC 6238 §5.2
-- ---------------------------------------------------------------------------
-- THE UNIQUE CONSTRAINT IS THE MECHANISM. It is not a backstop for application
-- logic; it IS the atomicity the replay guard's port contract requires.
--
-- The obvious implementation — SELECT, then INSERT if absent — races two
-- simultaneous presentations of the same code and both win, which is exactly the
-- concurrency an attacker relaying a code produces. `INSERT ... ON CONFLICT DO
-- NOTHING` with this constraint decides it in one statement.
--
-- Without any of this, an observed code — a screenshot, a log line, a phishing
-- relay — is presentable again for the whole 90-second acceptance window.
CREATE TABLE totp_replay (
    credential_id text   NOT NULL REFERENCES credential (credential_id) ON DELETE CASCADE,

    -- The RFC 6238 time step: unix seconds divided by the 30-second period.
    step bigint NOT NULL,

    used_at    timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,

    PRIMARY KEY (credential_id, step)
);

COMMENT ON TABLE totp_replay IS
    'Spent TOTP time steps. The primary key IS the replay guard, not a backstop for it.';

-- The sweep deletes by expiry; without this it scans the whole table.
CREATE INDEX totp_replay_expiry_idx ON totp_replay (expires_at);

-- ---------------------------------------------------------------------------
-- identity_token — single-use emailed secrets
-- ---------------------------------------------------------------------------
-- Digests only. The plaintext exists in exactly one place — the email that was
-- sent — and never reaches this database or a log line.
--
-- The digest is the PRIMARY KEY, and the purpose is mixed INTO it rather than
-- stored beside it, so a verification token cannot be redeemed as a reset even
-- by a query that forgot to filter.
CREATE TABLE identity_token (
    digest     bytea PRIMARY KEY,
    purpose    text  NOT NULL,
    subject_id text  NOT NULL REFERENCES user_view (subject_id) ON DELETE CASCADE,

    issued_at  timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,

    CONSTRAINT identity_token_purpose CHECK (
        purpose IN ('email_verification', 'password_reset')
    ),
    CONSTRAINT identity_token_digest_len CHECK (octet_length(digest) = 32)
);

COMMENT ON TABLE identity_token IS
    'Single-use emailed secrets, as digests. Consumed by DELETE ... RETURNING.';

-- "Void every other outstanding token for this subject" (identity.md §7 rule 7)
-- and the expiry sweep.
CREATE INDEX identity_token_subject_idx ON identity_token (subject_id, purpose);
CREATE INDEX identity_token_expiry_idx  ON identity_token (expires_at);

-- ---------------------------------------------------------------------------
-- session_view — one row per live session
-- ---------------------------------------------------------------------------
-- The idle deadline lives HERE and not in the log, because it moves on every
-- request: recording that movement as an event would make every authenticated
-- read a write. The absolute deadline is in the log and is duplicated here so a
-- single lookup answers both.
CREATE TABLE session_view (
    session_id text PRIMARY KEY,

    -- SHA-256 of the opaque bearer token. The token itself is never stored, so a
    -- database dump yields digests that cannot be presented.
    token_digest bytea NOT NULL UNIQUE,

    subject_id text NOT NULL REFERENCES user_view (subject_id) ON DELETE CASCADE,

    -- Pseudonym. The device NAME, platform and address are personal data and
    -- live in the vault under this id.
    device_id text,

    aal integer NOT NULL,

    idle_expires_at     timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,

    -- Restricts the session to profile and credential endpoints. Set when the
    -- password that established it was found in a breach corpus.
    requires_credential_rotation boolean NOT NULL DEFAULT false,

    elevated_scope text,
    elevated_until timestamptz,

    created_at   timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    revoked_at   timestamptz,

    CONSTRAINT session_view_aal CHECK (aal IN (1, 2)),
    CONSTRAINT session_view_digest_len CHECK (octet_length(token_digest) = 32),

    -- An idle deadline beyond the absolute one never fires, so the session would
    -- have one deadline while appearing to have two.
    CONSTRAINT session_view_idle_within_absolute CHECK (
        idle_expires_at <= absolute_expires_at
    ),

    -- An elevation must name a scope AND a deadline, or neither. One without the
    -- other is a step-up that either never expires or applies to everything.
    CONSTRAINT session_view_elevation_is_complete CHECK (
        (elevated_scope IS NULL AND elevated_until IS NULL) OR
        (elevated_scope IS NOT NULL AND elevated_until IS NOT NULL)
    )
);

COMMENT ON TABLE session_view IS
    'Live sessions. Token stored as a digest; idle deadline is authoritative here, not in the log.';

CREATE INDEX session_view_subject_idx ON session_view (subject_id)
    WHERE revoked_at IS NULL;
CREATE INDEX session_view_expiry_idx  ON session_view (absolute_expires_at)
    WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- login_history_view — every authentication outcome
-- ---------------------------------------------------------------------------
-- subject_id is NULLABLE, and that is the point: an attempt for an identifier
-- with no account has no subject. Inventing one would create a permanent record
-- keyed to a person who does not exist here, while the attempt still has to be
-- counted for stuffing detection — which is what email_index is for.
CREATE TABLE login_history_view (
    id          bigserial PRIMARY KEY,
    subject_id  text REFERENCES user_view (subject_id) ON DELETE CASCADE,
    email_index text,

    succeeded boolean NOT NULL,
    reason    text,
    methods   text[],
    aal       integer,
    device_id text,

    occurred_at timestamptz NOT NULL,

    -- A failure must say why, and a success must not pretend to have one.
    CONSTRAINT login_history_reason CHECK (
        (succeeded AND reason IS NULL) OR (NOT succeeded AND reason IS NOT NULL)
    )
);

COMMENT ON TABLE login_history_view IS
    'Authentication outcomes. subject_id is NULL when the identifier matched no account.';

-- The account activity view reads newest-first per subject; keyset pagination
-- needs the id to break ties (platform/page).
CREATE INDEX login_history_subject_idx
    ON login_history_view (subject_id, occurred_at DESC, id DESC);

-- Credential-stuffing detection reads by identifier across accounts.
CREATE INDEX login_history_index_idx
    ON login_history_view (email_index, occurred_at DESC)
    WHERE email_index IS NOT NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON user_view          TO chronos_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON credential         TO chronos_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON recovery_code      TO chronos_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON totp_replay        TO chronos_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON identity_token     TO chronos_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON session_view       TO chronos_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON login_history_view TO chronos_app;
GRANT USAGE, SELECT ON SEQUENCE login_history_view_id_seq  TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS login_history_view;
DROP TABLE IF EXISTS session_view;
DROP TABLE IF EXISTS identity_token;
DROP TABLE IF EXISTS totp_replay;
DROP TABLE IF EXISTS recovery_code;
DROP TABLE IF EXISTS credential;
DROP TABLE IF EXISTS user_view;
-- +goose StatementEnd

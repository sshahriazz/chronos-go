-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- api_key_view + api_key_secret — the SAME split session_view/session_token made
-- ---------------------------------------------------------------------------
-- Migration 00010 settled the rule and it is mechanical rather than
-- case-by-case:
--
--   IN THE LOG        -> projection. Truncated and replayed on rebuild.
--   NOT IN THE LOG    -> authoritative. Never truncated, never reconstructed.
--
-- A key's FACTS — who owns it, which organization it is bound to, what it may
-- do, when it expires, whether it was revoked — are all in the event log, so
-- they are a projection. Its SECRET is not and never will be: a digest in an
-- append-only log outlives every mechanism that could remove it. Its
-- `last_used_at` is not either, for the reason identity.md §13 gives at length
-- — an event per request makes the log grow with traffic rather than with
-- state, and the cost lands at rebuild time.
--
-- So: two tables. And here is the ONE place this deliberately diverges from the
-- session pair, because the divergence is a decision somebody will otherwise
-- read as an oversight.
--
-- `GetSessionByToken` INNER JOINs the secret to the projection, so a session
-- resolves only when both rows exist and a projection rebuild signs everybody
-- out for its duration. That is the right trade for humans: they sign in again.
-- It is the WRONG trade for machines. A rebuild that broke every integration in
-- the fleet — CI, deploys, webhooks, whatever a customer built — is an outage
-- with no human in the loop to recover from it, and it would be triggered by
-- routine maintenance on an unrelated projection.
--
-- So the authenticator resolves an API key from `api_key_secret` ALONE, and the
-- three facts it needs that are also in the log — the org binding, the owner
-- and the scopes — are written onto the secret row by the command handler that
-- minted it. They cannot drift from the projection, because nothing edits
-- either: there is no command that changes a key's scopes, owner or
-- organization. Changing any of them means a new key, by design (identity.md
-- §10).
--
-- Revocation is then structural rather than a flag anybody has to remember to
-- check: it DELETES the secret rows, so a revoked key has nothing to resolve.
-- `api_key_view.revoked_at` exists for the management screen and for the
-- rebuildable record of what happened, not as the enforcement.

-- ---------------------------------------------------------------------------
-- api_key_view — PROJECTION
-- ---------------------------------------------------------------------------
CREATE TABLE api_key_view (
    key_id text PRIMARY KEY,

    -- The IMMUTABLE organization binding (identity.md §10, review D2).
    --
    -- A person may belong to several organizations. Without this column a key
    -- silently inherits all of them, and a token leaked from one customer's CI
    -- reaches another customer's data — a cross-tenant breach originating in a
    -- feature nobody thought was tenant-scoped. Nothing updates it; moving
    -- scope means a new key.
    org_id text NOT NULL,

    -- The owner, as a TAGGED PAIR and never as two nullable columns.
    --
    -- Two nullable owner columns admit the row with both set and the row with
    -- neither, and both have to be interpreted by whoever reads them — which
    -- puts the interpretation in every reader instead of in the schema. Here
    -- "exactly one owner, of a known kind" is the only representable shape, and
    -- the id's own prefix is a second, independent check on the kind: the
    -- CHECK below refuses `service_account` paired with a `subj_` id, so a
    -- value that flipped the kind alone does not survive the write.
    owner_kind text NOT NULL,
    owner_id   text NOT NULL,

    -- The coarse capability list, `<resource type>:<read|write>`.
    --
    -- Projected from the event rather than only stored here, which is what
    -- makes the narrowing REPLAYABLE: the gate reads this column, and a rebuild
    -- reproduces exactly the scopes the log recorded. A scopes column that was
    -- only ever written by a handler could be widened by a bug with nothing in
    -- the log to contradict it.
    --
    -- The key's effective permission is the intersection of these and its
    -- OWNER's access (access.md §4). This column can only ever narrow.
    scopes text[] NOT NULL,

    -- Mandatory expiry with a policy-capped maximum (domain.MaxAPIKeyLifetime).
    -- Moves only on rotation, which re-arms the clock rather than inheriting the
    -- old deadline.
    expires_at timestamptz NOT NULL,

    -- Set by ApiKeyRevoked. The projection's half of an immediate revocation —
    -- the other half deletes the secret rows in the same request, because
    -- neither alone closes the window (operator/app/operators.go, Disable).
    revoked_at timestamptz,

    created_by text NOT NULL,
    created_at timestamptz NOT NULL,

    -- The most recent rotation, so a management screen can say when the secret
    -- last changed without reading the log. NULL for a key never rotated.
    rotated_at timestamptz,

    -- COALESCED, at most once per key per minute, and deliberately approximate
    -- (identity.md §10, §13). It is derived, it is rebuildable from nothing
    -- because nobody needs its history, and "last used about a minute ago" is
    -- the whole product requirement. It is NOT projected from an event, and
    -- there is deliberately no `ApiKeyUsed` — an event per request would make
    -- the log grow with traffic rather than with state.
    --
    -- The practical consequence, stated so it is not discovered: a projection
    -- rebuild CLEARS this column, because no replay can restore it. That is
    -- correct and harmless — the screen loses a hint, not a fact — and it is
    -- why this is the one column here nothing else depends on.
    last_used_at timestamptz,

    CONSTRAINT api_key_owner_kind CHECK (owner_kind IN ('user', 'service_account')),

    -- The kind and the id must agree. See owner_kind above: this is what makes
    -- a flipped kind fail to write rather than silently name whichever
    -- principal happened to share the id.
    CONSTRAINT api_key_owner_shape CHECK (
        (owner_kind = 'user'            AND owner_id LIKE 'subj\_%') OR
        (owner_kind = 'service_account' AND owner_id LIKE 'svc\_%')
    ),

    -- A key with no scopes can do nothing, which is useless rather than
    -- dangerous — but it is also exactly what a list dropped somewhere between
    -- the client and here looks like, and the second reading is the one worth
    -- refusing at the write. domain.normalizeScopes says the same thing one
    -- layer up.
    CONSTRAINT api_key_scopes_present CHECK (cardinality(scopes) BETWEEN 1 AND 32)
);

COMMENT ON TABLE api_key_view IS
    'PROJECTION. A key''s facts: owner, org binding, scopes, expiry, revocation. Holds NO secret — see api_key_secret. Rebuildable from the log, which signs every key out for the duration.';

COMMENT ON COLUMN api_key_view.last_used_at IS
    'Coalesced, at most once per key per minute, approximate by construction, and NOT projected from an event (identity.md §13). A rebuild clears it, which loses a hint and no fact.';

ALTER TABLE api_key_view ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_key_view FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON api_key_view
    USING (org_id = current_setting('app.org_id', true))
    WITH CHECK (org_id = current_setting('app.org_id', true));

-- identity.md §14 asks for `(key_id)` unique — that is the primary key above —
-- and `(owner_id, status)`. Status is `revoked_at IS NULL` here, so the index is
-- partial over the live keys, which is the set every screen and every
-- "revoke everything this owner has" sweep actually wants.
CREATE INDEX api_key_view_owner_idx
    ON api_key_view (owner_id) WHERE revoked_at IS NULL;

-- The management screen, newest first, in keyset order (platform/page).
CREATE INDEX api_key_view_org_idx
    ON api_key_view (org_id, created_at DESC, key_id DESC);

GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON api_key_view TO chronos_app;

-- ---------------------------------------------------------------------------
-- api_key_secret — AUTHORITATIVE
-- ---------------------------------------------------------------------------
-- The digest, and nothing that is in the log.
--
-- # No row-level security, and that is a decision rather than an omission
--
-- This table is read by the AUTHENTICATOR, which runs before gate 1 — before
-- any organization is known, because establishing which organization the
-- request is in is the next gate's job. A policy on `app.org_id` would return
-- nothing to it, and every API key in the system would fail to resolve. It is
-- the same position `session_token` is in and it is safe for the same reason:
-- the row's ONLY key is a 256-bit digest nobody can guess, and the query is a
-- primary-key probe on it.
--
-- The `org_id` column here is therefore not an isolation control, it is the
-- ANSWER gate 1 uses: a key names its own organization, so a request
-- authenticated with one cannot be pointed at another by a header.
CREATE TABLE api_key_secret (
    -- SHA-256 of the WHOLE presented token — environment, key id and secret
    -- together — under a domain separator (app.APIKeyTokenDigest). The token
    -- itself is never stored, so a database dump yields digests that cannot be
    -- presented.
    --
    -- Digesting the whole token rather than the secret alone is what binds the
    -- three parts: a token pairing key A's id with key B's secret hashes to
    -- nothing, and a staging token replayed against production hashes to
    -- nothing, without either needing a comparison anybody could forget.
    token_digest bytea PRIMARY KEY,

    -- No foreign key to api_key_view, deliberately: that table is truncated on
    -- every rebuild, and a constraint here would either block the rebuild or
    -- cascade this row away with it — destroying secrets no replay can restore.
    -- The same reasoning as session_token (migration 00010).
    --
    -- NOT unique. A rotation deliberately leaves TWO live secrets for one key
    -- during its overlap window, which is the whole mechanism that lets a key
    -- be rotated without an outage.
    key_id text NOT NULL,

    -- The bound organization. Not an isolation control — see the note above —
    -- but the ANSWER gate 1 uses: a key names its own organization, so a
    -- request authenticated with one cannot be pointed at another by a header.
    org_id text NOT NULL,

    -- The owner and the scopes, copied from the aggregate's own decision at the
    -- moment the secret was issued. See the header: they are here so a machine
    -- request never depends on a projection, and they cannot drift because
    -- nothing edits either — changing a key's owner, scopes or organization
    -- means a new key.
    --
    -- The same tagged-pair CHECK as api_key_view, and it is not redundant: this
    -- table is written by a different code path (a command handler rather than
    -- a projector), so a bug in one does not reach the other, and the constraint
    -- is what makes that true rather than hoped for.
    owner_kind text NOT NULL,
    owner_id   text NOT NULL,
    scopes     text[] NOT NULL,

    -- The key's own deadline at the time this secret was issued.
    expires_at timestamptz NOT NULL,

    -- When this secret retires, which is the ROTATION mechanism.
    --
    -- NULL for the current secret. Set to `rotated_at + overlap` on the secret a
    -- rotation supersedes, so the old secret stops resolving at a deadline
    -- recorded at the moment of the rotation — whether or not any sweep has run.
    --
    -- That is the difference between this and "mark the old secret for
    -- deletion". A mark is honoured by whoever remembers to read it, and the
    -- failure of forgetting is a superseded secret that stays live forever,
    -- which is exactly the situation a rotation performed after a leak was meant
    -- to end. The lookup compares against this column; the sweep only reclaims
    -- the row.
    retires_at timestamptz,

    created_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT api_key_secret_digest_len CHECK (octet_length(token_digest) = 32),
    CONSTRAINT api_key_secret_owner_kind CHECK (owner_kind IN ('user', 'service_account')),
    CONSTRAINT api_key_secret_owner_shape CHECK (
        (owner_kind = 'user'            AND owner_id LIKE 'subj\_%') OR
        (owner_kind = 'service_account' AND owner_id LIKE 'svc\_%')
    ),
    CONSTRAINT api_key_secret_scopes_present CHECK (cardinality(scopes) BETWEEN 1 AND 32)
);

COMMENT ON TABLE api_key_secret IS
    'AUTHORITATIVE, not a projection. API key digests, which are never in the log. No RLS: the authenticator reads it before any organization is known, and its only key is a 256-bit digest.';

COMMENT ON COLUMN api_key_secret.retires_at IS
    'When a superseded secret stops resolving. NULL for the current one. The lookup enforces it, so a rotation bounds the old secret whether or not the sweep has run.';

-- The revocation path and the leak response both work by key id: "delete every
-- secret this key ever had".
CREATE INDEX api_key_secret_key_idx ON api_key_secret (key_id);

-- The sweep reclaims rows past their expiry or their retirement; without this it
-- scans the whole table. Mirrors session_token_idle_idx.
CREATE INDEX api_key_secret_expiry_idx ON api_key_secret (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON api_key_secret TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS api_key_secret;
DROP TABLE IF EXISTS api_key_view;
-- +goose StatementEnd

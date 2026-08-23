-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- passkey_credential — one row per WebAuthn credential (ADR-057)
-- ---------------------------------------------------------------------------
-- A passkey does not fit `credential`'s shape, and the mismatch is not
-- cosmetic. That table holds ONE opaque `verifier` per row; a passkey needs
-- three values that behave completely differently:
--
--   credential ID  written once, read every ceremony, immutable, GLOBALLY unique
--   public key     written once, read every ceremony, immutable
--   sign count     written on EVERY successful login, mutable, monotonic
--
-- Packing them into one column makes the sign count unreadable by SQL, so the
-- monotonic comparison becomes a read-modify-write in Go and the atomic
-- `UPDATE … WHERE sign_count < $new` is unavailable.
--
-- # NOT rebuildable from the event log, and that is deliberate
--
-- It joins `credential` in that category. A public key never enters an event for
-- the same reason a verifier does not: the log is permanent and replicated, and
-- a credential ID plus a public key is exactly the pair the takeover below
-- needs. The event records THAT a passkey was registered and its id — never its
-- material.
--
-- # Not personal data either
--
-- So it is not in the vault. It is per-credential secret-adjacent material,
-- which is a third category with one existing member. Erasure DELETES the row
-- rather than shredding a key, because there is no subject key to destroy — a
-- difference from every other erasure path, stated here so it is not discovered
-- later.
CREATE TABLE passkey_credential (
    -- The raw credential ID, base64url as the authenticator produced it.
    --
    -- UNIQUE ACROSS THE WHOLE TABLE, not per subject, and that scope is the
    -- security control. WebAuthn L3 §7.1 step 27 requires verifying a credential
    -- ID is not already registered FOR ANY USER, and the spec's own rationale is
    -- an account takeover: an attacker who obtains a victim's credential ID and
    -- public key — neither of which is secret, both travel in an
    -- `allowCredentials` list — registers them as their own. If the RP replaces
    -- the victim's registration and the credentials are discoverable, the VICTIM
    -- IS SIGNED INTO THE ATTACKER'S ACCOUNT at their next attempt, and
    -- everything they do there is the attacker's.
    --
    -- A per-subject index would not catch that. This is the primary key, so the
    -- uniqueness is the table's own shape rather than an index somebody could
    -- drop.
    credential_id text PRIMARY KEY,

    subject_id text NOT NULL REFERENCES user_view (subject_id) ON DELETE CASCADE,

    -- The COSE public key, as bytes. Verification material, never displayed.
    public_key bytea NOT NULL,

    -- The authenticator's signature counter.
    --
    -- Its own column so the clone check is `UPDATE … WHERE sign_count < $new`,
    -- which is atomic. Zero is the ordinary value for a synced passkey: Apple
    -- and Google report 0 permanently, because there is no coherent place to
    -- keep a monotonic counter across N devices.
    sign_count bigint NOT NULL DEFAULT 0,

    -- Display material, immutable at registration. Listed apart from the public
    -- key only because it is shown to a person rather than used to verify.
    aaguid            bytea,
    transports        text[],
    backup_eligible   boolean NOT NULL DEFAULT false,
    backup_state      boolean NOT NULL DEFAULT false,
    user_verified     boolean NOT NULL DEFAULT false,

    -- The label the PERSON gave it, so a security screen can say "MacBook" and
    -- not a base64 blob. Free text they wrote about their own device.
    label text,

    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,

    -- Set when a sign count went BACKWARDS. A regression is not a hard deny —
    -- the spec lists an out-of-order race as a benign cause and this system
    -- treats concurrent sessions as ordinary — so it records the fact, raises an
    -- event and requires step-up.
    clone_warned_at timestamptz,

    CONSTRAINT passkey_credential_id_len CHECK (
        length(credential_id) BETWEEN 1 AND 1024
    ),
    CONSTRAINT passkey_public_key_present CHECK (octet_length(public_key) > 0),
    CONSTRAINT passkey_sign_count_unsigned CHECK (sign_count >= 0)
);

COMMENT ON TABLE passkey_credential IS
    'WebAuthn credentials (ADR-057). NOT rebuildable from the log: a public key never enters an event. credential_id is unique across every account — WebAuthn L3 §7.1 step 27.';

COMMENT ON COLUMN passkey_credential.sign_count IS
    'Authenticator signature counter. 0 is normal for synced passkeys. Advanced by an atomic UPDATE … WHERE sign_count < $new; a regression sets clone_warned_at and forces step-up rather than denying.';

-- "Which passkeys does this account have", for the security screen and for
-- building an allowCredentials list.
CREATE INDEX passkey_credential_subject_idx
    ON passkey_credential (subject_id, created_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON passkey_credential TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS passkey_credential;
-- +goose StatementEnd

-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- webauthn_challenge — one ceremony in flight
-- ---------------------------------------------------------------------------
-- # Why this is a table and not a cache entry
--
-- A challenge is single-use, and single-use has to be ATOMIC. The cache port
-- offers Get and Delete separately, so enforcing it there is a read-then-write
-- that two simultaneous finishes both win — one ceremony producing two
-- registrations, or two sessions. `identity_token` already solved exactly this
-- shape with `DELETE … RETURNING`, and identity.md §12 spells out why: "two
-- simultaneous clicks of one link would otherwise both find it valid".
--
-- It is the same argument, so it gets the same mechanism rather than a second,
-- weaker one.
--
-- # What it holds, and what it must not
--
-- The ceremony STATE, which is the library's session data: the challenge bytes,
-- the relying-party id, the allowed credential ids and the deadline. None of it
-- is personal data — the user handle in it is a SubjectID pseudonym (ADR-002) —
-- and none of it is a credential: it authenticates nothing on its own, which is
-- why it may live in a table a projector never touches.
--
-- It is NOT rebuildable from the log and is not meant to be. A ceremony that
-- does not complete is not a fact worth keeping; it expires and is swept.
CREATE TABLE webauthn_challenge (
    -- An opaque id handed to the browser and returned with the answer.
    --
    -- Needed because a DISCOVERABLE login has no subject yet — that is the
    -- point of usernameless sign-in — so the server cannot key the ceremony by
    -- whoever is at the keyboard. It is unguessable, and it is not a
    -- credential: holding one lets somebody complete a ceremony they still have
    -- to produce a valid signature for.
    challenge_id text PRIMARY KEY,

    -- NULL for a discoverable login, set for a registration.
    --
    -- Nullable rather than absent, because the two ceremonies differ in exactly
    -- this and a second table for one column would be two places to expire a
    -- challenge.
    subject_id text REFERENCES user_view (subject_id) ON DELETE CASCADE,

    -- 'registration' or 'login'. Checked at consume, so a challenge issued to
    -- add a passkey cannot be answered as a sign-in.
    purpose text NOT NULL,

    -- The library's session data. Opaque to everything but the ceremony
    -- adapter.
    state bytea NOT NULL,

    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,

    CONSTRAINT webauthn_challenge_purpose CHECK (
        purpose IN ('registration', 'login')
    ),
    CONSTRAINT webauthn_challenge_state_present CHECK (octet_length(state) > 0)
);

COMMENT ON TABLE webauthn_challenge IS
    'One WebAuthn ceremony in flight. Single-use, enforced by DELETE … RETURNING rather than read-then-write. Expires; swept.';

-- The sweep's work list.
CREATE INDEX webauthn_challenge_expiry_idx ON webauthn_challenge (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON webauthn_challenge TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS webauthn_challenge;
-- +goose StatementEnd

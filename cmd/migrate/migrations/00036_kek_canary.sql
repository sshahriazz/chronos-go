-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- kek_canary — proof that the key-encryption key has not changed
-- ---------------------------------------------------------------------------
-- # The failure this exists to make loud
--
-- Every subject's personal data is encrypted under a data key that is itself
-- wrapped by the KEK (ADR-028). If the KEK is REPLACED rather than rotated —
-- restored from a backup that predates it, migrated without its key material,
-- recreated by an operator, or lost with an in-memory dev instance — every
-- wrapped data key in the database becomes undecryptable. Permanently.
--
-- Nothing in the system notices. The key store answers healthy because it IS
-- healthy; it simply holds a different key. Accounts authenticate normally,
-- because authentication touches no personal data. What fails is every
-- notification, one at a time, as each one tries to turn a pseudonym into an
-- address — which surfaces as undelivered mail, not as data loss.
--
-- That is ADR-002 working exactly as designed: destroying the key destroys the
-- ability to read the data. It is correct when somebody exercised erasure and a
-- catastrophe when nobody did, and the system cannot tell the two apart from the
-- ciphertext alone.
--
-- # What the row is
--
-- One wrapped value, written the first time a build sees an empty table. Every
-- subsequent boot unwraps it and compares. Same key, it passes in a millisecond.
-- Different key, the process refuses to start and says so — turning a silent,
-- permanent, per-user loss into one loud failure at deploy time, where somebody
-- is watching and a rollback is still possible.
--
-- It holds NO personal data and is not a secret: the plaintext is a constant in
-- the source. What it proves is only that the KEK can still decrypt what this
-- installation encrypted.
CREATE TABLE kek_canary (
    -- One row, always. The primary key is a constant so a second INSERT
    -- conflicts rather than creating a second canary that could disagree with
    -- the first.
    id boolean PRIMARY KEY DEFAULT true CHECK (id),

    -- The KEK's name, so an installation that legitimately moved to a new named
    -- key can be told apart from one whose key was replaced underneath it.
    kek_name text NOT NULL,

    -- The wrapped canary. Opaque; only the key ring can read it.
    wrapped bytea NOT NULL,

    created_at timestamptz NOT NULL DEFAULT now(),
    verified_at timestamptz,

    CONSTRAINT kek_canary_wrapped_present CHECK (octet_length(wrapped) > 0)
);

COMMENT ON TABLE kek_canary IS
    'One wrapped value proving the KEK still decrypts what this installation encrypted (ADR-028). Checked at startup; a mismatch means every wrapped data key in the database is undecryptable and the process refuses to start.';

GRANT SELECT, INSERT, UPDATE ON kek_canary TO chronos_app;

-- Deliberately NO DELETE and NO TRUNCATE grant. Removing the canary would make
-- the next boot mint a fresh one against whatever key is present and report
-- success — which is precisely the check being defeated by the thing it is
-- meant to catch.

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS kek_canary;
-- +goose StatementEnd

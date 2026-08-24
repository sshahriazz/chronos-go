-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- Uncouple webauthn_challenge from the account PROJECTION too
-- ---------------------------------------------------------------------------
-- 00033 removed this key from `passkey_credential` and argued that
-- `webauthn_challenge` could keep its own, on the grounds that losing in-flight
-- ceremonies to a rebuild costs somebody a retry rather than a credential.
--
-- That reasoning was about the CASCADE, and it missed what a foreign key does to
-- the rebuild itself: PostgreSQL refuses to TRUNCATE a table that is referenced
-- by one. So the key did not make a rebuild lossy, it made a rebuild
-- IMPOSSIBLE — `identity_user`'s reset failed with "cannot truncate a table
-- referenced in a foreign key constraint" and the projection could never be
-- rebuilt at all.
--
-- Found by TestRebuildPreservesCredentials, which exists because this class of
-- mistake has now happened three times: 00008 → 00009 on `credential`, 00031 →
-- 00033 on `passkey_credential`, and here.
--
-- The rule, stated plainly for the next table: NOTHING references `user_view`.
-- It is a projection, it is truncated and replayed, and a foreign key to it
-- either destroys the referencing rows or prevents the rebuild.
ALTER TABLE webauthn_challenge
    DROP CONSTRAINT IF EXISTS webauthn_challenge_subject_id_fkey;

COMMENT ON COLUMN webauthn_challenge.subject_id IS
    'The subject a registration ceremony is for; NULL for a discoverable login. Deliberately NOT a foreign key to user_view: that table is a projection, and PostgreSQL refuses to TRUNCATE a table referenced by a foreign key — so the key would make a rebuild impossible rather than merely lossy.';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE webauthn_challenge
    ADD CONSTRAINT webauthn_challenge_subject_id_fkey
    FOREIGN KEY (subject_id) REFERENCES user_view (subject_id) ON DELETE CASCADE;
-- +goose StatementEnd

-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- Uncouple passkey_credential from the account PROJECTION
-- ---------------------------------------------------------------------------
-- 00031 gave `passkey_credential.subject_id` a foreign key to `user_view` with
-- ON DELETE CASCADE. That is the exact key migration 00009 removed from
-- `credential`, and it is removed here for the identical reason — recorded at
-- length because it was reintroduced within one session of being explained.
--
-- # What the key would do
--
-- `user_view` is a PROJECTION. A rebuild TRUNCATES it and replays the log. With
-- a cascading key in place, that truncate deletes every passkey in the
-- installation — and ADR-057 is explicit that `passkey_credential` is NOT
-- rebuildable from the event log, because a public key never enters an event.
--
-- So the outcome is: an operator rebuilds a read model, which is supposed to be
-- a safe and routine act, and every WebAuthn credential in the system is gone
-- permanently. Nobody can sign in with a passkey again, and no replay restores
-- them. The rebuild reports success.
--
-- # What replaces it
--
-- Nothing, deliberately. The coupling that matters is the other direction: a
-- passkey names a subject, and erasure deletes those rows explicitly
-- (DeletePasskeysForSubject) rather than relying on a cascade. An explicit
-- delete is also what ADR-057 asks for, since this is the one erasure path that
-- removes rows rather than destroying a key.
--
-- The cost is that a row can outlive the projection of its account, which is
-- precisely the state a rebuild passes through and precisely what must not be
-- destructive.
ALTER TABLE passkey_credential
    DROP CONSTRAINT IF EXISTS passkey_credential_subject_id_fkey;

COMMENT ON COLUMN passkey_credential.subject_id IS
    'The owning subject. Deliberately NOT a foreign key to user_view: that table is a projection, a rebuild truncates it, and a cascade would delete every passkey in the installation — none of which any replay can restore (ADR-057). Erasure removes these rows explicitly instead.';

-- The same key on `webauthn_challenge` is left in place, and the difference is
-- what a loss costs. A challenge is a ceremony in flight: it expires in minutes,
-- it is swept, and losing one costs somebody a retry. A rebuild taking the
-- in-flight ceremonies with it is an inconvenience, not an unrecoverable loss,
-- so the referential integrity is worth more there than it is here.

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Restoring the key would re-create the defect. It is written out rather than
-- omitted so that rolling back is a deliberate act with the consequence in front
-- of whoever does it.
ALTER TABLE passkey_credential
    ADD CONSTRAINT passkey_credential_subject_id_fkey
    FOREIGN KEY (subject_id) REFERENCES user_view (subject_id) ON DELETE CASCADE;

-- +goose StatementEnd

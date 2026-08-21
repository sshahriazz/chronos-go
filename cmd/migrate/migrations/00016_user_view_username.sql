-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- user_view carries the public handle, in the clear
-- ---------------------------------------------------------------------------
-- This column is the FIRST deliberate exception to "no projection may contain a
-- personal-data column" (compliance.md §1, ADR-051), and the exception needs
-- stating here rather than assumed, because the rule it breaks is the one that
-- makes erasure a key deletion instead of a migration.
--
-- A username is published by design. Its entire purpose is that other people see
-- it: @alice in a comment, /u/alice in a URL, "alice invited you" in an email
-- somebody else received. The PII vault exists so personal data can be destroyed
-- by destroying a key (ADR-002), and that mechanism requires the data to be
-- SECRET — crypto-shredding makes ciphertext unreadable and does nothing to a
-- value that was published. Putting a handle in the vault would give the
-- appearance of protection while every copy that matters lives in somebody
-- else's inbox, and would make the read model resolve a vault key on every page
-- render that names a person.
--
-- The consequence, which is the hard part: erasure must DELETE this column
-- rather than shred a key, and it must leave a TOMBSTONE on the handle's
-- reservation stream so the name is never reissued. Every other projection in
-- this system is erased by a key that stops working; this one is not.
--
-- NULLable, and NULL is not "unknown". It means the account has not claimed a
-- handle, which is exactly the window between Register and VerifyEmail — the
-- handle is claimed in the same atomic append as the verification and the first
-- password (identity.md §4.6), so an account with a NULL here is precisely an
-- account nobody can sign into. It is also what an erased account's row holds.
--
-- No backfill, and none is possible: the projection is rebuilt by replaying the
-- log from position zero, and an account registered before this column existed
-- has no UsernameAssigned event to replay. Those rows keep NULL, which is the
-- true statement about them.
ALTER TABLE user_view ADD COLUMN username text;

COMMENT ON COLUMN user_view.username IS
    'Public handle, CLEARTEXT and deliberately so (ADR-051). NULL means never claimed, or erased. '
    'The one personal-data column in a projection; erasure DELETES it and tombstones the handle.';

-- The uniqueness backstop, and it asserts EXACTLY the property the domain
-- guarantees — no more, which is the lesson ADR-052 was written to record.
--
-- What the domain guarantees here is stronger than it is for an address:
-- at most one account EVER holds a handle. There is no lease, nothing lapses,
-- and nothing is released — the only terminal transition is a tombstone, which
-- frees the name for nobody. So a full uniqueness constraint over the non-NULL
-- rows is not an over-claim the way `UNIQUE (email_index)` was in migration
-- 00008; it is the domain rule restated.
--
-- Partial on IS NOT NULL because NULL is common and carries no claim: every
-- Pending account, every erased one, and the placeholder row SetUserState
-- inserts for a subject whose UserRegistered has not arrived.
--
-- If it ever fires, the reservation stream admitted two winners and the
-- projector stops. That is the correct direction for THAT failure: two accounts
-- answering to one public name is an impersonation, and it is worth a stalled
-- projection to refuse to record it.
CREATE UNIQUE INDEX user_view_username_key
    ON user_view (username)
    WHERE username IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS user_view_username_key;
ALTER TABLE user_view DROP COLUMN IF EXISTS username;
-- +goose StatementEnd

-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- user_view records an outstanding deletion request
-- ---------------------------------------------------------------------------
-- identity.UserDeletionRequested is the handoff to `compliance`, and that module
-- does not exist yet. Until it does, the ONLY place a person or an operator can
-- see that an erasure is pending is this projection — so the columns exist now,
-- with the event, rather than when the consumer arrives. An event nothing
-- projects is an event whose replay is never exercised, and the first rebuild
-- after the consumer lands is a poor moment to discover that.
--
-- Two columns rather than one. `deletion_requested_at` answers "when did they
-- ask", which is the audit question; `deletion_scheduled_for` answers "when does
-- it fall due", which is the operational one and is the date the mail names
-- (NOTIFICATIONS.md §4). Deriving the second from the first would move every
-- outstanding deadline whenever the grace period changed, including backwards
-- past dates already communicated — so the deadline is carried in the event and
-- copied here verbatim.
--
-- NOT a new `state` value, and the CHECK constraint on user_view.state is
-- deliberately left alone. A request changes nothing the account can do: it
-- keeps its credentials, its sessions and its lifecycle position until
-- compliance acts. A state that read "deleted" would make every gate in the
-- system disagree with what the account actually still permits.
--
-- Both are nullable and both default to NULL, which is what "never asked" means.
-- The projection is rebuilt from position zero by replaying the log, so no
-- backfill is possible and none is needed: an account that never requested
-- deletion has no event to replay and keeps two NULLs.
ALTER TABLE user_view ADD COLUMN deletion_requested_at  timestamptz;
ALTER TABLE user_view ADD COLUMN deletion_scheduled_for timestamptz;

COMMENT ON COLUMN user_view.deletion_requested_at IS
    'When the holder asked for erasure. NULL means never. Not a lifecycle state: the account still works.';
COMMENT ON COLUMN user_view.deletion_scheduled_for IS
    'When erasure falls due, copied from the event. Never recomputed from the current grace period.';

-- Partial, because the query this serves is "which accounts are due for erasure"
-- and the overwhelming majority of rows have never requested one. A full index
-- would carry every account in the system to answer a question about a handful.
CREATE INDEX user_view_deletion_due_idx
    ON user_view (deletion_scheduled_for)
    WHERE deletion_requested_at IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS user_view_deletion_due_idx;
ALTER TABLE user_view DROP COLUMN IF EXISTS deletion_scheduled_for;
ALTER TABLE user_view DROP COLUMN IF EXISTS deletion_requested_at;
-- +goose StatementEnd

-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- user_view.email_index is unique among the accounts that STILL HOLD the address
-- ---------------------------------------------------------------------------
-- 00008 gave user_view.email_index a bare UNIQUE constraint and described it as
-- "a backstop rather than the mechanism", on the reasoning that uniqueness is
-- enforced at write time by the reservation stream. The reasoning is right and
-- the constraint was still wrong, because it asserts a property the domain has
-- never guaranteed.
--
-- What the domain guarantees is that AT MOST ONE ACCOUNT HOLDS an address at any
-- instant. It explicitly does NOT guarantee that at most one account has ever
-- been registered with it. An unverified claim lapses after
-- app.DefaultReservationLease (48h) — that lapse is the entire bound on the
-- squatting attack IDENTITY-REVIEW C8 leaves open — and
-- EmailReservation.Reserve then takes the lapsed claim over, recording
-- EmailReleased followed by EmailReserved. The squatter's Pending account is not
-- deleted by a release and is not supposed to be: nothing in the log says it
-- ever went away.
--
-- So the designed squat-recovery path produces two UserRegistered events sharing
-- one email index, and the old constraint made that state unrepresentable. The
-- consequence was not a rejected write in a request handler. It was:
--
--   projection: apply failed: ... UpsertUser: duplicate key value violates
--   unique constraint "user_view_email_index_key" (SQLSTATE 23505)
--
-- The identity_user projector stopped, and `projector -rebuild identity_user`
-- failed at the same event — so the table was no longer reconstructable by
-- replaying from position zero, which is the property every projection in this
-- codebase is required to have. A constraint that turns a bounded 48h denial of
-- service into a permanently stalled projection is not a backstop.
--
-- The fix keeps a real uniqueness guarantee and narrows it to the claim the
-- domain actually makes. email_released_at records that this account USED to
-- hold this address; the partial unique index below then permits exactly one
-- CURRENT holder per index and any number of superseded ones.
--
-- Why the superseded row keeps its email_index rather than having it blanked:
--
--   * It is not personal data. It is a keyed HMAC whose key is not in this
--     database (ADR-048), so ADR-002 is satisfied by keeping it exactly as it is
--     satisfied by keeping it on the live row.
--   * Blanking it would need the column to become nullable, and every account
--     that ever abandoned a registration would then collapse into one
--     indistinguishable class of rows — replacing "this account used to hold
--     that address" with "this account has no address", which is a different and
--     false statement.
--   * '' is not available as a sentinel: SetUserState inserts a placeholder row
--     with email_index = '' for a subject it has not seen a UserRegistered for,
--     so a blanked row would collide with that placeholder rather than with
--     nothing.
--
-- The read side moves with it. GetUserByEmailIndex — the login lookup, and a
-- :one query — gains `AND email_released_at IS NULL`. Without that clause two
-- rows would match after a lapse-and-reclaim and QueryRow would return whichever
-- the planner reached first: an authentication attempt for the address could
-- resolve to the SQUATTER's abandoned account. That is a worse failure than the
-- stalled projector, and it is silent.

ALTER TABLE user_view ADD COLUMN email_released_at timestamptz;

COMMENT ON COLUMN user_view.email_released_at IS
    'When this account stopped holding email_index. NULL means it still holds it.';

ALTER TABLE user_view DROP CONSTRAINT user_view_email_index_key;

-- Partial, and the predicate is the whole point: uniqueness applies to current
-- holders only. It is also the index GetUserByEmailIndex now matches exactly, so
-- the login lookup reads the narrower structure rather than a wider one it would
-- have to filter afterwards.
CREATE UNIQUE INDEX user_view_email_index_held_key
    ON user_view (email_index)
    WHERE email_released_at IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Restoring the bare UNIQUE constraint fails if any address is currently held by
-- one account and was previously held by another — which is exactly the state
-- this migration exists to permit. That is correct: the down path must not
-- silently discard rows to make an unrepresentable constraint fit.
DROP INDEX IF EXISTS user_view_email_index_held_key;
ALTER TABLE user_view ADD CONSTRAINT user_view_email_index_key UNIQUE (email_index);
ALTER TABLE user_view DROP COLUMN IF EXISTS email_released_at;

-- +goose StatementEnd

-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- Grant TRUNCATE on identity's projections to the application role
-- ---------------------------------------------------------------------------
-- Migration 00008 granted identity's tables SELECT, INSERT, UPDATE and DELETE,
-- and 00011 followed it. Every notification projection (00002) and the probe
-- tables (00004) also carry TRUNCATE, and identity's omission was an oversight
-- rather than a decision.
--
-- It is not a cosmetic one. The app connects as `chronos_app`, never the owner
-- (ADR-011) — a superuser bypasses RLS entirely, so connecting as the owner would
-- silently disable tenant isolation at the database while every test still
-- passed. That means a projection REBUILD also runs as `chronos_app`, and
-- `Projection.Reset` is exactly one TRUNCATE:
--
--   ERROR: permission denied for table login_history_view (SQLSTATE 42501)
--
-- Verified against the running database before writing this, not inferred from
-- the migration text.
--
-- The failure mode is worth stating because it is the expensive kind. Nothing
-- detects it until somebody rebuilds a projection — which happens when a
-- projector bug has already been found and the fix is to replay the log. The
-- recovery path would fail at the moment it was needed, and it would fail with a
-- permissions error that reads like an infrastructure problem rather than a
-- missing grant.
--
-- DELETE is not a substitute. `Reset` runs inside the same transaction that
-- clears the checkpoint, so a rebuild cannot half-happen; rewriting it as DELETE
-- would work and would accumulate dead tuples on tables that get rebuilt
-- repeatedly, and it would leave identity as the one module whose reset differs
-- in kind from every other module's for no reason a reader could recover.

GRANT TRUNCATE ON user_view              TO chronos_app;
GRANT TRUNCATE ON session_view           TO chronos_app;
GRANT TRUNCATE ON login_history_view     TO chronos_app;
GRANT TRUNCATE ON email_reservation_view TO chronos_app;

-- Deliberately NOT granted on `credential`, `recovery_code`, `identity_token`,
-- `session_token` or `totp_replay`. Those are AUTHORITATIVE, not projections:
-- they hold verifiers and single-use secrets that never enter an event, so no
-- replay can restore them and nothing should ever truncate them. Withholding the
-- privilege is the last line of defence behind migration 00009's foreign-key
-- removal — together they mean a rebuild cannot reach them by cascade or by
-- statement.

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
REVOKE TRUNCATE ON user_view              FROM chronos_app;
REVOKE TRUNCATE ON session_view           FROM chronos_app;
REVOKE TRUNCATE ON login_history_view     FROM chronos_app;
REVOKE TRUNCATE ON email_reservation_view FROM chronos_app;
-- +goose StatementEnd

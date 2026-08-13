-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- Separate the PROJECTION tables from the AUTHORITATIVE ones
-- ---------------------------------------------------------------------------
-- 00008 gave `credential`, `recovery_code` and `identity_token` a foreign key to
-- `user_view`. That is wrong, and it is wrong in a way that only shows up the
-- first time somebody rebuilds a projection.
--
-- The identity tables fall into two groups that must not be coupled:
--
--   PROJECTIONS, derived and rebuildable from position zero
--     user_view, session_view, login_history_view
--
--   AUTHORITATIVE, written by command handlers, NOT reconstructable
--     credential      password verifiers, TOTP secret references
--     recovery_code   single-use code digests
--     identity_token  single-use emailed secrets
--
-- Rebuilding a projection means emptying its tables and replaying the log into
-- them. With the FK in place, `DELETE FROM user_view` cascades into all three
-- authoritative tables — so a routine, documented, supposedly safe operation
-- destroys every password verifier in the system, and no replay can bring them
-- back because verifiers never enter events (identity.md §4).
--
-- Writing the projection's Reset is what surfaced it: there was no way to write
-- one that was both correct and safe. Sparing rows that still have credentials
-- leaves stale state behind — a user_view row that survives with
-- email_verified = true keeps it when the replay contains no EmailVerified event
-- — and deleting everything destroys the credentials. The constraint was the
-- problem, not the Reset.
--
-- So the FKs go. subject_id still relates the rows; nothing enforces it, which
-- is correct: a projection is allowed to be empty, mid-rebuild, or behind, and a
-- constraint that says otherwise is a constraint that fires during normal
-- operation.
--
-- session_view KEEPS its FK. It is a projection too, reset in the same
-- transaction as user_view, so the cascade is exactly the behaviour wanted
-- there.

ALTER TABLE credential     DROP CONSTRAINT credential_subject_id_fkey;
ALTER TABLE recovery_code  DROP CONSTRAINT recovery_code_subject_id_fkey;
ALTER TABLE identity_token DROP CONSTRAINT identity_token_subject_id_fkey;

-- login_history_view is a projection, but its FK to user_view is dropped too.
--
-- A login attempt for an identifier that matched NO account has a NULL subject
-- and is unaffected. The problem is the ordinary case: an attempt is recorded
-- against a subject whose user_view row has not been projected yet — the login
-- history is written by a handler at authentication time, while user_view is
-- written by a projector that may be behind. The FK turns that ordinary lag into
-- a failed insert.
ALTER TABLE login_history_view DROP CONSTRAINT login_history_view_subject_id_fkey;

-- recovery_code KEEPS its FK to credential: both are authoritative, both are
-- written by the same handler, and a code set without its credential row is
-- genuinely orphaned data.

COMMENT ON TABLE credential IS
    'AUTHORITATIVE, not a projection. Verifiers never enter events, so a rebuild cannot restore this.';
COMMENT ON TABLE identity_token IS
    'AUTHORITATIVE, not a projection. Single-use emailed secrets, as digests.';
COMMENT ON TABLE recovery_code IS
    'AUTHORITATIVE, not a projection. Single-use code digests.';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE credential
    ADD CONSTRAINT credential_subject_id_fkey
    FOREIGN KEY (subject_id) REFERENCES user_view (subject_id) ON DELETE CASCADE;
ALTER TABLE recovery_code
    ADD CONSTRAINT recovery_code_subject_id_fkey
    FOREIGN KEY (subject_id) REFERENCES user_view (subject_id) ON DELETE CASCADE;
ALTER TABLE identity_token
    ADD CONSTRAINT identity_token_subject_id_fkey
    FOREIGN KEY (subject_id) REFERENCES user_view (subject_id) ON DELETE CASCADE;
ALTER TABLE login_history_view
    ADD CONSTRAINT login_history_view_subject_id_fkey
    FOREIGN KEY (subject_id) REFERENCES user_view (subject_id) ON DELETE CASCADE;
-- +goose StatementEnd

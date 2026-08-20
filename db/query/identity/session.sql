-- Sessions and the account projection.
--
-- The projection statements are written to be REPLAYABLE: a projector may
-- re-apply an event after a restart, so every one of them is an upsert or is
-- otherwise idempotent. A statement that failed on replay would stop the
-- projector, and a rebuild from position zero would never complete.

-- name: UpsertUser :exec
INSERT INTO user_view (subject_id, user_id, email_index, state, registered_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (subject_id) DO UPDATE SET
    email_index = EXCLUDED.email_index,
    state       = EXCLUDED.state;

-- name: SetUserState :exec
INSERT INTO user_view (subject_id, user_id, email_index, state, registered_at)
VALUES ($1, '', '', $2, now())
ON CONFLICT (subject_id) DO UPDATE SET
    state          = EXCLUDED.state,
    activated_at   = CASE WHEN EXCLUDED.state = 'active'      THEN now() ELSE user_view.activated_at   END,
    deactivated_at = CASE WHEN EXCLUDED.state = 'deactivated' THEN now() ELSE user_view.deactivated_at END,
    suspended_at   = CASE WHEN EXCLUDED.state = 'suspended'   THEN now() ELSE user_view.suspended_at   END;

-- name: MarkEmailVerified :exec
UPDATE user_view SET email_verified = true, email_index = $2 WHERE subject_id = $1;

-- name: GetUserBySubject :one
SELECT subject_id, user_id, email_index, state, email_verified,
       registered_at, activated_at, deactivated_at, suspended_at
FROM user_view WHERE subject_id = $1;

-- name: GetUserByEmailIndex :one
-- The login lookup.
--
-- By INDEX, never by address: the address is not in this database. The caller
-- derives the index with the blind-index key and asks for it.
SELECT subject_id, user_id, email_index, state, email_verified,
       registered_at, activated_at, deactivated_at, suspended_at
FROM user_view WHERE email_index = $1;

-- name: UpsertSession :exec
-- The PROJECTION half, written by the projector from SessionCreated.
--
-- Carries no digest and no idle deadline: neither is in the log, so neither can
-- be projected. See migration 00010.
INSERT INTO session_view (
    session_id, subject_id, device_id, aal,
    absolute_expires_at, requires_credential_rotation, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (session_id) DO NOTHING;

-- name: IssueSessionToken :exec
-- The AUTHORITATIVE half, written by the login handler.
--
-- Separate statement, and separate WRITER: the handler holds the token, the
-- projector never sees one.
INSERT INTO session_token (token_digest, session_id, idle_expires_at)
VALUES ($1, $2, $3);

-- name: GetSessionByToken :one
-- Resolve a bearer token to a session. This is the authenticator's query, and it
-- runs on EVERY authenticated request.
--
-- By DIGEST, never by the token: the token is not stored, so a database dump
-- yields digests that cannot be presented.
--
-- An INNER JOIN across the two halves, and that is the security property rather
-- than a schema detail. A session is usable only when BOTH rows exist: the
-- secret (session_token) and the facts (session_view). During a projection
-- rebuild the facts are briefly absent, so nothing resolves and every request is
-- unauthenticated — which is the correct behaviour, because the alternative is
-- honouring a token whose subject and assurance level are unknown.
--
-- Both deadlines and the revocation are checked HERE rather than by the caller,
-- so there is no window in which a handler holds a session row it then has to
-- remember to validate. A revoked or expired session simply does not exist to
-- this query.
--
-- The last column, `enrolment`, is what a bootstrap assurance floor is relaxed
-- against (policy.Enrolment). It answers "has this ACCOUNT ever held a proven
-- second factor", and the whole value of the mechanism rests on it being read
-- server-side, from the session's own account, rather than claimed by a caller.
--
-- # Why "ever", and how each half of the OR earns its place
--
-- `activated_at IS NOT NULL` is the durable half. An account reaches `active`
-- only through UserActivated, which the domain records only once a REAL second
-- factor is proven (domain.User.maybeActivate — a recovery-code sheet is
-- explicitly not enough), and SetUserState's CASE stamps activated_at on that
-- transition and never clears it afterwards. So it survives every way a factor
-- can go away: TotpDisabled, a lockout, a deactivation, a suspension, and a
-- projection rebuild — which replays UserActivated and stamps it again.
--
-- The EXISTS half covers the window the first one cannot see: an account that
-- has proven a factor but has not activated, because some other precondition
-- (a verified address, a primary method) is still missing. `enabled_at IS NOT
-- NULL` is exactly "proven" — an enrolment in progress is written with it NULL
-- and only EnableCredential sets it — which matters here, because starting an
-- enrolment must NOT flip the answer to established: a re-enrolment upserts the
-- same row with enabled_at cleared, and an account whose answer moved on
-- EnrollTotp could never reach ConfirmTotp. The kind list is an exclusion of the
-- primaries and of recovery codes rather than an inclusion of 'totp', mirroring
-- domain.RoleOf's default: a second-factor kind added later counts without this
-- statement being edited, which is the direction that fails safe.
--
-- The credential half is also the half that is IMMEDIATE. It is written by the
-- command handler in the same request that proves the factor, so an account does
-- not spend the projector's lag reporting bootstrap with a factor already in
-- hand.
--
-- LEFT JOIN, and the CASE reports 'unknown' rather than 'bootstrap' when the
-- account row is absent. A plain `IS NOT NULL` over an outer join collapses "no
-- such account row" into "no factor", which is the one direction that must never
-- be taken silently: unknown denies the exemption, bootstrap grants it.
SELECT v.session_id, v.subject_id, v.device_id, v.aal,
       t.idle_expires_at, v.absolute_expires_at, v.requires_credential_rotation,
       v.elevated_scope, v.elevated_until, v.created_at, t.last_seen_at,
       (CASE
            WHEN u.subject_id IS NULL THEN 'unknown'
            WHEN u.activated_at IS NOT NULL THEN 'established'
            WHEN EXISTS (
                SELECT 1 FROM credential c
                WHERE c.subject_id = v.subject_id
                  AND c.enabled_at IS NOT NULL
                  AND c.kind NOT IN ('password', 'passkey', 'federated', 'recovery_code')
            ) THEN 'established'
            ELSE 'bootstrap'
        END)::text AS enrolment
FROM session_token t
JOIN session_view v ON v.session_id = t.session_id
LEFT JOIN user_view u ON u.subject_id = v.subject_id
WHERE t.token_digest = $1
  AND v.revoked_at IS NULL
  AND v.absolute_expires_at > $2
  AND t.idle_expires_at > $2;

-- name: TouchSession :exec
-- Push the idle deadline forward.
--
-- Writes the AUTHORITATIVE half only. The idle deadline is not in the log —
-- recording each refresh as an event would make every authenticated read a write
-- — so it lives with the digest and is never projected.
--
-- The new deadline is clamped to the session's ABSOLUTE deadline, read across
-- the join. Without the clamp, a session in constant use pushes its idle
-- deadline past the absolute one and the join's absolute check becomes the only
-- thing ending it — which works, and quietly means the idle deadline stopped
-- existing.
UPDATE session_token t
SET last_seen_at = now(),
    idle_expires_at = LEAST($2::timestamptz, v.absolute_expires_at)
FROM session_view v
WHERE t.session_id = $1 AND v.session_id = t.session_id AND v.revoked_at IS NULL;

-- name: ElevateSession :exec
UPDATE session_view
SET aal = $2, elevated_scope = $3, elevated_until = LEAST($4::timestamptz, absolute_expires_at)
WHERE session_id = $1 AND revoked_at IS NULL;

-- name: RevokeSession :execrows
UPDATE session_view SET revoked_at = now()
WHERE session_id = $1 AND revoked_at IS NULL;

-- name: RevokeAllSessions :execrows
-- Revoke every live session for a subject, optionally sparing one.
--
-- The exception is "sign out everywhere else", which must not sign the caller
-- out of the device they are asking from. Passing the empty string spares
-- nothing, which is what a password reset needs.
UPDATE session_view SET revoked_at = now()
WHERE subject_id = $1 AND revoked_at IS NULL AND session_id <> $2;

-- name: ListSessions :many
-- The device list, newest first.
--
-- Keyset pagination: ordered by (created_at, session_id) so the tiebreak column
-- is UNIQUE. An ordering that can tie loses or repeats rows at a page boundary
-- (platform/page).
SELECT v.session_id, v.device_id, v.aal, t.idle_expires_at, v.absolute_expires_at,
       v.created_at, t.last_seen_at
FROM session_view v
JOIN session_token t ON t.session_id = v.session_id
WHERE v.subject_id = $1
  AND v.revoked_at IS NULL
  AND v.absolute_expires_at > now()
  AND (v.created_at, v.session_id) < ($2::timestamptz, $3::text)
ORDER BY v.created_at DESC, v.session_id DESC
LIMIT $4;

-- name: ListLiveSessionIDs :many
-- Every session a subject can still use, for "sign out everywhere".
--
-- Deliberately NOT ListSessions with a wide cursor. That statement joins
-- session_token to render a device list, so a session whose token row has been
-- swept — revoked or expired, then cleaned up — disappears from it. Revocation
-- must not depend on the secret still existing: the session_view row is what a
-- rebuild replays, and a session missing from this list is one that never gets
-- its SessionRevoked event.
--
-- Unbounded on purpose. A LIMIT here would make "sign out everywhere" silently
-- partial, which is the one outcome that flow may not have — the caller believes
-- every device is signed out and one is not. The count is bounded in practice by
-- the number of devices a person signs in from, and by the absolute deadline
-- that removes the rest.
SELECT session_id
FROM session_view
WHERE subject_id = $1
  AND revoked_at IS NULL
  AND absolute_expires_at > $2
ORDER BY created_at DESC, session_id DESC;

-- name: SweepSessionTokens :execrows
-- Drop the SECRET half of sessions that can no longer be used.
--
-- Only the token. The projected half is left alone: it is the evidence that the
-- session existed, and "when did this device last sign in" is a question the
-- security-settings screen has to answer. Deleting the digest is what makes the
-- secret unrecoverable, which is the part that matters.
DELETE FROM session_token t
USING session_view v
WHERE t.session_id = v.session_id
  AND (v.absolute_expires_at <= now() OR v.revoked_at IS NOT NULL);

-- name: SweepExpiredSessionViews :execrows
-- Retention for the projected half, on a much longer horizon than the token.
DELETE FROM session_view WHERE absolute_expires_at <= $1;

-- name: RecordLoginAttempt :exec
-- subject_id is NULL when the identifier matched no account. Inventing one would
-- create a permanent record keyed to a person who does not exist here, while the
-- attempt still has to be counted for stuffing detection — which is what
-- email_index carries.
INSERT INTO login_history_view (
    subject_id, email_index, succeeded, reason, methods, aal, device_id, occurred_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: ListLoginHistory :many
SELECT id, succeeded, reason, methods, aal, device_id, occurred_at
FROM login_history_view
WHERE subject_id = $1 AND (occurred_at, id) < ($2::timestamptz, $3::bigint)
ORDER BY occurred_at DESC, id DESC
LIMIT $4;

-- name: CountRecentFailures :one
-- Consecutive-failure detection across accounts for one identifier: the
-- credential-stuffing signal.
SELECT count(*) FROM login_history_view
WHERE email_index = $1 AND succeeded = false AND occurred_at > $2;

-- name: TruncateIdentityProjections :exec
-- Empty every identity PROJECTION so it can be rebuilt from position zero.
--
-- Three tables in ONE statement, and both facts matter.
--
-- Only these three are projections. `credential`, `recovery_code` and
-- `identity_token` are authoritative — they hold verifiers and single-use
-- secrets that never enter events, so a replay cannot restore them and a rebuild
-- must not touch them. Migration 00009 dropped the foreign keys those tables had
-- to user_view precisely so this statement cannot reach them; before that, no
-- correct version of it existed.
--
-- One statement because session_view still references user_view, and TRUNCATE
-- refuses a table another references unless both are named together. Listing
-- them is better than CASCADE here: CASCADE would follow whatever foreign keys
-- exist at the time, which is exactly the behaviour that made this dangerous in
-- the first place. Naming the tables means adding a new one to the cascade path
-- cannot silently enrol it in the reset.
--
-- TRUNCATE rather than DELETE follows the notification projection's reasoning
-- (ADR-019): a rebuild runs in an unscoped system transaction. Identity's tables
-- carry no RLS, so DELETE would work here — TRUNCATE is chosen for consistency
-- with every other projection and because it does not accumulate dead tuples on
-- a table that may be rebuilt repeatedly.
TRUNCATE TABLE login_history_view, session_view, user_view;

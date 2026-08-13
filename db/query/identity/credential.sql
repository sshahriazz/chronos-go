-- Credential storage: the one identity table that is NOT rebuildable from the
-- log, because verifiers and TOTP secrets must never enter an event.
--
-- Every statement here runs inside db.SystemTX. These tables carry no RLS —
-- a user exists before any organization, so there is no workspace_id to scope
-- by — and the transaction helper is therefore the whole boundary.

-- name: UpsertCredential :exec
-- Record or replace a credential.
--
-- ON CONFLICT rather than a separate existence check: the projector may re-apply
-- an event after a restart, and a check-then-insert would either fail on the
-- replay or race a concurrent write. Both are avoidable by making the write
-- idempotent instead.
INSERT INTO credential (
    credential_id, subject_id, kind, verifier, pepper_version, enabled_at, created_at
) VALUES ($1, $2, $3, $4, $5, $6, now())
ON CONFLICT (credential_id) DO UPDATE SET
    verifier       = EXCLUDED.verifier,
    pepper_version = EXCLUDED.pepper_version,
    enabled_at     = EXCLUDED.enabled_at;

-- name: GetUsableCredential :one
-- The usable credential of a kind for an account.
--
-- `disabled_at IS NULL` is the whole point: a locked-out authenticator must not
-- be returned, or the caller verifies against a credential the domain considers
-- unusable and the lockout does nothing.
SELECT credential_id, subject_id, kind, verifier, pepper_version, enabled_at, failures
FROM credential
WHERE subject_id = $1 AND kind = $2 AND disabled_at IS NULL AND enabled_at IS NOT NULL;

-- name: ListCredentials :many
-- Every credential on an account, for the security-settings screen.
SELECT credential_id, kind, enabled_at, disabled_at, created_at, last_used_at
FROM credential
WHERE subject_id = $1
ORDER BY created_at DESC, credential_id DESC;

-- name: TouchCredential :exec
-- Record a successful use and clear the failure count.
--
-- Clearing on SUCCESS is what makes the ceiling a consecutive-failure counter
-- rather than a lifetime one. Without it, an account that has ever failed enough
-- times is locked out permanently, however many successes came after.
UPDATE credential
SET last_used_at = now(), failures = 0
WHERE credential_id = $1;

-- name: RehashCredential :execrows
-- Replace a verifier with one produced under current policy (PasswordRehashed).
--
-- A COMPARE-AND-SET, not a plain update, and the comparison is the whole reason
-- this is a separate statement from UpsertCredential.
--
-- A rehash is computed from the plaintext that a login just verified, and the
-- login has already returned by the time it is written. If the user changes
-- their password in that window, an unguarded `SET verifier = $new` overwrites
-- the NEW verifier with a re-encoding of the OLD password — silently restoring a
-- password the user has just replaced, possibly the one they replaced it because
-- of. Requiring the row to still hold the verifier that was verified makes that
-- outcome impossible rather than merely unlikely: a lost race writes nothing and
-- reports zero rows, and dropping a rehash costs one login's worth of delay.
--
-- `disabled_at IS NULL` for the same reason in the other direction: writing a
-- fresh verifier onto a locked-out authenticator leaves the lockout intact but
-- the row looking maintained, so the next reader sees a current verifier on a
-- credential nothing will ever accept.
--
-- The comparison is not constant-time, and does not need to be: the stored
-- verifier is not a secret this statement is guessing at — the caller already
-- read it — and anyone able to time this query already holds the row.
UPDATE credential
SET verifier       = sqlc.arg(new_verifier),
    pepper_version = sqlc.arg(pepper_version)
WHERE credential_id = sqlc.arg(credential_id)
  AND verifier      = sqlc.arg(expected_verifier)
  AND disabled_at IS NULL;

-- name: RecordCredentialFailure :one
-- Count a failed attempt and report the new total.
--
-- Returned so the caller can decide whether the ceiling was reached without a
-- second read that could disagree with this write.
UPDATE credential
SET failures = failures + 1
WHERE credential_id = $1
RETURNING failures;

-- name: DisableCredential :exec
-- Lock out one authenticator.
--
-- Per authenticator, never per account: locking the ACCOUNT on failed attempts
-- hands any attacker a denial of service against any address they can guess.
UPDATE credential
SET disabled_at = now()
WHERE credential_id = $1 AND disabled_at IS NULL;

-- name: DeleteCredential :exec
DELETE FROM credential WHERE credential_id = $1;

-- name: ListCredentialsAtPepperVersion :many
-- The rotation job's work list: password verifiers still sealed under an old
-- pepper key.
--
-- The job is not done until this returns zero rows, and the old transit key must
-- not be destroyed before then (identity.md §4). Nothing in code can enforce
-- that ordering, which is why the query exists as the check.
SELECT credential_id, subject_id, verifier
FROM credential
WHERE kind = 'password' AND verifier IS NOT NULL AND pepper_version < $1
ORDER BY credential_id
LIMIT $2;

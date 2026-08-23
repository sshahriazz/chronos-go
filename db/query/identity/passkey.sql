-- Queries for passkey_credential (ADR-057).
--
-- This table is NOT a projection. Nothing here is rebuildable from the log — a
-- public key never enters an event — so these statements are the system of
-- record for WebAuthn material, exactly as `credential`'s are for a verifier.

-- name: InsertPasskey :exec
-- Register one credential.
--
-- A plain INSERT, and the absence of an upsert is the point: the primary key is
-- the credential ID and it is UNIQUE ACROSS EVERY ACCOUNT (WebAuthn L3 §7.1
-- step 27). An upsert would silently REPLACE a victim's registration with an
-- attacker's — which is the exact takeover the uniqueness exists to prevent,
-- implemented as a convenience.
--
-- The caller checks first and handles the violation as a message; this refuses
-- under concurrency, where a check alone cannot.
INSERT INTO passkey_credential (
    credential_id, subject_id, public_key, sign_count,
    aaguid, transports, backup_eligible, backup_state, user_verified,
    label, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: GetPasskey :one
-- Find a credential by its id, for a ceremony.
--
-- NOT scoped by subject, deliberately. A WebAuthn assertion names the credential
-- and the RP looks it up to learn WHOSE it is — scoping by a subject the caller
-- supplied would mean trusting the caller's claim about their own identity,
-- which is what the ceremony exists to establish.
SELECT credential_id, subject_id, public_key, sign_count,
       aaguid, transports, backup_eligible, backup_state, user_verified,
       label, created_at, last_used_at, clone_warned_at
FROM passkey_credential
WHERE credential_id = $1;

-- name: ListPasskeysForSubject :many
-- Every passkey an account holds, newest first.
--
-- Used to build an `allowCredentials` list and to render the security screen.
SELECT credential_id, subject_id, public_key, sign_count,
       aaguid, transports, backup_eligible, backup_state, user_verified,
       label, created_at, last_used_at, clone_warned_at
FROM passkey_credential
WHERE subject_id = $1
ORDER BY created_at DESC;

-- name: AdvancePasskeySignCount :execrows
-- Move the signature counter forward, and ONLY forward.
--
-- The whole clone check, as one atomic statement. `sign_count < $2` is what
-- makes it safe under concurrent logins: two sessions authenticating at once
-- cannot both advance past each other, and the loser simply matches no row.
--
-- ZERO ROWS IS NOT AN ERROR, and reading it as one would lock people out. It
-- means the presented count did not exceed the stored one, which has two very
-- different causes:
--
--   * 0 → 0, which is the ordinary case for a SYNCED passkey. Apple and Google
--     report 0 permanently because there is no coherent place to keep a
--     monotonic counter across N devices. Refusing on it would refuse most of
--     the passkeys in existence.
--   * a genuine REGRESSION, which the caller turns into a warning and a step-up
--     rather than a denial — the spec lists an out-of-order race as a benign
--     cause, and this system treats concurrent sessions as ordinary.
--
-- The caller distinguishes them; this statement only refuses to go backwards.
UPDATE passkey_credential
SET sign_count = $2, last_used_at = $3
WHERE credential_id = $1 AND sign_count < $2;

-- name: TouchPasskey :exec
-- Record a successful use that did not advance the counter.
--
-- The 0 → 0 case above still happened, and "when did I last use this passkey"
-- is a question the security screen has to answer. Separate from the advance so
-- that neither statement has to branch.
UPDATE passkey_credential
SET last_used_at = $2
WHERE credential_id = $1;

-- name: WarnPasskeyClone :exec
-- Record that a signature counter went BACKWARDS.
--
-- Stamped rather than counted: what an operator needs is "has this credential
-- ever regressed, and when", and a counter would invite somebody to set a
-- threshold on a signal whose benign cause is a race.
UPDATE passkey_credential
SET clone_warned_at = $2
WHERE credential_id = $1;

-- name: DeletePasskey :execrows
-- Remove one credential.
--
-- Scoped by subject as well as by id, unlike GetPasskey above, and the
-- difference is the direction of trust: a ceremony asks "whose is this", while
-- a removal is a caller acting on their own account and must not be able to
-- delete somebody else's passkey by naming its id.
DELETE FROM passkey_credential
WHERE credential_id = $1 AND subject_id = $2;

-- name: DeletePasskeysForSubject :execrows
-- Erasure.
--
-- The row is DELETED rather than crypto-shredded, because there is no subject
-- key to destroy: this material is not encrypted under one. That makes it the
-- one erasure path that removes rows rather than making them unreadable
-- (ADR-057).
DELETE FROM passkey_credential WHERE subject_id = $1;

-- name: CountPasskeysForSubject :one
SELECT count(*) FROM passkey_credential WHERE subject_id = $1;

-- name: TruncatePasskeys :exec
TRUNCATE TABLE passkey_credential;

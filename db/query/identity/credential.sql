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

-- name: DeleteOrphanedPasswordCredential :execrows
-- Remove a password row that the event log does not account for.
--
-- Used by ONE caller — setting an account's first password, in the same
-- transaction as the insert that replaces it — and it exists because the write
-- order has to be verifier-then-event. An attempt that stores the verifier and
-- then fails to append leaves a row with no PasswordSet behind it: unusable,
-- because the aggregate rebuilt from the log has no password method, and fatal,
-- because the retry mints a fresh credential id and collides with
-- credential_one_usable_per_kind_idx. Without this statement that collision is
-- permanent and the account can never obtain a password at all.
--
-- `disabled_at IS NULL` matches the partial unique index exactly, so this
-- removes precisely the rows that could collide and leaves the lockout history
-- alone. Nothing cascades: recovery_code and totp_replay hang from credentials
-- of other kinds.
--
-- The safety of deleting anything here rests on the CALLER, not on this
-- statement: it is issued only after domain.User.SetPassword has succeeded,
-- which it does only when the account's own stream records no usable password.
-- See app.PasswordCredentials.StoreFirst.
DELETE FROM credential
WHERE subject_id = $1 AND kind = 'password' AND disabled_at IS NULL;

-- name: GetUsableCredential :one
-- The usable credential of a kind for an account.
--
-- `disabled_at IS NULL` is the whole point: a locked-out authenticator must not
-- be returned, or the caller verifies against a credential the domain considers
-- unusable and the lockout does nothing.
SELECT credential_id, subject_id, kind, verifier, pepper_version, enabled_at, failures
FROM credential
WHERE subject_id = $1 AND kind = $2 AND disabled_at IS NULL AND enabled_at IS NOT NULL;

-- name: GetCredentialOfKind :one
-- The credential of a kind for an account, ENABLED OR NOT.
--
-- Deliberately not GetUsableCredential, and the difference is the whole reason
-- this statement exists. A TOTP enrollment is provisioned before it is proven:
-- the row is written with enabled_at NULL and stays that way until a live code
-- confirms it. GetUsableCredential filters that row out — correctly, because a
-- login must never verify against an unproven factor — so the confirmation step
-- could not find the secret it has to open.
--
-- `disabled_at IS NULL` is still applied. A locked-out authenticator must not be
-- resurrected by a confirmation, and the partial unique index that keeps one
-- usable credential per kind is defined on the same predicate, so this returns at
-- most one row by construction rather than by hope.
SELECT credential_id, subject_id, kind, verifier, pepper_version, enabled_at
FROM credential
WHERE subject_id = $1 AND kind = $2 AND disabled_at IS NULL;

-- name: EnableCredential :execrows
-- Make a provisioned credential usable.
--
-- This is the write that completes a two-step enrollment, and it is separate from
-- UpsertCredential on purpose: the upsert also SETS the verifier, so confirming an
-- enrollment through it would require the caller to hand back the sealed secret it
-- has just read, and a caller holding a secret it does not need is a secret with
-- one more place to leak from.
--
-- `coalesce(enabled_at, now())` rather than a plain assignment, so a retried
-- confirmation neither moves the timestamp nor reports zero rows. The affected-row
-- count then answers exactly one question — does this credential still exist and
-- is it still usable — which is what the caller needs to know.
UPDATE credential
SET enabled_at = coalesce(enabled_at, now())
WHERE credential_id = $1 AND disabled_at IS NULL;

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

-- name: ListCredentialsAtKeyVersion :many
-- The rotation job's work list: credentials still sealed under an old key
-- version, for one kind.
--
-- The job is not done until this returns zero rows, and the old transit key must
-- not be destroyed before then (identity.md §4). Nothing in code can enforce
-- that ordering, which is why the query exists as the check.
--
-- KIND IS A PARAMETER, and that is a correction rather than a generalisation for
-- its own sake. This query previously hardcoded `kind = 'password'`, which was
-- right when a password verifier was the only sealed value in the table. TOTP
-- secrets are now sealed here too (migration 00013), under their own key set with
-- its own versions — and they were INVISIBLE to this query. The consequence was
-- the worst shape a rotation bug can take: the job would report zero rows while
-- every TOTP secret still depended on the old key, an operator would read that as
-- "safe to destroy", and every second factor in the system would stop opening at
-- once, with no way back.
--
-- Each kind has its OWN key set and its own version numbers, so a caller must ask
-- per kind. Rotating the password pepper says nothing about the TOTP sealing key,
-- and a single query returning both would compare two unrelated version
-- sequences.
--
-- Kinds with no sealed value (recovery_code, passkey) simply never match, because
-- their verifier is NULL.
SELECT credential_id, subject_id, verifier
FROM credential
WHERE kind = $1 AND verifier IS NOT NULL AND pepper_version < $2
ORDER BY credential_id
LIMIT $3;

-- name: CountCredentialsAtKeyVersion :one
-- The rotation job's DONE check, and the one an operator runs before destroying a
-- key.
--
-- Separate from the work list because the question is different: the list is
-- bounded by LIMIT and answers "what do I re-seal next", while this answers "is
-- anything left at all". Reading a zero-length page as "finished" is the mistake
-- this exists to remove — a page can be empty because the limit was reached on a
-- previous pass and the caller forgot to loop.
SELECT count(*)
FROM credential
WHERE kind = $1 AND verifier IS NOT NULL AND pepper_version < $2;

-- name: ListCredentialsToReseal :many
-- The re-sealing job's work list, resumable past rows it could not re-seal.
--
-- This is ListCredentialsAtKeyVersion with two additions, and both exist because
-- that query answers "what is left" while a JOB needs "what do I do next".
--
-- 1. A CURSOR. ListCredentialsAtKeyVersion is ordered and LIMITed with no
--    resume point, which is correct for an operator running it by hand and wrong
--    for a loop: a row that cannot be re-sealed keeps its old pepper_version, so
--    it matches the predicate again and comes back at the head of every
--    subsequent page. One unopenable secret would pin the job to the first page
--    forever and the pass would report progress while making none. Paging on
--    `credential_id > $after` steps over it. credential_id is the primary key
--    and the sort column, so the cursor is unique and total — the property
--    page.Keyset exists to enforce elsewhere.
--
-- 2. The USER ID, by LEFT JOIN. A password verifier is sealed with the user id
--    and the credential id as AES-GCM additional data (argon2id.aad), so it
--    cannot be opened without the user id — and `credential` does not carry one.
--    A TOTP secret binds to subject_id instead and does not need it; it is
--    fetched for both kinds anyway so that one work list serves both, and the
--    caller refuses a password row with no user id rather than inventing one.
--
--    LEFT, not INNER, and the difference is load-bearing. Migration 00009
--    dropped credential's foreign key to user_view precisely so that rebuilding
--    the projection cannot cascade into authoritative credential rows — which
--    means a credential can legitimately exist with no user_view row while a
--    rebuild is in flight. Under an INNER JOIN those rows would silently vanish
--    from the work list while still counting in CountCredentialsAtKeyVersion,
--    and the job would loop on an empty page forever with no explanation. Under
--    a LEFT JOIN they arrive with a NULL user id and are reported as failures,
--    which is what they are.
--
-- disabled_at is deliberately NOT filtered, so this matches
-- CountCredentialsAtKeyVersion row for row. See ResealCredential.
SELECT c.credential_id, c.subject_id, u.user_id, c.verifier
FROM credential c
LEFT JOIN user_view u ON u.subject_id = c.subject_id
WHERE c.kind = sqlc.arg(kind)
  AND c.verifier IS NOT NULL
  AND c.pepper_version < sqlc.arg(below_version)
  AND c.credential_id > sqlc.arg(after_credential_id)
ORDER BY c.credential_id
LIMIT sqlc.arg(page_size);

-- name: ResealCredential :execrows
-- Move one credential's sealed value to a newer key version.
--
-- A COMPARE-AND-SET, like RehashCredential and for the same race: the re-sealing
-- job reads a verifier, re-seals it outside the transaction, and writes it back.
-- Between those two moments the login-time rehash may have replaced it, or the
-- user may have changed their password, or a second-factor re-enrollment may
-- have replaced the TOTP secret. Requiring the row to still hold the value that
-- was opened makes overwriting any of those impossible rather than unlikely.
-- Zero affected rows is the NORMAL outcome of losing that race, never an error:
-- whoever won wrote a value sealed under the CURRENT key, which is exactly what
-- this statement was trying to achieve.
--
-- It is a separate statement from RehashCredential rather than a reuse of it,
-- for two reasons that both bite.
--
-- `disabled_at IS NULL` is ABSENT here, and that is the important one.
-- RehashCredential is right to require it — writing a fresh verifier onto a
-- locked-out authenticator leaves it looking maintained — but the rotation's
-- done check, CountCredentialsAtKeyVersion, counts disabled rows. Re-sealing
-- through a statement that skips them would leave the count permanently above
-- zero, and the operator would be told forever that it is not yet safe to
-- destroy the old key. One disabled credential would pin a retired key for the
-- life of the deployment. A disabled row is still sealed under that key, so
-- carrying it forward is also the truthful thing to do.
--
-- `pepper_version < $new` is PRESENT here, and RehashCredential has no
-- equivalent because it does not need one — it is driven by a login that has
-- just verified the plaintext. This one is driven by a batch, and the guard is
-- what makes "re-sealed under the version it already had" impossible at the
-- statement level rather than by the caller remembering. Without it a row whose
-- pepper_version column disagrees with its verifier (the migration allows this;
-- the verifier wins) could be rewritten at the same version on every pass — new
-- ciphertext, unchanged version, a done check that never falls, forever.
UPDATE credential
SET verifier       = sqlc.arg(new_verifier),
    pepper_version = sqlc.arg(pepper_version)
WHERE credential_id = sqlc.arg(credential_id)
  AND verifier      = sqlc.arg(expected_verifier)
  AND pepper_version < sqlc.arg(pepper_version);

-- name: ResetCredentialPassword :execrows
-- Replace a password verifier from a reset, but only if the row still holds the
-- one the reset was decided against.
--
-- A COMPARE-AND-SET, like RehashCredential, and here the comparison is the ONLY
-- serialization point the whole reset flow has. Two reset links can be redeemed
-- at the same instant — an attacker who triggered one and a victim who triggered
-- another, which is precisely the situation a reset exists for — and both
-- consume their own token successfully, because the tokens are different rows.
-- Without the guard both would write, and the surviving verifier would be
-- whichever transaction committed last: a password the user did not choose,
-- with no error anywhere. With it, exactly one wins, the loser writes nothing
-- and appends nothing, and the account is never left in a state between the two.
--
-- Separate from RehashCredential rather than a reuse of it, for two reasons.
--
-- `failures = 0` is the first. The consecutive-failure count refers to a
-- password that no longer exists after this statement, so carrying it forward
-- would let a run of guesses against the OLD password lock out the new one — and
-- the person it locks out is the one who just proved control of the mailbox.
-- RehashCredential must NOT do this: it runs after a login that already cleared
-- the count, and zeroing it there would hide a failure run that is still
-- accumulating against a credential nobody has successfully used.
--
-- `kind = 'password'` is the second. RehashCredential is driven by a login that
-- has just verified a password and therefore cannot name anything else; this is
-- driven by a credential id read from the account's event stream, and pinning
-- the kind in the statement means a bug that handed it a TOTP credential id
-- writes nothing rather than sealing a password verifier into the second-factor
-- row.
--
-- `disabled_at IS NULL` for RehashCredential's reason: a fresh verifier on a
-- locked-out authenticator leaves the lockout intact and the row looking
-- maintained.
UPDATE credential
SET verifier       = sqlc.arg(new_verifier),
    pepper_version = sqlc.arg(pepper_version),
    failures       = 0
WHERE credential_id = sqlc.arg(credential_id)
  AND verifier      = sqlc.arg(expected_verifier)
  AND kind          = 'password'
  AND disabled_at IS NULL;

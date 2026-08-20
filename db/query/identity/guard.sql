-- The two single-use guards: TOTP time steps and emailed tokens.
--
-- Both are written as ONE statement that both checks and consumes. That is not
-- a style preference — it is the entire security property. A SELECT followed by
-- an INSERT or DELETE lets two concurrent presentations of the same secret both
-- observe it as unused, and both succeed. That concurrency is not hypothetical:
-- it is exactly what an attacker relaying a code or a link produces.

-- name: ClaimTOTPStep :execrows
-- Spend a TOTP time step, or report that it was already spent.
--
-- RFC 6238 §5.2. A code stays valid for its whole step and for the skew window
-- either side, so without this an observed code — a screenshot, a log line, a
-- phishing relay — can be presented again inside that window and will validate.
--
-- The affected-row count IS the answer: 1 means this caller spent the step, 0
-- means somebody already had. Verified against live Postgres: eight concurrent
-- executions for one step produced exactly one winner.
INSERT INTO totp_replay (credential_id, step, expires_at)
VALUES ($1, $2, $3)
ON CONFLICT (credential_id, step) DO NOTHING;

-- name: SweepTOTPReplay :execrows
-- Drop spent steps whose codes can no longer be presented.
--
-- Retention, not correctness: a step that can no longer validate cannot be
-- replayed either, so keeping the row protects nothing and the table would grow
-- for the lifetime of the deployment.
DELETE FROM totp_replay WHERE expires_at <= now();

-- name: IssueToken :exec
-- Record a token digest.
--
-- The digest is the primary key and the purpose is mixed INTO it (see
-- adapter/token), so a verification token cannot collide with — or be redeemed
-- as — a reset token even though both live here.
INSERT INTO identity_token (digest, purpose, subject_id, expires_at)
VALUES ($1, $2, $3, $4);

-- name: ConsumeToken :one
-- Redeem a token exactly once and report whose it was.
--
-- DELETE ... RETURNING, in one statement. The obvious two-step — look it up,
-- then delete it — lets two simultaneous clicks of the same reset link both find
-- it valid, which turns a single-use credential into a multi-use one for anyone
-- who intercepted the mail.
--
-- The expiry is checked HERE rather than by the caller, so an expired token is
-- indistinguishable from an unknown one: both return no rows. Reporting "this
-- token was valid but has expired" would confirm that the address it was sent to
-- has an account.
DELETE FROM identity_token
WHERE digest = $1 AND purpose = $2 AND expires_at > $3
RETURNING subject_id;

-- name: RevokeTokens :execrows
-- Drop every outstanding token of a purpose for a subject.
--
-- Required by identity.md §7 rule 7: verification, reset and recovery void every
-- other outstanding token. Without it two reset links can be live at once, and
-- using one leaves the other usable — which is the window an attacker who
-- triggered an extra reset is waiting for.
DELETE FROM identity_token
WHERE subject_id = $1 AND purpose = $2;

-- name: SweepTokens :execrows
-- Retention. A token digest is not personal data, but it is evidence that a
-- particular account requested a reset, and it has no purpose past its expiry.
DELETE FROM identity_token WHERE expires_at <= now();

-- name: ConsumeRecoveryCode :one
-- Burn one recovery code, once.
--
-- Same single-statement discipline. `consumed_at IS NULL` in the WHERE clause is
-- what makes it single-use; a row that another transaction already consumed
-- fails the predicate and returns nothing.
--
-- The row is UPDATED rather than deleted so the count of codes ever issued
-- survives, and so "you have used 7 of 10" is answerable.
UPDATE recovery_code
SET consumed_at = now()
WHERE subject_id = $1 AND digest = $2 AND consumed_at IS NULL
RETURNING credential_id;

-- name: InsertRecoveryCode :exec
INSERT INTO recovery_code (subject_id, credential_id, digest)
VALUES ($1, $2, $3);

-- name: DeleteRecoveryCodes :exec
-- Replace the whole set. Whole-set replacement, never incremental top-up: a mix
-- of old and new codes makes "how many do I have left" unanswerable and leaves
-- codes the user believes were replaced still live.
DELETE FROM recovery_code WHERE subject_id = $1;

-- name: CountUnusedRecoveryCodes :one
SELECT count(*) FROM recovery_code
WHERE subject_id = $1 AND consumed_at IS NULL;

-- name: RevokeAllTokensForSubject :execrows
-- Drop every outstanding token for a subject, of EVERY purpose.
--
-- Deliberately not RevokeTokens with a loop over purposes in Go, and the
-- difference is not tidiness. A loop is several statements: a purpose added to
-- app.TokenPurpose without being added to the loop is a live token that survives
-- a reset, silently, and nothing in any test would notice because the loop
-- passes. Filtering on the subject alone cannot acquire that gap — a new purpose
-- is covered the day it is invented.
--
-- Required by identity.md §4.5: a password reset voids every outstanding token
-- of every purpose for that subject, not only reset tokens. The variant it
-- closes is the attacker who triggered a VERIFICATION mail (or a second reset)
-- before the victim recovered, and holds a live link that outlives the recovery.
DELETE FROM identity_token WHERE subject_id = $1;

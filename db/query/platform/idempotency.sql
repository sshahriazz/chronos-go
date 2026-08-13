-- The idempotency gate (CONVENTIONS §6). Every statement here is written so the
-- CLAIM is atomic: two concurrent duplicates must never both be told to execute,
-- because that is the double-click this table exists to stop.

-- name: ClaimIdempotencyKey :execrows
-- Take the claim, or report that somebody else holds it.
--
-- One statement, not check-then-act. A SELECT followed by an INSERT lets two
-- concurrent requests both read "nothing there" and both proceed — which is
-- exactly the failure being prevented, reintroduced by the check meant to
-- prevent it.
--
-- The ON CONFLICT branch takes over an EXPIRED row rather than refusing it, so a
-- key becomes reusable at its TTL without waiting for the retention sweep. Its
-- WHERE clause fails for a live row, so nothing is returned and the affected
-- count is zero — which is how the caller learns somebody else holds the claim.
--
-- Expiry is computed from the SERVER's clock. Passing a timestamp from Go would
-- make the TTL depend on which replica handled the request.
INSERT INTO idempotency_key (principal, operation, key, fingerprint, expires_at)
VALUES ($1, $2, $3, $4, now() + make_interval(secs => sqlc.arg(ttl_seconds)::double precision))
ON CONFLICT (principal, operation, key) DO UPDATE SET
    fingerprint = EXCLUDED.fingerprint,
    response    = NULL,
    claimed_at  = now(),
    expires_at  = EXCLUDED.expires_at
WHERE idempotency_key.expires_at <= now();

-- name: GetIdempotencyKey :one
-- Read the record held by whoever won the claim.
--
-- Reached only when ClaimIdempotencyKey found a LIVE row — an expired one is
-- taken over there and never gets this far, and `now()` is the transaction
-- timestamp, so the two statements cannot disagree about which side of the
-- expiry a row falls on.
--
-- The predicate is therefore unreachable defence, and that is deliberate rather
-- than accidental: verified by deleting it and watching the tests still pass,
-- then by deleting the claim's expiry check as well and watching them fail. If
-- the takeover above is ever loosened, this is what stops a response being
-- replayed past the TTL that bounds how long it may be kept.
SELECT fingerprint, response
FROM idempotency_key
WHERE principal = $1 AND operation = $2 AND key = $3 AND expires_at > now();

-- name: CompleteIdempotencyKey :execrows
-- Record the response against a claim this caller holds.
--
-- `response IS NULL` is the ownership check. Without it a late writer could
-- overwrite a completed record — replacing the answer a client has already been
-- given with a different one.
UPDATE idempotency_key
SET response = $4
WHERE principal = $1 AND operation = $2 AND key = $3
  AND response IS NULL
  AND expires_at > now();

-- name: ReleaseIdempotencyKey :execrows
-- Drop a claim whose execution failed, so a retry can run.
--
-- `response IS NULL` again, and here it is load-bearing: deleting a COMPLETED
-- record would let the mutation execute a second time under the same key, which
-- is the gate failing open.
DELETE FROM idempotency_key
WHERE principal = $1 AND operation = $2 AND key = $3
  AND response IS NULL;

-- name: DeleteExpiredIdempotencyKeys :execrows
-- Retention. A response can contain personal data, so this is not optional
-- housekeeping (ADR-002).
DELETE FROM idempotency_key WHERE expires_at <= now();

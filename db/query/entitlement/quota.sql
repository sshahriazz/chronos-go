-- Queries for quota reservations.

-- name: LockQuota :exec
-- Serialise every reservation for one (organization, limit).
--
-- This is what makes reserve atomic, and it took a wrong turn to get here. The
-- obvious `SELECT count(*) ... FOR UPDATE` is refused by PostgreSQL —
-- `FOR UPDATE is not allowed with aggregate functions` — and even if it were
-- allowed it would not work: with no rows yet there is nothing to lock, so the
-- FIRST two concurrent reservations would not serialise at all, which is
-- precisely the case that matters.
--
-- An advisory transaction lock has neither problem. It needs no row to exist,
-- it is released automatically at COMMIT or ROLLBACK, and it serialises exactly
-- the contenders for one limit rather than blocking the table.
--
-- Two different keys can hash to one lock, which costs a little unnecessary
-- contention and cannot cost correctness: the worst case is that two unrelated
-- limits queue behind each other.
SELECT pg_advisory_xact_lock(hashtext($1::text || ':' || $2::text));

-- name: CountLiveQuota :one
-- How many of this limit an organization is currently consuming.
--
-- Committed rows plus UNEXPIRED held rows. Counting only committed ones would
-- reopen the window the reservation exists to close: between reserve and commit
-- a second request would see the lower number and take the same last seat.
--
-- Correct only under LockQuota, taken first in the same transaction.
SELECT count(*)
FROM quota_reservation
WHERE org_id = $1
  AND limit_key = $2
  AND (committed_at IS NOT NULL OR expires_at > now());

-- name: InsertQuotaReservation :exec
INSERT INTO quota_reservation
    (reservation_id, org_id, limit_key, expires_at, subject_ref)
VALUES ($1, $2, $3, $4, $5);

-- name: CommitQuotaReservation :execrows
-- Turn a held reservation into usage.
--
-- Only an UNCOMMITTED, UNEXPIRED row is committable. A reservation that already
-- lapsed must not be resurrected: the seat it held was returned to the pool and
-- may already have been taken by somebody else.
UPDATE quota_reservation
SET committed_at = now()
WHERE reservation_id = $1
  AND committed_at IS NULL
  AND expires_at > now();

-- name: ReleaseQuotaReservation :execrows
-- Return a held reservation to the pool.
--
-- A COMMITTED row is untouched, which is what makes the gate's unconditional
-- `defer release()` safe: the handler that used its reservation committed it,
-- and this then does nothing.
DELETE FROM quota_reservation
WHERE reservation_id = $1 AND committed_at IS NULL;

-- name: ExpireQuotaReservations :execrows
-- The sweep. Held rows only; a committed row is usage and never expires.
DELETE FROM quota_reservation
WHERE committed_at IS NULL AND expires_at <= now();

-- name: ReleaseQuotaForSubject :execrows
-- Return everything a subject was holding or using — a workspace deleted, a
-- member removed. Committed rows included: this is usage going away.
DELETE FROM quota_reservation
WHERE org_id = $1 AND limit_key = $2 AND subject_ref = $3;

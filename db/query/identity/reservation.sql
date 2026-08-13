-- Email reservations — the lapse sweep's work list.
--
-- This table enforces NOTHING. Uniqueness of an address is enforced by the
-- reservation STREAM: two concurrent registrations for one address contend on
-- the same KurrentDB stream and exactly one append wins (ADR-044). A projection
-- is by definition behind the log, so a uniqueness check here would read "free"
-- for both of them.
--
-- It exists for the one question the log cannot answer cheaply: "which unverified
-- reservations have lapsed?" Answering that by replay would mean scanning every
-- reservation stream in the system on every sweep.
--
-- Like every projection statement, each of these must be safe to run twice: a
-- projector re-applies events after a restart and replays everything on a
-- rebuild, and a statement that failed the second time would stall it.

-- name: UpsertEmailReservation :exec
-- Applied from EmailReserved.
--
-- DO UPDATE, not DO NOTHING, because this event legitimately arrives for a row
-- that already exists: a lapsed claim can be taken over by a different subject,
-- and the takeover is recorded as EmailReleased followed by EmailReserved on the
-- same stream. Doing nothing would leave the row naming the previous holder.
--
-- Every column the new claim owns is overwritten, including released_at and
-- verified. A takeover of a released row must clear the release, and a row can
-- only be verified by a confirmation that comes AFTER this event in stream order.
INSERT INTO email_reservation_view (
    email_index, subject_id, verified, expires_at, reserved_at, released_at
) VALUES ($1, $2, false, $3, $4, NULL)
ON CONFLICT (email_index) DO UPDATE SET
    subject_id  = EXCLUDED.subject_id,
    verified    = false,
    expires_at  = EXCLUDED.expires_at,
    reserved_at = EXCLUDED.reserved_at,
    released_at = NULL;

-- name: ConfirmEmailReservation :exec
-- Applied from EmailReservationConfirmed.
--
-- expires_at is set to NULL rather than left in the past. A confirmed claim never
-- lapses, and clearing the deadline means the sweep cannot pick it up even if its
-- WHERE clause is later widened — the row simply has no deadline to compare
-- against. The CHECK constraint permits it precisely because verified is true.
--
-- Guarded on subject_id: a confirmation names the subject that proved control,
-- and applying one to a row held by somebody else would hand them the address.
-- The domain already refuses that (EmailReservation.Confirm), so a mismatch here
-- means the projection disagrees with the stream — in which case updating it
-- would be worse than leaving it to be swept.
UPDATE email_reservation_view
SET verified = true, expires_at = NULL, released_at = NULL
WHERE email_index = $1 AND subject_id = $2;

-- name: ReleaseEmailReservation :exec
-- Applied from EmailReleased.
--
-- The row is MARKED, not deleted. Deleting it would make the projection's state
-- depend on which events had been applied rather than on all of them — a
-- subsequent EmailReserved for the same address would insert a fresh row either
-- way, but a released row is the evidence that the address was once claimed and
-- freed, and the sweep needs to be able to tell "never claimed" from "claimed and
-- released" when it is deciding whether its own release already landed.
UPDATE email_reservation_view
SET released_at = $3
WHERE email_index = $1 AND subject_id = $2 AND released_at IS NULL;

-- name: GetEmailReservation :one
SELECT email_index, subject_id, verified, expires_at, reserved_at, released_at
FROM email_reservation_view
WHERE email_index = $1;

-- name: ListLapsedReservations :many
-- The sweep's work list: unverified claims whose lease has run out.
--
-- Returns the index and the holder, which is everything needed to load the
-- aggregate and issue the release AGAINST THE STREAM. The sweep never writes this
-- table — the projector does, from the resulting EmailReleased — so a stale row
-- costs one wasted aggregate load and never a wrong release.
--
-- Ordered by deadline so the oldest claim is freed first, and limited because a
-- sweep that tried to release everything in one pass would hold its work in
-- memory and retry all of it on any single failure.
--
-- `NOT verified` is REDUNDANT against these statements and is kept deliberately.
-- A mutation removing it survives the test suite, because ConfirmEmailReservation
-- also sets expires_at to NULL and a NULL never satisfies `expires_at <= $1`. Two
-- reasons it stays: the partial index below is defined on exactly this predicate,
-- and a query that does not match it does not use it; and the redundancy is the
-- point — freeing a verified address is the worst outcome this table can cause,
-- so it should take two independent mistakes rather than one.
SELECT email_index, subject_id, expires_at
FROM email_reservation_view
WHERE NOT verified
  AND released_at IS NULL
  AND expires_at <= $1
ORDER BY expires_at
LIMIT $2;

-- name: DeleteReleasedReservations :execrows
-- Retention for rows that have been released long enough that nothing will ask
-- about them again.
--
-- Safe to run on a projection because it deletes only what a rebuild would
-- recreate. It exists because released rows otherwise accumulate forever: an
-- address abandoned during registration leaves one behind every time.
--
-- `released_at IS NOT NULL` is redundant — a NULL released_at never satisfies the
-- comparison either — and is kept for the same reason as in the sweep: a reader
-- should not have to re-derive three-valued logic to be sure this cannot delete a
-- live claim.
DELETE FROM email_reservation_view
WHERE released_at IS NOT NULL AND released_at < $1;

-- name: TruncateEmailReservations :exec
-- Empty the projection so it can be rebuilt from position zero.
--
-- ONE table, on its own — unlike TruncateIdentityProjections, which must name
-- three because a foreign key ties them together. Nothing references this table
-- and it references nothing, which is what lets it be rebuilt independently of
-- the account and session projections.
TRUNCATE TABLE email_reservation_view;

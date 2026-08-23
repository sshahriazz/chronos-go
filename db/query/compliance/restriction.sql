-- Queries for Article 18 processing restrictions.

-- name: UpsertRestriction :exec
-- Record that processing is halted for a subject.
--
-- Upsert because a projector replays: the same event WILL arrive twice.
-- `restricted_at` is NOT updated on conflict — a replay must not move the
-- instant the person was told about, and the aggregate refuses a second
-- restriction for the same reason.
INSERT INTO processing_restriction_view (subject_id, restricted_at, actor_id)
VALUES ($1, $2, $3)
ON CONFLICT (subject_id) DO NOTHING;

-- name: DeleteRestriction :exec
-- Lifting deletes the row: presence IS the restriction.
DELETE FROM processing_restriction_view WHERE subject_id = $1;

-- name: IsProcessingRestricted :one
-- May this subject be contacted?
--
-- Read once per tenant-facing notification, so it is a primary-key lookup and
-- nothing more. The common answer is false — almost nobody is restricted — and
-- a table of exceptions makes that a miss on a small index.
SELECT EXISTS (SELECT 1 FROM processing_restriction_view WHERE subject_id = $1);

-- name: TruncateRestrictions :exec
TRUNCATE TABLE processing_restriction_view;

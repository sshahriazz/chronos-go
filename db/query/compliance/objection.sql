-- Queries for Article 21 processing objections.

-- name: UpsertObjection :exec
-- Record that one purpose is stopped for a subject.
--
-- Upsert because a projector replays: the same event WILL arrive twice.
-- `objected_at` is NOT updated on conflict — a replay must not move the instant
-- the person was told about, and the aggregate keeps the first instant for the
-- same reason.
INSERT INTO processing_objection_view (subject_id, purpose, objected_at, actor_id)
VALUES ($1, $2, $3, $4)
ON CONFLICT (subject_id, purpose) DO NOTHING;

-- name: DeleteObjection :exec
-- Withdrawing deletes the row: presence IS the objection.
--
-- Scoped to ONE purpose. A delete by subject alone would release every objection
-- the person holds when they withdrew one, which is the failure the composite
-- primary key exists to make impossible to write by accident.
DELETE FROM processing_objection_view
WHERE subject_id = $1 AND purpose = $2;

-- name: HasObjectedToPurpose :one
-- May this subject be processed for this purpose?
--
-- Read once per Activity- or Product-class notification — never for Security or
-- Transactional, which rest on contract and on legal obligations and which
-- Article 21 does not reach. So it is a primary-key lookup and nothing more, on
-- the minority of sends.
SELECT EXISTS (
    SELECT 1 FROM processing_objection_view
    WHERE subject_id = $1 AND purpose = $2
);

-- name: ListObjections :many
-- Every purpose one subject has stopped, oldest objection first.
--
-- For an operator answering a question about a person's own request. The
-- SUBJECT's own list is read from the aggregate instead, so somebody who has
-- just objected is not told their instruction has not taken effect while a
-- projector catches up.
SELECT subject_id, purpose, objected_at, actor_id
FROM processing_objection_view
WHERE subject_id = $1
ORDER BY objected_at, purpose;

-- name: TruncateObjections :exec
TRUNCATE TABLE processing_objection_view;

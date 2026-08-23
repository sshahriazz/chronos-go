-- Queries for data_export_view.
--
-- The subject's own poll, and the controller's evidence that a request was
-- answered. Every DECISION about an export is taken against the aggregate; this
-- table answers "where has my request got to", which tolerates lag.

-- name: UpsertDataExportRequest :exec
-- Applied from DataExportRequested.
--
-- Upsert, because a projector replays: the same event WILL arrive twice, and an
-- insert would fail the second time and stall the projection permanently.
--
-- The conflict clause touches NOTHING. Every column a later event owns — the
-- status, the manifest, the reason, the settlement time — must survive a
-- redelivered request, or a replay resurrects a finished export as pending and
-- the subject is told to wait for a bundle they already have. On a genuine
-- rebuild the INSERT path runs, because the table was truncated, and the later
-- events move it again in order.
INSERT INTO data_export_view (export_id, subject_id, status, requested_at)
VALUES ($1, $2, 'pending', $3)
ON CONFLICT (export_id) DO NOTHING;

-- name: CompleteDataExport :exec
-- Applied from DataExportCompleted.
--
-- NOT guarded on the current status, deliberately. A rebuild replays
-- requested → failed → completed for an export that failed once and was retried
-- into success, and a guard on `status = 'pending'` would leave that row failed
-- forever — reporting an error for a bundle that is sitting there. The
-- aggregate is what refuses an illegal transition; this records what the log
-- says happened.
UPDATE data_export_view
SET status = 'ready', manifest_key = $2, object_count = $3,
    failure_reason = NULL, settled_at = $4
WHERE export_id = $1;

-- name: FailDataExport :exec
-- Applied from DataExportFailed.
--
-- Guarded on `status <> 'ready'`, and that guard is the table's half of the rule
-- the aggregate holds: a late failure from an earlier attempt must never
-- overwrite a fetchable bundle. Without it a redelivered failure would tell
-- somebody their export failed while the manifest waited for them.
UPDATE data_export_view
SET status = 'failed', failure_reason = $2, settled_at = $3
WHERE export_id = $1 AND status <> 'ready';

-- name: GetDataExport :one
-- The subject's poll.
--
-- Scoped by subject_id as well as by id, and the export id alone would be enough
-- to find the row — which is exactly why it is not enough to return it. The id
-- is unguessable, but "unguessable" is not an authorization rule: one leaked id
-- would otherwise hand a stranger the manifest key for the most concentrated
-- copy of somebody's data in the system.
SELECT export_id, subject_id, status, manifest_key, object_count,
       failure_reason, requested_at, settled_at
FROM data_export_view
WHERE export_id = $1 AND subject_id = $2;

-- name: ListDataExports :many
-- What has this person asked for, newest first.
SELECT export_id, status, object_count, failure_reason, requested_at, settled_at
FROM data_export_view
WHERE subject_id = $1
ORDER BY requested_at DESC
LIMIT $2;

-- name: TruncateDataExports :exec
TRUNCATE TABLE data_export_view;

-- Queries for the tables the PLATFORM owns: projector checkpoints and reactor
-- deduplication. They belong to no module — every module's projector and every
-- module's reactor share them — so they are generated separately.
--
-- Not included here, and deliberately: session settings (set_config), advisory
-- locks (pg_try_advisory_lock) and role inspection (pg_roles). Those are not
-- queries against our schema; they are database primitives the kernel uses to
-- enforce tenancy and single-writer leases. sqlc has no schema to check them
-- against, and expressing them as .sql files would add ceremony without adding
-- the verification that is the entire point (ADR-011 carve-out).

-- name: LoadCheckpoint :one
SELECT commit_position, prepare_position, events_processed
FROM projection_checkpoint
WHERE name = $1;

-- name: SaveCheckpoint :exec
-- Queued into the same pipelined round trip as the rows it describes, so that
-- rows and checkpoint commit together (ADR-019).
INSERT INTO projection_checkpoint
    (name, commit_position, prepare_position, events_processed, last_event_at, updated_at, holder)
VALUES ($1, $2, $3, $4, now(), now(), $5)
ON CONFLICT (name) DO UPDATE SET
    commit_position  = EXCLUDED.commit_position,
    prepare_position = EXCLUDED.prepare_position,
    events_processed = EXCLUDED.events_processed,
    last_event_at    = EXCLUDED.last_event_at,
    updated_at       = EXCLUDED.updated_at,
    holder           = EXCLUDED.holder;

-- name: ClearCheckpoint :exec
DELETE FROM projection_checkpoint WHERE name = $1;

-- name: HasReactorProcessed :one
SELECT true FROM reactor_processed WHERE reactor = $1 AND event_id = $2;

-- name: MarkReactorProcessed :exec
-- ON CONFLICT DO NOTHING because two consumers racing on the same redelivered
-- event is normal for a competing-consumer group, and neither should fail.
INSERT INTO reactor_processed (reactor, event_id) VALUES ($1, $2)
ON CONFLICT (reactor, event_id) DO NOTHING;

-- name: ForgetProcessedBefore :execrows
-- The dedup table would otherwise grow forever. The window must comfortably
-- exceed the longest possible redelivery gap.
DELETE FROM reactor_processed
WHERE processed_at < now() - make_interval(days => sqlc.arg(older_than_days)::int);

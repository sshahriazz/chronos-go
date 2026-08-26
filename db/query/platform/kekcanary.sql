-- Queries for kek_canary.

-- name: GetKEKCanary :one
SELECT kek_name, wrapped FROM kek_canary WHERE id;

-- name: InsertKEKCanary :exec
-- Written once, the first time a build sees an empty table.
--
-- DO NOTHING on conflict rather than DO UPDATE: a second writer means two
-- processes started against an empty table at once, and the first one's canary
-- is as good as the second's. Overwriting would let a process that holds the
-- WRONG key replace the proof that it is wrong.
INSERT INTO kek_canary (kek_name, wrapped) VALUES ($1, $2)
ON CONFLICT (id) DO NOTHING;

-- name: TouchKEKCanary :exec
-- Record that the canary verified, so an operator can see the check is running
-- rather than assuming it.
UPDATE kek_canary SET verified_at = $1 WHERE id;

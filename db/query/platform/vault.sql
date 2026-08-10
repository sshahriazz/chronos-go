-- The PII vault. Only ciphertext and wrapped keys cross these queries.

-- name: GetSubjectKey :one
SELECT wrapped_dek, erased_at FROM pii_key WHERE subject_id = $1;

-- name: CreateSubjectKey :exec
-- DO NOTHING on conflict: two concurrent registrations for one subject must not
-- produce two keys, or half the values become unreadable under the other.
INSERT INTO pii_key (subject_id, wrapped_dek) VALUES ($1, $2)
ON CONFLICT (subject_id) DO NOTHING;

-- name: EraseSubjectKey :execrows
-- The key goes; the value rows stay, unreadable. Deleting them would leave
-- nothing to show the erasure happened (ADR-002).
-- Already-erased subjects match nothing, so erasure is idempotent.
UPDATE pii_key
SET wrapped_dek = NULL, erased_at = now()
WHERE subject_id = $1 AND erased_at IS NULL;

-- name: PutValue :exec
INSERT INTO pii_value (subject_id, field, ciphertext, updated_at)
VALUES ($1, $2, $3, now())
ON CONFLICT (subject_id, field) DO UPDATE SET
    ciphertext = EXCLUDED.ciphertext,
    updated_at = EXCLUDED.updated_at;

-- name: GetValue :one
SELECT ciphertext FROM pii_value WHERE subject_id = $1 AND field = $2;

-- name: ListValues :many
SELECT field, ciphertext FROM pii_value WHERE subject_id = $1;

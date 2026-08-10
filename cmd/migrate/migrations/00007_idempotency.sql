-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- idempotency_key — gate 5 of the request pipeline (ADR-021, CONVENTIONS §6)
-- ---------------------------------------------------------------------------
-- Every mutating RPC carries a client-generated Idempotency-Key. A retry with
-- the same key and the same body returns the STORED response instead of
-- executing again; the same key with a different body is a client bug and is
-- refused.
--
-- The primary key is (principal, operation, key), and the principal is the part
-- that matters. Keyed on the key alone, one tenant sending another's key is
-- handed that request's stored response — a cross-tenant read reachable by
-- guessing a ULID.
--
-- NOT tenant-scoped and carrying no RLS, for a reason worth stating: the gate
-- runs BEFORE the tenant scope is established (the request has not been
-- authorized yet), so a policy here could not be satisfied. Isolation comes
-- from the principal being part of the key instead. `principal` is a
-- pseudonymous subject id, never an email or a name (ADR-002).
--
-- `response` is a serialized reply and CAN contain personal data, which is why
-- `expires_at` is not optional and the retention sweep is not optional either.
CREATE TABLE idempotency_key (
    principal   text        NOT NULL,
    operation   text        NOT NULL,
    key         text        NOT NULL,

    -- SHA-256 of the request body. Distinguishes a genuine replay from a key
    -- reused for a different request.
    fingerprint bytea       NOT NULL,

    -- NULL until the handler succeeds. A row with a NULL response is a CLAIM:
    -- somebody is executing this right now.
    response    bytea,

    claimed_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,

    PRIMARY KEY (principal, operation, key),

    CONSTRAINT idempotency_key_fingerprint_len CHECK (octet_length(fingerprint) = 32)
);

COMMENT ON TABLE idempotency_key IS
    'One row per (principal, operation, Idempotency-Key). NULL response = claim in flight.';

-- The retention sweep deletes by expiry; without this it scans the whole table.
CREATE INDEX idempotency_key_expiry_idx ON idempotency_key (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON idempotency_key TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS idempotency_key;
-- +goose StatementEnd

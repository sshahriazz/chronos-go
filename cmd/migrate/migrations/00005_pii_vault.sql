-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- The PII vault
-- ---------------------------------------------------------------------------
-- The ONE mutable system of record (ADR-013). Everything else in this database
-- is derived from the event log and rebuildable; this is not, because it holds
-- exactly what the log deliberately does not.
--
-- Both tables hold ONLY ciphertext and wrapped keys. A copy of this schema
-- without OpenBao is unreadable — which is the point, and why these tables are
-- not tenant-scoped: there is nothing in them to scope, and a subject exists
-- before they belong to any organization.

-- Per-subject data keys, wrapped by the KEK that never leaves OpenBao.
--
-- Erasure destroys the wrapped key HERE, and every value below becomes
-- ciphertext nobody can open. The value rows stay: deleting them would leave
-- nothing to show the erasure happened, and an audit needs that (ADR-002).
CREATE TABLE pii_key (
    subject_id  text        PRIMARY KEY,
    wrapped_dek bytea,
    created_at  timestamptz NOT NULL DEFAULT now(),
    erased_at   timestamptz,

    -- Erasure sets wrapped_dek to NULL and stamps erased_at. Enforced here so a
    -- half-erasure — key gone, no record of why — cannot be written.
    CONSTRAINT erasure_is_complete CHECK (
        (erased_at IS NULL AND wrapped_dek IS NOT NULL) OR
        (erased_at IS NOT NULL AND wrapped_dek IS NULL)
    )
);

COMMENT ON TABLE pii_key IS
    'Per-subject data keys, wrapped by the OpenBao KEK. Erasure nulls the key.';

CREATE INDEX pii_key_erased_idx ON pii_key (erased_at) WHERE erased_at IS NOT NULL;

-- Encrypted values. One row per subject per field.
--
-- The ciphertext is AES-256-GCM and authenticates the SUBJECT ID as additional
-- data, so a row copied into another subject's id fails to open rather than
-- decrypting into the wrong person's profile.
CREATE TABLE pii_value (
    subject_id text        NOT NULL REFERENCES pii_key (subject_id) ON DELETE CASCADE,
    field      text        NOT NULL,
    ciphertext bytea       NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (subject_id, field)
);

COMMENT ON TABLE pii_value IS
    'Encrypted personal data. Unreadable without the subject key in pii_key.';

GRANT SELECT, INSERT, UPDATE, DELETE ON pii_key   TO chronos_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON pii_value TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS pii_value;
DROP TABLE IF EXISTS pii_key;
-- +goose StatementEnd

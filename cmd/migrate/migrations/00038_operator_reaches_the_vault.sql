-- +goose Up
-- +goose StatementBegin

-- ===========================================================================
-- The one place the operator plane crosses into tenant storage (operator.md §4)
-- ===========================================================================
--
-- Migration 00037 granted chronos_operator six tables and revoked chronos_app
-- from all six. This grants it two more, and they are TENANT tables — so it
-- deserves its own migration and its own argument rather than being folded in
-- beside the others where it would read as part of the same list.
--
-- # Why the crossing has to exist
--
-- operator.md §4 requires it: "personal data is resolved from the PII vault
-- ONLY on explicit, justified access (§5), never bulk-joined into a list view".
-- A support engineer answering a ticket needs the address of the person who
-- filed it, and the alternative designs are worse:
--
--   - Copy the address into an operator projection. That is a second permanent
--     copy of personal data, outside the vault, which erasure cannot reach by
--     destroying a key — the property ADR-002 exists to preserve.
--   - Call the tenant API for it. Then the tenant API needs an endpoint that
--     resolves an arbitrary subject for a caller who is not that subject, which
--     is the most dangerous endpoint compliance.md §3 explicitly refuses to
--     build.
--
-- So the operator plane reads the vault directly, and what makes that safe is
-- the shape of the read rather than the absence of the grant.
--
-- # What bounds it
--
-- SELECT only, on two tables, and every layer above narrows it further:
--
--   - RevealPersonalData takes ONE subject and a bounded field list. There is
--     no shape of call that returns a page of addresses.
--   - A justification is mandatory, refused at the edge by protovalidate, in
--     the domain by the audit aggregate, and in the database by
--     operator_audit_log's own CHECK constraint.
--   - The audit entry is appended BEFORE the vault is read and a failure to
--     append fails the call, so a disclosure that could not be recorded does
--     not happen.
--   - No operator projection has a personal-data column, so nothing here can be
--     joined into a list.
--
-- # What is NOT granted, and stays that way
--
-- INSERT, UPDATE and DELETE on either table. The operator plane READS the
-- vault; it may not write one, and it may not erase one. Erasure is a data
-- subject's right exercised through compliance, and an operator who could
-- perform it from the back office would be an operator who could destroy a
-- person's data without the request that makes it lawful.
--
-- The KEY MATERIAL is also untouched by this. pii_key holds WRAPPED data keys;
-- unwrapping them needs OpenBao transit, which is a separate credential this
-- process holds separately. A database dump of both tables decrypts nothing.

GRANT SELECT ON pii_key   TO chronos_operator;
GRANT SELECT ON pii_value TO chronos_operator;

COMMENT ON TABLE pii_value IS
    'The PII vault (ADR-002, ADR-013). The only mutable system of record. chronos_operator holds SELECT and nothing else — see migration 00038 for why that crossing exists and what bounds it.';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
REVOKE SELECT ON pii_key   FROM chronos_operator;
REVOKE SELECT ON pii_value FROM chronos_operator;
-- +goose StatementEnd

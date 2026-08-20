-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- Correct what credential.verifier holds for a TOTP credential
-- ---------------------------------------------------------------------------
-- 00008's inline comment on this column says: "For TOTP: NULL, because the
-- secret lives in the vault under the subject's key." That is wrong, and it
-- contradicts the same migration's own table header, which states that the
-- password verifier AND the TOTP secret both belong here because neither can
-- enter an event.
--
-- The header is right. The PII vault holds PERSONAL DATA under a key that
-- erasure destroys (ADR-002). A TOTP secret is key material, not personal data:
-- it is not a fact about the person, it cannot be returned by a subject access
-- request, and `pii.Field` is a closed set precisely so that the vault's whole
-- surface is enumerable — adding a member that is not personal data breaks the
-- property that makes that enumeration meaningful.
--
-- Migrations are append-only (ADR-011), so 00008's text stays as written and is
-- corrected here instead. A COMMENT rather than a comment: it lands in the
-- database, so `\d+ credential` in psql shows the truth to whoever is looking at
-- the table at 3am, which is not a place a stale line in a migration file can
-- reach.
--
-- What is actually stored, per kind:
--
--   password        the PHC-shaped verifier: Argon2id parameters, salt, and the
--                   GCM-sealed digest. One-way. Never opened, only compared.
--   totp            the sealed shared secret, `totp$v<n>$<base64url>`, AES-256-GCM
--                   under a key wrapped by the OpenBao KEK, AAD-bound to
--                   `<subject_id>:<credential_id>`. Two-way by necessity — a code
--                   cannot be checked without recovering the secret — which is
--                   the one structural difference from a password.
--   recovery_code   NULL. The digests live in `recovery_code`, one row per code.
--   passkey         NULL for now; slice 2 decides.
--
-- The AAD binding is the property worth stating: a verifier row copied to
-- another account fails to OPEN rather than authenticating the attacker against
-- the victim, because the ids it was sealed against no longer match.

COMMENT ON COLUMN credential.verifier IS
    'password: PHC-shaped one-way verifier. totp: the sealed shared secret (AES-256-GCM, AAD-bound to subject_id:credential_id) — NOT the vault, which holds personal data only. recovery_code/passkey: NULL.';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
COMMENT ON COLUMN credential.verifier IS NULL;
-- +goose StatementEnd

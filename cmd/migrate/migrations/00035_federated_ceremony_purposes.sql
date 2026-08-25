-- +goose Up
-- +goose StatementBegin

-- Federated sign-in reuses webauthn_challenge, which is now a misnomer for a
-- table that holds any ceremony in flight.
--
-- Reused rather than duplicated because the requirement is identical and hard:
-- single-use, enforced by `DELETE … RETURNING` in one statement, with the
-- purpose checked in the same statement so a ceremony issued for one flow cannot
-- be answered as another. A second table would be a second place to get that
-- right, and identity.md §12 already argues why read-then-delete loses.
--
-- The table is NOT renamed. Renaming it would rewrite an applied migration's
-- effect for cosmetic reasons, and migrations are append-only (ADR-011); the
-- comment below carries the correction instead.
ALTER TABLE webauthn_challenge
    DROP CONSTRAINT IF EXISTS webauthn_challenge_purpose;

ALTER TABLE webauthn_challenge
    ADD CONSTRAINT webauthn_challenge_purpose CHECK (
        purpose IN ('registration', 'login', 'federated_login', 'federated_link')
    );

COMMENT ON TABLE webauthn_challenge IS
    'One ceremony in flight — WebAuthn or federated. Single-use, enforced by DELETE … RETURNING rather than read-then-write, with the purpose checked in the same statement so a ceremony issued for one flow cannot be answered as another. The name predates federation reusing it.';

COMMENT ON COLUMN webauthn_challenge.state IS
    'The ceremony adapter''s session data. For WebAuthn, the library''s session. For a federated sign-in, the PKCE verifier and the nonce — both of which never leave this system, which is what makes them a binding rather than a claim.';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE webauthn_challenge DROP CONSTRAINT IF EXISTS webauthn_challenge_purpose;
ALTER TABLE webauthn_challenge
    ADD CONSTRAINT webauthn_challenge_purpose CHECK (purpose IN ('registration', 'login'));
-- +goose StatementEnd

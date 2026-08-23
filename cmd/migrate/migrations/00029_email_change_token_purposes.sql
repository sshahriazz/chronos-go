-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- identity_token.purpose — admit the two email-change purposes
-- ---------------------------------------------------------------------------
-- identity.md §12's flow mints two kinds of token that did not exist when
-- 00008 wrote this constraint: `email_change`, mailed to the address an account
-- is moving TO, and `email_change_revert`, mailed to the address it moved AWAY
-- from.
--
-- # This constraint is worth keeping, which is why it is widened rather than
-- # dropped
--
-- The purpose is mixed INTO the digest, so a token of one kind already cannot
-- be redeemed as another even by a query that forgot to filter. The CHECK is
-- the second, independent control: it stops a typo'd purpose from being stored
-- at all, which would otherwise produce a row that no lookup can ever match and
-- a link that is dead on arrival with nothing to say so.
--
-- It found exactly that, once. The email-change flow was built, unit-tested and
-- wired end to end before anybody noticed the constraint had not been widened —
-- and the symptom was not a compile error or a failing unit test but a token
-- issuance refused at runtime, inside the mail reactor, which would have parked
-- every requested change and mailed nobody. Dropping the constraint would have
-- "fixed" that by removing the thing that caught it.
--
-- # Why the values are literals and not a reference to Go
--
-- They cannot be anything else: a CHECK cannot read a Go constant. The pairing
-- is held instead by TestEveryTokenPurposeHasALifetime and by this comment. If
-- a purpose is ever added to app.TokenPurpose without a migration, the failure
-- is loud, immediate and localised to the issuance — which is the direction
-- this constraint exists to fail in.
ALTER TABLE identity_token DROP CONSTRAINT identity_token_purpose;

ALTER TABLE identity_token ADD CONSTRAINT identity_token_purpose CHECK (
    purpose IN (
        'email_verification',
        'password_reset',
        'email_change',
        'email_change_revert'
    )
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Narrowing back would fail against any row holding one of the new purposes, so
-- the outstanding ones are dropped first. They are single-use, short-lived
-- secrets whose loss costs their holder a fresh link — which is the correct
-- price for rolling a migration back under them.
DELETE FROM identity_token WHERE purpose IN ('email_change', 'email_change_revert');

ALTER TABLE identity_token DROP CONSTRAINT identity_token_purpose;

ALTER TABLE identity_token ADD CONSTRAINT identity_token_purpose CHECK (
    purpose IN ('email_verification', 'password_reset')
);

-- +goose StatementEnd

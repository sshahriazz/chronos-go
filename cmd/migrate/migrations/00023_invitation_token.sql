-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- invitation_token — the credential inside an invitation link
-- ---------------------------------------------------------------------------
-- Digests only, exactly as `identity_token` holds them. The plaintext exists in
-- one place — the mail that was sent — and never reaches this database or a log.
--
-- # Why a handler writes this, when handlers do not write PostgreSQL
--
-- The rule is that writes go to KurrentDB and projectors fill PostgreSQL, so
-- every projected table is reconstructable by replaying from position zero. A
-- token digest is the deliberate exception, and it is the same exception
-- `identity_token` takes: the digest must NOT be in the event log. A log is
-- replicated, retained far longer than any token's lifetime, and readable by
-- every projector — putting a live credential there would mean a token could be
-- recovered from a backup long after it was spent.
--
-- So this table is not a projection and is not rebuildable, and that is correct:
-- what is lost by losing it is the ability to redeem outstanding links, which is
-- a resend away. Nothing about who was invited, or what seat they hold, lives
-- here — all of that is in the log.
--
-- # Why the digest is the primary key
--
-- Redemption looks a token up BY the value presented. Keying on the invitation
-- id instead would mean scanning, and would allow two live digests for one
-- invitation — which is exactly what a rotation must not leave behind.
--
-- The purpose is mixed INTO the digest by platform/secret rather than stored
-- beside it, so an invitation token cannot be redeemed as a verification link
-- even by a query that forgot to filter. The column is kept for the same reason
-- identity_token keeps it: it makes the constraint below readable, and it makes
-- a row explicable to somebody looking at the table.
CREATE TABLE invitation_token (
    digest  bytea PRIMARY KEY,
    purpose text  NOT NULL,

    invitation_id text NOT NULL,

    -- Carried so a rotation can delete every outstanding digest for one
    -- invitation without a join, and so an operator can attribute a row.
    org_id text NOT NULL,

    issued_at  timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,

    CONSTRAINT invitation_token_purpose CHECK (purpose IN ('workspace_invitation')),
    CONSTRAINT invitation_token_digest_len CHECK (octet_length(digest) = 32)
);

COMMENT ON TABLE invitation_token IS
    'Invitation link credentials, as digests. Consumed by DELETE ... RETURNING. Not a projection.';

-- # No row security, deliberately
--
-- Redemption happens BEFORE any tenant scope exists: the person clicking the
-- link may have no account at all, and resolving which organization the
-- invitation belongs to is precisely what the lookup is doing. A policy keyed on
-- `app.org_id` would hide every row from the one caller who legitimately has not
-- set it.
--
-- Containment is the key itself. The lookup is by a 256-bit value from
-- crypto/rand that exists only in the recipient's mail — it is not guessable,
-- not enumerable, and not derivable from anything a caller can name. That is a
-- stronger control than a tenant predicate, and it is the same reasoning
-- `session_token` rests on.

-- Rotation deletes every outstanding digest for one invitation, and revocation
-- deletes them when the invitation settles. Without this both scan.
CREATE INDEX invitation_token_invitation_idx ON invitation_token (invitation_id);

-- The expiry sweep.
CREATE INDEX invitation_token_expiry_idx ON invitation_token (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON invitation_token TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS invitation_token;
-- +goose StatementEnd

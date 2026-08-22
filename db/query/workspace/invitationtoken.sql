-- Queries for the invitation link credential.
--
-- This is NOT a projection. See migration 00023 for why a handler writes it: a
-- token digest must never enter the event log, so it cannot be projected from
-- one. It is the same exception identity_token takes.

-- name: IssueInvitationToken :exec
-- Record a digest against an invitation, until it expires.
INSERT INTO invitation_token (digest, purpose, invitation_id, org_id, expires_at)
VALUES ($1, $2, $3, $4, $5);

-- name: LookupInvitationToken :one
-- Read a digest WITHOUT spending it, so the checks that can fail transiently run
-- first.
--
-- The alternative — consume, then check — burns the link for a failure the
-- recipient did nothing to cause: an organization that is briefly past due, or a
-- seat pool that is momentarily full. They would then hold a dead link for a
-- pending invitation, and only a resend could fix it.
--
-- Single use is NOT weakened by this. Consumption is still one atomic
-- DELETE ... RETURNING immediately before the append, so two simultaneous clicks
-- still resolve to exactly one winner; this only moves the transient failures to
-- the side of that line where they can be retried.
--
-- Same expiry treatment as the consume, for the same reason: an expired token
-- must be indistinguishable from an unknown one.
SELECT invitation_id, org_id FROM invitation_token
WHERE digest = $1 AND purpose = $2 AND expires_at > $3;

-- name: ConsumeInvitationToken :one
-- Redeem a token exactly once and report which invitation it belongs to.
--
-- DELETE ... RETURNING, in one statement. The obvious two-step — look it up,
-- then delete it — lets two simultaneous clicks of the same link both find it
-- valid, which turns a single-use credential into a multi-use one for anyone who
-- intercepted the mail.
--
-- The expiry is checked HERE rather than by the caller, so an expired token is
-- indistinguishable from an unknown one: both return no rows. Reporting "this
-- invitation was valid but has expired" tells an attacker holding a guessed
-- token that they guessed a real one, and tells anyone with an old mail whether
-- the organization still exists.
DELETE FROM invitation_token
WHERE digest = $1 AND purpose = $2 AND expires_at > $3
RETURNING invitation_id, org_id;

-- name: RevokeInvitationTokens :execrows
-- Drop every outstanding digest for one invitation.
--
-- Two callers, and they need the same statement for opposite reasons. A RESEND
-- must leave exactly one live link, or the "old token stays dead" rule in
-- workspace.md §5 is false and two people can accept one invitation. A
-- SETTLEMENT must leave none, or a revoked invitation is still redeemable by
-- whoever holds the mail.
DELETE FROM invitation_token WHERE invitation_id = $1;

-- name: SweepInvitationTokens :execrows
-- Retention. A digest is not personal data, but it is evidence that a particular
-- address was invited, and it has no purpose past its expiry.
DELETE FROM invitation_token WHERE expires_at <= now();

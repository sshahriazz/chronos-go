-- Queries for webauthn_challenge.
--
-- One ceremony in flight, single-use. Not a projection: a ceremony that does not
-- complete is not a fact worth keeping.

-- name: InsertWebauthnChallenge :exec
-- Record a ceremony.
--
-- A plain INSERT under an unguessable primary key. No upsert: two ceremonies
-- cannot share an id, and if they somehow did, overwriting one would let a
-- second Begin invalidate a first that is mid-flight in another tab.
INSERT INTO webauthn_challenge (
    challenge_id, subject_id, purpose, state, expires_at
) VALUES ($1, $2, $3, $4, $5);

-- name: ConsumeWebauthnChallenge :one
-- Redeem a ceremony exactly ONCE.
--
-- The whole single-use rule, as one statement. A read-then-delete races two
-- simultaneous finishes and both win, which for a registration is one ceremony
-- producing two credentials and for a login is two sessions from one signature.
-- `identity_token`'s ConsumeToken makes the same argument and takes the same
-- shape.
--
-- The PURPOSE is checked in the same statement, so a challenge issued to add a
-- passkey cannot be answered as a sign-in — the same binding that stops a
-- verification token being redeemed as a password reset.
--
-- The EXPIRY is checked here too, so an expired challenge is indistinguishable
-- from an unknown one. Reporting "valid but expired" would confirm that a
-- ceremony id was real, which is the only thing a holder of a stale one learns
-- for free.
DELETE FROM webauthn_challenge
WHERE challenge_id = $1 AND purpose = $2 AND expires_at > $3
RETURNING subject_id, state;

-- name: SweepWebauthnChallenges :execrows
-- Drop ceremonies nobody completed.
--
-- Abandoned challenges are the ordinary case — a person closes the tab, or the
-- browser prompt times out — so this is routine housekeeping rather than an
-- alarm. Consuming already deletes; this only reclaims what was never answered.
DELETE FROM webauthn_challenge WHERE expires_at <= $1;

-- name: TruncateWebauthnChallenges :exec
TRUNCATE TABLE webauthn_challenge;

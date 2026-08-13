-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- Split the session's SECRET from the session's FACTS
-- ---------------------------------------------------------------------------
-- 00008 put the bearer-token digest and the idle deadline in session_view
-- alongside the columns a projector builds. Writing the session projector is
-- what showed that cannot work: SessionCreated carries no token digest — a
-- digest in an event would outlive the session permanently, for the same reason
-- a password verifier must never enter one — so a projector has nothing to write
-- into a NOT NULL column, and a rebuild that truncated the table would log every
-- user out by destroying secrets no replay can restore.
--
-- The rule this settles, and it is mechanical rather than case-by-case:
--
--   IN THE LOG        -> projection. Truncated and replayed on rebuild.
--   NOT IN THE LOG    -> authoritative. Never truncated, never reconstructed.
--
-- Secrets are never in the log. Values that move on every request are never in
-- the log either — recording each idle-deadline refresh as an event would make
-- every authenticated read a write. Both therefore belong on the authoritative
-- side, and everything else belongs on the projected side.
--
-- Applied to a session:
--
--   session_token   digest, idle deadline, last seen        AUTHORITATIVE
--   session_view    subject, device, AAL, absolute deadline,
--                   elevation, revocation, creation          PROJECTION
--
-- A session is usable only when BOTH rows exist. During a rebuild the projection
-- is briefly empty, so no session resolves — every user is signed out for the
-- duration and signs in again afterwards. That is a real cost and it is the
-- right one: the alternative is a table that cannot be rebuilt at all, so a bug
-- in the session projector could never be corrected by replaying the log.

CREATE TABLE session_token (
    -- SHA-256 of the opaque bearer token. The token itself is never stored, so a
    -- database dump yields digests that cannot be presented.
    token_digest bytea PRIMARY KEY,

    -- No foreign key to session_view, deliberately: that table is truncated on
    -- every rebuild, and a constraint here would either block the rebuild or
    -- cascade this row away with it.
    session_id text NOT NULL UNIQUE,

    -- The idle deadline lives here because it moves on every request. The
    -- ABSOLUTE deadline stays in the projection: it is set once, at creation, and
    -- it is in the log.
    idle_expires_at timestamptz NOT NULL,
    last_seen_at    timestamptz NOT NULL DEFAULT now(),

    created_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT session_token_digest_len CHECK (octet_length(token_digest) = 32)
);

COMMENT ON TABLE session_token IS
    'AUTHORITATIVE, not a projection. Bearer-token digests and the idle deadline, which move outside the log.';

-- The sweep deletes by idle deadline; without this it scans the whole table.
CREATE INDEX session_token_idle_idx ON session_token (idle_expires_at);

-- session_view loses the two columns that were never projectable.
ALTER TABLE session_view DROP CONSTRAINT session_view_idle_within_absolute;
ALTER TABLE session_view DROP CONSTRAINT session_view_digest_len;
ALTER TABLE session_view DROP COLUMN token_digest;
ALTER TABLE session_view DROP COLUMN idle_expires_at;
ALTER TABLE session_view DROP COLUMN last_seen_at;

COMMENT ON TABLE session_view IS
    'PROJECTION. Rebuildable from the log; holds no secret and nothing that moves per request.';

GRANT SELECT, INSERT, UPDATE, DELETE ON session_token TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE session_view ADD COLUMN token_digest    bytea;
ALTER TABLE session_view ADD COLUMN idle_expires_at timestamptz;
ALTER TABLE session_view ADD COLUMN last_seen_at    timestamptz NOT NULL DEFAULT now();
DROP TABLE IF EXISTS session_token;
-- +goose StatementEnd

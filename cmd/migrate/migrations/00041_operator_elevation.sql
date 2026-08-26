-- +goose Up
-- +goose StatementBegin

-- ===========================================================================
-- Break-glass elevation (operator.md §5)
-- ===========================================================================
--
-- "Elevation beyond a role's default requires a recorded justification, is
-- time-boxed (minutes, not hours), auto-expires, and raises an alert to a
-- second person at the time of use — not in a report someone reads next
-- quarter."
--
-- # It lives on the SESSION, not on the operator
--
-- Three columns on `operator_session` rather than a table keyed by operator,
-- and the difference is the difference between "this person may do X for
-- fifteen minutes" and "this browser tab may".
--
-- An operator holding two sessions elevates one of them, and a bearer stolen
-- from the other is unaffected — which matters precisely because elevation is
-- when the stakes are highest. It also means signing out ends the elevation,
-- which is the behaviour anybody would expect and which a separate table would
-- have had to remember to implement.
--
-- # Whether an elevation is LIVE is decided in SQL, never by a timer
--
-- `ResolveOperatorSession` compares `elevated_until` against the same `now` it
-- already compares `expires_at` against. So a sweep that is late costs an audit
-- record its punctuality and can never grant a capability past its window.
--
-- That is ADR-045's rule applied to a second case. A revocation tombstone is
-- cleared by confirmation and never by a timer, because a timer that fires
-- early restores access with no event and no log line. Here the same reasoning
-- runs the other way: the timer may fire late, or never, and the grant still
-- ends on time — because the deadline is read rather than acted upon.

ALTER TABLE operator_session
    -- The single capability granted. One, never a set: an elevation granting
    -- several would be a role change with a timer, and the audit entry would
    -- not say which of them was actually needed.
    ADD COLUMN elevated_capability text,

    -- ABSOLUTE, like the session's own deadline, and for the same reason.
    -- Nothing extends it; a second elevation is a second event with its own
    -- justification and its own alert.
    ADD COLUMN elevated_until timestamptz,

    -- The recorded justification, verbatim. The second free-text column in the
    -- operator plane, and the second whose presence is what makes the act
    -- reviewable — see operator_audit_log.reason for the same argument.
    ADD COLUMN elevation_reason text,

    -- Set the first time the elevated capability is actually exercised.
    --
    -- It is what lets OperatorElevationExpired report whether the glass was
    -- broken for nothing. An elevation nobody used is a false alarm, and
    -- telling it apart from one that was needed is the difference between an
    -- alert people act on and an alert people mute.
    ADD COLUMN elevation_used_at timestamptz,

    -- Set when the expiry has been RECORDED in the log, so the sweep does not
    -- append a second OperatorElevationExpired for the same window.
    --
    -- Distinct from `elevated_until` passing, which is what makes the grant
    -- stop working. This column is about the audit record, and separating the
    -- two is what stops a sweep outage from either double-recording or
    -- silently extending anything.
    ADD COLUMN elevation_expiry_recorded_at timestamptz,

    -- Coherence, asserted by the database rather than by the code that writes
    -- it. Every one of these is reachable through a partial write, and a
    -- half-written elevation is either a grant with no deadline or a deadline
    -- with no grant.
    ADD CONSTRAINT operator_session_elevation_coherent CHECK (
        (elevated_capability IS NULL AND elevated_until IS NULL AND elevation_reason IS NULL)
        OR (elevated_capability IS NOT NULL AND elevated_until IS NOT NULL
            AND elevation_reason IS NOT NULL AND length(elevation_reason) >= 8)
    );

COMMENT ON COLUMN operator_session.elevated_until IS
    'Absolute; nothing extends it. Whether the grant is live is decided by comparing this in SQL, so a late sweep never extends a window (ADR-045''s reasoning, applied the other way round).';

-- The sweep's index: elevations whose window has closed and whose expiry has
-- not yet been recorded. Partial, so it holds only what the sweep scans.
CREATE INDEX operator_session_elevation_sweep_idx
    ON operator_session (elevated_until)
    WHERE elevated_capability IS NOT NULL AND elevation_expiry_recorded_at IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS operator_session_elevation_sweep_idx;
ALTER TABLE operator_session
    DROP CONSTRAINT IF EXISTS operator_session_elevation_coherent,
    DROP COLUMN IF EXISTS elevation_expiry_recorded_at,
    DROP COLUMN IF EXISTS elevation_used_at,
    DROP COLUMN IF EXISTS elevation_reason,
    DROP COLUMN IF EXISTS elevated_until,
    DROP COLUMN IF EXISTS elevated_capability;
-- +goose StatementEnd

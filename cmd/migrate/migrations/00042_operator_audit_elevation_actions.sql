-- +goose Up
-- +goose StatementBegin

-- The audit log's action CHECK predates break-glass, so it refuses the two
-- events operator.md §5 requires. A projection that cannot write its row stops
-- — which is the correct behaviour and the reason this is a migration rather
-- than a widened constraint written defensively in advance.
ALTER TABLE operator_audit_log
    DROP CONSTRAINT operator_audit_action_known;

ALTER TABLE operator_audit_log
    ADD CONSTRAINT operator_audit_action_known CHECK (
        action IN ('signed_in', 'signed_out', 'viewed_customer', 'viewed_personal_data',
                   'elevated', 'elevation_expired')
    );

-- A break-glass GRANT carries a justification, exactly as a personal-data read
-- does, and for the same reason: it is the evidence that makes the act
-- reviewable. The EXPIRY does not — the justification belongs to the grant, and
-- repeating it would put the same free text in the log twice.
ALTER TABLE operator_audit_log
    ADD CONSTRAINT operator_audit_elevation_justified CHECK (
        action <> 'elevated'
        OR (reason IS NOT NULL AND length(reason) >= 8)
    );

-- "Who is breaking the glass, and how often" — the query an anomaly review
-- runs, and the one a weekly check on unused elevations runs. Partial, so it
-- indexes only the two actions it serves.
CREATE INDEX operator_audit_elevation_idx
    ON operator_audit_log (operator_id, occurred_at DESC)
    WHERE action IN ('elevated', 'elevation_expired');

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS operator_audit_elevation_idx;
ALTER TABLE operator_audit_log
    DROP CONSTRAINT IF EXISTS operator_audit_elevation_justified;
ALTER TABLE operator_audit_log DROP CONSTRAINT operator_audit_action_known;
ALTER TABLE operator_audit_log
    ADD CONSTRAINT operator_audit_action_known CHECK (
        action IN ('signed_in', 'signed_out', 'viewed_customer', 'viewed_personal_data')
    );
-- +goose StatementEnd

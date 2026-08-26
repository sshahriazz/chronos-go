-- +goose Up
-- +goose StatementBegin

-- The eighth audit action: an operator write against a tenant (operator.md §7).
--
-- It is the third that carries a MANDATORY justification, beside a
-- personal-data read and a break-glass — the three acts on this plane whose
-- lawfulness rests on the account of why they were taken. Each is enforced in
-- the same three places, and this is the database's.
ALTER TABLE operator_audit_log
    DROP CONSTRAINT operator_audit_action_known;

ALTER TABLE operator_audit_log
    ADD CONSTRAINT operator_audit_action_known CHECK (
        action IN ('signed_in', 'signed_out', 'viewed_customer', 'viewed_personal_data',
                   'elevated', 'elevation_expired', 'managed_operators', 'changed_tenant')
    );

-- A tenant change without a reason is a decision nobody can defend having made,
-- and the org is always named — unlike a list, every write here touches exactly
-- one customer.
ALTER TABLE operator_audit_log
    ADD CONSTRAINT operator_audit_tenant_write_justified CHECK (
        action <> 'changed_tenant'
        OR (org_id IS NOT NULL AND reason IS NOT NULL AND length(reason) >= 8)
    );

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE operator_audit_log
    DROP CONSTRAINT IF EXISTS operator_audit_tenant_write_justified;
ALTER TABLE operator_audit_log DROP CONSTRAINT operator_audit_action_known;
ALTER TABLE operator_audit_log
    ADD CONSTRAINT operator_audit_action_known CHECK (
        action IN ('signed_in', 'signed_out', 'viewed_customer', 'viewed_personal_data',
                   'elevated', 'elevation_expired', 'managed_operators')
    );
-- +goose StatementEnd

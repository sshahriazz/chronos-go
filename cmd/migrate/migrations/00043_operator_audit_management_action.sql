-- +goose Up
-- +goose StatementBegin

-- Operator account management is the seventh action the audit log records, and
-- the CHECK predates it. A projection that cannot write its row stops — which
-- is the correct behaviour and the reason this is a migration rather than a
-- constraint widened defensively in advance.
--
-- The `target_subject_id` column carries the TARGET OPERATOR here rather than a
-- subject pseudonym. That is a small overload of one column and it is
-- deliberate: both are "the party this entry is about", the pattern is the same
-- one `fields` already follows, and a dedicated `target_operator_id` would be
-- an eighth nullable that one action out of seven populates.
ALTER TABLE operator_audit_log
    DROP CONSTRAINT operator_audit_action_known;

ALTER TABLE operator_audit_log
    ADD CONSTRAINT operator_audit_action_known CHECK (
        action IN ('signed_in', 'signed_out', 'viewed_customer', 'viewed_personal_data',
                   'elevated', 'elevation_expired', 'managed_operators')
    );

-- The personal-data justification rule names `viewed_personal_data` only, and
-- `target_subject_id` is now populated by a second action — so the constraint
-- has to be re-stated to keep meaning what it meant. Without this it would be
-- unchanged and still correct, and re-stating it is the cheaper way to be sure
-- of that than reasoning about it later.
--
-- (It IS unchanged. This comment is the review, recorded.)

-- "Who changed access, and when" — the query an access review runs, and the
-- reason this event exists at all rather than being folded into the operator's
-- own stream.
CREATE INDEX operator_audit_management_idx
    ON operator_audit_log (occurred_at DESC)
    WHERE action = 'managed_operators';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS operator_audit_management_idx;
ALTER TABLE operator_audit_log DROP CONSTRAINT operator_audit_action_known;
ALTER TABLE operator_audit_log
    ADD CONSTRAINT operator_audit_action_known CHECK (
        action IN ('signed_in', 'signed_out', 'viewed_customer', 'viewed_personal_data',
                   'elevated', 'elevation_expired')
    );
-- +goose StatementEnd

-- Queries for the operator plane (ADR-024, operator.md).
--
-- Every statement here runs as chronos_operator, which is granted these six
-- tables and nothing else. There is no `SET LOCAL app.workspace_id` anywhere in
-- this file and that is correct rather than an omission: operator tables carry
-- no tenant column, so there is no RLS policy for a scope to feed.

-- name: GetOperatorByBinding :one
-- Resolve an operator from what the IdP asserted. The sign-in path's first
-- question, and the reason it is a lookup on (issuer, provider_subject) rather
-- than on an address: an address can change hands, and a provider subject
-- cannot.
SELECT operator_id, subject_id, issuer, provider_subject, role, disabled_at, provisioned_at
FROM operator_account
WHERE issuer = $1 AND provider_subject = $2;

-- name: GetOperator :one
SELECT operator_id, subject_id, issuer, provider_subject, role, disabled_at, provisioned_at
FROM operator_account
WHERE operator_id = $1;

-- name: UpsertOperatorAccount :exec
-- The projection's write. Idempotent on operator_id so a replay lands the same
-- row rather than a duplicate.
INSERT INTO operator_account (
    operator_id, subject_id, issuer, provider_subject, role, disabled_at, provisioned_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, now())
ON CONFLICT (operator_id) DO UPDATE SET
    role        = EXCLUDED.role,
    disabled_at = EXCLUDED.disabled_at,
    updated_at  = now();

-- name: SetOperatorRole :exec
-- A plain UPDATE rather than an upsert, and it is safe because a catch-up
-- subscription preserves order WITHIN a stream: an operator's provisioning is
-- always applied before any role change on the same stream, on a live feed and
-- on a rebuild alike. An upsert here would need issuer and provider_subject,
-- which a role change does not carry, and would insert a row with empty
-- identity columns if it ever ran first.
UPDATE operator_account
SET role = $2, updated_at = now()
WHERE operator_id = $1;

-- name: DisableOperatorAccount :exec
-- Sets, never clears. Re-granting access is a new provisioning by a second
-- person, which is an audited act; a column that could be un-set would turn
-- offboarding into a toggle.
UPDATE operator_account
SET disabled_at = $2, updated_at = now()
WHERE operator_id = $1;

-- name: TruncateOperatorAccounts :exec
TRUNCATE operator_account;

-- ---------------------------------------------------------------------------
-- Credentials
-- ---------------------------------------------------------------------------

-- name: ListOperatorCredentials :many
SELECT credential_id, operator_id, public_key, sign_count, aaguid, transports,
       backup_eligible, backup_state, label, created_at, last_used_at, clone_warned_at
FROM operator_credential
WHERE operator_id = $1
ORDER BY created_at DESC;

-- name: CountOperatorCredentials :one
SELECT count(*) FROM operator_credential WHERE operator_id = $1;

-- name: GetOperatorCredential :one
SELECT credential_id, operator_id, public_key, sign_count, aaguid, transports,
       backup_eligible, backup_state, label, created_at, last_used_at, clone_warned_at
FROM operator_credential
WHERE credential_id = $1;

-- name: InsertOperatorCredential :exec
-- Plain INSERT, never an upsert. The primary key is unique across every
-- operator — WebAuthn L3 §7.1 step 27 — and ON CONFLICT DO UPDATE would REPLACE
-- another operator's registration with the caller's, which is precisely the
-- takeover the uniqueness rule exists to prevent. A conflict must surface.
INSERT INTO operator_credential (
    credential_id, operator_id, public_key, sign_count, aaguid, transports,
    backup_eligible, backup_state, label
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: AdvanceOperatorSignCount :execrows
-- Atomic, and the WHERE clause is the clone check. Zero rows means the counter
-- did not move forward, which the caller treats as a possible clone rather than
-- as a failed write.
UPDATE operator_credential
SET sign_count = $2, last_used_at = now()
WHERE credential_id = $1 AND sign_count < $2;

-- name: TouchOperatorCredential :exec
-- Records use without moving the counter, for the authenticators that report 0
-- permanently — every synced passkey does.
UPDATE operator_credential SET last_used_at = now() WHERE credential_id = $1;

-- name: FlagOperatorCredentialClone :exec
UPDATE operator_credential SET clone_warned_at = now() WHERE credential_id = $1;

-- ---------------------------------------------------------------------------
-- Sessions
-- ---------------------------------------------------------------------------

-- name: InsertOperatorSession :exec
INSERT INTO operator_session (
    token_digest, session_id, operator_id, stage, expires_at, from_ip, credential_id
) VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: ResolveOperatorSession :one
-- The authenticator's query, and it joins operator_account so a DISABLED
-- operator's live session stops working the moment the disable projects —
-- which is what operator.md §3 means by "offboarding is immediate".
--
-- Expiry is compared in SQL rather than in Go so that "expired" is decided by
-- the same clock that stored the row.
SELECT s.session_id, s.operator_id, s.stage, s.expires_at, s.credential_id,
       a.subject_id, a.role, a.disabled_at
FROM operator_session s
JOIN operator_account a ON a.operator_id = s.operator_id
WHERE s.token_digest = $1
  AND s.ended_at IS NULL
  AND s.expires_at > $2;

-- name: EndOperatorSession :execrows
UPDATE operator_session
SET ended_at = $2
WHERE token_digest = $1 AND ended_at IS NULL;

-- name: EndOperatorSessionsFor :exec
-- Offboarding's fan-out: end every live session an operator holds.
UPDATE operator_session
SET ended_at = $2
WHERE operator_id = $1 AND ended_at IS NULL;

-- name: SweepOperatorSessions :execrows
DELETE FROM operator_session WHERE expires_at < $1;

-- ---------------------------------------------------------------------------
-- Ceremonies
-- ---------------------------------------------------------------------------

-- name: InsertOperatorCeremony :exec
INSERT INTO operator_ceremony (ceremony_id, kind, operator_id, payload, expires_at)
VALUES ($1, $2, $3, $4, $5);

-- name: ConsumeOperatorCeremony :one
-- Single-use, atomically. The UPDATE … RETURNING is what makes a replay lose:
-- the second caller matches no row because consumed_at is no longer NULL, and
-- there is no window between a read and a write for it to slip through.
UPDATE operator_ceremony
SET consumed_at = $2
WHERE ceremony_id = $1
  AND kind = $3
  AND consumed_at IS NULL
  AND expires_at > $2
RETURNING ceremony_id, kind, operator_id, payload, expires_at;

-- name: SweepOperatorCeremonies :execrows
DELETE FROM operator_ceremony WHERE expires_at < $1;

-- ---------------------------------------------------------------------------
-- Audit
-- ---------------------------------------------------------------------------

-- name: InsertAuditEntry :exec
INSERT INTO operator_audit_log (
    entry_id, operator_id, operator_subject_id, action, method,
    org_id, target_subject_id, fields, reason, from_ip, occurred_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (entry_id) DO NOTHING;

-- name: ListAuditForOperator :many
SELECT entry_id, operator_id, operator_subject_id, action, method,
       org_id, target_subject_id, fields, reason, from_ip, occurred_at
FROM operator_audit_log
WHERE operator_id = $1
ORDER BY occurred_at DESC
LIMIT $2;

-- name: ListAuditForOrg :many
-- "Who looked at us" — the history operator.md §5 promises tenants.
SELECT entry_id, operator_id, operator_subject_id, action, method,
       org_id, target_subject_id, fields, reason, from_ip, occurred_at
FROM operator_audit_log
WHERE org_id = $1
ORDER BY occurred_at DESC
LIMIT $2;

-- name: TruncateAuditLog :exec
TRUNCATE operator_audit_log;

-- ---------------------------------------------------------------------------
-- The customer directory
-- ---------------------------------------------------------------------------

-- name: UpsertCustomer :exec
INSERT INTO operator_customer_list (
    org_id, slug, org_name, lifecycle_state, owner_subject_id, org_created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, now())
ON CONFLICT (org_id) DO UPDATE SET
    slug             = EXCLUDED.slug,
    org_name         = EXCLUDED.org_name,
    lifecycle_state  = EXCLUDED.lifecycle_state,
    owner_subject_id = EXCLUDED.owner_subject_id,
    updated_at       = now();

-- name: SetCustomerLifecycle :exec
UPDATE operator_customer_list
SET lifecycle_state = $2,
    suspended_at = $3,
    suspension_reason = $4,
    updated_at = now()
WHERE org_id = $1;

-- name: SetCustomerPlan :exec
UPDATE operator_customer_list
SET plan_id = $2, plan_version_id = $3, subscription_status = $4,
    trial_ends_at = $5, updated_at = now()
WHERE org_id = $1;

-- The counts are derived from SETS, never accumulated.
--
-- A projector is replayed on restart and on rebuild, so the same event WILL
-- arrive twice; `count = count + 1` applies twice and the directory's numbers
-- grow every time the plane restarts. Adding to a keyed set and recomputing is
-- idempotent by construction — and it also makes two projectors over one table
-- converge instead of summing. See migration 00039.

-- name: AddCustomerWorkspace :exec
INSERT INTO operator_org_workspace (org_id, workspace_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: RemoveCustomerWorkspace :exec
DELETE FROM operator_org_workspace WHERE org_id = $1 AND workspace_id = $2;

-- name: RecountCustomerWorkspaces :exec
UPDATE operator_customer_list c
SET workspace_count = (
        SELECT count(*) FROM operator_org_workspace w WHERE w.org_id = c.org_id
    ),
    updated_at = now()
WHERE c.org_id = $1;

-- name: AddCustomerSeat :exec
INSERT INTO operator_org_seat (org_id, subject_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: RemoveCustomerSeat :exec
DELETE FROM operator_org_seat WHERE org_id = $1 AND subject_id = $2;

-- name: RecountCustomerSeats :exec
UPDATE operator_customer_list c
SET member_count = (
        SELECT count(*) FROM operator_org_seat s WHERE s.org_id = c.org_id
    ),
    updated_at = now()
WHERE c.org_id = $1;

-- name: TruncateCustomerWorkspaces :exec
TRUNCATE operator_org_workspace;

-- name: TruncateCustomerSeats :exec
TRUNCATE operator_org_seat;

-- name: TouchCustomerActivity :exec
-- `greatest` rather than an assignment, so a replay in any order settles on the
-- latest instant rather than on whichever event was applied last. greatest()
-- ignores NULLs, so the first touch sets it.
UPDATE operator_customer_list
SET last_active_at = greatest(last_active_at, $2), updated_at = now()
WHERE org_id = $1;

-- name: GetCustomer :one
SELECT org_id, slug, org_name, lifecycle_state, plan_id, plan_version_id,
       subscription_status, trial_ends_at, workspace_count, member_count,
       last_active_at, signup_source, suspended_at, suspension_reason,
       owner_subject_id, org_created_at
FROM operator_customer_list
WHERE org_id = $1;

-- name: ListCustomers :many
-- One page of the directory.
--
-- The cursor is (org_created_at, org_id) rather than an OFFSET, so a page
-- boundary does not shift when a new organization signs up mid-listing — which
-- with OFFSET silently skips a customer.
SELECT org_id, slug, org_name, lifecycle_state, plan_id, plan_version_id,
       subscription_status, trial_ends_at, workspace_count, member_count,
       last_active_at, signup_source, suspended_at, suspension_reason,
       owner_subject_id, org_created_at
FROM operator_customer_list
WHERE (sqlc.narg('query')::text IS NULL
       OR org_name ILIKE '%' || sqlc.narg('query')::text || '%'
       OR slug ILIKE '%' || sqlc.narg('query')::text || '%')
  AND (sqlc.narg('lifecycle_state')::text IS NULL
       OR lifecycle_state = sqlc.narg('lifecycle_state')::text)
  AND (sqlc.narg('cursor_created_at')::timestamptz IS NULL
       OR (org_created_at, org_id) < (sqlc.narg('cursor_created_at')::timestamptz,
                                      sqlc.narg('cursor_org_id')::text))
ORDER BY org_created_at DESC, org_id DESC
LIMIT sqlc.arg('page_limit');

-- name: TruncateCustomers :exec
TRUNCATE operator_customer_list;

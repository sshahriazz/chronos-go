-- +goose Up
-- +goose StatementBegin

-- ===========================================================================
-- The customer directory's counts were not replay-safe
-- ===========================================================================
--
-- `operator_customer_list.workspace_count` and `.member_count` were maintained
-- by `SET count = count + 1` handlers. That is wrong in the one way a
-- projection must never be wrong: a projector is replayed on restart and on
-- rebuild, so the same event WILL arrive twice, and a bump applies twice.
--
-- Found by TestTheCustomerDirectoryIsActuallyBuilt, which appended one
-- organization, one workspace and one membership and read back
-- `workspace_count = 3, member_count = 3`. The projection was otherwise
-- correct — the row existed, the name and the slug and the lifecycle state were
-- all right — which is exactly how this class of bug survives review: every
-- field a reader checks is fine, and the numbers are merely too big.
--
-- It would have shipped as a directory whose counts grew every time the plane
-- restarted, and a support engineer reading "47 workspaces" for a customer with
-- three would have had no reason to suspect the number rather than the customer.
--
-- # The fix is to count a SET rather than to accumulate a total
--
-- Two association tables, both with a primary key, both written with
-- `ON CONFLICT DO NOTHING` / `DELETE`. Applying the same event twice reaches
-- the same set, so the count derived from it is the same. That is what
-- idempotent means here, and it is a property of the schema rather than of the
-- handler remembering to be careful.
--
-- It also fixes a second problem the same test exposed. Two projectors over one
-- table — the live plane's and a test's, or two replicas mid-deploy — both
-- bumped, so the total was the sum of however many were running. With a set
-- they converge on the same value no matter how many apply the same event.
--
-- # Why a seat table holding pseudonyms is acceptable, stated rather than assumed
--
-- `operator_org_seat` maps an organization to the SubjectID pseudonyms holding
-- a seat in it. That is a member list in the operator plane, and operator.md §2
-- excludes "member email addresses beyond the org owner's" and "anything
-- resembling analytics on individual end users". It is worth being explicit
-- about why this is neither.
--
--   - It holds pseudonyms, which is precisely what compliance.md §1 says a
--     projection stores: "projections store SubjectID; the vault resolves it at
--     read time". Nothing here is resolvable without the vault, and the vault
--     is reachable only through RevealPersonalData — one subject, a mandatory
--     justification, an audit entry written before the read.
--   - No RPC exposes it. It exists to make a count replay-safe, and the
--     directory returns the count, never the set. Adding an endpoint that
--     returned it would be adding a member list to the operator plane, which is
--     the thing §2 excludes — and would be a reviewable change rather than an
--     accident.
--
-- The alternative was to drop `member_count` entirely, and it was rejected
-- because the seat count is the number a support engineer is usually being
-- asked about: it is what the invoice charges for.

-- One row per workspace an organization currently has, ARCHIVED ONES EXCLUDED.
--
-- Archived rather than deleted is the tenant semantic (a workspace an org
-- archived is one they may restore), and the directory should report what the
-- customer can currently use — so the archive handler deletes from here and the
-- restore handler puts it back.
CREATE TABLE operator_org_workspace (
    org_id       text NOT NULL,
    workspace_id text NOT NULL,
    PRIMARY KEY (org_id, workspace_id)
);

-- One row per PERSON holding a seat in an organization — not per membership.
--
-- Five workspaces and one person is one row (workspace.md §2). The distinction
-- is only expressible because the events carry it: MemberJoined.SeatConsumed is
-- true exactly when the person was not already in the organization, and
-- MemberRemoved.SeatReleased when it was their last membership.
CREATE TABLE operator_org_seat (
    org_id     text NOT NULL,
    subject_id text NOT NULL,
    PRIMARY KEY (org_id, subject_id)
);

COMMENT ON TABLE operator_org_seat IS
    'Seat holders by pseudonym, so member_count survives a replay. No RPC exposes this set — the directory returns the count. Adding one would be adding a member list to the operator plane (operator.md §2).';

GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON operator_org_workspace TO chronos_operator;
GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON operator_org_seat      TO chronos_operator;

REVOKE ALL ON operator_org_workspace FROM chronos_app;
REVOKE ALL ON operator_org_seat      FROM chronos_app;

-- The columns they replace are recomputed from the sets, so the accumulated
-- values left behind by the old handlers are wrong and must not survive. They
-- are derived data in a rebuildable projection, so zeroing them is correct
-- rather than destructive — the next replay fills them in.
UPDATE operator_customer_list SET workspace_count = 0, member_count = 0;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS operator_org_seat;
DROP TABLE IF EXISTS operator_org_workspace;
-- +goose StatementEnd

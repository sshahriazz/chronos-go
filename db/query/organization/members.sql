-- Read queries for the organization membership index.
--
-- The WRITES live in db/query/workspace/members.sql, with the projection that
-- issues them. A table has exactly one writer (CONVENTIONS §8), and that writer
-- is the workspace module: organization grants membership through its own
-- events, workspace grants it by a join, and `workspace -> organization` is the
-- only direction the dependency may run (ADR-020) — so the module that can see
-- both sets of events is workspace, and the projection has to live there.

-- name: OrgMembership :one
-- Does this person belong to this organization, and as what?
--
-- Gate 1's verification. Filtered by subject_id as well as org_id, which is the
-- containment control: the caller names an organization, and this is what stops
-- them naming one they have nothing to do with.
SELECT role FROM org_member_index WHERE org_id = $1 AND subject_id = $2;

-- name: OrgsForSubject :many
-- Every organization this person belongs to, oldest first.
--
-- Gate 1 uses it when no organization was named: one membership is an
-- unambiguous answer, and more than one is a request that has to say which.
SELECT org_id, role FROM org_member_index
WHERE subject_id = $1
ORDER BY joined_at, org_id;

-- name: OrgMemberSubjects :many
-- Everyone in this organization, for notifications that concern all of them.
--
-- Ordered and bounded, and both matter. The order makes a partially delivered
-- fan-out resumable in a stable place; the LIMIT is what stops one very large
-- organization from turning a single event into an unbounded read and an
-- unbounded number of mails in one transaction.
--
-- The cap is a REFUSAL rather than a page: a notification that reaches the first
-- N members and silently omits the rest is worse than one that fails loudly,
-- because the omission is invisible from every side. The caller compares the
-- count against the limit and parks if it hit it.
SELECT subject_id, role FROM org_member_index
WHERE org_id = $1
ORDER BY joined_at, subject_id
LIMIT $2;

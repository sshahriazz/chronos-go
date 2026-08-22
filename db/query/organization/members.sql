-- Queries for the organization membership index.

-- name: UpsertOrgMember :exec
-- Upsert, because a projector replays: the same event WILL arrive twice.
--
-- joined_at is untouched on conflict — a replay must not move when somebody
-- joined — but the ROLE is updated, because a promotion is a real change and
-- the projection has to reflect it.
INSERT INTO org_member_index (org_id, subject_id, role, joined_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (org_id, subject_id) DO UPDATE SET role = EXCLUDED.role;

-- name: RemoveOrgMember :exec
DELETE FROM org_member_index WHERE org_id = $1 AND subject_id = $2;

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

-- name: TruncateOrgMembers :exec
TRUNCATE TABLE org_member_index;

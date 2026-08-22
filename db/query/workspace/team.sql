-- Queries for team_view and team_member_view.
--
-- Screens and enumeration only. Every DECISION about a team is taken against the
-- aggregate: a projection lags, and a decision taken from one can be taken twice
-- with two different answers.

-- name: UpsertTeam :exec
-- Upsert, because a projector replays: the same event WILL arrive twice.
--
-- The conflict clause touches only what the CREATION event owns. `status`,
-- `name` and `deleted_at` are written by later events — a rename moves the
-- second, a deletion the other two — so a redelivered creation must not write
-- any of them, or it resurrects a deleted team onto the screen and renames it
-- back to what it was called on day one.
--
-- On a genuine rebuild the INSERT path runs, so all three are set correctly
-- there and the later events move them again, in order.
INSERT INTO team_view (team_id, workspace_id, org_id, name, status, created_by, created_at)
VALUES ($1, $2, $3, $4, 'active', $5, $6)
ON CONFLICT (team_id) DO UPDATE SET
    workspace_id = EXCLUDED.workspace_id,
    org_id       = EXCLUDED.org_id,
    created_by   = EXCLUDED.created_by,
    created_at   = EXCLUDED.created_at;

-- name: RenameTeam :exec
-- Guarded on `active`, which is what makes a replay idempotent: renaming a
-- deleted team would put a name back on a row whose whole purpose is to record
-- that the id is spent.
UPDATE team_view SET name = $2 WHERE team_id = $1 AND status = 'active';

-- name: DeleteTeam :exec
-- A status change, never a DELETE.
--
-- access.md §7.5: a team id is never reused, because grants target
-- `team:x#member` and a reused id would silently inherit the deleted team's
-- access. Removing the row would make the id look free to anything that checked
-- this table.
UPDATE team_view SET status = 'deleted', deleted_at = $2
WHERE team_id = $1 AND status = 'active';

-- name: ListTeams :many
-- The team screen, alphabetical.
--
-- Keyset paging on `(name, team_id)`, because an offset shifts under a
-- concurrent creation and silently skips a row. The id breaks ties: two teams
-- may share a name, and a cursor on the name alone would either skip or repeat.
SELECT team_id, name, created_by, created_at
FROM team_view
WHERE workspace_id = $1
  AND status = 'active'
  AND (name, team_id) > ($2, $3)
ORDER BY name, team_id
LIMIT $4;

-- name: TeamMembers :many
-- Who is in this team.
--
-- Also what DELETION enumerates: every member's tuple has to be removed, and
-- this is the only place that can say who they were.
SELECT subject_id FROM team_member_view
WHERE team_id = $1
ORDER BY added_at, subject_id;

-- name: TeamsForSubject :many
-- Which teams is this person in, in this workspace?
--
-- What removing somebody from the WORKSPACE has to ask: a team member must be a
-- workspace member (workspace.md §6), so losing the second has to lose the
-- first — otherwise a team keeps granting to somebody who is no longer here.
SELECT team_id FROM team_member_view
WHERE workspace_id = $1 AND subject_id = $2;

-- name: UpsertTeamMember :exec
INSERT INTO team_member_view (team_id, workspace_id, org_id, subject_id, added_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (team_id, subject_id) DO NOTHING;

-- name: DeleteTeamMember :exec
DELETE FROM team_member_view WHERE team_id = $1 AND subject_id = $2;

-- name: DeleteTeamMembers :exec
-- Every member of one team, for a deletion.
DELETE FROM team_member_view WHERE team_id = $1;

-- name: TruncateTeams :exec
TRUNCATE TABLE team_view;

-- name: TruncateTeamMembers :exec
TRUNCATE TABLE team_member_view;

-- name: TeamsOfMember :many
-- Which teams inside this workspace is this person in?
--
-- The cascade workspace.md §6 requires in the other direction: a team member
-- must be a workspace member, so losing the second has to lose the first.
-- Without it somebody removed from a workspace keeps `team:x member user:y` in
-- the access graph, and the first thing shared with that team reaches a person
-- who was removed — with no event, no log line and nothing to notice.
--
-- Scoped to ONE workspace rather than the whole organization, because that is
-- what a removal is: leaving one workspace has to leave its teams and must not
-- touch the teams of another workspace the person is still in.
--
-- Unbounded, unlike every other list here, and deliberately: this is not a page
-- for a screen but the complete set a single removal has to settle, and a page
-- would silently leave the remainder attached.
SELECT team_id
FROM team_member_view
WHERE workspace_id = $1 AND subject_id = $2
ORDER BY team_id;

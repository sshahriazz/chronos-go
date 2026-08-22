-- Queries for invitation_view.
--
-- Screens and sweeps only. Every DECISION on the invitation paths reads the
-- aggregate: a projection is behind the log by construction, so a decision taken
-- from one can be taken twice with two different answers — and every decision
-- there spends a seat or a credential.

-- name: UpsertInvitation :exec
-- Upsert, because a projector replays: the same event WILL arrive twice.
--
-- Nothing is untouched on conflict, unlike the membership upserts. A replayed
-- issue is byte-identical to the first, so overwriting costs nothing — and an
-- ON CONFLICT DO NOTHING here would make a rebuild silently skip an invitation
-- whose row survived a partial truncate.
INSERT INTO invitation_view (
    invitation_id, workspace_id, org_id, subject_id, email_index,
    invited_by, role, status, expires_at, issued_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8, $9)
ON CONFLICT (invitation_id) DO UPDATE SET
    workspace_id = EXCLUDED.workspace_id,
    org_id       = EXCLUDED.org_id,
    subject_id   = EXCLUDED.subject_id,
    email_index  = EXCLUDED.email_index,
    invited_by   = EXCLUDED.invited_by,
    role         = EXCLUDED.role,
    status       = EXCLUDED.status,
    expires_at   = EXCLUDED.expires_at,
    issued_at    = EXCLUDED.issued_at,
    settled_at   = NULL;

-- name: ExtendInvitation :exec
-- A resend moved the deadline.
--
-- The window is the SWEEP'S key, so it has to reflect the current deadline
-- rather than the original — otherwise a resent invitation is swept at its first
-- expiry and its seat returned while a live link is still in somebody's inbox.
UPDATE invitation_view SET expires_at = $2
WHERE invitation_id = $1 AND status = 'pending';

-- name: SettleInvitation :exec
-- A terminal transition.
--
-- Guarded on `status = 'pending'`, which is what makes a replay idempotent: the
-- second application matches nothing and changes nothing, rather than moving an
-- accepted invitation to revoked because the log happened to be re-read in a
-- different order.
UPDATE invitation_view SET status = $2, settled_at = $3
WHERE invitation_id = $1 AND status = 'pending';

-- name: ListWorkspaceInvitations :many
-- The admin screen: who is outstanding in this workspace.
--
-- Ordered by expiry so the ones about to lapse are at the top, which is the
-- order somebody chasing them wants. Keyset paging by `(expires_at,
-- invitation_id)`, because an offset shifts under a concurrent settlement and
-- silently skips a row.
SELECT invitation_id, subject_id, invited_by, role, status, expires_at, issued_at
FROM invitation_view
WHERE workspace_id = $1
  AND status = $2
  AND (expires_at, invitation_id) > ($3, $4)
ORDER BY expires_at, invitation_id
LIMIT $5;

-- name: InvitationsBySubject :many
-- What did this person issue, and is it still outstanding?
--
-- The reactor that revokes an inviter's invitations when they leave the
-- organization reads this. Scoped by org, because an inviter removed from ONE
-- organization keeps whatever they issued in another.
SELECT invitation_id, workspace_id
FROM invitation_view
WHERE org_id = $1 AND invited_by = $2 AND status = 'pending';

-- name: PendingInvitationForAddress :one
-- Is there already an outstanding invitation to this address here?
--
-- By INDEX, never by address: the address is not in this database. A second
-- invitation to one address supersedes the first (workspace.md §5) rather than
-- taking a second seat, and this is what makes that recognisable.
SELECT invitation_id, workspace_id FROM invitation_view
WHERE org_id = $1 AND email_index = $2 AND status = 'pending'
ORDER BY issued_at
LIMIT 1;

-- name: TruncateInvitations :exec
TRUNCATE TABLE invitation_view;

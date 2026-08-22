-- Queries for invitation_view.
--
-- Screens and sweeps only. Every DECISION on the invitation paths reads the
-- aggregate: a projection is behind the log by construction, so a decision taken
-- from one can be taken twice with two different answers — and every decision
-- there spends a seat or a credential.

-- name: UpsertInvitation :exec
-- Upsert, because a projector replays: the same event WILL arrive twice.
--
-- # The conflict clause touches only what THIS event owns
--
-- `status`, `settled_at` and `expires_at` are all written by LATER events — a
-- settlement moves the first two, a resend moves the third — so a redelivered
-- InvitationIssued must not write any of them. The first version of this
-- statement set `status = 'pending'` and `settled_at = NULL` on conflict, which
-- resurrects an accepted invitation onto the admin screen and hands the expiry
-- sweep a settled row to expire. It was safe only because a catch-up
-- subscription happens to deliver in order, which is not a property this
-- statement should depend on.
--
-- The columns it DOES overwrite are immutable facts about the invitation: which
-- workspace, which organization, which address, who issued it, and as what. A
-- replay writes them back identically, and an ON CONFLICT DO NOTHING would
-- instead make a rebuild silently skip a row that survived a partial truncate.
--
-- On a genuine rebuild the INSERT path runs — the table was truncated — so
-- status, settled_at and expires_at are set correctly there and the later events
-- move them again, in order.
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
    issued_at    = EXCLUDED.issued_at;

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

-- name: ListDueInvitations :many
-- Which invitations have run out?
--
-- The reconciliation sweep's work list. It is the one question about invitations
-- that cannot be answered from the log without reading every invitation stream
-- in the system; everything else is decided against the stream, where the answer
-- is not eventually consistent.
--
-- Deliberately NOT scoped to a workspace or an organization, and therefore run
-- in a SYSTEM transaction: a seat held by a lapsed invitation is held whether or
-- not anybody is looking at that tenant, and a per-tenant sweep would only ever
-- free the tenants somebody happened to visit.
--
-- Oldest first, so the longest-held seats come back first and a bounded pass
-- makes progress against the worst of the backlog rather than a random slice of
-- it.
SELECT invitation_id, org_id, workspace_id, expires_at
FROM invitation_view
WHERE status = 'pending' AND expires_at <= $1
ORDER BY expires_at, invitation_id
LIMIT $2;

-- name: PendingInvitationsBySubject :many
-- What is this person still waiting on somebody to accept?
--
-- The reactor that revokes a departing inviter's outstanding invitations reads
-- this. Scoped by ORGANIZATION, because leaving one organization says nothing
-- about invitations issued in another — a consultant who administers two tenants
-- keeps what they issued in the one they are still in.
--
-- Pending only. A settled invitation has already released whatever it held, and
-- revoking one again would return a second seat for one hold.
SELECT invitation_id, workspace_id
FROM invitation_view
WHERE org_id = $1 AND invited_by = $2 AND status = 'pending';

-- name: PendingInvitationForAddress :one
-- Is there already an outstanding invitation to this address here?
--
-- By INDEX, never by address: the address is not in this database. A second
-- invitation to one address SUPERSEDES the first (workspace.md §5) rather than
-- taking a second seat, and this is what makes that recognisable.
--
-- Oldest first and one row. More than one pending invitation for an address is
-- the state supersession exists to prevent, so if it ever happens the oldest is
-- the one to settle — and the next issue settles the next one, converging rather
-- than picking arbitrarily.
--
-- Scoped by organization, not by workspace: the SEAT is per organization, so two
-- invitations to one address in two workspaces of one tenant are exactly the
-- double charge this prevents.
SELECT invitation_id, workspace_id
FROM invitation_view
WHERE org_id = $1 AND email_index = $2 AND status = 'pending'
ORDER BY issued_at
LIMIT 1;

-- name: TruncateInvitations :exec
TRUNCATE TABLE invitation_view;

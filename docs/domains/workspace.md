# Domain: workspace

**The goal domain.** Everything else exists so this one is correct: workspaces,
their members, their teams, and the invitations that bring people in.

The collaboration boundary, beneath the commercial one. Dependency is strictly
one-directional — **`workspace → organization`, never the reverse** (ADR-020).

---

## 1. Aggregates

| Aggregate | Boundary rationale |
| --- | --- |
| `Workspace` | Holds settings and the **admin set** — small, bounded, and carrying the "never zero admins" invariant. |
| `Membership` | One per `(workspace, user)`. Separate because a workspace may hold thousands and they churn constantly. |
| `Team` | Members are a bounded set within one workspace. |
| `Invitation` | Its own lifecycle, its own expiry clock, and it exists **before** the user does. |

The split follows the rule from `organization` §2: *invariant-bearing sets go
inside the aggregate; high-volume collections do not.* Admins are inside
`Workspace`; ordinary members are not.

---

## 2. Seats are per person per organization

The single most misunderstood part of the model, and getting it wrong either
overcharges customers or leaks revenue.

> **A seat is consumed by a *person in an organization*, not by a membership.**

Someone in five workspaces of one org consumes **one** seat. Entitlement counters
are org-scoped (entitlement.md §3), so:

- Adding a member to a *second* workspace consumes **no** additional seat.
- Removing someone from one workspace of several releases **no** seat.
- The seat is released only when they leave the **organization entirely**.
- Reservation at invite time is therefore conditional: **reserve only if this
  person is not already an org member**.

Guests count against `seats.guest`, members against `seats.member`, and the pools
are independent (ADR-027).

---

## 3. Workspace lifecycle

```
                create ──► Active ──► Archived ──► Deleted
                              ▲          │
                              └──restore─┘
```

Creation passes the full pipeline in order (ADR-021): authz (org `admin`) →
subscription (`grow`, so blocked unless `Trialing`/`Active`) → entitlement
(`workspaces.count` reserve) → handler.

- **Archived**: read-only, members retained, seats **still consumed**, resources
  intact. Reversible.
- **Deleted**: a saga — revoke tuples first, then memberships, then the aggregate
  (access.md §7.5 ordering). Content retention is governed by `compliance`.
- The org owner and org admins are admins here by inheritance
  (`workspace.parent = organization`), and that edge is breakable under the
  guards in ADR-027.

---

## 4. Membership

| Role | Inherits workspace tree | Invite | Manage members | Manage workspace |
| --- | --- | --- | --- | --- |
| `admin` | ✅ | ✅ | ✅ | ✅ |
| `member` | ✅ | per policy | ❌ | ❌ |
| `guest` | **❌ — explicit grants only** | ❌ | ❌ | ❌ |

Guests are structurally the *absence* of the membership edge (access.md §7.6),
not a role with deny rules.

### Invariants

- **Never zero admins.** The last admin cannot be removed or demoted; the command
  fails with an actionable error naming who could be promoted first.
- Org owner and org admins do not count toward the admin minimum **unless
  inheritance is broken** — a workspace private to its own members must have a
  direct admin (ADR-027).
- **Removal never orphans resources.** Anything owned solely by the departing
  member transfers to a workspace admin, and they are told what they inherited.
  Silent orphaning is how data becomes unreachable inside a live tenant.

---

## 5. Invitations — the terminal feature

Where three domains meet: `workspace` issues, `entitlement` reserves the seat,
`access` grants on acceptance.

```
                 ┌─────────┐
                 │ Pending │──── revoked ────► Revoked
                 └────┬────┘
                      │──── expired (7d) ───► Expired
                      │──── declined ───────► Declined
                      │──── bounced ────────► Undeliverable
                      ▼
                  Accepted ──► Membership created
```

### Issue

- Requires `admin` (or `member` if org policy allows member-invites).
- **Seat reserved at issue, not acceptance** (entitlement.md §4) — otherwise 60
  pending invitations against 50 seats all look valid and the 51st acceptance
  fails for someone who did nothing wrong.
- Reservation is conditional on the invitee not already being an org member (§2).
- Token is single-use, expiring, and stored **hashed** — an invitation token is a
  credential.
- Invitee address is personal data: vault-stored, referenced by `SubjectID`
  (compliance §1).

### Accept

Validated **at acceptance**, not trusted from issue time:

| Check | On failure |
| --- | --- |
| Token valid, unexpired, unused | `NOT_FOUND` (never "expired vs wrong") |
| Org still `Active`/`Trialing` | `ORG_SUSPENDED` |
| Workspace still `Active` | `NOT_FOUND` |
| Seat reservation still held | re-reserve, or `QUOTA_EXCEEDED` |
| Domain restriction satisfied | `ACCESS_DENIED` |

Two acceptance paths:

- **Existing user** — authenticate, then accept. If signed in as a *different*
  user, say so explicitly rather than silently binding the invitation to the
  wrong account.
- **New user** — the invitation *is* proof of address control, so accepting
  completes email verification. Requiring a separate verification mail after
  clicking an emailed link is friction with no security value.

### Edge cases

| Case | Handling |
| --- | --- |
| Invitee is already a member | **Idempotent success**, not an error — the inviter's intent is satisfied |
| Invitee is an org member, not in this workspace | Added directly; **no seat consumed** (§2) |
| Two invitations for the same address | Second supersedes the first; one seat reserved, not two |
| Inviter loses permission before acceptance | Invitation stands — it was authorised when issued |
| Inviter is removed from the org | Invitations they issued are **revoked** |
| Acceptance after workspace archived | Refused; seat released |
| Resend | Rotates the token, extends expiry, rate-limited |
| Hard bounce | → `Undeliverable`, seat released, inviter notified |
| Address later merges accounts | Invitation follows the **surviving** `SubjectID` (identity §7.5) |
| Revoked then re-invited | New invitation, new token; the old token stays dead |

Expiry, reminders and seat release are a **Temporal workflow** — the invitation
outlives any request.

---

## 6. Teams

- Created within a workspace; **flat, not nested**. The access engine could model
  nested teams (`team#member` referencing another team), but nesting makes
  effective membership non-obvious to the people managing it, and that is the
  problem teams exist to solve.
- Teams are **grantable subjects** — sharing with a team costs one tuple
  regardless of size (access.md §4, verified).
- A team member must be a workspace member; adding a non-member is refused rather
  than implicitly admitting them.
- **Deletion cascades to every grant naming the team, and team ids are never
  reused** (access.md §7.5) — otherwise a recreated team silently inherits the
  old one's access.
- Team maintainers can manage membership without being workspace admins.

---

## 7. Realtime

Workspace membership and team changes are exactly the events other people need to
see immediately:

- Projector updates `member_view` → publishes on the workspace channel.
- A revoked member's **access tombstone is written before the projection
  updates** (access.md §6), so removal takes effect immediately rather than at
  projector speed.
- Their Centrifugo subscription for that workspace is dropped on revocation.

---

## 8. Events published

`WorkspaceCreated` · `WorkspaceRenamed` · `WorkspaceSettingsChanged` ·
`WorkspaceArchived` · `WorkspaceRestored` · `WorkspaceDeleted` ·
`InheritanceBroken` · `InheritanceRestored` · `MemberInvited` ·
`InvitationResent` · `InvitationRevoked` · `InvitationExpired` ·
`InvitationDeclined` · `InvitationUndeliverable` · `InvitationAccepted` ·
`MemberJoined` · `MemberRoleChanged` · `MemberSuspended` · `MemberRemoved` ·
`GuestAdmitted` · `GuestPromoted` · `TeamCreated` · `TeamRenamed` ·
`TeamDeleted` · `TeamMemberAdded` · `TeamMemberRemoved` ·
`ResourceOwnershipTransferred`

`SubjectID` pseudonyms only (ADR-002).

---

## 9. Read models

| Projection | Serves | Key indexes |
| --- | --- | --- |
| `workspace_view` | list, settings | `(org_id, status, name)` |
| `member_view` | member list | `(org_id, workspace_id, role, joined_at DESC, id)` |
| `team_view` · `team_member_view` | teams | `(workspace_id, team_id)` |
| `invitation_view` | pending invitations | `(workspace_id, status, expires_at)` |
| `org_member_index` | **seat counting** (§2) | `(org_id, user_id)` unique |

`org_member_index` is what makes "one person, one seat" computable — a unique
`(org_id, user_id)` regardless of how many workspaces they belong to.

Every table carries `org_id`, `workspace_id` and `residency` (ADR-020, ADR-035).

---

## 10. Temporal workflows

| Workflow | Purpose |
| --- | --- |
| `InvitationLifecycleWorkflow` | reminders, expiry, seat release |
| `MemberRemovalWorkflow` | ownership transfer → tuple revocation → membership removal |
| `WorkspaceDeletionSaga` | tuples → memberships → teams → aggregate |
| `InheritanceBreakWorkflow` | verify a direct admin exists, then break, then notify |

---

## 11. What this domain does **not** own

- **The organization**, its subscription, owner or policy → `organization`, and
  **workspace never imports it back** (ADR-020)
- **Seat limits** → `entitlement` sets them; workspace only asks
- **Permission evaluation** → `access`; workspace emits resource-lifecycle events
  and calls `Checker`
- **Authentication** → `identity`
- **Invitation email delivery** → `notification`; workspace publishes
  `MemberInvited` and never sends anything

---

## 12. Test plan

**Domain (pure):**
- Last-admin protection across every removal, demotion and inheritance-break
  permutation
- Invitation state machine, including every illegal transition
- Role change matrix, including guest ⇄ member seat-pool movement

**Seat accounting — the highest-value tests:**
- One person in five workspaces of one org consumes **one** seat
- Removing them from one workspace releases **none**
- Leaving the org releases **one**
- Guest promoted to member moves pools atomically — never both, never neither
- Concurrent acceptance of the last seat: exactly one wins (`synctest`)

**Integration:**
- Invitation → acceptance → OpenFGA tuple → `Check` returns allow
- Removal → deny tombstone is effective **before** the projection updates
- Org admin inherits admin on a workspace created *afterwards*
- Breaking inheritance is refused without a direct admin, and the owner's
  break-glass reclaim works
- RLS negative test: another org cannot read this workspace's members
- **`workspace` compiles with `organization` present but `organization` compiles
  without `workspace`** — proving ADR-020's direction is real

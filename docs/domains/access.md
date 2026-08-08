# Domain: access

**The authorization engine. Not a feature — a primitive** every future capability
composes against (ADR-006).

Its whole job is one question: *may this principal perform this relation on this
resource?* It never knows what a resource **is**, only where it sits.

Everything below marked **✅ verified** was measured against the running OpenFGA
`v1.18.3`. Reproduce with
[`docs/evidence/access-topology-probe.py`](../evidence/access-topology-probe.py).

---

## 1. The one idea that makes this scale

> **Inheritance is by reference, never by copy.**

Take the analogy directly: a folder shared with a team, where every member gets
access to every file in it — *present and future*.

The naive implementation materializes effective permissions: 100 members × 10,000
files = 1,000,000 rows, rewritten whenever anyone is added or removed, and again
whenever a file is created. That is the design that dies at scale, and it dies
slowly enough that you only find out once you have customers.

The Zanzibar model stores **edges**, and evaluates at query time:

```
team:eng#member ──editor──► folder:root
                               ▲
                               │ parent
                          folder:projects
                               ▲
                               │ parent
                          folder:q3 ──parent──► file:anything
```

| Operation | Tuples written |
| --- | --- |
| Share a folder with a 100-person team | **1** |
| Add a person to that team | **1** (they gain access to everything, instantly) |
| Create a file anywhere in the subtree | **1** (the parent edge) |
| Revoke the team | **1 delete** (everyone loses everything, instantly) |

**✅ Verified.** A file created *after* the grant was immediately accessible to a
team member three levels down, with no new grant written. An entire new subtree
created after the grant likewise. This is the "present and future files" property,
and it falls out of the model rather than being implemented.

---

## 1.5 Measured envelope and hard limits

Measured against OpenFGA `v1.18.3` over HTTP from the host —
[`access-scale-probe.py`](../evidence/access-scale-probe.py). Treat these as
upper bounds; in-process gRPC will be faster.

| Scenario | p50 | p95 |
| --- | --- | --- |
| Check, depth 1 | 2.0 ms | 3.0 ms |
| Check, depth 10 | 4.4 ms | 6.6 ms |
| Check, depth 20 | 5.6 ms | 8.8 ms |
| **Check via a 1000-member team** | **2.1 ms** | 5.6 ms |
| Check with contextual tuples | 1.9 ms | — |
| `ListUsers` on a 1000-member team | 12 ms (**1000 rows**) | — |

Three results matter more than the rest.

### ⛔ Depth 25 is a hard wall — and it fails closed

```
depth 20 → allow, 5.6 ms
depth 25 → ERROR  authorization_model_resolution_too_complex
```

This is OpenFGA's resolve-node limit. **It is not a slow path; it is a total
failure.** Every check inside a subtree nested 25+ deep returns an error, and
because we fail closed (§12) that means **nobody can reach those resources at
all** — an availability outage caused by a user creating one folder too deep.

> **Nesting depth is capped in the product, structurally, well below the limit.**
> Default cap **15**, enforced at create and at move alongside the cycle check
> (§7.5). The cap is configuration, and raising it requires raising OpenFGA's
> limit first — never the other way round.

Today's tenancy uses depth 2 (`organization → workspace`), so the headroom is
enormous. The cap exists for the verticals that come later, because by the time
someone hits it the data already exists and the fix is a migration.

### ✅ Team grants really are free

A check through a **1000-member team costs the same as a direct grant**
(2.1 ms vs 2.0 ms). The "one tuple for any team size" claim (§4) holds at the
latency level too, not just the write level. Wide teams are the cheap path in
every dimension except `ListUsers`.

### ⚠ `BatchCheck` is a round-trip optimisation, not a compute one

```
50 sequential Checks : 108 ms
1 BatchCheck         :  78 ms      → 1.4× on localhost
```

Earlier drafts of this document implied a larger win. Honestly stated: the saving
is **network round trips**, which matters far more across a real network than on
loopback — server-side evaluation cost is unchanged.

The number that matters is the absolute one: **~78 ms to authorize a 50-item
page.** That is a real budget, and it is why list screens must
(a) page from the projection, (b) `BatchCheck` only the page, and (c) use the
decision cache in §6.2. Authorizing a page must never scale with corpus size.

---

## 2. Primitives

The complete vocabulary. Every future feature composes these; none of them names
a business concept.

```
Principal    who is asking — user · team-member · service-account · api-key · link-holder
ResourceRef  (type, id) — opaque; the engine never interprets type
Relation     a named capability on a type — viewer · commenter · editor · owner
Edge         parent(parentRef, childRef) — the inheritance link
Grant        Principal × Relation × ResourceRef, optionally conditional
Condition    CEL expression — expiry, IP, AAL, device trust
Decision     allow | deny + reason (for Expand)
Watermark    log position at which a resource's ACL last changed (§6)
```

Five operations, and nothing else:

| Operation | Question | Cost profile |
| --- | --- | --- |
| `Check` | may X do Y on Z? | hot path, ~ms |
| `BatchCheck` | the same, for a page of resources | one round trip |
| `ListObjects` | what can X reach? | **expensive, and UNMEASURED at scale** — §7 |
| `ListUsers` | who can reach Z? | **expands groups** — §7 |
| `Expand` | *why* — the decision tree | debugging only |

---

## 3. Topology

**Containers nest into themselves**, which is what gives arbitrary depth from a
fixed model:

```
folder.parent : [folder]        # self-referential ⇒ unbounded nesting
file.parent   : [folder]
folder.editor : direct ∪ (editor from parent)
folder.viewer : direct ∪ editor ∪ (viewer from parent)
```

`viewer: editor ∪ …` encodes role implication once — an editor is always a
viewer, and no caller ever checks two relations.

**✅ Verified** at depth 4 (`root → projects → q3 → file`), inherited through a
team, in **~4 ms per check** over HTTP from the host including Docker networking.

### Breaking inheritance

**Remove the `parent` edge.** That is the entire mechanism.

The subtree keeps its structural position in Postgres — the UI still draws it
nested — but the permission edge is gone, so only direct grants apply. This is
precisely Drive's restricted-folder behaviour.

**✅ Verified**: removing the edge revoked inherited access while a direct grant
inside the subtree continued to work; re-adding the edge restored inheritance
immediately.

**Tenancy uses this directly.** `workspace.parent = organization` means the org
owner and every org admin are admins of every workspace, present and future, for
one tuple (ADR-027). Breaking that edge makes a workspace private to its own
members.

Two guards on that break live in the **`organization` domain**, never here — the
engine must not learn what a workspace is (ADR-006):

1. the workspace must already have a **direct** admin, so the break cannot orphan it;
2. the org owner retains an audited **break-glass reclaim**, so a departing
   workspace admin cannot permanently lock an org out of its own data.

The alternative — an exclusion (`but not blocked`) that denies specific
subjects — is supported but **discouraged**. Deny rules make effective permission
non-obvious, are slow to evaluate, and turn "why can't Bob see this?" into an
investigation. Reserve for a genuine per-subject block.

**Two trees, deliberately.** Postgres holds the *structural* tree (display,
breadcrumbs, move operations); OpenFGA holds the *permission* tree. They are
usually identical, and diverge exactly where inheritance is broken. Conflating
them is why break-inheritance is hard in systems that store one tree.

---

## 4. Grants

| Kind | Shape | Notes |
| --- | --- | --- |
| Direct user | `user:alice → editor → folder:x` | 1 tuple per person |
| **Team** | `team:eng#member → editor → folder:x` | **1 tuple for any team size — prefer this** |
| Org/workspace role | inherited from the container | the default path |
| **Conditional** | grant + CEL condition | expiry, IP range, minimum AAL |
| **Link share** | anonymous principal + condition | §8 |

**Conditional grants remove whole categories of machinery.** "Access expires in
7 days" is a CEL condition evaluated at check time — no expiry job, no sweeper,
no window where a stale grant is still live. The same mechanism carries
`min_aal`, IP restriction and device-trust requirements.

### Team grants are the scale lever

Sharing with 100 individuals costs 100 tuples; sharing with a team costs 1.
**✅ Verified** both work identically for access, but they differ enormously in
write amplification and in `ListUsers` cost (§7). The product should nudge toward
teams, and the API should make bulk-individual sharing visibly the expensive
path.

---

## 5. The session boundary

`access` and `identity` are related and separate — the connection is a **kernel
primitive both speak**, so neither imports the other (ADR-001).

```
identity  ──produces──►  Principal + AuthContext  ──consumed by──►  access
                              (kernel types)
```

```
Principal   { Kind: user|service_account|api_key|link, ID, OnBehalfOf }
AuthContext { AAL, DeviceTrusted, IP, SessionID, ActiveOrg }
```

- The **session establishes** the principal and the assurance level. It says
  nothing about permissions.
- `access` **consumes** them: the principal is the subject of the check, and the
  auth context is supplied as **contextual tuples** so conditions can reference
  it.
- This is how "destructive actions require AAL2" is expressed as an authorization
  rule rather than scattered `if session.AAL < 2` checks through handlers.

**API keys and service accounts** are principals too. A key's effective
permission is the **intersection** of its scopes and its owning principal's
access — a key can never exceed its creator, and narrowing the creator narrows
every key they issued.

### Where the two domains must stay coordinated

| Event | Consequence |
| --- | --- |
| Session revoked | drop that session's decision cache; disconnect its Centrifugo channel |
| Principal's access changes | invalidate decision caches for that subject across all their sessions |
| AAL downgraded (step-up expired) | conditional grants requiring AAL2 stop resolving — automatically |

---

## 6. Consistency — the new enemy problem

The hardest correctness problem in the domain, and the one "revoked in realtime"
runs straight into.

**The attack.** Alice removes Bob from a folder, then adds a sensitive file. If a
check is served from a snapshot taken *before* the removal, Bob reads the new
file. Ordering between the ACL change and the content change was lost. Zanzibar
solves this with **zookies** — consistency tokens threaded through reads.

> **⚠ OpenFGA has no zookie equivalent.** It offers consistency *preferences*
> (`MINIMIZE_LATENCY`, `HIGHER_CONSISTENCY`, `NO_CONSISTENCY`) but no snapshot
> token; the Zanzibar-style feature is on their roadmap, not shipped. **We must
> close this ourselves.**

**✅ Measured:** on this single-node dev stack, `MINIMIZE_LATENCY` and
`HIGHER_CONSISTENCY` returned identical results and identical latency (~4 ms), so
**no stale window was observable locally**. That is not reassurance — it means
the local environment cannot reproduce the risk, because caching and read
replicas are what create it. Any test asserting freshness here would pass
vacuously and prove nothing in production.

### Our solution: the event log *is* the zookie

Being event-sourced hands us the thing OpenFGA lacks — a **global, totally
ordered position**. Tuples are written by a projector with a checkpoint
(ADR-013), so we always know how far the authorization projection has caught up.

**Watermark.** Each resource records `acl_version` — the log position at which
its permissions last changed. A check is *safe* when the access projector's
checkpoint ≥ the resource's `acl_version`.

This is the **same comparison** used for read-your-writes in §6.3; only the
source of the position differs:

| Position from | Answers | Used by |
| --- | --- | --- |
| `acl_version` on the resource | "has the projector caught up past this resource's last ACL change?" | **any** reader — the new-enemy guard |
| consistency token from the client | "has the projector caught up past **my** write?" | the writer — read-your-writes |

One mechanism — compare a commit position against the access projector's
checkpoint — with two callers. Implement it once.

Two asymmetric paths, because grants and revokes have opposite risk profiles:

| | Mechanism | Why |
| --- | --- | --- |
| **Grant** (allow sooner) | **contextual tuples** carrying the just-written grant | worst case is the actor briefly seeing their own new access — harmless |
| **Revoke** (deny sooner) | **negative tombstone in Valkey**, short TTL, consulted before OpenFGA | worst case of being late is a **security failure** — so denial must never wait for a projector |

A revocation therefore takes effect **immediately and synchronously**, before the
projector has run, because the deny cache is checked first. This is safe in the
only direction that matters: the tombstone can only ever produce a *deny*.

#### The tombstone is cleared by confirmation, not by a timer

An earlier formulation said the tombstone "expires once the projector has
certainly caught up". That is a bug: if the TTL fires **before** the projector
removes the tuple, access silently returns — a revoked user regains entry with no
event, no log line, and no way to notice.

> **The projector deletes the tombstone after it has confirmed the tuple
> removal.** Positive confirmation, never a timer.

TTL remains, set generously (1 hour) purely as garbage collection for a tombstone
whose projector died, and **a tombstone reaching its TTL is an alert**, not a
routine expiry — it means the access projector is broken.

### 6.2 Decision cache and the revocation epoch

At ~78 ms per authorized page (§1.5), caching is not optional at scale.

- Positive decisions cache in Valkey, keyed
  `(principal, relation, resource, model_id, epoch)`.
- Each subject carries a **revocation epoch**. Any revocation affecting them
  bumps it, which invalidates *all* their cached decisions at once — conservative
  and O(1), rather than tracking which entries to evict.
- Negative decisions are **never cached**: a deny must be able to become an allow
  the instant a grant lands.
- The tombstone is checked **only when the decision is allow** — a deny needs no
  second opinion, which keeps the extra lookup off the majority path.

### 6.3 Newly created resources

A resource's `parent` edge is written by the projector, so between the append and
the tuple write **nobody can reach it — including its creator**. Contextual
tuples cover the creating request, but not a page reload 200 ms later.

The command returns a **consistency token** (the commit position). Clients pass
it back, and the interceptor compares it against the access projector's
checkpoint:

- checkpoint ≥ token → serve normally
- checkpoint < token → **bounded wait** (default 500 ms), then serve
- still behind → serve with `HIGHER_CONSISTENCY` plus contextual tuples

This makes projector lag a *latency* problem rather than a *correctness* one, and
it needs an SLO: **access-projector lag p99 < 500 ms**, alerted. That projector is
on the critical path for perceived correctness in a way no other projector is.

`HIGHER_CONSISTENCY` is then reserved for genuinely sensitive operations rather
than applied globally, where OpenFGA's own docs warn it materially degrades
performance.

---

## 7. Scale rules

Learned partly from the probe, partly from how Drive behaves.

### Never authorize from a projection

Two different jobs, and conflating them is a data leak:

| Purpose | Source | Authoritative? |
| --- | --- | --- |
| **Browsing** — "shared with me", pagination, sorting | Postgres projection | **no** |
| **Authorizing** — may they open it? | `Check` / `BatchCheck` | **yes** |

The pattern for every list screen:

```
1. page the projection            → candidate IDs (fast, sortable, paginated)
2. BatchCheck that page           → one round trip, bounded by page size
3. filter, then render
```

This bounds authorization cost to *page size* rather than corpus size, and keeps
`ListObjects` off the hot path entirely. **Measured: ~78 ms for a 50-item page**
(§1.5) — so page size is a latency decision, not just a UX one, and the decision
cache (§6.2) is what keeps repeat views cheap. A projection may briefly list something
the user just lost access to — step 2 removes it before render.

### `ListUsers` expands groups — do not use it for the share dialog

**✅ Verified:** `ListUsers` on a file whose access came from a 100-person team
plus individual grants returned **101 users**. With a 10,000-person team it
returns 10,000.

So the share dialog renders **grants**, from our own projection — *"team:eng —
editor"*, *"alice — viewer"* — which is compact, is what the user actually edits,
and is what Drive shows. `ListUsers` is reserved for audit and access-review
reports, paginated, off the request path.

### Further rules

- **Never materialize effective permissions.** Tempting for "shared with me";
  fatal on write amplification.
- **Decision caching is specified once, in §6.2** — keyed by
  `(principal, relation, resource, model_id, epoch)` and invalidated by bumping
  the subject's revocation epoch. Do not reintroduce a TTL-based scheme here; a
  TTL cannot express "this subject was just revoked".
- **Pin the model ID** on every check. "Use latest" makes deploys racy (ADR-002
  of the OpenFGA section in INFRA.md).
- **Bound depth** at 15 (§1.5) — enforced, not advisory, because 25 is a hard
  error rather than a slow path.
- **`ListObjects` is unmeasured at scale.** The probe returned 52 objects in
  5 ms, which proves nothing about a corpus of 100k. Before any feature depends
  on it, measure it against a realistic corpus — and prefer the
  page-then-`BatchCheck` pattern above, which has no corpus-size term at all.

---

## 7.5 Graph integrity guards

Three failure modes the engine cannot detect for itself, because it does not know
what a resource is (ADR-006). All three are enforced by the **owning module**
before a tuple is written.

### Cycle prevention (review D5)

Nothing in OpenFGA stops a container's parent being set to its own descendant.
The result is not a crash — resolution is depth-bounded — but **wrong answers and
latency**, which is worse because it looks like a permissions bug.

> Every move / re-parent runs an **acyclicity check against the structural tree
> in Postgres** before the tuple is written: the new parent must not be a
> descendant of the resource being moved.

Postgres holds the structural tree (§3), so the check is a bounded ancestor walk
on an indexed table — not a graph traversal in OpenFGA.

### Depth cap (see §1.5)

The same move/re-parent command that checks for cycles also checks depth:

> The resulting subtree depth must not exceed the configured cap (**15**), which
> is deliberately far below OpenFGA's hard limit of **25** where checks stop
> failing gracefully and start erroring.

Both checks run against the structural tree in Postgres, in one bounded ancestor
walk, before any tuple is written.

### Team deletion cascades to its grants (review D6)

Grants target `team:x#member`. Deleting the team leaves those tuples in place,
and the second-order failure is the dangerous one:

> **If a team id were ever reused, the new team would silently inherit the
> deleted team's access.**

So: deleting a team **cascades to every grant naming it**, in the same Temporal
saga as the deletion, and **team ids are never reused** — belt and braces,
because the cascade can fail partway and the reconciler needs time to notice.

### Resource deletion cleans up its tuples (review D7)

Same class, wider scope. Deleting any resource removes its `parent` edge and
every grant naming it. Otherwise the drift reconciler (§11) flags orphans
forever, and real drift gets lost in the noise.

Deletion order matters: **tuples first, then the aggregate**. A resource that
still exists with no tuples is inaccessible and recoverable; tuples pointing at a
resource that no longer exists are a live grant to a resurrected id.

---

## 7.6 Guests (review D8)

Guests consume a separate seat pool (ADR-027). The boundary is now explicit, and
it is the Drive external-collaborator model:

> **A guest has explicit grants only. They never inherit workspace access.**

| | Member | Guest |
| --- | --- | --- |
| Inherits from workspace | ✅ | **❌ — nothing** |
| Sees resources | all they inherit | **only what was explicitly shared** |
| Sees the member list | ✅ | ❌ |
| Sees the workspace tree | ✅ | only shared subtrees |
| Creates resources | ✅ | ❌ |
| Invites | per role | ❌ |
| Seat pool | `seats.member` | `seats.guest` |

Structurally this is simply **the absence of the inheritance edge**: a guest is
never added to `workspace#member`, so nothing flows down to them. It needs no
new relation, no deny rule, and no special case in the engine — which is exactly
the test that the topology abstraction is right.

A guest promoted to member gains the membership edge and atomically moves seat
pools (entitlement.md §3).

---

## 8. Link shares

A link is an **anonymous principal plus conditions** — not a special code path.

- `link:<opaque>` granted a relation on a resource, carrying CEL conditions:
  expiry, audience (`domain == "acme.com"`), password-required, view-only.
- Revocation deletes the tuple; rotation issues a new opaque id.
- A link holder is a principal like any other, so every downstream rule —
  inheritance, break-inheritance, audit — applies with no extra logic.

---

## 9. Registering a new resource type (ADR-006)

The reuse contract, restated as the whole procedure:

1. Declare the type in the module's own `.fga` fragment.
2. Emit kernel resource-lifecycle events (`ResourceCreated` with parent,
   `ResourceMoved`, `ResourceDeleted`).
3. Register the role catalogue in the module's provider set — **including the
   type's `minVisibility` relation**.
4. Call `Checker` / `Lister` from use cases.

> **Step 3's `minVisibility` is not optional.** It is the relation the error
> disclosure ladder checks on a resource's *parent* to decide between
> `ACCESS_DENIED` and `NOT_FOUND` (ADR-036). A type registered without one has no
> safe answer available, so registration **fails at startup** rather than
> silently defaulting — defaulting to `NOT_FOUND` breaks in-tenant UX, and
> defaulting to `ACCESS_DENIED` leaks existence across tenants.

**Zero lines of `access` change.** Inheritance, break-inheritance, link shares,
team grants, conditions, `Expand` and the drift reconciler all work immediately.

Today's registered types are `organization`, `workspace`, `team`. The probe
proves the mechanism with `folder`/`file` — types that exist **only in the test
fixture**, which is exactly the guarantee ADR-006 requires.

---

## 10. Model lifecycle

- The authorization model is **assembled from module fragments** at build time,
  never hand-edited as one file.
- Every deploy produces a new immutable model ID; checks pin it.
- Model changes ship as a migration with a rollback path, and a **shadow-check**
  phase: run new and old models in parallel over live traffic and diff decisions
  before switching. An authorization model change is the highest-blast-radius
  deploy in the system.

### Deploy ordering is not negotiable

Tuples are model-agnostic triples, but a tuple naming a **type** absent from the
pinned model is rejected. So a new resource type must exist in the model *before*
any code can emit its events:

```
1. deploy the new authorization model      (additive only)
2. deploy code that pins the new model id
3. deploy code that writes the new tuples
```

Reversing 1 and 3 means the access projector starts rejecting writes and falls
behind — which, via §6.3, surfaces as newly created resources being unreachable.
Model deploys are therefore always **additive**; removing a type is a separate,
later migration once no tuples reference it.

---

## 11. Drift and reconciliation

Tuples are a **projection**; the event log is truth (ADR-013). They can diverge —
a failed write, a manual edit, a bug.

A reconciler replays grant events, derives the expected tuple set, and diffs it
against OpenFGA:

- tuple present with no originating event → **injected** → remove, raise incident
- event present with no tuple → **lost** → repair
- condition mismatch → repair

Same technique as credential tamper detection in `identity` §4.2, and it works
for the same reason: derived state that disagrees with its source was written
outside the application.

---

## 12. Failure behaviour

**Fail closed. Always.** (ADR-010.)

If OpenFGA is unreachable, deny. Resilience must never become a privilege
escalation path — an attacker who can DoS the authorization service must not gain
access by doing so.

The single permitted softening: the **positive-decision cache of §6.2**, so an
outage degrades gradually for already-active sessions rather than locking
everyone out instantly. Uncached decisions and all negatives still deny. The deny
tombstone (§6) continues to work during an outage, since it is consulted first
and lives in Valkey.

---

## 13. Events published

`AccessGranted` · `AccessRevoked` · `GrantConditionChanged` ·
`InheritanceBroken` · `InheritanceRestored` · `ResourceParentChanged` ·
`LinkShareCreated` · `LinkShareRevoked` · `OwnershipTransferred` ·
`AuthorizationModelDeployed` · `AccessDriftDetected`

All carry `SubjectID` pseudonyms only (ADR-002).

---

## 14. Read models

| Projection | Serves | Notes |
| --- | --- | --- |
| `grant_view` | the share dialog | grants, **not** expanded users |
| `shared_with_me` | browsing entry point | candidates only — always BatchCheck before render |
| `resource_tree` | structural nesting, breadcrumbs | the *display* tree, distinct from the permission tree |
| `acl_watermark` | `(resource_id → log position)` | drives §6 |
| `access_audit` | who could reach what, when | compliance access reviews |

---

## 15. Ports

Declared by this domain, implemented in adapters (ADR-001):

```
Checker      Check · BatchCheck            ← the hot path
Lister       ListObjects · ListUsers
Expander     Expand                        ← debugging
TupleWriter  Write · Delete                ← projector-only, never a handler
ModelDeployer Deploy · Pin
```

`TupleWriter` is **only** reachable from a projector. A use case that writes a
tuple directly has bypassed the event log and created drift — this is enforced by
package visibility, not convention.

---

## 16. What this domain does **not** own

- What a resource *is*, its content, its name → the owning module
- Membership of an org or workspace → `organization` / `workspace`
- Who someone is, sessions, credentials → `identity`
- Whether a *plan* allows a feature → `entitlement` (a distinct question:
  entitlement asks "is this capability purchased?", access asks "may this
  principal use it?" — both must pass)

---

## 17. Test plan

**Topology matrix**, run against a fixture-only `testresource` type so an
abstraction leak breaks the build (ADR-006):

- inheritance at depth 1, 4, and the configured maximum
- present **and future** children of a grant
- break-inheritance, direct grant inside a broken subtree, restore
- team grant vs 100 individual grants — identical decisions
- conditional grant before, at, and after expiry
- link share with each condition kind
- ownership transfer

**Limits and guards (§1.5, §7.5) — these fail closed, so they need tests most:**
- depth cap refused at 16; **depth 25 confirmed to error**, proving the cap sits
  below the wall rather than at it
- cycle refused on move, including a 3-hop indirect cycle
- team deletion removes every grant naming it
- resource deletion removes tuples **before** the aggregate

**Consistency:**
- deny tombstone denies before the projector has run
- **tombstone is cleared by the projector's confirmation, never by TTL** — and a
  tombstone reaching TTL raises an alert
- revocation epoch bump invalidates that subject's cached decisions and no others
- consistency token forces a bounded wait when the projector lags, then proceeds
- a newly created resource is reachable by its creator on the next request
- **model deploy ordering**: emitting a tuple for a type absent from the pinned
  model is rejected, and the projector reports it rather than silently stalling
- contextual tuples give the actor read-your-writes on grant
- watermark comparison forces `HIGHER_CONSISTENCY` when the projector lags
- **new-enemy scenario explicitly**: revoke, then add content, assert no access

**Scale (load, not unit):**
- `BatchCheck` latency across page sizes
- `ListObjects` against a wide corpus — establish where it stops being viable
- write amplification: team grant vs individual grants

**Security:**
- OpenFGA unreachable ⇒ every check denies
- API key cannot exceed its owning principal
- tuple writes are unreachable outside a projector
- reconciler detects injected, lost, and mutated tuples

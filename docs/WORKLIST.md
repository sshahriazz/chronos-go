# Worklist

The live list. Updated as items move. Read this to know what is happening and
why, without reading the code.

**Status key:** `[x]` done and green · `[>]` in progress · `[ ]` not started

---

## Now: Slice 1 — access substrate

Why this slice: nothing in organization or workspace can be *enforced* until
OpenFGA answers. All 22 authz rules today are `self`, which never reaches the
graph. See [ORG-WORKSPACE-SCOPE.md](ORG-WORKSPACE-SCOPE.md) §2.

### 1a — model pipeline  ✅ complete

- [x] **Fragment vocabulary** — `internal/platform/authz/model`
      Modules declare their types in domain words; access assembles them.
      *Why:* ADR-006 — access must not know what a workspace is.
- [x] **Assembler + validation** — same package
      Refuses undefined types, duplicate owners, unholdable relations, dead
      inheritance. *Why:* each of those fails silently at runtime otherwise.
- [x] **Wire translation + deploy** — `internal/adapter/openfga/deploy.go`
      Fragment → OpenFGA Userset; store provisioning; model deploy.
- [x] **Proof against live OpenFGA** — `deploy_integration_test.go`
      Org admin inherits admin on a workspace created afterwards, 2 tuples.
      *Why:* that inheritance is the reason this topology was chosen.
- [x] **`genauthzmodel` tool** — assemble → `docs/access/authorization-model.fga`,
      plus `-check`, now part of `make check`.
      *Why:* the model becomes diffable in review, and the gate catches fragments
      drifting from the reviewed artifact. Same pattern as the OpenAPI gate.
- [x] **Store provisioned, model pinned** — `make authz-deploy`
      *Why:* `OPENFGA_STORE_ID` was blank, so the checker was never built.
      **The server now boots with zero ERROR lines** (it had two).
- [x] **`make authz-model` / `authz-check` / `authz-deploy`**

### 1b — the access module  ⏸ deferred until organization exists

**Reordered, deliberately.** Every item here needs events to react to, and there
are none: all 22 authz rules are `self`, which writes no tuples, and
organization and workspace do not exist. Building them now would mean adapters
wired to nothing — which this repo has already done once, with `inapp`,
`webpush` and `seaweedfs` fully built, fully tested and constructed by no
binary. So 1b now FOLLOWS the organization aggregate.

- [x] **Access projector** — `internal/modules/access/projection/tuples.go`.
      Writes membership, workspace-admin and team-membership edges. Its blocker
      cleared when organization landed, and the boxes above stayed unticked long
      after the work was done.
- [x] **Revocation tombstones (ADR-045)** — `platform/authz`'s `Tombstones`,
      `Revoker` and `Revocations` ports, cleared by the access projector's
      confirmation and never by a timer.
- [x] **Gate 1 (`OrgResolver`)** — `orgapi.NewOrgResolver`, wired in `cmd/api`.

## Slice 2 — organization core  ✅ complete

Pulled forward ahead of 1b, because 1b has nothing to react to until this
exists. Built inside-out: the pure domain first, since it needs no
infrastructure and every later piece depends on its shape.

- [x] **`Organization` aggregate + lifecycle state machine**
      30 transitions asserted, legal and illegal. `PendingActivation` and
      `Expired` are gone — both were about a card at signup.
- [x] **Owner + admin set, last-owner invariant**
      The owner cannot be removed as an admin, and adding the owner as an admin
      records nothing (it would put them in a set they can be removed from).
- [x] **Organization access fragment** — now used by the 1a proof instead of its
      fixture. `billing_manager` resolves to the owner alone (ADR-027).
- [x] **Events registered in all three binaries** + a notification decision for
      each. The existing gates caught both omissions.
- [x] **Subscription gate (the decision)** — all 42 cells of the operation-class
      × status matrix asserted. Pure, so it needed no projection; fails CLOSED
      when the status cannot be read.
- [x] **`org_status_view`** — migration 00018 with RLS, sqlc queries, the
      projection, and the `StatusReader` gate 3 depends on. Proved against a real
      database: one org cannot read another's status, and an unprojected org is
      refused rather than waved through.
- [x] **`CreateOrganization` use case + RPC** — proto, use case, handler, wired
      into cmd/api. Both uniqueness rules hold at the WRITE: one atomic append
      to three streams, each with `NoStream`. Two concurrent creations by one
      person produce exactly one organization, proved against real KurrentDB.
- [x] **Billing: provisioning only** — a THIN slice of billing, pulled forward.

      *Why the plan changed:* it said "billing is additive after" the other
      slices. That was wrong. An organization is unusable in `provisioning`, and
      BILLING-PLAN §2 Option A — chosen to avoid two code paths — makes Stripe
      the only thing that can start a trial. So slices 3–5 all sit behind this.

      In scope: the Stripe customer, a cardless trialing subscription, and the
      reactor that appends `OrganizationTrialStarted`.
      OUT of scope, still slice 6: invoicing, the customer portal, webhook
      ingestion, the plan catalogue. The trial Price comes from config, not a
      catalogue.

      - [x] Config: `STRIPE_SECRET_KEY`, `STRIPE_TRIAL_PRICE_ID`,
            `STRIPE_TRIAL_DAYS`. A LIVE key outside production fails startup.
      - [x] `app.Provisioning` + `app.Trials` — Stripe first, event second, and
            a test proving a failed provisioner appends nothing.
      - [x] `internal/adapter/stripe` — the only package that imports the SDK.
            Cardless, `missing_payment_method: pause`, idempotent on our org id
            in Stripe metadata.
      - [x] The reactor, wired into cmd/worker.
      - [x] Stripe test key and $0 recurring Price configured.
      - [x] **Proved against the real Stripe test account:** a cardless trialing
            subscription with no payment method, `missing_payment_method: pause`,
            and provisioning twice returns the SAME customer and subscription.
      - [x] **The loop closes:** `OrganizationCreated` -> reactor -> Stripe ->
            `trialing`, asserted against the event log. A redelivery changes
            nothing — same subscription, same revision.
- [x] **Then 1b**: access projector consuming `OrganizationCreated`, tombstones,
      `OrgResolver` — all three landed with slice 2 and after. This parent line
      outlived its own sub-items, the same way the three above it did.

Deliberately excluded: domain verification, ownership transfer. Neither blocks
workspace.

---

## Billing — webhook ingestion  ✅ complete

**Pulled forward for the same reason provisioning was.** Stripe pauses a
cardless trial at day 14 and emits `customer.subscription.paused`. Without an
endpoint to receive it we never learn, `org_status_view` says `trialing`
forever, and the trial that was supposed to end never does — a free forever
account, which is exactly the leak the `Provisioning` state was introduced to
prevent.

- [x] `STRIPE_WEBHOOK_SECRET` config, with rotation overlap
- [x] The endpoint: verifies the signature against the RAW body, dedupes on
      Stripe's event id, refuses to be served at all without a secret
- [x] Re-fetches the object from Stripe rather than trusting the payload
- [x] Stripe status -> org lifecycle, all 8 statuses asserted
- [x] **Proved end to end with `stripe listen`:** cancelling a real trialing
      subscription drove `customer.subscription.deleted` through verification,
      dedupe, re-fetch and append, and the organization reached `closed`.
- [x] **`customer.subscription.paused` at real trial end**, via a Stripe test
      clock: a real subscription reaches day 14, Stripe pauses it, and the
      organization suspends. `trial ended -> stripe paused -> org suspended`.

## Now: Slices 3+4 MERGED — entitlement, then workspace

**Merged, and the reason is the 1b lesson again.** Gate 4 has no consumer until
a method declares an entitlement, and none does: `CreateWorkspace` is the first.
Building entitlement alone would leave the gate implemented and unreachable —
adapters wired to nothing. The ordering reason still stands, so entitlement
comes FIRST INSIDE this slice rather than as a slice of its own, and
`CreateWorkspace` is quota-gated from its first commit.

Trial caps: **3 workspaces, 5 seats**.

### Entitlement first

- [x] The catalogue: limits keyed by string, with the trial plan a REAL plan
      rather than an `if trialing` branch in the derivation
- [x] check -> reserve -> commit/release in POSTGRES, not Valkey. **Two
      concurrent reservations for the last unit: exactly one wins**, and 5 of 5
      runs fail without the advisory lock.
- [x] Gate 4, the `Entitlements` interface that had never had an implementation

### Then workspace, gated from the start

- [x] `Workspace` aggregate, never-zero-admins (proved by mutation), archive/restore
- [x] `CreateWorkspace` declaring `authz(admin on organization)` + `GROW` +
      `entitlement(workspaces.count)` — the FIRST RPC to declare an entitlement,
      so the first that gate 4 has ever run for
- [x] **1b finished, because this needed it:** gate 1 (`OrgResolver`, verifying
      membership rather than trusting a header), the `org_member_index`
      projection, and the ACCESS PROJECTOR writing tuples from the event log
- [x] **cmd/api now boots with all six gates wired and zero ERROR lines**
- [x] **End-to-end proof: 3 workspaces succeed, the 4th is refused** with
      QUOTA_EXCEEDED, through authn -> org-context -> authz -> subscription ->
      entitlement -> idempotency. Raising the cap to 4 fails the test.
- [x] **Seat accounting: one person per ORGANIZATION, not per membership.**
      All three rules proved by mutation — reserving per membership overcharges
      5x, releasing on every removal leaks revenue, and releasing the old pool
      before taking the new one leaves the person holding neither.
      Seats are reserved in the USE CASE, not gate 4: gate 4 reserves
      unconditionally, and the rule is conditional.
- [x] The member RPCs — `AddWorkspaceMember`, `RemoveWorkspaceMember` and
      `ChangeWorkspaceMemberRole`. `Seats` now has a caller, and the seat rule is
      proved through the RPC as well as in isolation.
- [x] **Revocation tombstones (ADR-045) now have a writer.** The machinery was
      complete — the Guard consults them, the confirming writer clears them — and
      nothing had ever laid one, so every revocation waited on projector lag. A
      removal and a demotion lay one now, after the append and before returning,
      and the access projector's delete is what confirms it.
- [x] **`resource_id_field` works.** It had been declared in the schema and
      published in the OpenAPI document since the option existed, while the gate
      returned `ErrGateUnavailable` for every method that used one. These are the
      first three RPCs that could ever have carried it.
- [x] **The creator is a real member.** `WorkspaceCreated` named the first admin
      and nothing carried that into the membership category, so the creator had
      no Membership aggregate: removing them was a no-op that returned 200,
      changing their role was NOT_FOUND, and their membership consumed no seat.
      Creation is now one atomic append of the workspace and their `MemberJoined`.
- [x] **`org_member_index` moved to the workspace module.** Membership comes from
      organization events AND from workspace joins; one table has one writer, and
      `workspace -> organization` is the only permitted direction (ADR-020), so
      the projection has to live on the workspace side. Without the join handler
      a person added to a workspace could authenticate and then do nothing —
      gate 1 refuses to resolve an organization they demonstrably belong to.
- [x] **The access projector was skipping every membership event.** Its filter
      named `workspace-` and `organization-`; memberships live in their own
      category. A grant that never lands DENIES, which is what a healthy
      authorization graph looks like from the outside.
- [x] `entitlement.ReserveFor` / `ReleaseFor` implemented — `Seats` declared the
      port and nothing satisfied it, so the seat rule could not have run.

## Now — Slice 5, invitations

workspace.md §5. Decomposed because it is the largest slice so far and touches
four modules; each step below is a commit that leaves the tree green.

The shape of the problem: an invitation is a **credential sent to an address**,
and both halves cross a module boundary. The token is a credential, and identity
owns credentials. The address is personal data, and only the vault may hold it.
`modules/A` may import `modules/B/contract` and nothing else (CONVENTIONS §2), so
neither can be reached for directly — the port is declared by workspace and
satisfied at the composition root.

- [x] **5a — the token primitive moves to `platform/`.** Identity's minter is
      module-private, so workspace may not import it, and copying 200 lines of
      credential-hashing into a second module is the version of this that rots.
      Behaviour unchanged; identity's adapter becomes a thin wrapper.
- [x] **5b — the Invitation aggregate.** Pending → Accepted / Revoked / Expired /
      Declined / Undeliverable, as a transition table. Its own stream category,
      for the reason memberships have one.
- [x] **5c — Issue.** Seat reserved AT ISSUE and conditionally (workspace.md §5):
      60 pending invitations against 50 seats otherwise all look valid, and the
      51st acceptance fails for somebody who did nothing wrong. Address goes to
      the vault and never into an event; the blind index is what the event
      carries.
- [x] **5d — Accept.** Five checks, all revalidated at acceptance rather than
      trusted from issue time. Two paths: an existing user authenticates first; a
      new user's acceptance IS proof of address control, so it completes email
      verification rather than sending a second mail.
- [x] **5e — Revoke, decline, resend.** Resend rotates the token and extends
      expiry; the old token stays dead.
- [x] **5f — `invitation_view`** projection, keyed `(workspace_id, status,
      expires_at)`.
- [x] **5g — the invitation mail**, through the notification reactor and a
      Temporal activity, addressed from the vault at send time (ADR-002).
- [x] **5h — the Temporal workflow**: expiry, reminders and seat release, in
      three commits. The per-invitation timer makes expiry timely and reminders
      possible; the hourly reconciliation sweep makes expiry certain when a timer
      was never started. Plus workspace.md §5s two remaining edge cases —
      supersession (one seat per address, and the old link dies) and a departing
      inviters outstanding invitations being revoked.

## Now — Slice 6, teams

workspace.md §6 and access.md §7.5. A team is a GRANTABLE SUBJECT: sharing with
one costs a single tuple whatever its size, which access.md §4 measured and §6
confirmed at the latency level too (a check through a 1000-member team costs
2.1 ms against a direct grant's 2.0 ms).

- [x] **6a — the Team aggregate and its place in the graph.** Flat, never
      nested: the engine could model `team#member` referencing another team, and
      the reason not to is that nesting makes effective membership non-obvious to
      the people managing it, which is the problem teams exist to solve.
- [x] **6b — create, rename, delete, and the projection.**
- [x] **6c — membership.** A team member must already be a workspace member;
      adding a non-member is refused rather than implicitly admitting them.
      Maintainers manage membership without being workspace admins.

      Three things landed with it that the line above does not say. The
      `team:x member user:y` tuples, without which a team is a list in Postgres
      the access engine has never heard of and every grant to a team silently
      resolves to nobody. The authorization decision, which the gate cannot take
      — it admits any workspace member, because maintainers must manage their own
      team — so the handler carries "a maintainer of THIS team, or an admin of
      the workspace", and an unreadable admin answer denies. And the DEPARTURE
      CASCADE below.

### The departure cascade, which was a live gap

workspace.md §6 runs in both directions: a team member must be a workspace
member, so **leaving the workspace has to leave its teams**. Only the first
direction had code. The second is a permission that outlives its grant — a
removed person keeps `team:x member user:y`, and the first thing ever shared
with that team reaches them, with no event and no log line.

It landed here rather than being deferred with the deletion cascade because the
two are not alike. This one is reachable by an ordinary removal, and the fix is
bounded: `team_member_view` is already indexed on `(workspace_id, subject_id)`,
so enumeration is one query. `workspace-team-departure` is its own subscription
group, not a second job inside `workspace-inviter-departure`, because the two
react to DIFFERENT subsets of `MemberRemoved` — that one ignores a removal with
`SeatReleased=false`, this one must not, since the rule is per workspace.

### Deferred, deliberately: the deletion cascade

access.md §7.5 requires deleting a team to cascade to **every grant naming it**,
because a reused id would silently inherit the deleted team's access.

Half of that is being built: team ids are ULIDs and are never reused, and
deletion removes the team's own tuples. The CASCADE is not, and the reason is
that there is nothing to cascade to. A grant naming `team:x#member` is a share,
sharing needs resources, and feature verticals inside a workspace are explicitly
out of scope (ADR-006) — so no such tuple can exist yet.

Building the cascade now would also need something that does not exist: the
adapter has no way to enumerate tuples, and access.md §3 says the enumeration
should come from **our own grants projection**, which arrives with sharing. A
cascade written against an OpenFGA `Read` today would be a second, weaker
implementation to throw away.

So it is written down here rather than half-built: **the cascade lands with the
first feature that can grant to a team**, and until then the invariant it
protects is held by ids that are never reused.

Deleting a team also leaves its `team:x member user:y` edges in the graph, for
the same reason and with the same remedy — they are inert until something can
grant to a team, and removing them needs the member list, which the access
reactor cannot read without racing the projector that empties the same table on
that event. Both land together.

## Now — Billing

Per [BILLING-PLAN.md](BILLING-PLAN.md). Webhook ingestion was already complete;
what landed since is the part that turns a trial into revenue.

- [x] **The Customer Portal.** `CreateBillingPortalSession`, gated
      `billing_manager` (the owner alone) and classed `BILLING_MANAGE`, which
      gate 4 never blocks — if it did, a suspended organization could never pay
      and suspension would stop being reversible. The Portal is the ONLY way a
      card is ever added: there is no card field of ours, by design.
- [x] **The trial-ending warning.** `customer.subscription.trial_will_end` three
      days out, which for a cardless trial is the only warning anybody gets. The
      guard is a recorded DEADLINE rather than a boolean, because Stripe permits
      extending a trial and a boolean would announce the old date and never the
      real one.
- [x] **Invoices (§5).** A reference and a status per invoice, projected from
      webhooks; `ListInvoices` gated `billing_viewer`, which includes admins
      (ADR-027). We render nothing and compute no totals.

### Still open in the plan

- [x] **§7 key custody.** A KV v2 engine beside the transit KEK — a different
      job in the same server: the KEK never leaves OpenBao, while these values
      must, because a Stripe key is useless unless we can send it to Stripe. So
      it is CUSTODY, not secrecy-in-use: read once at startup over an
      authenticated channel instead of sitting in every process's environment,
      `docker inspect`, a crash dump and the deploying shell's history.

      `OPENBAO_STRIPE_PATH` is the switch and it is deliberately binary. Unset,
      the environment is used, which is what a dev machine wants. Set, OpenBao
      is AUTHORITATIVE and a missing `api_key` is a startup failure — there is
      no third mode where custody is configured and the environment quietly
      fills a gap, because that fallback makes a rotation that failed to land
      look exactly like one that worked.

      Resolution is a step after `config.Load` rather than inside it: Load is
      pure, and folding a network read into it would make configuration fail on
      a blip and report "bad configuration" when the configuration is fine. The
      overlay re-runs `validate()`, so ADR-008's live-key-outside-production
      rule is about the VALUE rather than about where it came from — and custody
      is the more likely place for a live key to appear.

      Still environment-only: every other secret in the build. The mechanism is
      general and the remaining move is mechanical.
- [ ] **§9.3** — does a trial convert automatically at trial end when a card was
      added mid-trial? Stripe's default is yes. Worth confirming rather than
      inheriting.
- [x] **§9.4 — annual plans: YES, from the start.** Decided before the catalogue
      exists, which is the whole reason it was worth asking: the catalogue
      carries `interval` as a dimension from day one rather than being reshaped
      once annual arrives. Two Prices per plan per currency, and a monthly→annual
      switch is a subscription UPDATE that Stripe prorates — never a second
      subscription (billing.md §5 case 19: one active subscription per org).

### Suspension: tells EVERY member — done

`OrganizationSuspended` is an `On` over `AudienceOrgMembers`, resolved from
`org_member_index` — the first audience in the system that needs a READ MODEL
rather than the envelope's own metadata, which is what `notify.SubjectAudiences`
had been refusing to guess at.

ONE wording for everyone, which is a constraint rather than a preference and is
worth recording as such. The catalogue is one event to one Spec — a second entry
panics with "would send twice" — and `Data` is computed once from the EVENT, not
per recipient, so a template cannot branch on whether the reader is the owner.
Two templates by role would therefore mean either sending twice or reshaping a
well-designed piece for a wording nicety. The copy addresses both without
conditionals, which is the ordinary shape for broadcast mail anyway.

An oversized organization is REFUSED rather than truncated: a notification that
reaches the first N members and omits the rest is invisible from every side —
the sender saw a success, and the people left out have nothing to notice.

### The original note, kept because it records why this was open

`OrganizationTrialEndingSoon` mails: "your trial ends in three days". When it
actually ends, `OrganizationSuspended` is `cat.Silent`, so the customer hears
nothing. The stated reason still holds — suspension ends access for EVERY
member, and telling the owner alone tells the one person who can fix it and
nobody who is affected — but the half-conversation is worse than the silence
was. It needs an organization-member audience, which does not exist yet.

---

## Now — compliance, the erasure path

The stock-take found the one place this system promised something it could not
do: a person could request deletion, we recorded it and mailed them a date, and
nothing ever ran.

- [x] **The domain.** `UserDeletionCancelled`, `UserErased`, a terminal
      `StateErased` that `mutable()` refuses, and an `Erase` that requires an
      outstanding request — the guard against a workflow started for the wrong
      subject, which has no undo.
- [x] **Identity's half.** Address reservation released, username TOMBSTONED
      (not released — a published handle reissued is an impersonation vector
      aimed at the person who left), account marked erased last so nothing
      claims completion until it is complete.
- [x] **Sessions.** Handled by the SESSION PROJECTION rather than a use case:
      it owns `session_view` and `session_token` (CONVENTIONS §8), and it is the
      only path that survives a rebuild. `GetSessionByToken` checks neither the
      account's state nor its existence — deliberately, it runs on every
      request — so without this an erased account's tokens keep resolving until
      they expire.
- [x] **The orchestration.** compliance's `Erasure`: confirm, destroy the key,
      then identity's half. It owns none of the data it erases and reaches
      everything through ports, which the import contract makes structural.
- [x] **The grace period.** A Temporal workflow that re-reads on every wake, so
      a cancellation actually stops it, and follows a deadline that moves.
- [x] **The confirmation.** Sent BEFORE the destroy, because afterwards there is
      no address to send it to, and stating what is retained — a confirmation
      implying total deletion when tax records survive is a misleading statement
      about processing.

### What is NOT done, and is the next step

- [x] **The cancel endpoint.** `CancelAccountDeletion`, AAL2, no typed
      confirmation — the asymmetry with requesting is deliberate: a confirmation
      guards what cannot be undone, and this IS the undo. Cancelling nothing
      succeeds, because the link is clicked twice or after an operator already
      withdrew it.

      Three stale doc blocks on the request RPC were corrected with it. They
      each said erasure was unconsumed and uncancellable, which stopped being
      true one commit earlier.
- [x] **Temporal is on the status surface even when switched off.** It was not:
      the disabled branch registered the three SCHEDULE probes and NOT the
      Temporal probe itself, so a deployment with durable work off reported
      three missing schedules and said nothing about the dependency they all
      rest on.

      Criticality stays **Degradable** rather than becoming Critical — a worker
      that cannot reach Temporal still runs every reactor and fills every read
      model, and taking the binary out of the load balancer would be a larger
      outage than the one being reported. What changed is `Impact()`, which now
      names ERASURE FIRST: every other durable job degrades into a delay, and
      this is the one that simply does not happen.
- [ ] **Legal holds and retention exemptions** (compliance.md §4 steps 2–3) are
      not consulted. Nothing can place a hold yet, so there is nothing to check;
      it becomes real with the `LegalHold` aggregate.
- [ ] **The subject graph is not traversed** (step 4). Only identity holds
      personal data today, so erasing it is erasing everything — but that stops
      being true the moment a second module does, and the traversal is what
      makes the guarantee hold then.
- [x] **The reconciliation sweep.** The workflow is durable, so a lost one is
      unlikely rather than impossible; a sweep over overdue requests is the
      backstop billing.md §5 case 15 uses for the same class of failure.
- [ ] **The other five DSAR rights** — access, portability, rectification,
      restriction, objection (compliance.md §3). Erasure was the one with a
      hollow guarantee; the rest are unbuilt features.

## The remaining work, analysed

Every open item was read against its spec and the code before being ranked. Two
turned out to be BLOCKED BY SCOPE rather than by effort, and saying so is the
point of the exercise — building either would repeat the failure this repository
already has a name for.

### P1 — erasure is incomplete, and these are why

- [x] **An erased subject's AVATARS survive.** The crypto-shred destroys the
      vault key, which makes every vault field unreadable at once — and an
      avatar is not in the vault. It is an OBJECT in SeaweedFS, and a photograph
      of a person is personal data by any reading.

      Nothing deletes it. ADR-056 named object lifecycle as unbuilt and this is
      the case where that stops being a tidiness question: erasure reports
      success while the person's picture is still served by a signed URL.

      Tractable because `AvatarPrefix(subjectID)` is a deterministic digest, so
      deletion is prefix-scoped rather than a scan — and it covers ABANDONED
      uploads too, which ADR-056 also left unreclaimed. Needs a `List` on the
      blob port, which does not exist yet.

      This IS compliance.md §4 step 4 — "traverse the subject graph → which
      streams, rows, objects" — with its first real member. The traversal was
      previously listed as premature because only identity held personal data;
      that was wrong, and this is the correction.

- [ ] **No reconciliation sweep.** The erasure workflow is durable, so a lost
      one is unlikely rather than impossible. Every other timer in this system
      has a sweep behind it for exactly that reason (billing.md §5 case 15), and
      erasure is the one where the backstop matters most because the failure is
      a statutory deadline nobody notices passing.

### P2 — small, and each closes a decision

- [x] **§9.3 — Stripe's auto-convert default: CONFIRMED, and it is what we
      want.** Verified against the real test account with a test clock rather
      than reasoned from the documentation
      (`TestATrialWithACardConvertsToActive`): a card attached mid-trial, the
      clock advanced a day past trial end, and the subscription is `active`.

      The thing worth verifying was not the default itself but whether
      `missing_payment_method: pause` suppressed it. Both behaviours are
      configured by the same field, so it was entirely possible for the setting
      that makes a cardless trial pause to also stop a card-holding one
      converting. It does not.

      The subscription ID is UNCHANGED across the conversion, which is
      billing.md §5 case 25's requirement — one subscription for the
      organization's whole life, so billing history stays continuous and the
      mirror needs no re-keying.
- [x] **`identityit TestADeactivatedAccountCanGetBackIn` — a real race, found by
      READING it rather than by running it again.** Ten more clean runs produced
      nothing, which is what a narrow timing window does; the cause was visible
      in the test.

      It asserted the caller's bearer was dead IMMEDIATELY after
      `DeactivateAccount` returned. Revocation is an APPEND and
      `GetSessionByToken` reads `revoked_at` from `session_view`, a PROJECTION —
      so there is a window in which the call has returned and the token still
      authenticates. Under load the projector is far enough behind to land
      inside it, and the failure reads as "deactivation does not revoke
      sessions" when the revocation is recorded and merely not applied yet.

      The same shape as the password-reset flake fixed earlier this session, and
      the harness already had `awaitLiveSessions` for exactly this. The test now
      waits for the revocation to project.

- [ ] **`protocolit .../DeactivateAccount` — still open, and now better
      isolated.** Checked for the same shape and it does not have it:
      `bootstrapBearer` already calls `awaitSessionProjected` before returning a
      token, so the step-up assertions are not racing the session projection.

      Nineteen clean runs this session. Its standing explanation remains the
      exhausted per-IP rate-limit buckets, and that fix has landed — as has
      `-p 1`, which removed a second confound of the same family
      (cross-package contention producing failures in unrelated assertions).
      Two removed confounds is not proof, so it stays open; but a sighting now
      would be genuinely informative rather than ambiguous.

### P3 — real features, unblocked

- [x] **Restriction (Art. 18).** Its own aggregate and stream per subject, a
      projection where a row's PRESENCE is the restriction, and a check in the
      notification dispatcher.

      It sits beside the erased check in `Dispatch` rather than in `allowed()`,
      because Security and Transactional bypass preferences deliberately — and a
      legal obligation a class can bypass is not an obligation.

      An unreadable lookup REFUSES to send. A rebuild that has not yet replayed a
      restriction leaves the table empty, so treating the failure as permission
      would resume processing for exactly the people who asked it to stop, and a
      sent notification looks like success.

      **SECURITY IS EXEMPT — reversed, one commit after shipping it the other
      way.** It first suppressed Security too, because compliance.md §6 says "no
      email, no push" without qualification. Building the RPC surfaced the
      argument that settles it, already written in this codebase for the
      identical attack on notification preferences: *"if switching off email
      could stop a security alert, an attacker who gains access to an account
      would simply switch it off and silence the very message that reveals them
      — the account-takeover tripwire disabled by the takeover itself."*

      Restriction is such a control. Restrict the victim, then operate on their
      account with no password-changed, no new-device and no
      credential-compromised mail arriving. Requiring AAL2 raises the bar and
      does not close the hole. Art. 18(2) makes the exemption lawful rather than
      convenient: restriction does not bar processing needed to protect a natural
      person's rights, and a warning to the account's own holder is exactly that.

      Narrow: only Security. Transactional, Activity and Product are all still
      stopped.

- [x] **The restriction RPCs.** `chronos.compliance.v1.ComplianceService` —
      restrict, lift, and read the state. Its own service rather than an addition
      to identity, because compliance will grow: export, rectification and the
      rest of the DSAR surface belong beside it.

      Every method names NO subject and acts on the authenticated caller. AAL2
      to change, AAL1 to read — somebody must be able to see the state of their
      own request from an ordinary session. An API key is refused: it carries a
      key's identifier rather than a person's pseudonym, and there is no
      delegation convention to make exercising a data subject's rights on their
      behalf mean anything yet.

      Its tests drive the REAL gate pipeline rather than calling the handler,
      because `interceptor.PrincipalFrom` reads a context key whose type is
      unexported precisely so no test can forge a caller. Building it that way
      immediately paid: the first run failed every mutation with step-up, which
      was the min_aal gate working.
- [x] **Rectification (Art. 16) — ALREADY SATISFIED, except for one field, and
      that field is identity's not compliance's.**

      Checked rather than assumed. compliance.md §6 asks for "a correction event,
      never a rewrite", and the event-sourced design gives that for free: every
      correction IS a new event and no projection is ever rewritten in place.
      What remained was whether a person can actually correct each field.

      - display name, locale, timezone, avatar — `UpdateProfile`, self-service ✓
      - **email address — NOT CORRECTABLE.** identity.md §12 says so in terms:
        "NOT BUILT — no RPC, no use case, no event."
      - phone — no RPC, and no flow anywhere writes it.

      So there is no `PersonalDataCorrected` event to add: inventing one for
      fields `UpdateProfile` already corrects would be a second write path to the
      same data. The gap is a missing identity FEATURE, not a missing compliance
      mechanism.

- [ ] **Email change — identity's, well specified, and the last real
      rectification gap.** identity.md §12 already states what it must do:
      verify the NEW address before switching, notify the OLD one, allow a revert
      window, and obey §4.4 in both directions — re-verification voids every
      session, and a password reset MUST void any PENDING change, or an attacker
      queues a change to their own address and the victim's recovery hands the
      account back afterwards.

      Every primitive it needs already exists: token minting and single-use
      consumption, the email reservation aggregate, the blind index, and a
      `VerifyEmail` that already voids sessions. It is a slice of its own rather
      than a step in a compliance one.
- [ ] **Export and portability (Art. 15/20)** — the same traversal as erasure,
      which is why compliance.md §5 says they are built together: a traversal
      that misses data exports incompletely AND erases incompletely, and only
      one of those is noticed. Needs the P1 traversal first.
- [ ] **The plan catalogue.** Billing's webhooks, portal and invoices are done;
      the catalogue is one hardcoded lookup and `STRIPE_TRIAL_PRICE_ID` is still
      an env var whose own comment says it disappears when the catalogue lands.
      Carries the annual-plans decision already recorded above.

### BLOCKED BY SCOPE — analysed, and deliberately not built

- [ ] **`access` grants (access.md §4).** The substrate is complete: `Check`,
      `BatchCheck`, `Write`, `Delete`, the topology, and a projector writing
      membership and team edges. What is missing is a `Grant` aggregate, grant
      RPCs and a grants projection.

      **They cannot be built yet, and the reason is not effort.** A grant is
      `Principal × Relation × ResourceRef`, and the authorization model declares
      exactly four types — `user`, `organization`, `workspace`, `team`. There is
      NOTHING TO GRANT ON. Granting a relation on a workspace is membership,
      which exists; everything else access.md §4 describes targets a resource
      inside a workspace, and feature verticals inside a workspace are
      explicitly out of scope (ADR-006, FEATURES.md).

      Building it now would produce a grant aggregate, an RPC and a projection
      wired to a resource type that does not exist — which is precisely the
      "adapters wired to nothing" failure slice 1b was reordered to avoid.

      It unblocks the moment one shareable resource type exists, and it is what
      the two deferred cascades — team deletion to grants, and the team's own
      member edges — are waiting for.

- [ ] **Legal holds (compliance.md §4 step 2).** Same shape. The erasure ignores
      holds because NOTHING CAN PLACE ONE: a hold has an owner and a recorded
      justification, both of which are operator concerns, and `operator` is a
      separate deployable (ADR-024) that does not exist. A `LegalHold` aggregate
      with no way to create a hold is a check that can only ever pass.

- [ ] **`operator` — the back-office (operator.md).** A separate binary, build
      order #10, "once there is something to operate". Large, and the gate for
      legal holds above.

## Parked

- [ ] **The two deactivation flakes — NOT reproduced, and one plausible cause
      removed.** `protocolit .../DeactivateAccount` and
      `identityit TestADeactivatedAccountCanGetBackIn`.
      Nine clean runs after the rate-limit fix: five of identityit's lifecycle
      tests, four full package runs across both suites. Neither reproduced.
      The hypothesis worth recording is that they were downstream of the
      exhausted per-IP buckets rather than of deactivation itself — the
      protocolit sighting happened during a run where those buckets were being
      spent, and a refusal there fails a later assertion for a reason that has
      nothing to do with what the test is about.
      Left OPEN rather than closed: "did not reproduce" is not "fixed", and a
      speculative change to a test that currently passes would be worse than
      waiting for a tenth sighting with better evidence. If either recurs now,
      it is a real race and the rate limits are no longer a confound.
- [x] **Timing-sensitive unit tests fail under load** — both fixed at the root,
      and neither was load sensitivity.
      `argon2id TestACancelledCallerDoesNotWaitForASlot` found a real defect: the
      hasher consulted the context only on the WAIT path, so a caller that had
      already hung up was SERVED whenever a slot was free. The test occupied the
      one slot first, but signalled before it was inside Hash — so it raced, and
      the answer depended on load. Fixed in the hasher; split into the two
      properties it was conflating.
      `identity/app TestTwoConcurrentResetsProduceExactlyOnePasswordChange`
      pinned the stored verifier to the LAST-REPORTED winner, while the stored
      value belongs to the last WRITER. Two independent orders; it passed
      whenever they agreed. Now asserts membership.
- [x] **The integration suite is not repeatably runnable in one day.** Both
      harnesses now clear the per-IP counters before starting their server, which
      is the test-suite equivalent of truncating a table. The LIMITS are
      untouched: they are security controls whose numbers cmd/api/identity.go
      argues against specific attacks, and a knob that relaxes them for tests is
      a knob that can relax them in production. Verified by four consecutive full
      protocolit runs and two of identityit, where the third used to fail.
- [ ] `account_name` deprecated field — **BLOCKED, and now probed rather than
      assumed.** Deleting field 1 was attempted with `reserved 1;` and
      `reserved "account_name";`, which is the standard protobuf path and the
      obvious thing to try. `buf breaking` still refuses:

      ```
      Previously present field "1" with name "account_name" on message
      "EnrollTotpRequest" was deleted.
      ```

      The FILE ruleset's FIELD_NO_DELETE does not admit a reserved range, and
      the baseline is the `main` branch rather than a tag — so with no release
      ever cut, every deletion is a breaking change against the previous commit.
      Relaxing the ruleset to admit it would be widening a gate to fit a change,
      which the field's own comment already refuses.

      It comes out at the first release boundary, when the baseline can move to
      a tag. Recorded here so the next person does not spend the same twenty
      minutes discovering that `reserved` is not the escape hatch it looks like.
- [x] **WebAuthn storage ADR — written as [ADR-057](DECISIONS.md).** A passkey's
      material goes in its own `passkey_credential` table rather than
      `credential.verifier`, because the three values behave differently: the
      credential ID and public key are immutable and written once, the sign count
      is mutable and written on EVERY login. Packing them into one opaque column
      makes the monotonic comparison a read-modify-write in Go instead of an
      atomic `UPDATE`.

      The credential ID is UNIQUE across every account, which is WebAuthn L3
      §7.1 step 27 and IDENTITY-REVIEW C3: an attacker who registers a victim's
      credential ID and public key as their own signs the victim into the
      ATTACKER's account. Neither value is secret, so the control is a unique
      index plus a pre-insert check.

      Settled now rather than in slice 2 because `credential`'s migration is
      already applied and migrations are append-only (ADR-011) — deciding later
      means columns added to the wrong table, and columns are far harder to
      remove than to never add.

- [x] **CONVENTIONS §5 doc/code reconciliation — the cause fixed, not the cells.**
      §5 carried a hand-written copy of the error catalogue, and four of its
      eleven rows disagreed with `internal/server/connect`:
      `PLAN_UPGRADE_REQUIRED` and `ORG_SUSPENDED` documented as
      `FailedPrecondition`, actually `PermissionDenied`; `QUOTA_EXCEEDED` as
      `FailedPrecondition`, actually `ResourceExhausted`; `CONFLICT` as
      `Aborted`, actually `AlreadyExists`.

      `docs/api/errors.md` is GENERATED from the same package and was correct all
      along, so the table was a second copy of a generated document. It is gone,
      replaced by a pointer to the generated one — patching the four cells would
      have left the mechanism that produced the drift in place.

      §5.1 also described the disclosure ladder's parent-visibility check in the
      present tense. It is NOT built: `interceptor/gates.go` returns `NOT_FOUND`
      for every authz denial and says so in a comment. The doc now says so too,
      including what it costs — a member refused something inside their own
      organization is told the same thing as a stranger, so the actionable "ask
      an admin" journey is unreachable for those cases. A product gap, not a
      security one.

      Also fixed while here: CLAUDE.md's first numbered line said "47 ADRs" and
      there are 57.

---

## Decisions already made (not open)

| | |
| --- | --- |
| Trial | Cardless, 14 days, 3 workspaces / 5 seats |
| Trial end, no card | Suspended (Stripe `paused`), never purged |
| Entry path | Cardless trial only — `provisional_owner` and `PendingActivation` deleted |
| Orgs owned per subject | 1 (organization.md §1) |
| Trial plan | A designated `trial` plan at $0; plan chosen at upgrade |
| Stripe object | Created at org creation, brief `Provisioning` state |
| Upgrade | Card attached to the EXISTING subscription, never a new one |

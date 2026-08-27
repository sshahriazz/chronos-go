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
- [x] **§9.3** — does a trial convert automatically at trial end when a card was
      added mid-trial? CONFIRMED against the real test account with a test
      clock, not inherited from the documentation. See the entry in "The
      remaining work, analysed"; the thing worth verifying turned out not to be
      the default but whether `missing_payment_method: pause` suppressed it.
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
- [x] **Legal holds — BUILT, and the erasure now defers on them.** The
      `LegalHold` aggregate, the operator RPCs that place and lift one, and
      step 2 of the erasure workflow. `NewErasure` REFUSES a nil hold checker,
      because an eraser without one destroys a key a court order says must be
      preserved — silently, since every other step succeeds.

- [x] **Retention exemptions (step 3) — BUILT.** §7's table said invoices are
      retained under Article 17(3)(b) and nothing read it. The erasure carried a
      package-level `[]string` of three English sentences, passed to the
      confirmation and to the export manifest — honest about being static, and
      static was the problem: nothing compared it to §7, nothing could enumerate
      it, and adding a data class with a statutory retention would have left the
      confirmation saying what it always said while a new category of record
      quietly survived.

      §7's whole table is now `domain.RetentionSchedule()` — six classes with a
      period, a disposition (`erased` / `pseudonymised` / `retained`), a legal
      basis and a sentence for the person. `RetentionExemptions()` is derived
      from it, so a class whose disposition changes moves between the two
      answers by editing one field.

      **The erased classes are in the table too**, which is what makes
      compliance.md §16's "invoices survive erasure; session logs do not"
      assertable — it is a statement about two rows of one table, and a list of
      exemptions alone cannot make it. Absence would also mean both "erased" and
      "nobody thought about it", which is the ambiguity `cat.Silent` exists to
      remove.

      `app.Exemptions` resolves the set PER SUBJECT: unconditional classes (the
      event log, the operator audit trail) apply to everybody, and conditional
      ones (invoices, breach records) are asked of the module that holds the
      records. `NewErasure` and both export constructors REFUSE a nil resolver,
      and `Execute` refuses an EMPTY set before the destroy — two exemptions are
      unconditional, so empty means a broken resolver rather than a subject with
      little data, and the confirmation it would produce says everything is gone.

      **The failure direction is inverted on purpose.** An unanswerable question
      STATES the class. Implying total deletion when tax records survive is the
      misleading statement §7 names; telling somebody their invoices may be
      retained when they have none is a smaller wrong.

      **`AssumeRecordsExist` is the honest placeholder**, wired at both
      composition roots rather than defaulted inside the resolver. Nothing can
      yet ask billing whether a subject appears on an invoice — `invoice_view` is
      keyed by organization — so the conditional classes are stated for
      everybody. Replacing it is one line in `cmd/api/deps.go` and one in
      `cmd/worker/erasure.go`.

      The confirmation and the manifest now carry the class, the period and the
      ARTICLE as separate fields rather than as prose, so the mail templates
      render a legal basis as a legal basis and a translator can produce the
      "why" in their own language. The manifest's `retained` changed shape, so
      `ExportFormatVersion` is **2**.
- [ ] **The subject graph is not traversed** (step 4). Only identity holds
      personal data today, so erasing it is erasing everything — but that stops
      being true the moment a second module does, and the traversal is what
      makes the guarantee hold then.
- [x] **The reconciliation sweep.** The workflow is durable, so a lost one is
      unlikely rather than impossible; a sweep over overdue requests is the
      backstop billing.md §5 case 15 uses for the same class of failure.
- [x] **The remaining DSAR rights — BOTH BUILT.** Compliance §3 lists six.
      Erasure is built; RESTRICTION is built (`RestrictProcessing`, `Lift`,
      `Get`); ACCESS and PORTABILITY are both served by the asynchronous export.
      The two that were genuinely unbuilt — **rectification (Article 16)** and
      **objection (Article 21)** — now are. See the two entries below.

- [x] **Rectification (Art. 16) — BUILT, and this REVISES the entry further down
      that closed it as "already satisfied".**

      That entry was right about the mechanism and wrong about the record. Its
      reasoning was: `UpdateProfile` already corrects display name, locale and
      timezone, so a `PersonalDataCorrected` event would be "a second write path
      to the same data". The first half holds. The second does not, because the
      event was never going to be the write.

      `RectifyMyData` records that a RIGHT was exercised and executes the
      correction **through profile's own use case**, reached by a port
      (`app.PersonalDataCorrections`) that `cmd/api` satisfies with the same
      `*profileapp.Updates` instance the settings screen uses. One writer to the
      vault, one `profile.ProfileUpdated.v1`, one projection — the thing the
      earlier entry was protecting.

      **What it adds is the distinction the earlier entry collapsed.** "Somebody
      edited their profile" and "a data subject asserted that what we hold about
      them is inaccurate and required its correction" are different legal facts
      with different obligations: Article 12(3)'s one-month clock, and Article
      19's duty to pass the correction to whoever the data was disclosed to. A
      controller asked to evidence its Article 16 handling cannot answer with a
      list of settings saves, and could not tell one from the other.

      **The email address is still not correctable here, and that is now a named
      refusal rather than a silence.** `domain.ErrEmailNotRectifiable` carries
      its reason: identity.md §12 owns the change, with a token to the new
      address, a revert token to the old one, and a window — all three because a
      login identifier is also the account-recovery route. A rectification field
      for `email` would move it on one authenticated call with none of that
      proof, turning a statutory right into a bypass of an authentication
      control. Article 16 does not require the correction to be unverified; it
      requires it to be possible, and `ChangeEmail` makes it possible. A field
      absent from a schema is a decision nobody can see, so the refusal names
      itself and is asserted against.

      **Phone is deliberately out of scope.** No flow anywhere writes
      `pii.FieldPhone`, so there is nothing inaccurate to correct — and adding a
      write path would make compliance the only writer of a security-relevant
      identifier that identity should own.

      The event carries FIELD NAMES and never values (ADR-002), and the response
      does the same: echoing a corrected name would put personal data into proxy
      logs and support screenshots for no gain. It is `cat.Silent`, because
      `ProfileUpdated` is already a Security-class alert naming the fields that
      changed — two mails minutes apart from two modules is two messages for one
      event.

- [x] **Objection (Art. 21) — BUILT, scoped NARROWLY, with the scope written
      down.**

      The obvious risk was building a second `RestrictProcessing` under another
      name. It is not one, and the difference is observable rather than
      doctrinal: a RESTRICTION is total and temporary — everything but storage
      halts, transactional receipts included, while a dispute about the data runs
      — and an OBJECTION is per-purpose and open-ended, so the account works
      normally and one purpose stops until its author withdraws it. A subject can
      hold both, and lifting the restriction must not release the objection.
      `TestAnObjectionDoesNotStopTransactionalMail` is that difference as an
      assertion; if it ever passes trivially, one right has absorbed the other
      and the narrower one should be deleted rather than kept as a synonym.

      **The purpose set contains only what the system can actually STOP.**
      Article 21 reaches processing grounded in Article 6(1)(e)/(f), which here
      is `activity_notifications` and `product_updates` — the two notification
      classes that rest on legitimate interests. Security and transactional mail
      rest on contract and on our own legal obligations, so the right does not
      reach them; the aggregate REFUSES an unknown purpose, because an objection
      nothing consults is a promise, and the person is told the processing
      stopped while the mail keeps arriving.

      `product_updates` is opt-in already (NOTIFICATIONS §3), so objecting
      overlaps with not consenting. It is offered anyway for the one difference
      that matters: consent withheld may be solicited again, and an objection may
      not be.

      **It is not a preference either.** A preference is per channel and ours to
      re-solicit; an objection is a legal instruction about a PURPOSE, stops it
      on every channel, and only its author may clear it. Enforced in the
      dispatcher beside the Article 18 check and above the channel loop, which is
      what makes the second property structural. It is consulted ONLY for the two
      objectionable classes, so the extra lookup costs nothing on the majority of
      sends.

      **Article 21(1)'s controller override is NOT implemented, deliberately.**
      Continuing on "compelling legitimate grounds" needs a documented balancing
      test performed by a person, with the burden on the controller. Until an
      operator workflow records one, an objection is honoured unconditionally —
      the safe direction, and the correct behaviour absent the assessment the
      exception requires. The event carries no `reason` field for ADR-002's usual
      reason, and that is only tenable while there is no override to weigh it
      against.

      Migration **00045** adds `processing_objection_view`, keyed
      `(subject_id, purpose)` so withdrawing one purpose cannot release the rest.
      No CHECK constraint on `purpose`: a projector replays the log, and a
      constraint narrower than the log turns a retired purpose into an
      unreplayable projection. `Objection.Apply` applies a purpose the WRITE
      would refuse, for the same reason — dropping it on replay would resume
      processing somebody stopped, silently, and only for the people who objected
      earliest.

      Both new ports are asserted at the composition root
      (`TestBothDataSubjectRightsAreWiredIntoTheSendingPath`): a nil port here is
      permissive and therefore invisible, which is the shape that shipped three
      dead notification channels.

- [x] **Article 12(4): a deferred erasure now SAYS it was deferred.** Legal holds made deferral reachable for the first
      time. `Execute` now returns `ErrHeld` and the workflow waits, and nobody
      tells the requester anything.

      12(4) requires a controller that does not act on a request to say so, and
      on what ground, within a month. The ground exists — 17(3)(e), processing
      necessary for legal claims — and the answer is a RESPONSE TO THEIR
      REQUEST rather than a broadcast about our decision, which is exactly what
      keeps it from being tipping off.

      Built as `ErasureDeferred` / `ErasureResumed` on a per-subject `Deferral`
      aggregate, with `compliance.erasure_deferred` as the mail.

      **The template names the GROUND and never the matter.** Article 17(3)(e)
      is a legal basis, is the same sentence for everybody, and is what 12(4)
      asks for. The matter would tell somebody they are under investigation —
      it stays on the hold's own event and in `operator_audit_log`, under access
      controls. A struct-shape test fails on a `matter`-like field existing at
      all on either deferral event, rather than on a value, because a value test
      passes on the day the field is added and left empty.

      **It also closed a retry storm I had warned about and not prevented.**
      `ErrHeld`'s own comment said a hold retried on a backoff "would hammer the
      store for however long a matter runs" — and the workflow's retry policy
      has NO attempt limit and a one-minute ceiling, so that is exactly what it
      did. A hold is now a non-retryable `errTypeDeferred` and the WORKFLOW
      waits, hourly, on a cadence chosen for how often the answer changes rather
      than for how quickly a transient error clears.

      Two workflow tests assert against all three wrong answers: failing the run
      ends a live request; retrying is a query per minute for a month; and
      completing as `erased` is the worst, because it reports success while the
      data is still there and nothing looks again.

      **The deferral is an aggregate rather than workflow state**, so one person
      gets one answer even if the workflow is restarted from scratch — and
      because 12(4) compliance is something we may have to evidence, which a
      variable inside a workflow's history is a poor place to keep.

## Session findings and follow-ups

- [x] **Session revocation is immediate now, and ADR-018's promise is kept.**
      The gap: `GetSessionByToken` refuses a row whose `session_view.revoked_at`
      is set, and the PROJECTOR writes that column. So a revocation was durable
      in the log and not yet in effect — milliseconds while the projector is
      healthy, unbounded while it is stopped, being rebuilt, or wedged on an
      unrelated event, and silent in every case, because a request served by a
      revoked session is indistinguishable from one served by a live session.

      That is a fail-OPEN under component failure. ADR-010 permits exactly one
      deliberate fail-open in this system and it is OpenFGA's inverse.

      The fix is the shape API keys already use and migration 00051 argues in
      full: revocation destroys the SECRET half in the same request that appends
      the event. `session_token` is authoritative rather than projected
      (migration 00010) — a token may never enter an event (ADR-002), so no
      replay can restore it — which is why a handler deleting from it is not a
      handler writing a read model, and ADR-019 is untouched. The event still
      appends and the projector still sets `revoked_at`; neither half is
      sufficient alone.

      NOT the Valkey denylist ADR-018 names for emergencies. Everything in
      Valkey carries a TTL and `FLUSHALL` must be survivable, so a denylist that
      was the only record of a revocation resurrects every revoked session on a
      flush — the failure ADR-045 forbids for access tombstones, somewhere it
      matters more.

      Every revocation path is covered, because all of them route through
      `RevokeSession` or `RevokeAllSessions`: the sessions screen, sign-out
      everywhere, password reset, both email-change paths, registration's
      address verification, and deactivation. Erasure was already structural —
      the session projection deletes digests by subject on `UserErased`.

      Ordering is append-then-destroy, matching RevokeAPIKey: destroying first
      would sign somebody out with nothing in the log saying why if the append
      then failed. A destroy that fails is REPORTED rather than swallowed, for
      the reason the whole change exists.

      Asserted at both levels, and both mutation-checked. Six use-case tests
      cover the ordering, the set (the spared session keeps its digest), and the
      loud failure; two integration tests drive the running server and assert
      the projector-INDEPENDENT fact — that the `session_token` row is gone —
      because a 401 alone is satisfied by a fast projector.

      It also removed the 20-second poll this session had added to
      `TestTheIdempotencyContractHoldsForEveryAuthenticatedMutation`. That
      tolerance existed only because of this gap; the test asserts the refusal
      on the very next request again, and means it.

- [x] **Three integration tests were races against the projector, and adding two
      projections exposed all three.** Wiring the shared registry into the
      protocol harness added billing's invoice mirror and identity's API key
      projection to a suite that had run neither. Nothing about the machine
      changed and three tests began failing intermittently — which is the useful
      version of this discovery, because each was asserting a timing property
      the design never offered.

      `awaitExport` and `awaitExportWithin` both fatalled on the FIRST
      `NOT_FOUND` from `GetDataExport`. The id came from `ExportMyData` a moment
      earlier, so the export exists in the log by definition and the row is
      written by a projection: NOT_FOUND is what the poll is supposed to see
      until it catches up. Both loops were byte-identical, so the fix was to
      delete one — `awaitExport` now calls `awaitExportWithin` with a shorter
      deadline, and there is one place that decides what NOT_FOUND means.

      `TestTheIdempotencyContractHoldsForEveryAuthenticatedMutation` asserted
      that a replay of `DeactivateAccount` is refused by the gate on the very
      next request. It is not, and cannot be: deactivation ends its sessions by
      appending `SessionRevoked` to each session's stream, and the authenticator
      joins `session_view`, which the PROJECTOR writes. That is deliberate —
      `identity/app/ports.go` says on `LiveSessions` that a port able to write
      the view could end a session with no event saying so, and the view would
      stop being reconstructable from the log (ADR-019).

      So the replay is now polled for up to 20 seconds. The property is
      unchanged and is the one that matters — a caller who may no longer make
      the request may not read the stored answer to it either, so the gate must
      answer before `Idempotency.Do` — and what is bounded is only how long the
      revocation may take to become visible.

      This is the entry the two earlier "deactivation flakes" were circling. One
      of them "survived seventy-two clean observations with three hypotheses
      eliminated"; the mechanism was a projection-lag window that the harness of
      the day was too idle to open.

- [x] **`AssumeRecordsExist` replaced for the class that could be answered.**
      Billing now answers "does this subject appear on a retained invoice" —
      `SubjectHasRetainedInvoices` joins `invoice_view` to `org_member_index`,
      in a system transaction because an erasure spans every organization the
      person belongs to and has no tenant scope of its own. The answer that
      crosses the boundary is a single boolean, so nothing about any tenant is
      returned.

      Membership rather than ownership, deliberately: ownership can move, and a
      former owner whose name is on a two-year-old invoice would otherwise be
      told everything about them was destroyed. It over-states in the direction
      §7 calls the smaller wrong.

      What it buys: every trial account that never converted — which is most of
      them — no longer gets a confirmation saying invoice data may be kept about
      them for seven to ten years.

      `RecordsByClass` routes each conditional class to whoever can answer it and
      states the rest. The breach register is still stated for everybody, because
      it does not exist; `Unanswered()` names exactly which classes are in that
      state, and `TestEveryConditionalClassIsEitherAnsweredOrNamed` fails when a
      third one joins them silently.

- [x] **`app.Exports` — the dead SYNCHRONOUS export — REMOVED, surgically.**
      `Bundle`, `RetainedRecord`, `ExportedObject`, `SubjectProfile`,
      `ExportStore` and `DefaultExportExpiry` all survive; the async path uses
      every one.

      Its tests were the real find. `export_test.go` asserted the bundle's
      contents, the retained-records statement and the erased-class omission —
      all against the implementation that shipped in no binary, while the one
      people actually receive their personal data from was covered by none of
      them. They now drive `ExportRuns` through the same harness the rest of
      exportrun_test.go uses, so they assert the bytes the object store is
      handed. Verified by mutation: dropping a profile field fails the test.

- [x] **`docs/domains/compliance.md` §12/§13/§14 reconciled with the code.**
      §12 listed nineteen events; twelve exist, and five of the listed names
      never will in that form — erasure's completion is `identity.UserErased`,
      because the act that satisfies Article 17 is destroying the key and the key
      is identity's. §13 listed six projections; three exist, and two of the
      absent three are absent by design (the retention schedule is a compiled
      table on purpose; a legal hold is asked about one subject at a time). §14
      named five workflows under names none of them have.

      Each section now separates built from not-built rather than describing an
      aspiration in the present tense.

---

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

- [x] **The reconciliation sweep — BUILT.** The erasure workflow is durable, so
      a lost one is unlikely rather than impossible; the sweep is the backstop
      billing.md §5 case 15 uses for the same class of failure. Duplicated the
      entry below for a while, which is how a worklist starts lying.

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

- [x] **`protocolit .../DeactivateAccount` — CLOSED as not reproducible, with the
      evidence and the next diagnosis written down.**

      Seventy-two clean observations: twenty-nine recorded earlier, then forty
      runs of the subtest IN ONE PROCESS plus three full-package runs. The
      in-process axis was impossible until `-count=N` was fixed this session —
      three packages panicked on a second run — so this is the first time the
      cheap axis was available at all.

      **Three hypotheses eliminated, by reading and measuring rather than by
      running it again:**

      1. *The sibling's race shape.* `identityit`'s version asserted a
         revocation immediately after the call returned, racing the session
         projection. This one does not have it: `disposableAccount` leaves TWO
         live sessions and waits for both with `awaitSessionProjected`.

      2. *The work list depending on the token row.* `ListLiveSessionIDs` reads
         `session_view` alone — no join to `session_token` — and its own comment
         says why. A swept token cannot make a session invisible to revocation.

      3. *The movable clock outrunning the session.* The absolute window is
         thirty days (`DefaultAbsoluteWindow`); the suite's one large jump is
         past the IDLE deadline, about fourteen days, and every other advance is
         a TOTP step of ~30s. Reaching thirty days would need some 46,000 of
         them.

      **What is left, and why closing beats leaving it open.** No mechanism is
      identified, and "did not reproduce" is not "fixed". But an open item with
      no action attached is not a plan — and the one action that WAS available
      has been taken: the assertion is split, so a sighting now says which half
      broke. `scanned` is the work list, read from `session_view`, so a zero
      there is the projection or the clock; `revoked` is what the session
      aggregates accepted, so a zero there with a non-empty list is the domain
      refusing. Observed value is `scanned 2 and revoked 2`.

      Reopen on a sighting. It will arrive with a number attached.

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

      **SUPERSEDED — see "Rectification (Art. 16) — BUILT" above.** The
      conclusion was half right and is left here rather than deleted, because the
      half that was wrong is worth keeping visible. "A second write path" assumed
      the event would BE the write. It is not: `RectifyMyData` executes the
      correction through profile's own use case and records only that a statutory
      right was exercised — which is a different fact from a settings save, with
      Article 12(3) and Article 19 attached to it, and which nothing in this
      system could distinguish while the entry stood.

- [x] **Email change — BUILT.** See "Done — email change" below.
- [x] **Export and portability (Art. 15/20).** `ExportMyData` produces a JSON
      bundle of every vault field, writes it to SeaweedFS and returns an
      expiring signed link.

      The bundle is written under the SUBJECT'S OWN object prefix — the same
      namespace the erasure empties — so compliance.md §4 step 9's "purge
      exported bundles on erasure" is a property of where the bundle lives
      rather than a step somebody has to remember. That is the payoff of P1's
      traversal, and it is asserted by a test.

      It carries a statement of what is RETAINED, because Article 15(1) asks
      about the processing rather than only the values: a file listing a name and
      an address while saying nothing about invoices held under a statutory
      obligation is accurate and misleading.

      It carries NO event log, no password hash, no TOTP secret and no session
      digests. The first names pseudonyms and positions meaningless outside this
      deployment; the rest are derived from credentials rather than data about
      the person, and exporting them turns a privacy right into an offline attack
      surface.

      `OPERATION_CLASS_EXPORT`, which gate 4 never blocks: withholding a person's
      own data from a suspended tenant is a portability violation, not leverage.

      **Not yet resumable.** compliance.md §5 asks for long-running and resumable
      with progress visible in the workflow. It is synchronous today because the
      bundle is one vault read and one small object; it needs the workflow
      treatment when a subject's data spans modules that do not exist yet.
- [x] **The plan catalogue.** `billing/domain.Published()` is the catalogue;
      `cmd/worker` mirrors it into Stripe at startup and provisioning asks it for
      the trial price and trial length. `STRIPE_TRIAL_PRICE_ID` and
      `STRIPE_TRIAL_DAYS` are gone. Annual ships from day one, so `Interval` is a
      dimension of `PlanVersion` rather than a field added later.

      Three findings from the live API, none reachable from a unit test:
      idempotency is by `lookup_key` and NOT by searching metadata (a Price was
      still unfindable by search sixty seconds after creation); `lookup_key`
      uniqueness spans ARCHIVED Prices, so a republished version needs
      `transfer_lookup_key` — taken only after proving no active Price holds the
      key, so a race cannot steal it; and the Stripe Product id is derived from
      the plan, which is why `PlanID` is constrained to Stripe's id charset.

      Mutating the entitlement bridge found a real bug: it kept the FIRST monthly
      version per plan and `All()` is sorted by id, so a v2 would never have
      reached entitlement. It asks for the latest by name now.

      **Not built: the operator's editing half.** billing.md §2 describes an
      operator publishing a catalogue with a two-phase flow and a mirror reactor.
      That needs `operator`, which is a separate deployable that does not exist.
      When it arrives this becomes its seed rather than its replacement.

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

- [x] **Legal holds — UNBLOCKED and built.** This entry was right about why it
      was blocked: a hold has an owner and a recorded justification, both
      operator concerns, and "a `LegalHold` aggregate with no way to create a
      hold is a check that can only ever pass" is exactly the vacuous shape it
      would have had. Operator slice 2 supplied the missing half.

- [x] **`operator` — the back-office (operator.md). SLICE 1 SHIPPED.** The
      binary, its identity, its audit, the customer directory, and the four
      structural separations — see "Done — `operator`, slice 1: the plane"
      above. Slice 2 (break-glass, view-as, writes) is what still gates legal
      holds.

## Done — `operator`, slice 2: elevation, and the writes that were buildable

Slice 1 made the plane exist and proved it end to end. It is a VIEWER: every
method is a read, and operator.md §7's table of eight writes is entirely
unbuilt. This is that table, plus the two controls that have to stand in front
of it.

The order is by dependency, not by size. Elevation first because it is what a
dangerous action is supposed to require; account management second because it
retires a CLI-only path; the tenant-affecting write third because it establishes
the cross-plane pattern every remaining write copies; legal holds fourth because
they have been waiting for exactly that pattern.

- [x] **A · Break-glass elevation** (§5). Time-boxed, justified, auto-expiring,
      and it raises an alert AT THE TIME OF USE rather than in a report somebody
      reads next quarter. Two decisions the spec leaves open and this slice has
      to settle: WHICH capabilities a role may elevate to, and what "alert a
      second person" means on a plane that deliberately holds no operator
      addresses.
- [x] **B · Operator account management** (§7, `operator_admin`). The aggregate
      already exists and only the RPCs are missing, so this is small — and it
      retires `provisionoperator` for every operator except the first, which no
      RPC can ever create.
- [x] **C · Suspend and reinstate an organization** (§7, `operator_admin`;
      organization.md §5). The first write that touches a TENANT aggregate, and
      therefore the one that establishes the pattern: operator writes go through
      the same domain commands as everything else, because a privileged
      back-channel that skips domain rules is what corrupts state that then
      cannot be replayed.
- [x] **D · Legal holds** (compliance.md §4 steps 2–3). Unblocked by C. A hold
      has an owner and a recorded justification, and both now have somewhere to
      come from.
- [ ] **E · The billing writes** (§7) — **BLOCKED BY SCOPE, and my own estimate
      of it was wrong.** This entry said they were "mechanical once C exists".
      They are not, and the check that proved it took a minute:

      | §7 row | What it would write through | What exists |
      | --- | --- | --- |
      | Issue refund | a refund model | billing has ONE event, `InvoiceRecorded` |
      | Create / revoke coupon | a `Coupon` aggregate | nothing, anywhere — billing.md §6 is unbuilt |
      | Grant entitlement override | an override aggregate | entitlement has a catalogue and **no events at all** |
      | Extend a trial | a command moving `TrialEndsAt` | the org aggregate has `StartTrial` and no way to move the deadline |
      | Resolve a dispute flag | a dispute model | no dispute exists in any module |
      | Publish / archive plan version | a catalogue aggregate | the catalogue is `domain.Published()`, COMPILED INTO THE BINARY — publishing a version is a deploy |
      | Migrate subscribers | all of the above | — |

      Every one needs a TENANT-SIDE domain that does not exist. Building them in
      the operator plane would mean inventing billing's domain inside the back
      office, which is precisely the "privileged back-channel that skips domain
      rules" §7 forbids — and slice 2's whole point was demonstrating the
      opposite.

      So this is the same finding as `access` grants, reached the same way:
      blocked by scope rather than by effort, and worth stating rather than
      producing something that looks like the feature. **The unblocking work is
      billing's and entitlement's, not the operator plane's** — coupons
      (billing.md §6), an override model, and a catalogue that is data rather
      than a compiled function. Each becomes an operator RPC in an afternoon
      once it exists, following C's pattern exactly.

- [ ] **F · View-as** (§6) — **deferred, and honestly it is nearly a rename
      today.** §6 permits rendering "a tenant's view FROM OPERATOR
      PROJECTIONS", and the operator plane has one customer-facing projection:
      `operator_customer_list`. So a view-as built now would show what
      `GetCustomer` already shows, wrapped in an impersonation session and two
      extra events.

      That is not nothing — `OperatorImpersonationStarted` and `…Ended` bound a
      window the tenant can be shown, which is §6's real requirement — but it
      is machinery around a view with nothing extra in it. It becomes worth
      building when there is more to render, which is the same condition E is
      waiting on.

---

## Done — `operator`, slice 1: the plane

The gate that held this closed is open (see the identity section below), so this
is the next slice. It is the most dangerous domain in the system — the only one
that deliberately breaks tenant isolation — so the slice is scoped around the
structural guarantees rather than around the features.

**Where it lives.** `internal/operator/**`, NOT `internal/modules/operator`. The
depguard rule `api-excludes-operator` already denies
`github.com/chronos/chronos-go/internal/operator` to `cmd/api`, `internal/server`
and every module, and it has been sitting there since ADR-024 waiting for a
package to deny. Putting the code anywhere else silently opts out of the one
rule that makes the separation real.

**Its own enforcement plane.** Operator methods do NOT carry
`chronos.options.v1.authz`. That option names an OpenFGA relation on a tenant
resource, and an operator is authorized by role and explicit scope instead —
there is no tenant to resolve, no org context, no entitlement. So the operator
proto declares its own method options and `cmd/operator` loads them with its own
policy loader, refusing to serve an unannotated method exactly as the tenant
plane does. Reusing the tenant option would not be reuse; it would be an
operator endpoint whose declared permission is a lie.

- [x] **Sign-in — SSO then WebAuthn, in that order** (§3). Both halves exist as
      adapters already. The OIDC ceremony resolves the operator against
      `operator_account` and issues a session that can call NOTHING except the
      WebAuthn pair; the assertion, with user verification REQUIRED, is what
      makes the session usable. An unknown or disabled operator is refused at
      the first step, so a valid Workspace login is not itself access.
- [x] **Audit on READ** (§5). Every RPC, reads included, appends an audit event
      before it answers. The conformance test enumerates the service descriptor
      and fails on a method with no audit — a new endpoint without one cannot
      merge.
- [x] **`operator_customer_list`** (§9). Org, status, plan, counts, last active.
      Built from organization and billing events, with a REDUCED field set:
      minimisation is structural, so the schema test asserts the projection has
      no content column and no personal-data column, and a later migration that
      adds one fails the suite.
- [x] **`RevealPersonalData`** (§4, §5). The only path to a vault field, one
      subject at a time, justification mandatory and recorded. Never joined into
      a list.
- [x] **The `chronos_operator` DB role** (§4, §11). Grants name operator tables
      only. Asserted against a real database: the role's SELECT on a tenant
      content table must be REFUSED, not merely unused.

**Deferred to slice 2, named so they are not forgotten:** break-glass elevation
(§5), impersonation/view-as (§6), and every operator WRITE (§7) — refunds,
suspension, plan publication, coupons, overrides. Slice 2 is also what unblocks
legal holds.

### Verified end to end, against real everything

Not "the RPCs return plausible errors". A real Google account, a real
authenticator, real infrastructure, and the audit trail read back out of
Postgres afterwards:

    signed_in            —                                —              ::1
    viewed_customer      ListCustomers                    —              ::1
    viewed_customer      GetCustomer     org_01M0YD4FKM…  —              ::1
    viewed_personal_data RevealPersonal… org_01M0YD4EN3…  subj_01M0Y79T… email
                                                          "to check something"
    signed_out           —                                —              ::1

Three things in that trail are the design rather than the output:

  - `ListCustomers` names NO org, and `GetCustomer` names one. A page is an
    aggregate over many tenants and naming one of them would be false.
  - The personal-data row carries the target, the field list and the
    justification verbatim — and the database's own CHECK constraint would have
    refused it without them.
  - Every row has an origin, which is what evidences the IP restriction held.

The sign-in was a first sign-in, so it enrolled an authenticator through the
bootstrap window; the next one required it.

Two tools came out of doing this. `internal/tools/operatorlab` is the browser
harness — two of the three things this plane does can only be exercised by a
browser, so without a page there is no way to prove the sign-in works.
`internal/tools/oidcsubject` closes a bootstrap gap the design creates on
purpose: provisioning matches on the IdP's immutable subject, the plane refuses
to tell you yours, and on a laptop there was nowhere else to read it from.

### What the build found that the design did not predict

1. **The tenant plane's `ALTER DEFAULT PRIVILEGES` would have handed
   chronos_app the entire operator plane.** `infra/postgres/init/02-app-role.sql`
   grants chronos_app every FUTURE table, which is right for ninety tenant
   tables and exactly wrong for six operator ones — including the audit log that
   records what operators did. Migration 00037 revokes all six explicitly, and
   `TestTheTenantRoleCannotReachOperatorTables` is the half of the boundary that
   is easy to omit. Both directions verified against the running database.

2. **The minimisation test passed while inspecting nothing.**
   `information_schema.columns` is filtered by PRIVILEGE: it shows a role only
   the columns of tables that role can touch. Run as chronos_app — the obvious
   choice — it returned ZERO columns for every operator table, found no
   forbidden column among them, and reported PASS. The `len(columns) == 0`
   guard is what turned that into a failure, and it is exactly the shape
   WORKFLOW.md's rule names: ask what the test would do if the feature were
   deleted.

3. **The customer directory's member count would have been permanently zero.**
   Membership events live on `membership-`, not on `workspace-` — a membership
   is its own aggregate so that adding a person does not contend with every
   other change to the workspace. A filter of organization and workspace alone
   compiles, runs, and produces a directory that reads as "this customer has
   nobody" rather than as a bug.

4. **The policy loader caught its own first omission before any code ran.**
   `BeginWebAuthn` declared `sso_only` and no audit action, which the loader
   refused. The fix was not to annotate it but to decide the rule: the sign-in
   ceremony's own steps read no tenant data, so they are exempt — and the
   exemption is closed from the other side by
   `TestOnlyTheWebAuthnPairIsReachableWithAPendingSession`, which enumerates the
   `sso_only` methods against a literal pair.

5. **A completeness guard had to be split rather than skipped.**
   cmd/worker's `TestEveryEventHasANotificationDecision` walks `internal/` and
   fails on any event with no decision — so eight operator events failed it.
   Registering them in cmd/worker would have linked the operator schema into a
   binary with no business holding it. The universe now skips
   `internal/operator`, and `TestEveryOperatorEventIsRegistered` plus
   `TestOperatorEventsNotifyNobody` apply the same two rules to the same events
   against the codec that actually reads them. The skip names the test and the
   test names the skip, because a skip in a completeness guard is otherwise how
   a gap gets in.

6. **The customer directory's counts did not survive a replay**, and the test
   that found it was written for a different reason. An empty directory and a
   broken one look identical, so the test appends real events and watches the
   row appear — and it read back `workspace_count = 3, member_count = 3` for one
   workspace and one member. `count = count + 1` applies twice on every replay,
   and every other field was correct, which is how the bug survives review: the
   numbers are merely too big.

   The same run exposed a second thing that took a moment to recognise as
   ordinary rather than as test pollution — the LIVE plane was applying those
   events to that table too. Two projectors over one table both bumped, which is
   what any rolling deploy does. Counting a keyed set instead makes them
   converge.

7. **The network restriction refused every IPv6 caller**, found by starting the
   binary and calling it. The guard resolved the caller through
   `clientip.Scope`, which is a rate-limit BUCKET KEY — and for IPv6 that key is
   a `/64` PREFIX. Every unit test in the guard would have passed, because the
   bug is in what a neighbouring package returns rather than in what this one
   does with it. `clientip.Resolver` gained `Address`, which answers the
   different question under the same hop policy.

8. **protovalidate was never wired into `cmd/operator`.** Every bound in
   `operator.proto` was a comment: `reason`'s `min_len` of 8 documented a
   justification requirement while accepting `"x"`. Caught by asking what the
   binary actually applies rather than what it imports, which is the same
   question that found three dead notification adapters.

9. **`SELECT current_user` tripped the SQL-in-Go ban, and the ban was right.**
   The role assertion belongs in `internal/adapter/postgres`, beside
   `VerifyNotPrivileged`, which is the same check pointed at the opposite
   failure. The carve-out exists for statements about the CONNECTION rather than
   about data; writing a second one in `cmd/operator` would have started the
   drift the ban prevents.

---

## Done — service accounts and API keys (identity.md §10)

Machine credentials. Four events, two aggregates, two migrations, an
authenticator, a gate rule and six RPCs. The design decisions worth carrying
forward, each with the alternative it was chosen over:

- **A service account is a distinct PRINCIPAL KIND, not a flag on an account.**
  `ids.ServiceAccount` (`svc_…`), its own aggregate, its own table. The operator
  plane refused the same shape for the same reason and said it more sharply
  (operator.md §3): a boolean that grants something is exactly the field an
  injection bug sets. It carries no `SubjectID` pseudonym and needs none — a
  pseudonym stands in for personal data the vault holds, and a service account
  has nothing to shred.

- **A key's OWNER is a tagged pair, never a nullable column.**
  `(owner_kind, owner_id)`, both NOT NULL, with a CHECK that the id's prefix
  matches the kind. Two nullable columns admit "both set" and "neither set", and
  both readings then live in every reader rather than in the schema. The prefix
  check is a second, independent control: a flipped kind alone does not survive
  the write, and does not survive the READ either
  (`interceptor.ownerPrincipalKind`).

- **Rotation is an overlap with a RECORDED DEADLINE.** `retires_at` is stamped on
  the superseded secret at the instant of the rotation, so the old secret dies
  whether or not any sweep has run — the sweep only reclaims the row. Default 24
  hours (one deploy cycle), capped at seven days, and `immediate` collapses it to
  nothing for a leak response. The two failures this is between are both real:
  no overlap makes rotation an outage that has to be scheduled, so it never
  happens; an unbounded one means the leaked secret a rotation was performed to
  remove is still live.

- **Revocation is both halves, in one request.** The command DELETES every secret
  row and appends `ApiKeyRevoked`; the projection marks the row. Neither alone
  closes the window — the event waits for the projector, and the delete leaves
  nothing in the log saying why the key stopped working. This is the shape
  operator offboarding settled on (`internal/operator/app/operators.go`,
  `Disable`), append first so a failure never cuts off an integration with
  nothing recorded.

- **A key-authenticated request is AAL1, permanently.** A machine cannot present
  a second factor, and no step-up ceremony exists that a program could perform.
  All four key-management mutations declare `min_aal = ASSURANCE_LEVEL_2`, so a
  key can never mint a second key or revoke the first to cover a track. The gate
  additionally refuses a machine credential on every SELF-SCOPED method: those
  are a person's own account screens, and a key acting on one would be acting on
  the account of whoever owns it.

- **Scopes are enforced, and the requirement is DERIVED.** `<resource type>:read`
  or `:write`, compared against `<policy.ResourceType>:<read|write>` taken from
  the RPC's own `(chronos.options.v1.authz)` declaration. Nothing to annotate
  separately, so a new RPC cannot arrive with a forgotten scope rule — and gate 2
  then asks OpenFGA about the key's OWNER, which is access.md §4's intersection
  with the two halves enforced by different code at different points.

**Five things the build decided that the design did not say:**

1. **The authenticator resolves a key from `api_key_secret` ALONE**, and this is
   a deliberate divergence from the session pair. `GetSessionByToken` INNER JOINs
   `session_view`, so a projection rebuild signs every human out — they sign in
   again. The same behaviour for machines is an outage with no human in the loop,
   triggered by routine maintenance on an unrelated projection. So the owner, the
   organization and the scopes are written onto the secret row by the command
   handler. They cannot drift, because nothing edits any of them: changing a
   key's owner, scopes or organization means a new key.

2. **`api_key_secret` carries no row-level security, and that had to be decided
   rather than inherited.** The authenticator runs before gate 1, so a policy on
   `app.org_id` would make every key in the system fail to resolve. Its safety is
   that its only key is a 256-bit digest. `api_key_view` and
   `service_account_view` DO carry RLS, so the adapter holds both kinds of
   transaction — the only one in identity that does.

3. **`ids.PatternFor` and the API key token collided in `checkopenapi`.** The
   gate recognises a published identifier as "an anchored pattern whose first
   token is a lower-case word followed by `_`", and the token's `^chr_…` matched.
   It demanded a `chr` Kind in `internal/platform/ids`, which would have been a
   lie — a credential is not a prefixed ULID and nothing parses one. The gate now
   also requires the pattern to be ONE segment (no `_` outside a character
   class), which is what its own comment already claimed it detected. The
   identifier rule is unchanged; both drift cases that motivated it are still
   caught.

4. **`notify` has an `AudienceActor` and it is the right audience here, not a
   fallback.** These events are about a key and a machine principal, neither of
   which is a data subject — `AudienceSubject` would resolve to nobody and the
   reactor would PARK the message, which is a security alert silently not
   delivered. The actor is the admin whose authority minted the credential, and
   they are the one person who can say "I did not do that". `ServiceAccountCreated`
   is silent, because a service account holds no credential until a key exists
   and the key is what notifies.

5. **Gate 1 had to learn about a bound organization**, and a service account is
   not a member of one. A key names its organization immutably, so the resolver
   ENFORCES rather than resolves: a header naming a different organization is
   refused (as NOT_FOUND, so it is not a probe for which org a key belongs to).
   `org_member_index` records people, so `RoleIn` would refuse every service
   account — the binding replaces the check there, and is stronger, because it was
   written once by an admin at AAL2 rather than re-derived from a projection per
   request. A USER-owned key IS still membership-checked, which closes
   identity.md §10's "revoke when the owner loses the organization" window
   SYNCHRONOUSLY rather than waiting for the `MemberRemoved` reactor that does
   not exist.

**Deliberately NOT built, with the reason:**

- **No `ApiKeyUsed` event.** identity.md §13 removes it and this build honours
  that: `last_used_at` is a coalesced projection write, at most once per key per
  minute, enforced in SQL rather than by a read-modify-write in the
  authenticator.
- **No IP allowlist and no per-key rate limit** (identity.md §10). The allowlist
  needs a trustworthy client address, which `clientip.Resolver` supplies only
  under a configured hop policy; the per-key limiter needs a bucket keyed on the
  key id, which is `ratelimit`'s to declare. Both are additive.
- **No `ServiceAccountDisabled`.** The containment an incident needs is revoking
  the account's keys, which removes everything it can do. A disable that only set
  a flag would be a second, weaker answer to the same question.
- **No `MemberRemoved` reactor.** Gate 1 refuses a departed owner's key at the
  next request, which is strictly faster than a reactor. The reactor is still
  worth building — it removes the ROW rather than the access — and it now has a
  synchronous control it cannot regress.

## Done — identity slice 2 (passkeys) and federation (identity.md §7)

**Why this surfaced late, stated plainly.** Passkeys were scoped as slice 2 from
the beginning — `contract.MethodPasskey`'s own comment says "arrives in slice 2"
— and this session followed the ordering it was given: billing, compliance, the
plan catalogue, email change, export. None of it reached slice 2. What was wrong
was reporting identity work as finished without ever publishing the inventory
below, so the gap surfaced as an `operator` blocker instead of as a plan.

**`operator` is NO LONGER HELD.** It was blocked on this: operator.md §3
requires SSO-only sign-in with mandatory WebAuthn and explicitly no passwords
and no TOTP fallback. A `cmd/operator` serving cross-tenant reads with no
authentication is the most dangerous thing this codebase could ship.

Both halves of that sentence now exist. Federation shipped the SSO half
(`internal/adapter/oidc`, verified against a real Google client), passkeys
shipped the WebAuthn half (`internal/adapter/webauthn`, verified against real
hardware including the discoverable path an operator sign-in needs). The gate is
open, and `operator` is the next slice.

**The inventory.** Every event identity.md §13 declares and the codec does not
register:

| Gap | Where it is specified | State |
| --- | --- | --- |
| `PasskeyRegistered`, `PasskeyRemoved` | §4, ADR-057, IDENTITY-SLICE-1 C3 | **done** |
| `FederatedIdentityLinked`, `FederatedIdentityUnlinked` | §7, and §4.4's last unbuilt flow | **done** |
| `ApiKeyCreated`, `ApiKeyRotated`, `ApiKeyRevoked` | FEATURES.md, §10 | **done** |
| `ServiceAccountCreated` | FEATURES.md, §10 | **done** |
| `DeviceTrusted` | §9 | not started |
| `SessionCompromiseDetected` | §9 | not started |
| `SecondFactorSucceeded` | §13 (`SecondFactorChallenged` exists) | not started |

**Slice 2's own carry-overs, from IDENTITY-SLICE-1 §"Outstanding":**

- **C3** credential-ID uniqueness across every account — ADR-057 settles it as a
  UNIQUE index plus a pre-insert check, with a negative test in the INTEGRATION
  suite because what is being asserted is the index.
- **C4** AAL3 undeliverable — already held: `contract.AssuranceLevel.Valid()`
  admits AAL1 and AAL2 only, and ADR-057 explains why AAL3 is unreachable with
  syncable authenticators.
- **T1** `go-webauthn`'s `CloneWarning` — `FinishLogin` SUCCEEDS on a sign-count
  regression and sets a flag. An application that never reads it has clone
  detection that does nothing while every test passes, which is the exact failure
  this repository shipped three times in notification adapters.
- **T2** `pquerna/otp` at or above v1.5.0 — already satisfied (v1.5.0 in go.mod).
  Recorded because no CVE was ever filed, so `govulncheck` will never report it.

## Done — email change (identity.md §12)

- [x] **Email change.** Four RPCs, an aggregate, a reservation demotion, a mail
      reactor on its own group, two projection handlers and a migration. Both
      directions of §4.4 enforced and tested end to end — building this flow is
      what made IDENTITY-REVIEW C8's **unexpired email change** variant
      reachable, so it is closed in the same slice.

      **Four things the build found that the design did not predict:**

      1. **`user_view.email_index` never moved on a change.**
         `AccountByEmailIndex` reads that table, so a completed change would have
         left the person unable to sign in with their new address while whoever
         caused the change kept signing in with the old one — the change
         achieving the exact opposite of its purpose.

      2. **The `identity_token.purpose` CHECK constraint refused the two new
         purposes.** Found by the integration test, not by any unit test: the
         event appended fine and the MAIL REACTOR failed to issue, so every
         requested change would have parked and mailed nobody. Migration 00029
         widens it. The constraint is worth keeping precisely because it caught
         this.

      3. **The vault had no way to CLEAR a field.** `pii.Validate` refuses an
         empty value on purpose — a field reading back as `""` would be
         indistinguishable from one nobody ever set, and the notification path
         depends on telling those apart. So `pii.Vault` gained `Forget`, which
         removes one row and touches no key. It is not erasure: the subject keeps
         their key and every other field.

      4. **A mutation of the revert mail's address survived every test in the
         repository.** Changing `AddressPrevious` to `AddressPrimary` mails the
         undo link, with its live token, to the party the undo is aimed at. It is
         the single most dangerous line in the flow and nothing covered it until
         the reactor got its own tests.

      **Not built: no `CancelEmailChange` mail.** Cancelling is silent, and the
      catalogue records why: all three causes are already known to the holder,
      and the address that was being claimed never proved it wanted anything, so
      mail to it would be unsolicited (NOTIFICATIONS §5).

## Done — export resumability (compliance.md §5)

- [x] **The export is asynchronous and resumable.** Four RPCs, an aggregate, a
      workflow with a paged listing, a reactor, a projection, two notifications
      and a migration. Nine mutations, all killed.

      **Three decisions taken with the user:** notify-then-poll, break the
      contract now, and include the object store as a second source. All three
      are recorded in compliance.md §5.1 with their reasoning.

      **Five things the build found:**

      1. **EXPORT was not a MUTATING operation class**, and it is now: the call
         appends a request and derives its id from the caller's key, so a retry
         without one starts a second workflow. Being mutating is independent of
         gate 4's exemption — BILLING_MANAGE was already both.

      2. **`newExportReactor` was built and registered in nothing** for one
         commit. The linter caught it only because the constructor was unused,
         which is luck: a constructor called from a test would have been "used"
         and the reactor would still have been wired to nobody. There is a
         wiring test now.

      3. **The vault had no way to CLEAR a field.** `pii.Validate` refuses an
         empty value on purpose — "" is indistinguishable from never-set, and
         the notification path depends on telling those apart. `pii.Vault`
         gained `Forget`.

      4. **`minimum: 0` is proto3's zero value** and vanishes from the published
         document; the floor has to be a `gte` rule. RevokeAllSessionsResponse
         already carried that comment — this is the second time it earned it.

      5. **int64's maximum does not survive the document's float64 round trip.**
         The published ceiling is the largest int64 a JSON number carries
         exactly, because a bound a client cannot read back is worse than an
         honest smaller one.

      **The integration test is written, and it found three things.** Eight tests
      in `protocolit`, in three layers, and the layering is deliberate — each one
      covers what the one below it cannot:

      1. **The request half** through the real API and projector.
      2. **The bundle half**, by driving the workflow's ACTIVITIES against the
         real KurrentDB, vault and object store — then fetching the manifest
         through the signed URL a browser would use and decoding it. It also
         seeds real objects under the subject's prefix, so the listing finds
         something and every download link is fetched and its bytes compared.
      3. **The whole path with NOBODY DRIVING IT**: a real Temporal worker on a
         unique queue, the real reactor on a real KurrentDB persistent
         subscription, one API call, then only polling. Between an accepted
         request and a built bundle sit four things that exist only at runtime —
         the subscription receiving the event, the reactor starting a run, a
         worker answering to the workflow NAME, and that worker having every
         activity registered under the name the workflow executes. Every one
         fails silently, and layer 2 proves none of them.

      1. **The export asked for a one-hour download link and the object store
         refuses anything over fifteen minutes.** Every ready export answered its
         poll with `internal`: the person was told their data was ready and could
         not fetch it. It was PRE-EXISTING — the synchronous version had the same
         constant — and nothing caught it because the use case's tests used a
         fake store that granted whatever it was asked for, the handler's tests
         used a fake use case, and the two numbers live in packages that do not
         import each other. `TestTheExportExpiryFitsTheStoresCeiling` now holds
         them together.

      2. **`protocolit`'s harness never registered compliance's events**, so the
         export projection consumed its first event, could not decode it,
         returned ErrPoison and STOPPED — sitting at an old position while every
         other projection advanced.

      3. **Neither compliance projection was in that harness's registry**, whose
         own comment claimed it ran every projection `cmd/projector` runs.
         `TestTheHarnessRunsEveryProjectionTheProjectorDoes` compares the two by
         name now, and `cmd/projector` gained a test that its own registry names
         compliance.

         SUPERSEDED. That test compared this suite's list against a third
         hand-written copy, so it caught only the drift somebody had already
         found — identity's API key projection went missing afterwards and it
         said nothing. Both lists are gone: `internal/projections` holds the one
         registry and everything that runs projections calls it.

## Open — a service account can hold a key and reach nothing

- [ ] **Grants for service accounts (identity.md §10, access.md §5).**
      A service account can be created, a key minted for it, and that key
      authenticates correctly — the digest resolves, the organization binding is
      read off the secret row, and gate 1 admits it without a membership check
      (correctly: a service account is owned by an organization, not a member of
      it).

      Gate 2 then refuses it for every method in the system. It asks OpenFGA
      about the key's OWNER, and `docs/access/authorization-model.fga` declares
      four types — `organization`, `team`, `user`, `workspace` — and no
      `service_account`. No tuple naming one can exist, and no RPC grants one
      anything: `CreateServiceAccount` deliberately "records the principal, and
      gives it nothing", and nothing else ever gives it something.

      So the second column of identity.md §10's table — the integration
      credential that survives an employee's departure — is unreachable today.
      Personal access tokens work end to end.

      What it needs: a `service_account` type in identity's access fragment, the
      organization and workspace relations widened to admit it, a model deploy
      (access.md §10's three-step ordering, and a re-pin of `OPENFGA_MODEL_ID`),
      an RPC to grant and revoke a service account's role, and the reactor that
      writes the tuple.

      Asserted by `TestAServiceAccountKeyAuthenticatesAndCanReachNothing` in
      `internal/adapter/protocolit`, which FAILS when the feature lands and is to
      be replaced by the positive case then.

---

## Parked

- [x] **The two deactivation flakes — CLOSED.** One was a real race found by
      reading the test; the other survived seventy-two clean observations with
      three hypotheses eliminated. Both are written up in "The remaining work,
      analysed". The note below is the original entry, kept for the `-count=N`
      finding it records.

- [x] **`-count=N` now works, which it did not before this session.**
      Repeated-run hunting was itself broken until this session: three packages
      panicked under `go test -count=2` — `internal/server/policy` and
      `internal/server/interceptor` re-registered the same synthetic protobuf
      descriptors into the global registry, and `internal/platform/obs` found its
      own previous run's deliberately-unkillable goroutine in the baseline. All
      three are fixed, and `go test ./... -race -count=2` is clean, so the tool
      the remaining flake needs is available. `protocolit .../DeactivateAccount` and
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
- [x] `account_name` deprecated field — **deleted.** It was parked as BLOCKED,
      and the note was right about the thing it refused: `reserved` is not an
      escape hatch from FIELD_NO_DELETE, and RELAXING the ruleset to admit the
      deletion would be widening a gate to fit a change.

      What changed is not the gate — nothing in `buf.yaml` moved — but that this
      repository has now taken a deliberate break with the gate intact, the same
      one `ExportMyDataResponse` took. No release has been cut, so the baseline
      is the previous commit rather than a published contract, and the break
      costs one gate failure on the commit that makes it. `buf breaking` reports
      exactly one finding.

      Carrying it was the more expensive option: every client generated from the
      schema offered a parameter whose value the server discards. The number is
      RESERVED, so an old client decodes nothing rather than reading a future
      field into what it calls `accountName`.

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

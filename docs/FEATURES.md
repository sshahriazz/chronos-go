# Feature Inventory

The complete surface, one section per domain. This is the **breadth** pass — we
refine each domain to depth afterwards, one at a time.

Read alongside [DECISIONS.md](DECISIONS.md) (settled architecture) and
[INFRA.md](INFRA.md) (the runtime substrate).

---

## Scope boundary

**In scope — the platform spine**, terminating at **workspace + teams + member
invitations**:

- `identity` — authentication
- `organization` — the commercial boundary: contract, subscription, owner, policy
- `workspace` — the collaboration boundary: members, teams, invitations
- `access` — the authorization engine
- `entitlement` · `billing` · `compliance` · `notification` — support the above
- `operator` — the SaaS back-office, a **separate deployable** (ADR-024)

**Out of scope — feature verticals *inside* a workspace.** Once a workspace
exists and has members, whatever those members would actually work on — Drive,
documents, files, editors — is not built now.

Google Drive appears in this document **only** as the reference topology the
access engine must be able to express (ADR-006). We build the sharing mechanics,
not the things being shared.

Each section states what the domain **does not own**. Those lines are the
anti-duplication contract: if two domains could plausibly own something, exactly
one does, and the other names it as excluded.

---

## Legend

- **Aggregates** — write-model consistency boundaries. One aggregate = one
  stream = one optimistic-concurrency scope.
- **Read models** — Postgres projections built by Go projectors from the log.
- **Publishes** — events other modules may subscribe to. These live in the
  module's `contract` package and are the *only* thing others may import.
- **P1 / P2** — P1 is the spine required to reach the goal; P2 supports it and
  follows.

---

# 0. platform — the primitive kernel

Not a domain. Has no business rules, no aggregates, no events of its own. It is
the vocabulary every domain speaks so that no domain speaks to infrastructure
(ADR-001).

### Event sourcing primitives
- `Aggregate[ID, E]` — apply/decide, uncommitted events, version tracking
- `EventStore` port — append with expected revision, read stream, read `$all`
- `EventEnvelope` — id, type, subject refs, causation, correlation, occurred-at
- `Snapshotter[S]` — optional, for long streams
- `StreamID`, `ExpectedVersion`, `Position`

### Projection primitives
- `Projector[S]` — handle(event, tx), rebuild-from-zero
- `Checkpoint` — position persisted **in the same transaction** as projected rows
- `Runner` — catch-up subscription lifecycle, backpressure, restart
- Poison handling — park, inspect, replay

### CQRS primitives
- `Command` / `Query` / `Handler` / `Bus`
- Middleware chain: validation → authn → authz → idempotency → transaction →
  telemetry. Composed once, reused by every use case.

### Authorization primitives
- `Subject`, `Relation`, `Object`, `Tuple` — the domain's vocabulary
- `Checker`, `Lister`, `Expander` ports. **Never an OpenFGA type in a domain.**
- `ConsistencyToken` — for read-your-own-writes after a grant

### Privacy primitives (ADR-002)
- `SubjectID` — pseudonym; the only identity reference allowed in an event
- `KeyRing`, `SubjectKey`, `Encryptor`, `Shredder`
- `pii.Vault` port — the mutable side-store personal data actually lives in

### General primitives
- Typed IDs (ULID-backed, compile-time distinct: `OrgID` ≠ `WorkspaceID`)
- `Money`, `Currency` — integer minor units, never float
- `Clock`, `IDGen`, `Random` — injected, so tests are deterministic
- `Result` / `DomainError` — coded, translatable, never `errors.New` in a domain
- `Page[T]`, `Cursor` — one pagination model for the whole system
- Ports: `Publisher` (realtime), `Blob` (object storage), `Mailer`, `Workflow`
- Concurrency: bounded worker pool, `errgroup` helpers, idempotency keys

**Does not own:** anything with a business rule. If it knows what a workspace is,
it is in the wrong package.

---

# 1. identity — who someone is

> **Refined to depth: [domains/identity.md](domains/identity.md).** That
> document supersedes this summary — session state machine, AAL model, passkeys,
> federated linking rules, the account switcher, native/headless clients, API
> keys and the security regression suite.

Authentication only. Never authorization.

**Aggregates:** `User`, `Credential`, `Session`, `MfaEnrollment`, `ApiKey`

### Registration & credentials — P1
- Email + password registration; email verification with expiring token
- argon2id hashing, tuned params, rehash-on-login when params change
- Password change, reset via single-use token
- Breached-password check (k-anonymity range query), reuse prevention
- Password policy per ASVS L2 — length over composition rules

### Session & login — P1
- Login, logout, logout-everywhere
- Session lifecycle: absolute + idle timeout, rotation on privilege change
- Active session listing with device/IP/last-seen; individual revoke
- Brute-force lockout, per-account and per-IP rate limits (Valkey)
- JWT denylist on revoke (Valkey, TTL-bounded)

### Multi-factor — P2
- TOTP enrollment, verification, disable-with-reauth
- Single-use recovery codes
- Step-up authentication for sensitive operations (ownership transfer, erasure)

### Federated & machine — P2
- OIDC/SAML per organization, JIT provisioning
- SCIM provisioning/deprovisioning
- API keys and service accounts — scoped, expiring, rotatable, last-used tracked

### Account lifecycle — P1
- Deactivate, reactivate, lock
- Deletion request → hands off to `compliance` for erasure

**Read models:** `user_view`, `session_view`, `credential_meta`, `mfa_status`

**Publishes:** `UserRegistered`, `EmailVerified`, `UserAuthenticated`,
`AuthenticationFailed`, `SessionRevoked`, `PasswordChanged`, `MfaEnabled`,
`UserDeactivated`, `UserDeletionRequested`

**Does not own:** membership of an org or workspace (`organization` / `workspace`), any permission
decision (`access`), consent records (`compliance`), notification delivery
(`notification`).

---

# 2. organization — the commercial boundary

> **Refined to depth: [domains/organization.md](domains/organization.md).**
> Lifecycle, the payment-gated ownership bootstrap, the four enforcements, and
> the extension seam for whitelabeling.

**Aggregates:** `Organization`, `OrganizationDomain`, `OwnershipTransfer`

Split from `workspace` per ADR-020 — dependency runs **`workspace →
organization`, never the reverse**. Organization is the commercial boundary
(contract, subscription, owner, policy, domains); workspace is the collaboration
boundary. See the deep spec; the summary below covers the workspace half.

---

# 2b. workspace — the collaboration boundary

> **Refined to depth: [domains/workspace.md](domains/workspace.md).** Seat
> accounting, the invitation state machine, teams, and the never-orphan rules.

**The goal domain.** Everything else exists to make this correct.

**Aggregates:** `Workspace`, `Membership`, `Team`, `Invitation`

### Workspace — P1
- Create within an organization; rename; archive; restore; delete
- Settings, visibility (org-visible vs invite-only)
- **Owns resources, features and entitlements** — the container everything hangs
  from (ADR-003)
- Registers itself as a resource type in the access topology, with
  `parent = organization` so org roles inherit down (ADR-006)
- Creation passes the full pipeline: authz → subscription (`grow`) →
  entitlement reservation (ADR-021)

### Membership — P1
- Roles: `admin`, `member`, `guest` — workspace-level
  (org `owner`/`admin` live in `organization` and inherit down)
- Add, remove, suspend, reinstate
- Role change with last-admin protection per workspace
- Removal triggers resource-ownership transfer, never orphaning

### Invitations — P1 · *the terminal feature of this goal*
- Invite by email to a workspace, with a target role
- Invite by shareable link, optionally domain-restricted
- Single-use token, expiry, resend with rotation, revoke
- Accept flows for both existing users and new sign-ups
- Decline; bounce handling; pending-invite listing
- Seat availability checked against entitlement **before** the invite is issued
- Guest/external collaborator admission with reduced default scope
- **Guest seats are a separate entitlement pool from member seats** (ADR-027);
  promoting a guest to member moves the reservation atomically between pools

### Teams — P1
- Create, rename, delete within a workspace
- Add/remove members; nominate team maintainers
- Teams are **grantable subjects** in access control — share to a team, not to
  each member

**Read models:** `workspace_view`, `member_view`, `team_view`,
`team_member_view`, `invitation_view`, `seat_usage`

**Publishes:** `WorkspaceCreated`, `WorkspaceArchived`, `WorkspaceDeleted`,
`MemberInvited`, `InvitationAccepted`, `InvitationRevoked`, `MemberJoined`,
`MemberRoleChanged`, `MemberRemoved`, `TeamCreated`, `TeamMemberAdded`,
`TeamMemberRemoved`

**Does not own:** the organization, its subscription, its owner or its policy
(`organization` — and **workspace never imports it back**, ADR-020);
authentication (`identity`); permission evaluation (`access`); seat *limits*
(`entitlement` sets them, workspace only asks); invitation email delivery
(`notification`).

---

# 3. access — the Drive-topology authorization engine

> **Refined to depth: [domains/access.md](domains/access.md).** That document
> supersedes this summary, and its topology claims are verified against the
> running OpenFGA — reproduce with
> [`evidence/access-topology-probe.py`](evidence/access-topology-probe.py).

Resource-agnostic by construction (ADR-006). This is the module that makes the
Drive comparison real.

**Aggregates:** `ShareGrant`, `LinkShare`, `AuthorizationModel`

### Topology — P1
- Resources as `(type, id, parent)`; arbitrarily deep nesting
- Inheritance flowing down the tree
- **Break-inheritance** on a subtree — restricted container inside a shared one
- Move re-parents and re-evaluates the effective set
- Ownership transfer

### Model management — P1
- Authorization model assembled from **module-contributed** type definitions
- Versioned; model ID pinned per request (never "use latest")
- Deployment as a migration step with a rollback path

### Grants — P1
- Direct grant to a user or a team, with a role
- Role catalogue per resource type (`viewer` / `commenter` / `editor` / `owner`)
- Revoke, expire, list
- **Conditional grants (ABAC)** — CEL conditions for time-boxed access, so
  "expires in 7 days" needs no cron job

### Link sharing — P2
- Anyone-with-link; expiry; password; domain-restricted audience
- Revoke and rotate; per-link audit

### Query surface — P1
- `Check` — the hot path, one boolean
- `BatchCheck` — for list screens; never N sequential checks
- `ListObjects` — "what can this subject reach?"
- `ListUsers` — powers the share dialog
- `Expand` — *why* is access granted; the debugging surface

### Consistency — P1
- Tuples are written by a **projector**, not inline — the event is truth,
  OpenFGA is a projection
- Contextual tuples supply read-your-own-writes immediately after a grant, so
  the eventual-consistency gap is invisible to the user
- Drift detector: periodic reconciliation of tuples against the log

**Read models:** OpenFGA tuple store (external), `share_view`,
`effective_access_view`, `access_audit`

**Publishes:** `AccessGranted`, `AccessRevoked`, `LinkShareCreated`,
`LinkShareRevoked`, `InheritanceBroken`, `AuthorizationModelDeployed`

**Does not own:** what a resource *is* — only its position in the tree.
Membership (`workspace`), org roles (`organization`), authentication (`identity`).

---

# 4. entitlement — features, quotas, usage

> **Refined to depth: [domains/entitlement.md](domains/entitlement.md).**
> Reservation protocol, org-pooled limits, exactly-once metering, over-limit
> policy.

Sits between billing and everything else. Answers "may this workspace do this,
and how much has it already done?"

**Aggregates:** `PlanDefinition`, `WorkspaceEntitlement`, `UsageCounter`

### Catalogue — P1
- Feature flags (boolean), limits (numeric), meters (accumulating)
- Plan → entitlement mapping; per-org and per-workspace overrides
- Org subscription grants workspace entitlements — explicit mapping (ADR-003)

### Enforcement — P1
- `check → reserve → commit/release` so concurrent requests cannot both pass a
  limit check and then both consume the last seat
- Soft limits (warn), hard limits (block), grace periods, overage policy
- Hot-path check served from Valkey, reconciled against the projection

### Metering — P1
- Record usage idempotently; **exactly-once over an at-least-once stream** via
  idempotency key + checkpoint-in-transaction
- Per-billing-period aggregation aligned to the cycle owned by `billing`
- Metered dimensions: seats, workspaces, storage bytes, API calls
- Backfill and correction path with an audit trail

### Lifecycle — P2
- Trial entitlements and expiry
- Upgrade/downgrade recalculation, including over-limit-after-downgrade handling

**Read models:** `entitlement_snapshot` (hot), `usage_period_view`,
`quota_status_view`

**Publishes:** `EntitlementGranted`, `EntitlementRevoked`, `UsageRecorded`,
`QuotaExceeded`, `QuotaWarning`, `TrialExpired`

**Does not own:** prices and invoices (`billing`), seat *assignment*
(`workspace`).

---

# 5. billing — Stripe-backed money

> **Refined to depth: [domains/billing.md](domains/billing.md).** Catalogue
> mirror with plan versioning, hosted-surface strategy, webhook ingestion, and
> the 24-case edge-case table.

Stripe is the source of truth for money; we keep a local projection (ADR-004).

**Aggregates:** `BillingAccount`, `Subscription`, `Invoice` (mirror),
`PaymentMethod` (mirror)

### Subscription — P2
- Customer + subscription provisioning per organization
- Checkout session, billing portal handoff
- Lifecycle: trialing → active → past_due → canceled / paused
- Upgrade, downgrade, proration, scheduled changes
- Seat-based + metered hybrid pricing

### Cycle orchestration — P2
- Temporal workflow per billing period: close → roll up usage → report meters →
  finalize → reconcile
- Deterministic workflow, all I/O in activities

### Payments & recovery — P2
- Webhook ingestion: **signature-verified and idempotent**, translated to domain
  events at the adapter edge
- Dunning, retry schedule, grace period, downgrade-to-free on final failure
- Tax via Stripe Tax; invoices and receipts

**Read models:** `subscription_view`, `invoice_view`, `payment_method_view`,
`billing_status`

**Publishes:** `SubscriptionActivated`, `SubscriptionChanged`,
`SubscriptionCanceled`, `PaymentSucceeded`, `PaymentFailed`, `InvoiceFinalized`

**Does not own:** usage counting (`entitlement`), feature semantics
(`entitlement`). A Stripe outage must never block reads or access decisions.

---

# 6. compliance — GDPR and the audit trail

> **Refined to depth: [domains/compliance.md](domains/compliance.md).** Erasure
> orchestration, export, retention exemptions, and the no-personal-data-in-
> projections rule.

**Aggregates:** `ConsentRecord`, `DataSubjectRequest`, `RetentionPolicy`,
`LegalHold`

### Consent — P2
- Capture and withdraw, versioned against policy revisions
- Separate marketing vs functional consent; provable timestamped record

### Data subject rights — P1 *(erasure shapes every event schema, ADR-002)*
- Access, portability (export bundle), rectification, restriction
- **Erasure**: destroy subject key → purge PII vault → rebuild projections
- Erasure and export share one subject-graph traversal — built together
- Replay of an erased subject as a tombstone is a **tested path**, not a hope
- Orchestrated by Temporal with a 30-day statutory clock

### Retention & holds — P2
- Retention schedules per data class, automated purge
- Legal hold overriding erasure, with justification recorded

### Audit & records — P1
- Immutable audit log derived from the event log (event sourcing gives this
  nearly free — the reason it is not a separate write path)
- Records of processing (Art. 30), subprocessor registry, DPA acceptance
- Data residency tagging
- Breach register + 72-hour notification workflow
- Access review reports ("who could reach what, when")

**Read models:** `consent_view`, `dsar_view`, `audit_log_view`,
`retention_schedule_view`

**Publishes:** `ConsentGranted`, `ConsentWithdrawn`, `ErasureRequested`,
`ErasureCompleted`, `ExportReady`, `LegalHoldPlaced`

**Does not own:** authentication (`identity`), access decisions (`access`).

---

# 7. notification — delivery

> **Refined to depth: [domains/notification.md](domains/notification.md).**
> Channel arbitration, presence model, web push mechanics, read-state sync.

Everything else publishes facts; this domain decides how a human hears about it.
**Pure delivery, zero business logic** — nothing ever calls it, it subscribes.

**Aggregates:** `NotificationPreference`, `DeliveryAttempt`

### Channels — P1
- Transactional email through a Temporal activity (never inline in a handler)
- Realtime push via Centrifugo — channel per user, workspace, and resource
- In-app notification feed, mark-read, digest

### Templates & preferences — P2
- Versioned, localized templates
- Per-user and per-workspace preferences; unsubscribe honouring consent
- Delivery tracking, retry, bounce and complaint handling

**Read models:** `notification_feed`, `preference_view`, `delivery_view`

**Publishes:** `NotificationSent`, `NotificationFailed`, `DeliveryBounced`

**Does not own:** the facts it announces. It subscribes; it never asks a domain
to notify.

---

# 8. operator — the SaaS back-office

> **Refined to depth: [domains/operator.md](domains/operator.md).**

> **Separate binary** (`cmd/operator`), separate DB role, internal network only
> (ADR-024). The only context in the system that is cross-tenant by design.

**Aggregates:** `Operator`, `OperatorRole`, `Elevation`

### Scope now — P2
- Customer directory: org, status, plan, lifecycle
- **Payment detail**: subscription, invoices, failures, disputes, refunds
- **Plan catalogue CRUD** and subscriber migration
- **Coupon / discount CRUD**
- Entitlement overrides for negotiated deals
- Minimal activity: workspace and member counts, last-active
- Read-only "view as"; **no write impersonation**

### Explicitly excluded
Customer content · bulk PII · per-user analytics · any privileged back-channel
that skips domain commands

**Read models:** `operator_customer_list`, `operator_billing_detail`,
`operator_activity_summary`, `operator_audit_log`, `operator_incident_queue`

**Publishes:** `OperatorViewedCustomer`, `OperatorViewedPersonalData`,
`OperatorElevated`, `PlanVersionPublishedByOperator`, `CouponDefinedByOperator`,
`OverrideGrantedByOperator`, `RefundIssuedByOperator`,
`OrganizationSuspendedByOperator`

**Does not own:** billing logic (`billing`), entitlement semantics
(`entitlement`), tenant permissions (`access`), tenant authentication
(`identity`). **Reads are audited events here** — under GDPR, looking is
processing.

---

## Cross-cutting security baseline (ASVS 4.0 L2 — ADR-005)

Not a domain; a requirement set every domain inherits and is tested against:

- Session management, credential storage, MFA — `identity`
- Access control, deny-by-default, no IDOR — `access` + `workspace_id` RLS
- Input validation and output encoding — API adapter layer
- Cryptography at rest and in transit — kernel `crypto` primitives
- Error handling and logging with no sensitive data in logs
- Immutable audit trail — `compliance`
- Dependency and vulnerability management — `govulncheck` in CI
- Business-logic limits and anti-automation — rate limiting, quota reservation

---

## Build order

1. **platform kernel** — primitives and ports; nothing above compiles cleanly
   without it
2. **identity** — users, credentials, sessions
3. **organization** — lifecycle, payment-gated ownership, the enforcement pipeline
4. **workspace** — members → teams → **invitations** *(the goal)*
5. **access** — topology engine, proven against a Drive-shaped fixture
6. **entitlement** — seat limits, which invitations depend on
7. **compliance** — erasure path, exercised against real event schemas
8. **billing** — catalogue mirror, webhooks, cycle orchestration
9. **notification** — folded in as each domain needs it
10. **operator** — back-office, once there is something to operate

Each is a full vertical slice — domain → projections → API → tests — because a
horizontal build demonstrates nothing until the very end.

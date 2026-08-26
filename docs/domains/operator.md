# Domain: operator

The SaaS operator's back-office — where **we** see our customers.

You spotted this correctly as a hidden domain. It is also the most dangerous one
in the system, because **it is the only thing that deliberately breaks tenant
isolation**. Everything else in this architecture assumes one tenant per request:
RLS policies, the enforcement pipeline, all four layers of ADR-015. This domain
assumes the opposite by design.

Governed by ADR-024 (separate deployable).

---

## 1. Why it is a separate binary

| | Tenant plane | Operator plane |
| --- | --- | --- |
| Principal | `user`, scoped to one org | `operator` — an employee |
| Tenancy | one org per request | **cross-tenant** |
| Authorization | OpenFGA graph | operator roles + explicit scope |
| DB role | RLS-enforced, non-owner | separate role, narrow audited bypass |
| Network | public internet | internal / VPN only |
| Binary | `cmd/api` | **`cmd/operator`** |

A cross-tenant capability living in the same process as the tenant API is one
routing mistake, one middleware-ordering bug, or one forgotten annotation away
from total data disclosure. Separation makes that class of bug **impossible
rather than unlikely**: the operator endpoints are not reachable from the public
surface because they are not in the running binary.

Shared domain logic is imported. **The tenant API never imports operator
packages** — enforced by depguard alongside ADR-001's other boundaries.

---

## 2. Scope for now

Deliberately narrow, per your framing — verbose on payment, minimal on activity.

**In scope**

- Customer directory: orgs, status, plan, lifecycle state
- **Payment detail**: subscription, invoices, payment failures, disputes, refunds,
  MRR-relevant state, Stripe deep links
- **Plan catalogue CRUD** — publish versions, archive, migrate subscribers
  (billing §2)
- **Coupon and discount CRUD** (billing §6)
- **Entitlement overrides** — negotiated deals, support credits
- Minimal activity: workspace count, member count, last-active date, signup
  source
- Support context: is this org suspended, why, and since when

**Explicitly out of scope for now**

- Customer content of any kind
- Member email addresses beyond the org owner's, and only where a task needs it
- Write impersonation (§6)
- Bulk export of tenant data
- Anything resembling analytics on individual end users

---

## 3. Operator identity

Operators are **not** tenant users and must never be modelled as one with a flag.
A boolean that grants cross-tenant reads is exactly the field that gets set by an
injection bug.

- Separate principal kind, separate credential store, **SSO-only** with
  **mandatory hardware-backed MFA** (WebAuthn) — no passwords, no TOTP fallback.
- Sessions are short and non-extendable; no "remember me".
- Access is IP-restricted to internal ranges.
- Offboarding is immediate and verified — an operator account outliving
  employment is a breach waiting to happen.

### Roles

| Role | Capability |
| --- | --- |
| `support` | read-only: customer list, status, payment state |
| `billing_ops` | + refunds, coupons, subscription repair |
| `catalogue_admin` | + plan versions, migrations |
| `operator_admin` | + operator account management |

Least privilege by default; every role addition is itself an audited event.

---

## 4. Data access rules

**Minimisation is structural, not procedural.** The operator read models are
built to contain only what operators may see, so there is no query that *could*
return customer content — the columns do not exist in the projection.

- Operator projections are **separate tables**, built from the same events but
  projecting a **reduced** field set.
- Personal data is resolved from the PII vault **only on explicit, justified
  access** (§5), never bulk-joined into a list view.
- Lists show org-level aggregates; drilling into a person requires elevation.
- The operator DB role has **no access at all** to tenant content tables — a bug
  in operator code cannot reach them because the grant does not exist.

This is the same principle as ADR-015: make the bad outcome unreachable rather
than merely forbidden.

---

## 5. Audit — reads included

> **Under GDPR, looking is processing.** Operator *reads* of tenant data are
> audited events, not log lines.

Every operator action records: who, what, which tenant, when, from where, and —
for personal-data access — **why**. The audit stream is append-only in the event
log, so it inherits the same tamper-evidence as everything else (ADR-013).

- Tenants can be shown operator-access history. Building for that from the start
  is cheap; retrofitting it is not.
- Anomaly detection on operator behaviour: unusual volume, off-hours access, or
  repeated access to one customer.
- Audit records are retained beyond the operator's employment.

### Audit retention vs erasure (review D14)

Two requirements meet head-on: audit records must be **retained** beyond an
operator's employment, and GDPR erasure must **destroy** a subject's personal
data. Resolved structurally, not by policy:

> **The audit log stores `SubjectID` pseudonyms only — never resolvable personal
> data.**

Erasure destroys the subject key (ADR-028), so the audit record survives as a
**non-identifying fact**: *"operator X viewed billing for org Y at time T"*
remains true and provable, while the erased person is no longer identifiable
from it.

- Operator audit entries reference `org_id` and `SubjectID`, never an email or a
  name. The operator UI resolves them for display through the vault, at read
  time, and that resolution is itself audited.
- Where an entry must stay identifying for a **legal obligation** (a fraud
  investigation, a retained dispute record), that basis is recorded per entry and
  registered in the Article 30 record — an exception with a paper trail, never a
  default.
- This must be decided before `compliance` is built; retrofitting means
  rewriting the audit schema after it holds real data.

### Concurrent operator edits (review D15)

Two operators publishing plan versions or editing the same coupon at once.
Operator writes go through ordinary domain commands (§7), so they inherit
**optimistic concurrency on the aggregate** — the second write fails with
`CONFLICT` and the operator is shown what changed. No operator write bypasses
the aggregate, which is precisely why this needs no separate mechanism.

### Break-glass

Elevation beyond a role's default requires a **recorded justification**, is
**time-boxed** (minutes, not hours), auto-expires, and raises an alert to a
second person at the time of use — not in a report someone reads next quarter.

---

## 6. Impersonation

The feature every support team asks for and the one most likely to become a
breach.

**Now: read-only "view as", or nothing.** An operator may render a tenant's view
from operator projections. They cannot act.

Write impersonation, if ever added, requires all of:

1. Explicit tenant consent per session, or a contractual basis recorded in
   advance
2. Time-boxed with an automatic hard stop
3. **Visible to the tenant while it is happening**, and in their own audit log
4. Every action attributed to `operator X acting as user Y` — never to Y alone
5. Blocked entirely for credential changes, ownership transfer and billing
   mutations

If those cannot all be honoured, the feature does not ship. A support convenience
is not worth an unattributable write.

---

## 7. What operators can change

Reads dominate. Writes are few, deliberate and audited:

| Action | Role | Notes |
| --- | --- | --- |
| Publish / archive plan version | `catalogue_admin` | mirrored to Stripe (billing §2) |
| Migrate subscribers between versions | `catalogue_admin` | Temporal, dry-run first, resumable |
| Create / revoke coupon | `billing_ops` | mirrored to Stripe |
| Grant entitlement override | `billing_ops` | reason mandatory, time-boxable |
| Issue refund | `billing_ops` | executed in Stripe; clawback is a separate decision |
| Suspend / reinstate an org | `operator_admin` | reason mandatory, tenant notified |
| Extend a trial | `billing_ops` | |
| Resolve a dispute flag | `billing_ops` | |

**Operator writes go through the same domain commands as everything else** — they
emit the same events and honour the same invariants. There is no privileged
back-channel that skips domain rules, because that back-channel is exactly what
corrupts state that then cannot be replayed.

---

## 8. Events published

`OperatorSignedIn` · `OperatorViewedCustomer` · `OperatorViewedPersonalData` ·
`OperatorElevated` · `OperatorElevationExpired` · `OperatorImpersonationStarted`
· `OperatorImpersonationEnded` · `PlanVersionPublishedByOperator` ·
`CouponDefinedByOperator` · `OverrideGrantedByOperator` ·
`RefundIssuedByOperator` · `OrganizationSuspendedByOperator` ·
`OperatorRoleChanged`

The `Viewed*` events are the point: **reads are events here**, unlike anywhere
else in the system.

---

## 9. Read models

Separate, reduced projections — never a join onto tenant tables.

| Projection | Contains |
| --- | --- |
| `operator_customer_list` | org, status, plan, MRR, workspace/member counts, last active |
| `operator_billing_detail` | subscription, invoices, failures, disputes, Stripe links |
| `operator_activity_summary` | coarse aggregates only — no per-user activity |
| `operator_audit_log` | every operator action, including reads |
| `operator_incident_queue` | disputes, failed payments, drift alerts, over-limit orgs |

---

## 10. What this domain does **not** own

- Billing logic → `billing`; the panel is a UI over its commands
- Entitlement semantics → `entitlement`
- Tenant permissions → `access`; operator authorization is a separate model
- Tenant user authentication → `identity`; operators authenticate separately
- Customer content — it has none and can reach none

---

## 11. Test plan

- **Isolation**: the tenant binary exposes **zero** operator routes; a
  conformance test asserts the operator packages are not linked into `cmd/api`.
- **Grants**: the operator DB role cannot read tenant content tables — asserted
  against a real database, not assumed.
- **Audit completeness**: every operator RPC, including reads, produces an audit
  event. A new endpoint without one fails the suite.
- **Break-glass**: elevation expires on time; expired elevation is refused;
  alerts fire.
- **Minimisation**: operator projections contain no content columns, asserted on
  the schema so a later migration cannot quietly add one.
- **Attribution**: operator-initiated domain changes carry operator attribution
  through to the tenant's own audit trail.
- **Offboarding**: a disabled operator's sessions are invalid immediately.

---

## 12. What is built (slice 1)

Slice 1 is **the plane**: the binary, its identity, its audit, and the customer
directory. Everything below is running and gated.

| §  | Requirement | Where it lives | What proves it |
| -- | ----------- | -------------- | -------------- |
| §1 | Separate binary; tenant API links no operator package | `cmd/operator`, depguard `api-excludes-operator` | `TestTheOperatorPlaneIsNotLinkedIntoTheTenantAPI` — asserts on the protobuf registry, which registers from `init()` and so reflects what was LINKED rather than what is imported |
| §1 | Not on the public surface | `proto-operator/` is a second buf module; `make api-docs` generates from `proto` alone | `TestTheOperatorPlaneIsNotInThePublishedSpec` reads the shipped document |
| §3 | SSO-only, mandatory WebAuthn, no password, no TOTP | `internal/operator/app/signin.go` | Two-stage session: the SSO step issues a token that authorizes only the WebAuthn pair, and `TestOnlyTheWebAuthnPairIsReachableWithAPendingSession` enumerates that pair |
| §3 | Short, non-extendable sessions | `SessionTTL`, `operator_session.expires_at` | No refresh endpoint and no idle deadline exist — an idle timeout that renews on activity IS extension |
| §3 | IP-restricted to internal ranges | `api.Guard.allow` | `OPERATOR_ALLOWED_NETWORKS`; an empty list needs `OPERATOR_ALLOW_ANY_IP` or the binary refuses to start |
| §3 | Offboarding is immediate | `ResolveOperatorSession` JOINs `operator_account` | A disabled operator's live session stops working as the disable projects, in one statement rather than after two round trips |
| §4 | Minimisation is structural | `operator_customer_list` has org-level columns only | `TestOperatorProjectionsHoldNoPersonalData` asserts the column list against the LIVE schema |
| §4 | The operator role cannot reach tenant content | migration 00037 | `TestTheOperatorRoleCannotReachTenantTables` asserts the REFUSAL against a real database |
| §4 | Personal data only on justified access | `RevealPersonalData`, migration 00038 | One subject, a bounded field list, a mandatory reason; the role holds SELECT on the vault and `TestTheOperatorRoleReadsTheVaultAndCannotWriteIt` proves it holds nothing more |
| §5 | Reads are audited | `internal/operator/app/audit.go` | The audit is appended BEFORE the read and a failure to append fails the call; `TestEveryAuthenticatedMethodRecordsAnAuditAction` fails on an endpoint that declares none |
| §5 | Audit survives erasure as a non-identifying fact | every event carries `SubjectID` only | `operator_audit_log` has no address column, in either direction — the operator's own or the tenant's |
| §8 | Events published | `internal/operator/contract` | Eight of §8's thirteen, plus two §8 does not list — `OperatorCredentialEnrolled` and `OperatorSignedOut`, each with its argument written where it is declared |
| §9 | Reduced projections | `operator_account`, `operator_audit_log`, `operator_customer_list` | Built by `cmd/operator`'s own catch-up subscriptions, as `chronos_operator` — not by `cmd/projector`, which connects as the tenant role |

### Deferred, and why each is a slice and not an oversight

- **Break-glass elevation (§5)** and **impersonation (§6)**. Both are additions
  to a plane that now exists; neither is reachable without it.
- **Every operator WRITE (§7)** — refunds, suspension, plan publication,
  coupons, overrides, trial extension, dispute resolution. The capability table
  in `internal/operator/domain` already declares all of them, so the role
  question is settled and what remains is the command path.
- **`operator_activity_summary` and `operator_incident_queue` (§9).** The first
  needs activity events the tenant plane does not yet emit; the second needs the
  dispute and drift signals billing §5 describes.
- **Legal holds (compliance.md §4).** Unblocked by this slice — a hold has an
  owner and a recorded justification, and both now have somewhere to come from.

### One decision worth stating, because it is not in the spec above

**Operator authorization is capabilities, not a role ladder.** §3 renders the
four roles as a ladder with "+" rows, and reading that ladder as `>=` would
silently grant a `catalogue_admin` the power to issue refunds — the roles are
not a total order in the spec's own table. So the ladder is written out as an
exhaustive table, once, in `internal/operator/domain/role.go`, and every check
asks for a named capability. `Permits` returns false for an unknown role and for
an unknown capability, so a role string from a future build and a deleted
constant both deny.

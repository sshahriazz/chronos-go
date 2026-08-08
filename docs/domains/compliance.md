# Domain: compliance

**Where the legal obligations become executable code.** Consent, data-subject
rights, retention, audit, and the breach register.

This is the domain that makes ADR-002 real. Everything else in the architecture
has been shaped by the requirement that a person can be erased from an
append-only log; here is where that actually happens.

Governed by ADR-002 (crypto-shredding + vault), ADR-028 (OpenBao key custody),
ADR-013 (the PII vault is the only mutable system of record), ADR-033 (it cannot
be rebuilt), ADR-035 (residency).

---

## 1. The rule that makes erasure possible

> **No projection ever stores personal data. Projections store `SubjectID`;
> personal data lives only in the PII vault and is resolved at read time.**

This is the load-bearing constraint of the whole system, and it is easy to
violate by accident — a `member_view` with an `email` column looks completely
natural and quietly makes erasure impossible without rewriting every projection.

| Layer | Holds |
| --- | --- |
| Event log | `SubjectID` pseudonyms only (ADR-002) |
| **Projections** | **`SubjectID` + a blind index for lookup — never a name or address** |
| **PII vault** | the actual personal data, encrypted per subject (ADR-028) |
| Read path | resolves `SubjectID` → value at render time |

**Consequence for reads.** Listing 50 members means 50 vault lookups, so
resolution is **batched** (`ResolveMany`) and cached in Valkey with a short TTL,
keyed by subject and invalidated on erasure. This is the price of erasability and
it is paid on the read path, deliberately, where it can be cached — rather than
on the erasure path, where it could not.

**Consequence for erasure.** Destroying the key makes every reference to that
subject resolve to a tombstone, everywhere, at once. No projection rewrite, no
event rewrite, no migration.

---

## 2. Aggregates

| Aggregate | Purpose |
| --- | --- |
| `ConsentRecord` | granular, versioned, provable consent |
| `DataSubjectRequest` | one per DSAR, with its statutory clock |
| `RetentionPolicy` | per data class, with legal-basis exemptions |
| `LegalHold` | suspends erasure and retention purges |
| `ProcessingRecord` | Article 30 register |
| `BreachRecord` | incident + 72-hour notification obligation |

---

## 3. Data subject requests

Six rights, each a Temporal workflow with a **30-day statutory clock** (Art. 12),
extendable once by two months with a recorded justification.

| Right | Article | Implementation |
| --- | --- | --- |
| Access | 15 | subject-graph traversal → report |
| **Portability** | 20 | same traversal → machine-readable bundle (§5) |
| Rectification | 16 | **a correction event**, never a rewrite (§6) |
| **Erasure** | 17 | crypto-shred (§4) |
| Restriction | 18 | processing halted, data retained (§6) |
| Objection | 21 | halts a specific processing purpose |

### Identity verification is not optional

> **A DSAR endpoint that acts on an unverified request is a data-exfiltration
> API.**

Every request requires an **authenticated session plus step-up to AAL2**
(identity §2). A request arriving by email or support ticket is verified out of
band before anything is executed, and that verification is recorded on the
request.

This is the single most dangerous endpoint in the product: it exports everything
we know about a person, on demand, in a convenient bundle.

---

## 4. Erasure

The orchestration, as a Temporal workflow (ADR-017):

```
1. verify requester                      ← §3, AAL2
2. check LegalHold                       → held ⇒ defer + explain
3. resolve retention exemptions          → §7, some data is legally retained
4. traverse the subject graph            → which streams, rows, objects
5. DESTROY the subject key in OpenBao    ← ✅ the irreversible step (ADR-028)
6. purge PII vault rows for the subject
7. release identifier reservations       ← EVENT-SOURCING §5
8. invalidate vault caches + revoke sessions
9. purge exported bundles from SeaweedFS
10. emit ErasureCompleted (SubjectID only)
11. confirm to the requester
```

Step 5 is the point of no return, and everything before it is reversible on
failure. **Verified mechanism** (ADR-028): encrypt → decrypt → destroy key →
decrypt fails with `encryption key not found`.

### Replaying an erased subject is a tested path

After erasure, every event referencing that subject still exists and still
replays. Projectors will encounter a `SubjectID` whose vault entry is gone.

> **A projector that panics on a tombstone is a compliance bug, not a crash bug**
> — it makes the log unreplayable and takes the whole rebuild capability with it.

So: resolution returns an explicit `Tombstone` value, never an error; projections
render "Deleted user"; and the test suite replays a stream containing an erased
subject and asserts a clean rebuild.

### What erasure does *not* touch

- **Audit records** keep the pseudonym and survive as non-identifying facts
  (operator.md §5).
- **Invoices and tax records** are retained under legal obligation (§7).
- **Aggregate structure** — an organization does not disappear because its owner
  was erased; ownership transfers first (organization.md §8).

---

## 5. Export and portability

The same subject-graph traversal as erasure, which is why they are built
together — a traversal that misses data exports incompletely *and* erases
incompletely, and only one of those is noticed.

- Output is a structured, machine-readable bundle (JSON + attachments).
- Written to **SeaweedFS** — this is the object store's first real writer.
- Delivered by a **short-lived signed URL**, never as an email attachment.
- The bundle is itself personal data: encrypted at rest, expiring, and **purged
  on erasure** (§4 step 9).
- Long-running and resumable, with progress visible in the workflow.

---

## 6. Rectification and restriction in an event-sourced system

**Rectification does not rewrite history.** Events are immutable (ADR-029). A
correction is a **new event** — `PersonalDataCorrected` — and the projection
reflects the corrected value. The historical record remains truthful: it recorded
what we believed at the time, and when we learned otherwise.

**Restriction** is a flag on the subject that gates processing without deleting
anything: projectors continue, but **reactors skip** the subject — no email, no
push, no export, no profiling. Storage continues, which is exactly what Art. 18
requires.

---

## 7. Retention and legal holds

Retention is **per data class**, with an explicit legal basis for anything that
outlives an erasure request:

| Data class | Retention | On erasure |
| --- | --- | --- |
| Session and auth logs | 90 days | erased |
| Notification delivery | 180 days | erased |
| **Invoices, tax records** | **7–10 years, statutory** | **retained — legal obligation** |
| Operator audit | 7 years | pseudonym retained, key destroyed |
| Breach records | 7 years | retained |
| Event log | indefinite | pseudonymised by key destruction |

**The invoice exemption is the one that surprises people.** Article 17(3)(b)
permits retention where processing is necessary for a legal obligation; tax law
requires invoice retention. So erasure minimises the personal data in an invoice
to what the obligation requires and retains it — it does not delete it, and the
DSAR response says so explicitly rather than implying total deletion.

**Legal holds** suspend both erasure and retention purges, with a recorded
justification and an owner. A held subject's erasure request is **deferred, not
refused**, and executes automatically when the hold lifts.

---

## 8. Consent

- **Granular by purpose** — marketing, analytics, optional processing. Never a
  single global toggle.
- Versioned against the policy text in force; the record stores the policy
  version, timestamp, and a pseudonymised source.
- Withdrawal is as easy as granting, and takes effect immediately.
- Consent is **never** the legal basis for security notifications or
  transactional mail (NOTIFICATIONS.md §3) — those rest on contract and
  legitimate interest, which is why they carry no unsubscribe.

---

## 9. Audit trail

Event sourcing gives this almost free — the log *is* the audit trail — but two
things must be deliberate:

- **Derived, not written twice.** The audit projection is built from the event
  log, so it cannot disagree with what happened. A separate audit write path
  would eventually drift.
- **Pseudonymised** (operator.md §5), so retention and erasure coexist.

Access reviews — *"who could reach what, and when"* — come from `access`'s
`ListUsers` plus the grant history, produced as a point-in-time report.

---

## 10. Records of processing, subprocessors, residency

- **Article 30 register** maintained as data, not a document: purposes, legal
  bases, categories, recipients, retention, transfers.
- **Subprocessor registry** — Stripe, the email relay, any hosting provider —
  with the customer-notice obligation on change.
- **Residency** (ADR-035) tagged per organization from the first migration.
  Cross-region queries are structurally absent, so nothing accidentally depends
  on one.

**Controller vs processor** matters and is often muddled: we are the
**controller** for our own users' account data, and a **processor** for the
content our customers put in their workspaces. The obligations differ, and the
Article 30 register records both roles separately.

---

## 11. Breach register

- Every suspected breach is recorded with detection time — the 72-hour clock
  (Art. 33) runs from **awareness**, not from confirmation.
- A Temporal workflow drives assessment → notification decision → supervisory
  authority → affected subjects, with the reasoning recorded either way.
- Deciding *not* to notify is itself a recorded, justified decision.

---

## 12. Events published

`ConsentGranted` · `ConsentWithdrawn` · `DsarReceived` · `DsarVerified` ·
`DsarRejected` · `ErasureRequested` · `ErasureDeferred` · `ErasureCompleted` ·
`ExportRequested` · `ExportReady` · `ExportPurged` · `PersonalDataCorrected` ·
`ProcessingRestricted` · `ProcessingResumed` · `LegalHoldPlaced` ·
`LegalHoldLifted` · `RetentionPurgeExecuted` · `BreachRecorded` ·
`BreachNotified`

---

## 13. Read models

| Projection | Serves |
| --- | --- |
| `dsar_view` | request queue, clock, status |
| `consent_view` | current consent per subject and purpose |
| `retention_schedule_view` | what expires when |
| `audit_log_view` | pseudonymised audit trail |
| `legal_hold_view` | active holds |
| `processing_register` | Article 30 |

---

## 14. Temporal workflows

| Workflow | Purpose |
| --- | --- |
| `ErasureWorkflow` | §4, with the statutory clock |
| `ExportWorkflow` | §5, resumable, produces the bundle |
| `RetentionSweep` | **Schedule** (CONVENTIONS §1.5), per data class |
| `BreachNotificationWorkflow` | 72-hour obligation |
| `ConsentReconfirmation` | on policy version change |

---

## 15. What this domain does **not** own

- **Authentication or account deletion mechanics** → `identity` (it requests;
  compliance executes)
- **The key custody mechanism** → `platform/crypto` + OpenBao; compliance calls
  `Shredder`, it does not manage keys
- **Operator access control** → `operator`
- **Billing records** → `billing`; compliance owns their *retention policy*, not
  their content

---

## 16. Test plan

- **Erasure**: key destroyed ⇒ every reference resolves to `Tombstone`; the same
  event stream replays cleanly and rebuilds every projection.
- **The negative that matters**: assert **no projection schema contains a
  personal-data column** — a schema-level test, so a later migration cannot
  quietly add one (§1).
- Export and erasure traverse the **same** subject graph — a property test
  asserting the two sets are identical.
- Legal hold blocks erasure; lifting it resumes automatically.
- Invoices survive erasure; session logs do not.
- DSAR without step-up is refused.
- Restriction stops reactors and does not stop projectors.
- Exported bundles are purged on subsequent erasure.
- Statutory clocks measured in **UTC** (ADR-008), including across a DST change.

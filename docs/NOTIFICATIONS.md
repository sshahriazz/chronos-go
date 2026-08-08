# Notification Catalogue

What the system tells a user, when, and which domain causes it.

**Complete — every domain is catalogued.** Sections 5–10 cover identity,
billing, entitlement, organization, workspace, compliance and access.

---

## 1. Who decides what

A domain **publishes facts**. It never asks for an email.

```
identity          notification
   │                   │
   │ PasswordChanged   │
   ├──────────────────►│  maps event → template → channel → recipient
   │  (contract event) │  resolves SubjectID → address at send time
   │                   │  applies preference + rate policy
   │                   ▼
   │              Temporal activity ──► SMTP / Centrifugo / in-app
```

The **event→notification mapping is owned by `notification`**, not by the
producing domain. `identity` does not know email exists; it records that a
password changed. This is what keeps `notification` swappable and keeps mail
templating out of authentication logic.

Consequence: adding a notification for an existing event requires **no change to
the producing domain**.

---

## 2. Delivery is a reactor, never a projector

Mail is sent by a **reactor** (ADR-019). This is the rule that prevents the
catastrophe where rebuilding a read model re-sends every welcome email, every
reset link, and every security alert ever generated.

- Reactor checkpoints are **never rewound**.
- Every send dedups on **event ID**.
- Sends run as Temporal activities with the **event ID as workflow ID**, so
  Temporal deduplicates as a final backstop (ADR-017).
- A new reactor starts at the **current** position, never at zero.

---

## 3. Notification classes

Class determines whether a user may turn it off. This is a legal distinction as
much as a product one.

| Class | Opt-out? | Examples |
| --- | --- | --- |
| **Security** | **Never** | password changed, MFA disabled, new sign-in, compromise |
| **Transactional** | **Never** (the flow requires it) | verify email, reset link, invitation |
| **Activity** | Yes, per user | API key expiring, sessions signed out |
| **Product / marketing** | **Opt-in only**, consent-gated | release notes |

**Security and transactional mail carries no unsubscribe link and ignores
notification preferences.** A user cannot switch off "your password was changed"
— that message is the only thing standing between a silent account takeover and
a detected one. Marketing consent is a separate record owned by `compliance` and
never gates the first two classes.

Security and marketing mail are sent from **separate streams and subdomains**, so
marketing complaint rates can never damage the deliverability of security alerts.

---

## 4. Rules every notification obeys

**Addressing.** Events carry only `SubjectID` (ADR-002). The reactor resolves the
pseudonym to an address from the PII vault **at send time**, never from the event
payload. If the subject has been erased, the send is **skipped, not failed** —
an erased user has no address, and that is a correct outcome, not an error.

**Content.**
- Never contains a credential, token, recovery code, or full session identifier.
- States **what happened, when (in the user's timezone), and from where**
  (device and city-level location) — enough to recognise, nothing more.
- Every security message carries a **"this wasn't me"** action: a signed,
  single-use, expiring link that revokes all sessions and forces a credential
  reset. That link **never authenticates the clicker** — it only triggers the
  protective action, so a leaked alert email cannot become an account takeover.
- Rendered in the user's locale; timestamps converted from UTC at render time
  only (ADR-008).

**Anti-abuse.** Verification and reset mail are an email-bombing vector. Limits
apply per address, per account, and per source IP, with an hourly ceiling per
address across *all* classes.

**Enumeration resistance.** API responses are identical whether or not an account
exists. Mail may differ, because only the mailbox owner sees it — so a reset
request for an unknown address sends *"someone requested a reset; no account
exists here"*, which helps a real user who forgot which address they used and
tells a prober nothing.

**Bounces.** A hard bounce on a verified address is a security concern, not just
a delivery one: that user can no longer receive security alerts. It flags the
address, surfaces an in-app warning, and blocks class-changing operations until
resolved.

**Realtime pairing.** Every Security-class notification is also written to the
in-app feed and pushed via Centrifugo, so a user with a compromised mailbox still
sees it.

---

## 5. Identity — notification catalogue

`Sec` = Security · `Txn` = Transactional · `Act` = Activity
**★** = cannot be disabled

### Onboarding and verification

| Trigger event | Notification | Recipient | Class | Timing |
| --- | --- | --- | --- | --- |
| `UserRegistered` (password) | Verify your email address | new address | Txn ★ | immediate |
| `EmailVerified` | **Welcome** — what to do next | user | Txn ★ | immediately after verification |
| `UserRegistered` (federated) | **Welcome** — notes sign-in is via *provider*, no password set | user | Txn ★ | immediate |
| `EmailVerificationRequested` (resend) | Verify your email address | new address | Txn ★ | rate-limited |

The welcome email fires on **verification**, not registration, for password
signups. Mailing an unverified address is unsolicited mail to someone who may not
have asked for it, and confirms the address exists to whoever typed it.

Federated signups are already verified by the provider, so welcome is immediate —
and it must say **how** the account signs in, or the user returns later, sees a
password field, and is stuck (§7 of the identity spec).

### Password lifecycle

| Trigger event | Notification | Recipient | Class | Timing |
| --- | --- | --- | --- | --- |
| `PasswordResetRequested` | Reset link | user | Txn ★ | immediate, rate-limited |
| *(reset requested, no such account)* | "No account exists for this address" | address | Txn ★ | immediate, rate-limited |
| `PasswordSet` (first, on a passwordless account) | A password was added to your account | user | Sec ★ | immediate |
| `PasswordChanged` | Password changed + "wasn't me" | user | Sec ★ | immediate |
| `PasswordResetCompleted` | Your password was reset | user | Sec ★ | immediate |
| `BreachedCredentialDetected` (login-time, §4.1) | Your password appeared in a breach — change it | user | Sec ★ | immediate |
| `CredentialRotationRequired` | Reminder: password change required by *date* | user | Sec ★ | scheduled, escalating |

### Multi-factor and passkeys

| Trigger event | Notification | Recipient | Class | Timing |
| --- | --- | --- | --- | --- |
| `TotpEnabled` | Two-factor authentication enabled | user | Sec ★ | immediate |
| `TotpDisabled` | **Two-factor authentication disabled** | user | Sec ★ | immediate |
| `PasskeyRegistered` | New passkey added — *name, device* | user | Sec ★ | immediate |
| `PasskeyRemoved` | Passkey removed | user | Sec ★ | immediate |
| `RecoveryCodesGenerated` | Recovery codes regenerated | user | Sec ★ | immediate |
| `RecoveryCodeConsumed` | A recovery code was used | user | Sec ★ | immediate |
| *(recovery codes ≤ 2 remaining)* | Running low on recovery codes | user | Act | on threshold |

`TotpDisabled` and `PasskeyRemoved` are the highest-value alerts in the entire
catalogue — disabling a second factor is the step an attacker takes immediately
after taking over an account. `RecoveryCodeConsumed` matters because it usually
means a lost device, and sometimes means someone else has the codes.

### Sessions and sign-in

| Trigger event | Notification | Recipient | Class | Timing |
| --- | --- | --- | --- | --- |
| `AuthenticationSucceeded` (new device or country) | New sign-in from *device*, *city* | user | Sec ★ | immediate |
| `AuthenticationFailed` (threshold crossed) | Repeated failed sign-in attempts | user | Sec ★ | aggregated, throttled |
| `SessionCompromiseDetected` | **Urgent — suspicious activity, all sessions signed out** | user | Sec ★ | immediate, highest priority |
| `SessionRevoked` (user chose "sign out everywhere") | Signed out of *n* devices | user | Act | immediate |
| `DeviceTrusted` | Device marked as trusted | user | Sec ★ | immediate |
| `CredentialTamperDetected` (§4.2) | Security incident on your account | user | Sec ★ | immediate + internal alert |

Only **new** devices or locations trigger sign-in mail. Alerting on every login
trains users to ignore the alert, which destroys the value of the one that
matters.

### Email address changes

| Trigger event | Notification | Recipient | Class | Timing |
| --- | --- | --- | --- | --- |
| `EmailChangeRequested` | Confirm your new address | **new** address | Txn ★ | immediate |
| `EmailChangeRequested` | **A change was requested — revert** | **old** address | Sec ★ | immediate |
| `EmailChanged` | Address changed | **both** | Sec ★ | immediate |

Notifying the **old** address is mandatory and is the control that stops a
hijacked session from silently taking permanent ownership of an account. The
revert link stays valid for the full revert window.

### Federated identity

| Trigger event | Notification | Recipient | Class | Timing |
| --- | --- | --- | --- | --- |
| `FederatedIdentityLinked` | *Provider* account linked | user | Sec ★ | immediate |
| `FederatedIdentityUnlinked` | *Provider* account unlinked | user | Sec ★ | immediate |

### API keys and service accounts

| Trigger event | Notification | Recipient | Class | Timing |
| --- | --- | --- | --- | --- |
| `ApiKeyCreated` | New API key *name* created | owner | Sec ★ | immediate |
| `ApiKeyRotated` | API key rotated — old key valid until *date* | owner | Act | immediate |
| `ApiKeyRevoked` | API key revoked | owner | Act | immediate |
| *(key expires in 7 / 1 days)* | API key expiring | owner | Act | scheduled |
| `ServiceAccountCreated` | Service account created in *workspace* | org admins | Sec ★ | immediate |

### Account lifecycle

| Trigger event | Notification | Recipient | Class | Timing |
| --- | --- | --- | --- | --- |
| `UserDeactivated` | Account deactivated | user | Sec ★ | immediate |
| `UserSuspended` | Account suspended | user | Sec ★ | immediate |
| `UserDeletionRequested` | Deletion scheduled for *date* — cancel | user | Sec ★ | immediate + reminders |

---

## 6. Billing and entitlement — notification catalogue

### The rule that governs this whole section

> **Stripe already emails your customers.** Its dunning and payment-failure mail
> is configured **on** (ADR-023). Every notification below must be checked
> against Stripe's own, or the customer receives two messages about one event —
> which reads as a broken system and trains them to ignore both.

Division of labour:

| Sent by **Stripe** | Sent by **us** |
| --- | --- |
| Payment failed, each retry attempt | *Consequence* — what stops working, and when |
| Invoice ready / receipt | Trial ending, quota warnings |
| Card expiring | Over-limit remediation |
| Payment method updates | Suspension and reinstatement |

We describe **consequences in product terms**; Stripe describes **payment
events**. That split keeps both useful.

### Billing

| Trigger event | Notification | Recipient | Class | Timing |
| --- | --- | --- | --- | --- |
| `SubscriptionActivated` | Subscription active — what you now have | org owner | Txn ★ | immediate |
| `SubscriptionTrialEnding` | Trial ends in *n* days — add a payment method | owner + billing admins | Txn ★ | 7d and 1d before |
| `TrialExpiredWithoutConversion` | Trial ended — you're on the free plan now | owner | Txn ★ | immediate |
| `PaymentFailed` (first) | *(none — Stripe sends it)* | — | — | — |
| `SubscriptionPastDue` | **What happens next**, and by when | owner + billing admins | Sec ★ | immediate |
| `SubscriptionUnpaid` | **Workspace suspended** — how to restore | owner + billing admins | Sec ★ | immediate |
| `OrganizationReinstated` | Access restored | owner + all admins | Txn ★ | immediate |
| `SubscriptionChanged` (up/down) | Plan changed — what changed | owner | Txn ★ | immediate |
| `SubscriptionCanceled` | Canceled — active until *date*, export window | owner | Sec ★ | immediate |
| `DisputeOpened` | *(tenant: none)* — **operator alert only** | operator | Sec ★ | immediate |
| `RefundIssued` | Refund issued | owner | Txn ★ | immediate |
| `PaymentActionRequired` | Action needed to complete payment (SCA) | owner | Txn ★ | immediate |
| `PlanMigrationScheduled` | Your plan is changing on *date* | owner | Txn ★ | ≥30d notice |

`DisputeOpened` deliberately notifies **nobody in the tenant**. A dispute is
often a confused customer or a family member's card; emailing them about it
escalates a query into a confrontation. It goes to the operator queue
(billing §5 case 10).

### Entitlement

| Trigger event | Notification | Recipient | Class | Timing |
| --- | --- | --- | --- | --- |
| `QuotaWarning` (80% / 95%) | Approaching your *limit* | org + workspace admins | Act | on threshold, deduped per period |
| `QuotaExceeded` | *Limit* reached — what is blocked | admins | Txn ★ | immediate |
| `OverLimitEntered` | Over your new plan's limit — reduce by *n* by *date* | owner + admins | Sec ★ | immediate + escalating |
| `OverLimitGraceExpiring` | *n* days until excess becomes read-only | owner | Sec ★ | 7d, 1d |
| `OverLimitCleared` | Back within limits | owner | Act | immediate |
| `OverrideGranted` | An adjustment was applied to your account | owner | Act | immediate |
| `SeatsExhausted` (invite blocked) | Cannot invite — no seats left | the inviting admin | Txn ★ | in-band with the failure |

`QuotaWarning` is deduped **per billing period per threshold**. A workspace
hovering at 80% must not generate a message per request — the single fastest way
to make every notification in the product ignorable.

`SeatsExhausted` is delivered **in-band as the API error first**, and only mailed
if the actor is not present — the person who just clicked "invite" does not need
an email to learn it failed.

---

## 7. Organization

| Trigger event | Notification | Recipient | Class | Timing |
| --- | --- | --- | --- | --- |
| `OrganizationActivated` | Organization is live — next steps | owner | Txn ★ | immediate |
| `OrganizationExpired` (abandoned checkout) | Your setup expired — start again | provisional owner | Txn ★ | on expiry |
| `OrganizationSuspended` | **Suspended** — what stopped, how to restore | owner + org admins | Sec ★ | immediate |
| `OrganizationReinstated` | Access restored | owner + all admins | Txn ★ | immediate |
| `OwnershipTransferRequested` | You have been offered ownership — accept by *date* | recipient | Sec ★ | immediate + reminders |
| `OwnershipTransferRequested` | A transfer was initiated | **current owner** | Sec ★ | immediate |
| `OwnershipTransferAccepted` | Ownership transferred | both parties + admins | Sec ★ | immediate |
| `OrganizationDomainVerified` | Domain *x* verified | requesting admin | Act | immediate |
| `OrganizationDomainVerificationFailed` | Verification failed — DNS record not found | requesting admin | Act | after retries |

Ownership transfer notifies **both** parties at request time. A transfer the
current owner did not initiate is exactly the event they must learn about
immediately.

---

## 8. Workspace

| Trigger event | Notification | Recipient | Class | Timing |
| --- | --- | --- | --- | --- |
| `MemberInvited` | You have been invited to *workspace* | invitee | Txn ★ | immediate |
| *(invitation unaccepted)* | Reminder — expires in *n* days | invitee | Txn ★ | 3d and 1d before expiry |
| `InvitationAccepted` | *Name* joined | inviter | Act | immediate |
| `InvitationDeclined` | *Name* declined | inviter | Act | immediate |
| `InvitationUndeliverable` | Invitation bounced — check the address | inviter | Txn ★ | immediate |
| `InvitationExpired` | Invitation expired — seat released | inviter | Act | immediate |
| `MemberRoleChanged` | Your role in *workspace* changed | the member | Sec ★ | immediate |
| `MemberRemoved` | You were removed from *workspace* | the member | Sec ★ | immediate |
| `ResourceOwnershipTransferred` | You now own *n* items from *name* | receiving admin | Txn ★ | immediate |
| `InheritanceBroken` | *Workspace* is now private to its members | org owner + workspace admins | Sec ★ | immediate |
| `InheritanceRestored` (break-glass) | **Org access to *workspace* was restored by the owner** | workspace admins | Sec ★ | immediate |
| `GuestAdmitted` | You have guest access to specific items | the guest | Txn ★ | immediate |

`InheritanceRestored` is deliberately loud. Break-glass reclaim (ADR-027) must
never be silent — a workspace's admins are entitled to know the org owner let
themselves back in.

`MemberRemoved` and `MemberRoleChanged` go to the **affected member**, not the
actor. Someone losing access learns it from us, not from a 403.

---

## 9. Compliance

| Trigger event | Notification | Recipient | Class | Timing |
| --- | --- | --- | --- | --- |
| `DsarReceived` | Request received — we will respond by *date* | subject | Txn ★ | immediate |
| `DsarVerified` | Identity confirmed, processing | subject | Txn ★ | immediate |
| `ExportReady` | Your data is ready — link expires in *n* days | subject | Txn ★ | immediate |
| `ErasureCompleted` | Erasure complete — **what was retained and why** | subject | Txn ★ | immediate, **before** the address is purged |
| `ErasureDeferred` | Deferred — legal hold, expected *date* | subject | Txn ★ | immediate |
| `ProcessingRestricted` | Processing restricted as requested | subject | Txn ★ | immediate |
| `LegalHoldPlaced` | *(subject: none)* — operator only | operator | Sec ★ | immediate |
| `BreachNotified` | Security incident affecting your data | affected subjects | Sec ★ | within 72h obligation |

**`ErasureCompleted` must be sent before the address is purged** — the ordering
matters, and it is the one notification that cannot be retried afterwards.

It also states **what was retained and why** (invoices under legal obligation,
compliance §7). A confirmation implying total deletion when tax records survive
is a misleading statement about processing.

---

## 10. Access

| Trigger event | Notification | Recipient | Class | Timing |
| --- | --- | --- | --- | --- |
| `AccessGranted` (direct, to a person) | *Name* shared *resource* with you | grantee | Act | immediate, coalesced |
| `AccessGranted` (via team) | *(none)* | — | — | — |
| `AccessRevoked` | Access to *resource* was removed | grantee | Act | immediate |
| `LinkShareCreated` | *(none — the sharer distributes it)* | — | — | — |
| *(link share expiring)* | Link to *resource* expires in *n* days | creator | Act | 3d before |
| `AccessDriftDetected` | *(tenant: none)* — operator incident | operator | Sec ★ | immediate |

**Team grants notify nobody.** Adding a resource to a team-shared folder would
otherwise mail everyone in the team on every file — the single fastest way to
make people mute the product. Direct person-to-person shares are coalesced into
one digest per sharer per few minutes.

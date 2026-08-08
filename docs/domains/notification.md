# Domain: notification

**Pure delivery. Zero business logic.**

It never decides *whether* something happened, only *how someone is told*. It has
no aggregates that another domain cares about, publishes no facts about the
business, and — critically — **no domain ever calls it**. It subscribes.

Governed by ADR-019 (reactor, never projector) and ADR-026 (channel arbitration).
The policy catalogue — what gets sent, to whom, in which class — lives in
[NOTIFICATIONS.md](../NOTIFICATIONS.md); this document is the machinery.

---

## 1. The contract

```
any domain          notification
    │                    │
    │ PasswordChanged    │  1. is this event in the registry?  ── no ─► ignore
    ├───────────────────►│  2. resolve recipients
    │  contract event    │  3. resolve address from PII vault (send time)
    │                    │  4. render template
    │                    │  5. decide channels  ◄── ADR-026
    │                    ▼
    │        email · in-app feed · web push
```

**Only events present in the registry produce anything.** Every other event
passes unnoticed. That registry is the entire surface area of this domain's
"decisions", and it is configuration rather than code branching.

Adding a notification for an existing event touches **no producing domain**.

---

## 2. Channels

| Channel | Durable? | Purpose |
| --- | --- | --- |
| **Email** | yes | the record of account and security events |
| **In-app feed** | yes | the persistent list, always written |
| **In-app realtime** | no | the *alert* — a toast/badge via Centrifugo |
| **Web push** | no | the *alert* when no attentive tab exists |

The distinction that makes this tractable:

> **The feed item is persistence and is always written. The alert is
> interruption and is arbitrated.**

Conflating them is what produces both "the user got two pings" and "the
notification vanished because they were offline".

---

## 3. Alert arbitration

Per ADR-026 — the requirement that in-app and web push suppress each other, and
that push only fires when the tab is inactive or closed.

```
notification created  ──►  feed item written  (always, unconditional)
                                │
                                ▼
                    presence lookup for the user
                                │
        ┌───────────────────────┴───────────────────────┐
        │ connected AND visible                          │ otherwise
        ▼                                                ▼
  in-app realtime alert                        hold T (~15s)
  push suppressed                                   │
                                        ┌───────────┴───────────┐
                              in-app ack arrives          timeout
                                        │                      │
                                  cancel push            send web push
```

### Presence is two signals

| Signal | Source | Meaning |
| --- | --- | --- |
| Connected | Centrifugo presence on `user:<id>` | a socket is open |
| **Attentive** | client heartbeat from the Page Visibility API | the tab is actually visible |

**Connected is not attentive.** A WebSocket survives in a background tab
indefinitely; treating that as presence would mean a user with a forgotten tab
never receives a push again. Only *connected **and** visible* suppresses push.

### The race, and the backstop

The user opens their laptop during the hold window; a push is already in flight.

- Both channels carry the same **`notification_id`**.
- The client keeps a short-lived seen-set and drops the duplicate.
- The service worker checks `clients.matchAll()` and, if a visible client already
  displayed it, posts a message to that client instead of a second banner.

This is a **backstop, not the mechanism** — see ADR-026 for why the decision
cannot be deferred to the service worker.

### Reconnect recovery (review A7)

Centrifugo runs with `force_recovery`, so a reconnecting client **replays missed
messages** — including alerts already delivered by push while it was away.

The client's seen-set must therefore **survive a reconnect**, keyed by
`notification_id` and persisted (session storage), not held in page memory. A
recovered message whose id is already in the set updates the feed silently and
raises no alert.

Without this, closing a laptop and reopening it produces a burst of duplicate
alerts for everything that arrived in between — the exact failure ADR-026 exists
to prevent, arriving by a different route.

### Degraded presence

If Centrifugo is unavailable, **send the push**. A duplicate alert is a much
better failure than a security notification nobody receives.

---

## 4. Web push mechanics

- **VAPID** keypair; the public key is served to clients, the private key lives
  in the secrets vault.
- A push **subscription is per browser profile per device**, not per user — one
  user commonly has several. Each is stored with its endpoint, keys, user agent,
  and creation time.
- **`userVisibleOnly: true`** is mandatory in Chrome and shapes ADR-026: a push
  that shows nothing risks a browser-generated "site updated in the background"
  notice and, repeated, the loss of push permission for the origin.
- **`410 Gone` / `404` on send ⇒ prune the subscription immediately.** Stale
  endpoints accumulate fast and silently degrade delivery rates.
- **`notificationclick`** focuses an existing tab if one exists, otherwise opens
  the deep link, and marks the notification read.
- Permission state is tracked per subscription; `denied` disables the channel for
  that device and falls back to email policy without retrying.
- Payload is minimal — a title, a short body and the `notification_id`. **No
  personal data in a push payload**: it transits a third-party push service and
  may render on a lock screen (ADR-002).

---

## 5. Read-state synchronisation

Reading on one device must dismiss everywhere, or the badge count becomes a lie.

- Read state lives server-side on the feed item.
- Marking read publishes on the user's Centrifugo channel; every connected client
  updates and dismisses any displayed banner.
- The service worker closes matching OS notifications by tag on that signal.
- `notificationclick` marks read, closing the loop from the push side.

---

## 6. Email

Policy is by **class**, independent of alert arbitration (ADR-026):

| Class | Email |
| --- | --- |
| Security · Transactional | **always** — ignores preferences, no unsubscribe |
| Activity | per preference; **suppressed if read in-app within 15 min** |
| Product / marketing | opt-in only, consent-gated |

Only the Activity class is suppressed by in-app reading. Security mail is the
durable record precisely for the case where the in-app channel is compromised or
unavailable — suppressing it would remove the account-takeover tripwire.

Sending is a Temporal activity with retries, bounce and complaint handling
(NOTIFICATIONS.md §4).

---

## 7. Delivery discipline

- **Reactors, never projectors** (ADR-019). Rebuilding a read model must never
  resend. Reactor checkpoints are never rewound; every send dedups on event ID;
  Temporal workflow id = event id as the final backstop.
- **Addresses resolve at send time** from the PII vault, never from the event
  payload. An erased subject means the send is **skipped, not failed**.
- **Rate limits** per recipient across all classes, plus per-class caps, plus a
  global hourly ceiling per address (NOTIFICATIONS.md §4).
- **Digest and coalescing** for high-frequency Activity notifications — one
  message per threshold per period, never per event.
- Every attempt is recorded with its outcome, so "did they get it?" is
  answerable.

---

## 8. Preferences

- Per user, per class, per channel — with Security and Transactional locked on.
- Quiet hours suppress *alerts only*; the feed item is still written and email
  policy is unchanged.
- Preference changes take effect immediately; they are read at send time, never
  cached into a queued message.

---

## 9. Aggregates

| Aggregate | Purpose |
| --- | --- |
| `NotificationPreference` | per-user channel and class settings |
| `PushSubscription` | one per browser profile per device |
| `Notification` | a feed item — recipient, class, payload ref, read state |
| `DeliveryAttempt` | per channel, per attempt, with outcome |

---

## 10. Events published

`NotificationCreated` · `AlertRouted` · `InAppDelivered` · `InAppAcknowledged` ·
`PushSent` · `PushSuppressed` · `PushSubscriptionExpired` · `EmailSent` ·
`EmailBounced` · `EmailComplained` · `NotificationRead` ·
`NotificationDeliveryFailed` · `PreferenceChanged`

These are **operational** facts, never business facts. No other domain should
subscribe to them for business logic.

---

## 11. Read models

| Projection | Serves |
| --- | --- |
| `notification_feed` | the in-app list, unread counts |
| `push_subscription_view` | active endpoints per user |
| `preference_view` | settings UI |
| `delivery_view` | per-notification delivery status, support answers |
| `bounce_view` | addresses needing attention (NOTIFICATIONS.md §4) |

---

## 12. Ports

```
Mailer          Send · outcome                       (kernel)
RealtimePublisher  Publish · Presence · PresenceStats (kernel — Centrifugo)
WebPusher       Send · Prune                          (VAPID)
Renderer        template + locale + timezone → body
Vault           SubjectID → address                   (kernel)
```

`Presence` on the realtime port is what makes ADR-026 implementable and is the
reason presence must be enabled on the user namespace in the Centrifugo config.

---

## 13. Temporal workflows (ADR-017)

| Workflow | Purpose |
| --- | --- |
| `DeliveryWorkflow` | one per notification: arbitrate, hold, send, retry |
| `DigestWorkflow` | periodic coalescing for Activity class |
| `BounceHandlingWorkflow` | classify, retry or flag the address |
| `SubscriptionPruneWorkflow` | remove expired push endpoints |

The hold window (§3) is a **workflow timer**, not a `time.Sleep` — it must
survive a process restart, or a deploy during the window silently drops alerts.

---

## 14. What this domain does **not** own

- **The facts.** It subscribes; nothing asks it to notify.
- **Whether an event occurred, or its business meaning** → the producing domain.
- **Consent records** → `compliance` (notification *reads* consent).
- **The email address** → the PII vault, resolved at send time.
- **Access control on channels** → `access` issues the Centrifugo subscription
  token after a `Check`; notification never authorises a subscriber.

---

## 15. Test plan

**Arbitration matrix** — every cell asserted:

| Presence | Expected |
| --- | --- |
| connected + visible | in-app alert, **no push** |
| connected + hidden | hold, then **push** |
| disconnected | hold, then **push** |
| presence unavailable | **push** (fail toward delivery) |
| ack during hold | push **cancelled** |
| push already sent, tab opens | client dedups on `notification_id` |

**Other:**
- Feed item is written in **every** case, including when all alert channels fail
- Replay the full event stream ⇒ **zero** additional sends (ADR-019)
- Read on device A dismisses on device B, and closes the OS notification
- `410 Gone` prunes the subscription and does not retry
- Erased subject ⇒ send skipped, not failed
- Security-class email is sent even when the in-app alert was read
- Quiet hours suppress the alert but not the feed item or security email
- Hold window survives a worker restart mid-flight
- No personal data appears in a push payload — asserted on the serialized body

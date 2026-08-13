# Domain: identity

**Answers exactly one question: *who is this?*** It never answers *what may they
do* — that is `access` — and it never knows what an organization or workspace is
— that is `organization` and `workspace`.

A `User` is **global**. Membership is tenancy's concern. This separation is what
makes the account switcher and the org switcher two different features
(§6).

Prerequisites: [DECISIONS.md](../DECISIONS.md) ADR-001 (kernel purity), ADR-002
(no personal data in events), ADR-012 (app-side encryption), ADR-018 (token
model).

---

## 1. Aggregates

| Aggregate | Boundary rationale |
| --- | --- |
| `User` | Owns **all authentication methods** as entities, because the invariant "a user always retains at least one usable credential" spans every method. Splitting them would make de-linking unsafe. |
| `Session` | Separate: high write volume, independent lifecycle, per-device. |
| `ApiKey` | Separate: machine principal, own rotation and expiry clock. |
| `ServiceAccount` | Separate: a non-human principal owned by an org, not a user. |
| `AuthenticationAttempt` | Not an aggregate — an append-only event stream keyed by hashed identifier, so failed attempts against non-existent users still have somewhere to go. |

### The `User` aggregate

```
User
├── identifiers   (email, normalized + verified state)
├── status        (pending → active → deactivated → suspended → erased)
└── methods[]     ← the invariant boundary
    ├── PasswordCredential   (0..1)
    ├── PasskeyCredential    (0..n)   WebAuthn
    ├── TotpEnrollment       (0..1)
    ├── RecoveryCodeSet      (0..1)
    └── FederatedLink        (0..n)   google | github | apple | microsoft
```

**Core invariant — `AtLeastOneUsableMethod`.** A user in `active` status must
retain ≥1 method capable of *primary* authentication (password, passkey, or
federated link). TOTP and recovery codes are second factors and never satisfy it.
Every removal command checks this and fails with `LastCredentialRemoval` rather
than locking the user out.

---

## 2. Authentication assurance levels

One vocabulary unifies passwords, passkeys, TOTP and step-up. Every session
carries its current AAL; every sensitive command declares the AAL it requires.

| Level | Satisfied by |
| --- | --- |
| `AAL1` | Password alone, or federated link alone, or passkey with `UV=false` |
| `AAL2` | Password + TOTP · password + WebAuthn · **passkey with `UV=true`** (possession + biometric/PIN in one gesture) |
| `AAL3` | Hardware-bound authenticator with attestation |

**A passkey with user verification is AAL2 on its own.** This is why passkeys are
the preferred path: one gesture, stronger than password + TOTP, and phishing
resistant.

**Step-up** raises a session to a required AAL for a **time-boxed window**
(default 5 minutes) without creating a new session. Required for: password
change, MFA disable, credential removal, email change, API key creation, account
deletion, ownership transfer.

---

## 3. Session state machine

The single most important state machine in the system.

```
                      ┌──────────────┐
                      │  Anonymous   │
                      └──────┬───────┘
                    primary factor verified
                             ▼
          ┌──────────────────────────────────┐
          │  PendingSecondFactor             │  ttl 5m, no API access
          │  (only when policy requires MFA) │
          └──────┬──────────────────┬────────┘
        2nd factor OK          timeout / fail×N
                 ▼                  ▼
          ┌─────────────┐    ┌─────────────┐
     ┌────│   Active    │    │   Expired   │
     │    └──┬───┬───┬──┘    └─────────────┘
     │       │   │   └──────────────┐
 step-up     │   │ idle/absolute    │ explicit revoke
     ▼       │   ▼                  ▼
┌──────────┐ │ ┌─────────┐   ┌─────────────┐
│ Elevated │─┘ │ Expired │   │   Revoked   │
│  (5 min) │   └─────────┘   └─────────────┘
└──────────┘
     │
     │  retired refresh token replayed  ⇒ theft proven
     ▼
┌──────────────┐
│ Compromised  │ → whole token family revoked, user notified,
└──────────────┘   all sessions on that device flagged
```

### Transition rules

| From | Event | To | Guard |
| --- | --- | --- | --- |
| `Anonymous` | primary factor verified | `PendingSecondFactor` | org or user policy requires MFA |
| `Anonymous` | primary factor verified | `Active` | no MFA required, or passkey UV satisfied AAL2 |
| `PendingSecondFactor` | second factor verified | `Active` | within 5 min, attempts < 5 |
| `PendingSecondFactor` | timeout / attempts exhausted | `Expired` | |
| `Active` | step-up satisfied | `Elevated` | AAL requirement met |
| `Elevated` | 5 min elapsed | `Active` | automatic downgrade |
| `Active` | idle > 14d, or absolute > 30d | `Expired` | |
| `Active` | user revokes / password changed | `Revoked` | |
| any | retired refresh token replayed | `Compromised` | ADR-018 |

**`PendingSecondFactor` holds no API authority.** It can call exactly one RPC —
the second-factor verification — and nothing else. This is where half-built
implementations leak: a partially-authenticated token that is accepted by the
general interceptor is a complete authentication bypass.

Password change revokes **all other** sessions by default, keeping the current
one. Compromise revokes everything including the current one.

---

## 4. Password authentication

- **argon2id**, tuned parameters stored *with* the hash so they can be raised
  later; transparent rehash on next successful login.
- **Minimum 8 characters, and at least 64 accepted.** Eight is permitted because
  a second factor is mandatory (§2) — a password is never a single factor here.
  Rejecting a long passphrase because of a column width is a common and
  embarrassing violation, so the upper bound is a floor, not a target.
- No forced composition, no forced periodic rotation, paste and password managers
  allowed.
- **Unicode NFC normalization, applied identically at set and at verify.** Not
  optional and not a detail: a password typed on macOS decomposes (NFD) and will
  not verify against a hash created on Windows or Linux without it. NFC — not
  NFKC — per RFC 8265 §4's `OpaqueString` profile, which also mandates **no case
  mapping and no width folding**, because folding a password reduces its entropy
  and causes false accepts. The form is baked into every stored hash, so changing
  it later invalidates every credential.
- Reset: single-use, expiring, **stored as `SHA-256(token)` — never the raw
  token** — looked up by that hash and then compared in constant time.
  A fast hash is correct here: against 256 bits of uniform randomness there is
  nothing to guess, so a slow KDF per lookup would be pure DoS surface. Single
  use is enforced as one atomic conditional update, never read-then-write.
  Invalidated on use, on any password change, and on email change; every other
  outstanding token for the subject dies with it. **The link is always sent to
  the stored verified address, never to the address the request supplied.**
  Response and timing identical whether or not the account exists.
- Optional by design — a passwordless account is a first-class state, not a
  degraded one (§5, §7).
- **Peppered by encrypting the digest, not by concatenating a secret into it:**

  ```
  digest = argon2id(NFC(password), salt, m, t, p)
  stored = AES-256-GCM(pepper_key_v, nonce, digest,
                       AAD = user_id ‖ credential_id)
  ```

  An attacker with a database dump and no application secret cannot mount an
  offline attack at all. Two properties follow that `argon2id(password ‖ pepper)`
  cannot give:

  **It can be rotated.** Concatenation and HMAC are one-way, so re-deriving under
  a new pepper needs the plaintext password — which exists only during a login.
  A pepper that cannot be rotated cannot be rotated *in response to a
  compromise*, which is the one moment it matters. Encryption makes rotation a
  batch job: decrypt with `v`, re-encrypt with `v+1`, no plaintext and no forced
  reset. The key is transit-wrapped and cached in-process under a capped TTL,
  exactly as ADR-041 does for subject keys — never an environment variable, which
  would be a second key-custody system beside the one ADR-028 exists to be.

  **The AAD binds the row.** §4.2's claim that an attacker with write access
  "cannot construct a hash that will verify" holds only with it. They need not
  forge anything: they can copy their *own* valid credential row onto the
  victim's and log in with a password they chose. GCM authentication fails when
  the ciphertext moves to a different `user_id`, and that is what actually
  prevents it.

  Every credential row carries `pepper_key_version`. Rehash-on-login treats a
  stale version as degraded, so the batch job has a mop-up path for accounts it
  missed. **The old transit key must not be destroyed until that job reports zero
  rows at the old version** — destroying it early permanently locks out every
  un-migrated user, and unlike an erasure that is not a feature.

### 4.1 Compromised-credential detection — a lifecycle, not a signup check

Screening only at set-time is the common half-measure: a password that was clean
when chosen appears in a corpus published two years later, and nothing notices.
Detection therefore runs at **three** points.

| When | Mechanism | Response |
| --- | --- | --- |
| **At set / change** | k-anonymity range query — SHA-1 prefix (5 chars) sent, never the password or full hash | Reject with a specific reason; the user picks another |
| **At every successful login** | Same check, on the plaintext we hold for that instant only | Accept the login, then **force rotation** (below) |
| **On new corpus publication** | Re-screening workflow over `password_screened_at` watermarks | Flag affected users, force rotation on next login |

**Login-time screening is the load-bearing one.** The stored value is a peppered
argon2id hash and cannot be tested against a corpus offline — the single moment
the plaintext exists is during verification. That instant is the only opportunity
to re-screen an existing credential, so it is taken.

Rules for that check:

- **Never block the login itself.** The credential is correct; the user is
  legitimate. Locking them out hands an attacker a denial-of-service by proxy
  and trains users to distrust the system.
- The session is created but marked `RequiresCredentialRotation`, which
  restricts it to profile and credential endpoints until the password is
  changed — the same mechanism as `PendingSecondFactor` (§3), reused rather than
  reinvented.
- Grace period is org policy: immediate for admins and owners, up to N days for
  members.
- The plaintext is screened and discarded; nothing about it is stored beyond
  `password_screened_at` and the corpus version.
- Screening failure (breach service unreachable) **fails open** with a logged
  metric. This is the opposite of OpenFGA (ADR-010) and deliberately so: this
  check protects the user from their own weak password, it is not an
  authorization boundary, and failing closed would lock out the entire user base
  on a third-party outage.

**Credential stuffing** is a separate control from corpus screening and must not
be conflated: it is detected by *rate and distribution* — many accounts probed
from one origin, or one account from many origins — and handled by progressive
delay and anomaly response (§11), not by password quality.

### 4.2 Credential tamper detection

Two independent integrity controls, because the threat is an attacker who has
reached the database rather than the login form.

**1. Peppered hashes make forgery useless.** Without the application pepper, an
attacker with `INSERT`/`UPDATE` on the credential table cannot construct a hash
that will verify. Direct row manipulation produces a credential nobody can
authenticate with, rather than a backdoor.

**2. The event log is the integrity oracle — and this is nearly free.** Every
credential is *derived state*: a projection of `PasswordSet`, `PasswordChanged`,
`PasskeyRegistered`, `FederatedIdentityLinked` and their removals (ADR-013).
Therefore:

> Any credential row that disagrees with the state obtained by replaying that
> user's event stream **was written outside the application**. There is no benign
> explanation.

A reconciliation job replays credential-affecting events and compares the derived
set against `auth_method_view`. Divergence means one of:

- a credential present in the table but with no originating event → **injected**
- a credential in the log but absent from the table → **deleted**
- a hash differing from the one the log's event produced → **substituted**

Any of the three raises a security incident, revokes the affected user's
sessions, and notifies them. Detection also covers a **rollback attack** —
restoring an old row to reinstate a revoked credential — because the log's later
removal event still exists.

Also verified continuously:

- `SessionCompromiseDetected` on refresh-token reuse (ADR-018) is the equivalent
  control for sessions.
- Argon2 parameters below the current policy minimum are treated as degraded and
  rehashed on next login.
- Credential changes with no corresponding authenticated session in the audit
  trail are flagged, catching a mutation that bypassed the API entirely.

---

## 5. WebAuthn / passkeys

- **Registration**: discoverable (resident) credentials for usernameless login;
  `userVerification: preferred`; attestation `none` by default, `direct` when an
  org policy demands AAL3.
- **Authentication**: both usernameless (discoverable) and identifier-first
  flows.
- Multiple authenticators per user, each with a user-assigned name, created-at,
  last-used-at, AAGUID-derived model label, and independent revocation.
- Signature counter checked when the authenticator provides a non-zero one;
  **not** treated as mandatory, because most synced passkeys never increment it.
  A regression here locks out legitimate users.
- Removal is guarded by `AtLeastOneUsableMethod` and requires step-up.
- **Lockout risk is the real design problem**: a user whose only method is a
  passkey on a lost device must still recover. Recovery codes are therefore
  issued at first passkey registration, not offered as an afterthought.

---

## 6. Multi-account and multi-session

Two features that look alike in the UI and are completely different underneath.
Conflating them is a data-leak vector.

| | Account switcher | Organization switcher |
| --- | --- | --- |
| What changes | **Which `User` you are** | Which org one user is acting in |
| Owned by | `identity` | `organization` / `workspace` |
| Sessions | **N independent sessions** | one session |
| Re-auth to switch | no, if that session is `Active` | no |

### The session ring

The browser holds N independent sessions plus a pointer to the active one.

- **One cookie per account** — `__Host-sid.<opaque-ref>` — so revoking one
  cannot affect another, and no single cookie contains a joinable set of
  identities.
- A separate `active-account` selector cookie names which ref is current.
- Adding an account runs a full authentication flow **without disturbing
  existing sessions**.
- Removing one revokes only that session.

### Isolation invariants — each is a test

1. A request resolves to **exactly one** account; a request naming two is
   rejected outright.
2. CSRF tokens are per-session, never shared across the ring.
3. Cache keys, rate-limit keys and idempotency keys are **namespaced by session**
   — a shared key across accounts is a cross-account leak.
4. Step-up applies to one account only; elevating account A must never elevate B.
5. Every audit record names the acting account, never "the browser".
6. Revoking A leaves B `Active`; logout-everywhere for A leaves B untouched.

---

## 7. Federated identity

**Providers:** Google, Microsoft, Apple (OIDC) · GitHub (OAuth2 + user API).

All flows use authorization code + **PKCE** (S256 only, never `plain`), `state`
(CSRF), `nonce` (replay), the **`iss` parameter (RFC 9207)**, and a strict
redirect-URI allowlist with exact string matching.

`iss` is not optional here. Chronos federates to four authorization servers from
one client, which is exactly the multi-AS condition RFC 9700 §4.4.2 addresses:
without binding the intended issuer to the user agent for each request, a mix-up
attack redirects a code issued by one provider into an exchange with another.

PKCE and `nonce` defend different attacks and neither replaces the other. `nonce`
is a client-side check on an ID token; PKCE is enforced by the authorization
server and is the only thing binding a stolen code to the session that requested
it. GitHub issues no ID token at all, so PKCE is the only code binding available
there.

### Provider-specific realities that must be coded for

| Provider | What bites you |
| --- | --- |
| **GitHub** | No OIDC `id_token`. Email comes from the user API and **may be unverified or private** — must call the emails endpoint and read the `verified` flag. |
| **Apple** | **`name` only on first authorization**, in the form-POST body, never in the ID token — persist immediately or it is gone forever. `email` returns on every sign-in, but only if the `email` scope was requested on the *first* authorization; otherwise never. Email may be a **private relay** address, unique per app and **revocable**, after which mail to it bounces permanently. `email_verified` serialises as string *or* boolean — parse both. Requesting scopes forces `response_mode=form_post`, so the redirect arrives as a **cross-site POST** and needs its own `SameSite=None; Secure` state cookie. The `client_secret` is an **ES256 JWT expiring within 6 months** and must be regenerated on a schedule. |
| **Microsoft** | **`email` is NOT verified and `email_verified` is not trustworthy** — see the rule below. Identity is **`tid` + `oid`**, never `sub` (pairwise per-app), never `upn`, never `email`. `preferred_username` is user-mutable and reassignable; there is no safe fallback to it. |
| **Google** | `email_verified` is reliable for consumer accounts; for Workspace it means "the domain admin says so". Identity is `sub` — it survives an email change, and email does not. Hosted-domain (`hd`) claim is useful for org domain matching. |

### Account linking — the takeover vulnerability

This is the single most dangerous flow in the domain.

> **Never auto-link a federated identity to an existing account on email match
> alone.**

The attack: an attacker registers at a provider using the victim's email address,
the provider does not verify it, the attacker signs in, and naive matching hands
them the victim's account.

**Rules:**

1. Auto-link **only** when the provider asserts `email_verified = true` **and**
   the local account's email is already verified **and** the provider is on the
   trusted-verification list.

   **The trusted list is: Google, and Microsoft Entra only when the optional
   `xms_edov` claim is true.** Nothing else.

   > **Microsoft does not qualify on its standard claims, and believing it does
   > is an account-takeover path.** Entra's `email` claim is not verified and
   > Entra emits no trustworthy `email_verified`. Anyone can create a free Entra
   > tenant, set `mail` on a user they control to the victim's address, and be
   > handed the victim's account. This is **nOAuth**, disclosed in June 2023 and
   > still found in 9 of 104 Entra Gallery applications in 2025. The victim's
   > MFA, conditional access and Zero Trust policies are all irrelevant, because
   > the attack never touches their tenant. `xms_edov` (email-domain-owner
   > verified) is the only verification signal Entra offers, and it must be
   > configured on the app registration to be emitted at all.

   GitHub's unverified emails never qualify, and neither do its
   `@users.noreply.github.com` addresses — those are `verified: true` but are not
   deliverable mail. Apple private-relay addresses never qualify as a contact
   address, because the user can revoke them.
2. Otherwise, sign-in creates **no link**. The user must authenticate with an
   existing method and link explicitly from settings.
3. Linking while authenticated requires **step-up** and a **fresh
   re-authentication** — not an elevated session inherited from earlier in the
   session's life.
4. A provider identity (`issuer` + `subject`) links to **at most one** user.
5. Matching is on the provider's immutable identifier, never on email. That
   identifier is `sub` for Google and Apple, the numeric `id` for GitHub, and the
   **`tid` + `oid` tuple** for Entra. Apple's `sub` is scoped to the developer
   *team*, so one person across two teams is two subjects.
6. **`email_verified` is tri-state, not a boolean**: `verified`, `unverified`, or
   `not asserted`. Entra and GitHub-noreply are "not asserted", which is not the
   same as `false` and must never silently become it.
7. **When an identifier transitions to verified — and on any password reset or
   recovery — void every session, every pending identifier change, and every
   authentication method not proven by the acting party.** This closes the
   *pre-account-takeover* ordering attack, where the attacker registers on the
   victim's address first and waits: without this rule they retain a live
   session, a planted recovery identifier, or a pending email change that
   survives the victim taking ownership.

### De-linking

Requires step-up; guarded by `AtLeastOneUsableMethod`. Removing the last
federated link from a passwordless account is refused with an actionable error
telling the user to set a password or register a passkey first.

### Social signup ends passwordless — by design

A user who signs up with Google has no password and does not need one. If they
later want one:

- They are **already authenticated and email-verified via the provider**, so
  this is a *set* operation, not a *reset*: step-up, then set. No email round
  trip, because sending a reset link to an address the provider already verified
  adds friction without adding assurance.
- If unauthenticated and they only remember "I used Google", the login screen
  detects existing federated links for that email and says so, rather than
  failing opaquely — a common dead end.

---

## 7.5 Duplicate accounts, merge, and recovery

### Account merge (review D1)

Refusing to auto-link (§7) is correct — and it creates duplicates. Someone signs
up with email + password, later signs in with Google on the same address, and now
owns two accounts with data on both. This is one of the most common real-world
identity situations, and it worsens with time.

**Detection is at sign-in, not later.** When a federated identity resolves to an
address that already has an account and auto-link is refused, the response says
so explicitly rather than silently creating a second user.

The merge flow:

1. The user **proves control of both**: authenticate with the existing method,
   then complete the provider flow. Neither alone is sufficient — one-sided proof
   is the account-takeover path §7 exists to close.
2. **Step-up to AAL2** is required.
3. A `surviving` and a `merged` account are chosen; surviving is the older by
   default and the user may override.
4. Transfer under the surviving `SubjectID`: authentication methods, org and
   workspace memberships, team memberships, API keys, and access grants.
5. **Conflicts are refused, not guessed** — if both accounts are members of the
   same org with different roles, the merge halts and asks. Silently picking the
   higher role is a privilege-escalation bug.
6. The merged account's sessions are **all revoked**; its identifiers are
   released (below); the merge is audited on both streams and both addresses are
   notified.

Merge is a **Temporal workflow** — it spans multiple aggregates and several
reservation releases, and must not half-happen (ADR-017).

### Identifier reuse after erasure (review D3)

Erasure destroys the subject key, so the blind index is meaningless and the
uniqueness reservation is released (EVENT-SOURCING §5). The address becomes
claimable again and a returning person gets a **fresh `SubjectID`** with no link
to the erased one.

The alternative — blocking the address permanently — would require retaining
exactly the identifier erasure was meant to remove.

### Last-resort recovery (review D4)

Every factor lost: password forgotten, passkeys gone with the device, recovery
codes lost. Operators cannot impersonate (operator.md §6), so there must be a
designed path or the first occurrence becomes an unaudited database edit.

**Tiered, so support is not the common case:**

| Who is locked out | Who recovers them |
| --- | --- |
| Workspace member or guest | a **workspace admin** triggers a verified reset |
| Workspace admin | an **org admin** |
| Org admin | the **org owner** |
| **Org owner** | **operator**, with identity verification |

Rules for every tier:

- A reset **invalidates all existing factors** and forces re-enrolment; it never
  reveals or reuses a credential.
- The account holder is notified on the verified address, and the acting party is
  recorded — so a malicious admin cannot reset an account invisibly.
- A **mandatory delay** (24h default, org-configurable) before the reset takes
  effect, cancellable by the account holder. This is what stops a compromised
  admin session from instantly seizing a colleague's account.
- Time-boxed, single-use, fully audited.

Only the org owner has nobody above them, which is the sole case that reaches
operators — and it is exactly the case where identity verification is worth the
support cost.

---

## 8. Native and headless clients

- **RFC 8252 (OAuth for Native Apps)**: authorization code + PKCE, **no client
  secret** (it cannot be kept secret in a distributed binary).
- **System browser only** — `ASWebAuthenticationSession` / Custom Tabs. Embedded
  webviews are rejected: they let the host app observe credentials and break
  passkeys and provider SSO.
- Redirects: claimed `https` App Links / Universal Links preferred; custom scheme
  accepted; **loopback `127.0.0.1:<random port>`** for desktop.
- **RFC 8628 (Device Authorization Grant)** for CLI and TV: user code + polling,
  with rate-limited polling and a short user-code lifetime.
- Refresh-token rotation applies identically (ADR-018). Tokens live in Keychain /
  Credential Manager / libsecret, never in plain files.
- Each device registers a name and platform so it is identifiable in the session
  list (§9).

---

## 9. Session visibility and revocation

The user-facing surface behind "which device, where, when".

Per session: device name and platform, client type (web/mobile/desktop/CLI), IP,
**coarse** geolocation (city-level — precise location is unnecessary personal
data), created-at, last-seen-at, current AAL, and whether it is *this* session.

Actions: revoke one · revoke all others · revoke all · rename device · mark
device trusted.

- Revocation takes effect **immediately** on the refresh path and within the
  access-token TTL (10 min) otherwise; emergency revocation uses the Valkey
  denylist for instant effect (ADR-018).
- Revocation also drops the Centrifugo connection, so realtime does not outlive
  the session.
- IP and geolocation are **personal data**: stored in the PII vault, referenced
  by pseudonym, and covered by erasure (ADR-002, ADR-013).

---

## 10. API keys and service accounts

Two distinct principals. Conflating them is why automation breaks when an
employee leaves.

| | Personal Access Token | Service Account |
| --- | --- | --- |
| Acts as | the user, scoped down | its own principal |
| Owned by | a user | an org or workspace |
| On user departure | dies with the user | survives |
| Use for | scripts, personal CLI | integrations, CI, automation |

### Key format

```
chr_<env>_<keyid>_<secret>
     │      │       └─ 256-bit random, shown once, never stored
     │      └───────── public lookup id → O(1) index, no hash scanning
     └──────────────── enables secret scanners and leak-response automation
```

- Stored as **HMAC-SHA256 with a server-side pepper**, not argon2id. The secret
  is already 256 bits of entropy, so a slow KDF buys nothing and would put a
  deliberate CPU cost on every API request.
- Constant-time comparison.

### Organization scope is mandatory (review D2)

> **Every key is bound to exactly one organization at creation, immutably.**

A user may belong to several orgs. Without this binding a key silently inherits
*all* of them, so a token leaked from one customer's CI reaches another
customer's data — a cross-tenant breach originating from a feature nobody
thought was tenant-scoped.

- The org is chosen at creation and **cannot be changed**; moving scope means a
  new key.
- If the owner loses membership of that org, the key is **revoked
  automatically** — a reactor on `MemberRemoved`.
- The key's effective permission is the intersection of its scopes, its
  principal's access, **and** its bound org.

### Controls

- **Scopes** (coarse capability: `workspace:read`, `members:write`) **plus**
  OpenFGA ACL (fine, per-resource). A key's effective permission is the
  **intersection** of its scopes and its principal's access — a key can never
  exceed the principal that created it.
- Mandatory expiry with a policy-capped maximum; rotation with an overlap window
  so rotation needs no downtime.
- Optional IP allowlist; per-key rate limits; `last_used_at` and last-used IP.
- Secret shown exactly once at creation.
- Revocation is immediate — API keys have no cached-token equivalent.
- Leak response: revoke, then produce the audit trail of everything that key
  touched.

---

## 11. Risk, anomaly and abuse controls

- Progressive delay on failed attempts, per-account **and** per-IP. Deliberately
  *not* a hard lock — that is a trivial account-denial vector.
- New device, new country, impossible travel → notify, and optionally require
  step-up under org policy.
- Credential stuffing: breach corpus check, per-IP limits, and identical
  response shape and timing for existent and non-existent accounts.
- Enumeration resistance across **registration, login, reset and invitation** —
  all four leak account existence if written naively.
- Every attempt, success or failure, is an event feeding the audit trail
  (`compliance`).

---

## 12. Identifier and email lifecycle

- Email normalized (lowercase, Unicode NFC) with a uniqueness constraint on the
  normalized form; plus-addressing preserved, never stripped.
- The email itself is **personal data**: PII vault, blind index for lookup
  (ADR-012).
- **Email change** verifies the *new* address before switching, notifies the
  *old* address, and allows a revert window — otherwise an attacker with a
  hijacked session silently takes ownership.
- Verification tokens: single-use, expiring, constant-time lookup, invalidated on
  email change.

---

## 13. Events published

`UserRegistered` · `EmailVerificationRequested` · `EmailVerified` ·
`EmailChangeRequested` · `EmailChanged` · `PasswordSet` · `PasswordChanged` ·
`PasswordResetRequested` · `PasskeyRegistered` · `PasskeyRemoved` ·
`TotpEnabled` · `TotpDisabled` · `RecoveryCodesGenerated` ·
`RecoveryCodeConsumed` · `FederatedIdentityLinked` · `FederatedIdentityUnlinked`
· `AuthenticationSucceeded` · `AuthenticationFailed` ·
`SecondFactorChallenged` · `SecondFactorSucceeded` · `SessionCreated` ·
`SessionElevated` · `SessionRevoked` · `SessionExpired` ·
`SessionCompromiseDetected` · `DeviceRegistered` · `DeviceTrusted` ·
`ApiKeyCreated` · `ApiKeyRotated` · `ApiKeyRevoked` · `ApiKeyUsed` ·
`ServiceAccountCreated` · `UserDeactivated` · `UserSuspended` ·
`UserDeletionRequested`

**Every one carries `SubjectID` pseudonyms only** — no email, no IP, no device
name, no user agent in the payload (ADR-002). Those live in the PII vault,
joined at projection time.

---

## 14. Read models

| Projection | Serves | Key indexes |
| --- | --- | --- |
| `user_view` | profile, status | `(normalized_email_blind_index)` unique |
| `auth_method_view` | the security settings screen | `(user_id, method_type)` |
| `session_view` | device list | `(user_id, status, last_seen_at DESC)` |
| `linked_account_view` | connected providers | `(issuer, subject)` unique |
| `api_key_view` | key management | `(key_id)` unique, `(owner_id, status)` |
| `login_history_view` | "recent activity" | `(user_id, occurred_at DESC)` |
| `auth_attempt_counter` | rate limiting (Valkey, TTL) | — |

---

## 15. Ports

**From the kernel:** `Clock` · `IDGen` · `Random` · `KeyRing` · `pii.Vault` ·
`Publisher` · `Mailer` · `Workflow` · `access.Checker`

**Declared by this domain** (ADR-001 — declared by the consumer, implemented in
adapters):

```
PasswordHasher      Hash / Verify / NeedsRehash
BreachChecker       IsBreached(password) — k-anonymity
TotpVerifier        Generate / Verify with drift window
WebAuthnRelyingParty  BeginRegistration / FinishRegistration / BeginLogin / FinishLogin
FederatedProvider   AuthorizeURL / Exchange / Identity  — one impl per provider
TokenIssuer         IssueAccess / IssueRefresh / Rotate / Verify
DeviceResolver      user-agent + hints → device name, platform
GeoResolver         IP → coarse location
```

`FederatedProvider` is the important one: four providers behind one interface, so
their differences (§7) are contained in adapters and the domain sees a uniform
`FederatedIdentity{Issuer, Subject, Email, EmailVerified, DisplayName}`.

---

## 16. Temporal workflows (ADR-017)

| Workflow | Why |
| --- | --- |
| `EmailVerificationWorkflow` | expiry + reminder + escalation over days |
| `PasswordResetWorkflow` | expiry, single-use enforcement, notification |
| `SessionReaperWorkflow` | idle and absolute timeout sweeps |
| `ApiKeyExpiryWorkflow` | pre-expiry warning, rotation nudge, disable |
| `SuspiciousLoginWorkflow` | notify → await response → escalate to revoke-all |
| `AccountDeletionWorkflow` | grace period, then hand off to `compliance` erasure |

---

## 17. What this domain does **not** own

- **Any permission decision** → `access`
- **Org membership and policy** → `organization`; **workspace membership, teams,
  invitations** → `workspace` (ADR-020)
- **Consent records, DSAR, erasure execution** → `compliance`
- **Email delivery** → `notification` (identity publishes; it does not send)
- **Seat limits gating registration** → `entitlement`

---

## 18. Test plan (TDD)

**Domain — pure, no infrastructure:**
- Session state machine as an exhaustive transition table, including every
  *illegal* transition
- `AtLeastOneUsableMethod` against every removal permutation
- AAL computation per method combination
- Account-linking decision matrix: `{provider trusted?} × {provider email
  verified?} × {local email verified?} × {existing link?}` — the full grid, with
  the takeover case asserted as **refused**

**Concurrency — `testing/synctest` (Go 1.26):**
- Concurrent refresh rotation: exactly one wins, the loser triggers reuse
  detection
- Session expiry races against active use
- Simultaneous logins from N devices

**Integration — against the running stack:**
- Session revocation propagates to Centrifugo
- RLS negative test: another tenant cannot read these sessions
- Each federated provider against its recorded fixtures

**Security regression suite — every one an assertion, not a checklist item:**
- `PendingSecondFactor` token is rejected by every RPC except second-factor
  verification
- Account-switch isolation (all six invariants in §6)
- Enumeration: identical response and timing across all four leaking surfaces
- API key cannot exceed its creating principal's permissions

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
| `Active` | step-up satisfied | `Active`, elevated (see below) | AAL requirement met |
| `Active` | `elevated_until` passes | `Active`, no longer elevated | automatic, by clock |
| `Active` | idle > 14d, or absolute > 30d | `Expired` | |
| `Active` | user revokes / password changed | `Revoked` | |
| any | retired refresh token replayed | `Compromised` | ADR-018, from ANY state |

**Elevation is ATTRIBUTES on an active session, not a state.** The diagram above
draws `Elevated` as a peer of `Active`; that is the older design and the
implementation does not follow it. A session carries `(aal, elevated_scope,
elevated_until)`, and elevation sets all three.

The reason is that a single state cannot answer the question the gate actually
asks. "Elevated" alone cannot express *elevated to AAL2 while this action needs
AAL3*, and it cannot express *elevated in order to change an email, which does
not authorize deleting the account* — elevation must be scoped to the ceremony
that produced it, or one step-up becomes a skeleton key for every sensitive
operation in the session's remaining life.

`elevated_until` is clamped to the session's own absolute deadline
(`LEAST($4::timestamptz, absolute_expires_at)`), so an elevation cannot outlive
the session it elevates. It is deliberately **not** carried in any access token:
a 10-minute token holding a 5-minute elevation would outlive its own window, and
the window is the entire control.

The `Compromised` transition is reachable from **every** state, not only from an
elevated one — the diagram's single arrow is a drawing artifact, and reading it
as the rule would leave replay undetected for ordinary sessions, which are the
overwhelming majority.

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
  degraded one (§5, §7). **Every account passes through it.** Registration takes
  an address and nothing else; the first password is supplied to `VerifyEmail`,
  by whoever follows the link that was mailed to that address. See §4.3.

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

### 4.3 The first password is set by whoever proves the mailbox

**`Register` creates no credential.** It claims the address, creates a Pending
account and asks for the address to be proven. `VerifyEmail` takes the token AND
the password, and creates the credential in the same request as the proof.

This is the fix for **IDENTITY-REVIEW C8** (pre-hijacking, Sudhodanan & Paverd,
USENIX Security 2022), which was executed end to end against the running system
before it landed. The attack:

1. The attacker registers the VICTIM's address with a password of their own.
2. The victim receives a verification mail they never asked for — an ordinary
   mail from a real service — and follows it, believing they are finishing their
   own signup.
3. Verification proves control of the MAILBOX. It does not prove that whoever
   set the password controls that mailbox.
4. The attacker signs in with the password only they know. The bootstrap
   carve-out (§2) admits them at AAL1 and that session enrols their own
   authenticator.

The paper's own rule — on verification, void every session and every credential
not proven by the verifying party — **cannot be applied here**: there is no
password-reset flow, so voiding the password locks out every legitimate
registrant. Removing the premise costs nothing by comparison, because the
credential that would be voided never exists.

Three independent layers carry it:

| Layer | Rule |
| --- | --- |
| Wire | `RegisterRequest` has no password field; field 2 is reserved so one cannot reappear at the same number |
| Aggregate | `domain.User.SetPassword` refuses a password while `email_verified` is false, so any other route inherits the rule |
| Authentication | A passwordless account has no usable credential, so the bootstrap carve-out has nothing to admit |

**Screening runs before the token is spent.** Length and the breach corpus are
checked on the submitted password before `Consume`, so a person who picks a weak
password keeps their link. That is not a guessing surface: both refusals are
functions of the caller's own bytes and consult neither the token nor the
account, and a wrong token still fails at `Consume` identically. Everything
after `Consume` — the hash, the credential write, the append — does spend the
token, and the recovery is `ResendEmailVerification`, which still admits the
account because nothing was appended.

**What this does not fix.** An attacker can still CLAIM an address they do not
own and deny it to its real owner until the reservation lapses
(`DefaultReservationLease`, 48h). Registration's indistinguishability means the
real owner is told nothing actionable. That is a denial of service on one
identifier, bounded and self-clearing — strictly less than takeover, and not
zero. Closing it needs a control registration does not have today: proof of
intent before the claim, or a shorter unverified lease.

### 4.4 The revocation rule every future credential flow inherits

**When an identifier becomes verified — and on any password reset or recovery —
void every session, every pending identifier change, and every identifier not
proven by the acting party.**

This is the remaining rule from Sudhodanan & Paverd, and it covers the three
variants §4.3 did not: **unexpired session** (the attacker keeps a live session
across the victim's recovery), **trojan identifier** (the attacker pre-attaches
an identifier or federated link that survives it), and **unexpired email change**
(a pending change survives it).

`VerifyEmail` already enforces it: it calls `RevokeAllSessions` for the subject,
with no `Except`, before it appends. **Today that call revokes nothing** — a
pre-verification account has no credential, so no session can exist — and that is
precisely why it was written now. The rule is free while it is a no-op and
expensive to retrofit once it is not.

The three variants are currently **unreachable, and only because the flows they
attack do not exist**: there is no password reset, no email change and no
federated linking in this module — no RPC, no use case, no event. That is not a
mitigation, it is an absence, and it expires the day any of them is built. Each
one carries the requirement in its own section (§4.5, §7, §12) rather than only
here, because a rule recorded far from the code that must obey it is a rule that
gets missed.

### 4.5 Password reset — NOT BUILT, and what it must do on arrival

There is no reset flow. When one is written it MUST, in the same transaction as
the credential change:

- **Void every session for the subject**, including the one performing the reset
  if it predates the proof. A reset exists because control may have been lost;
  keeping any prior session is assuming the opposite.
- **Void every pending identifier change**, or an attacker's queued email change
  survives the recovery and re-takes the account afterwards.
- **Void every outstanding token of every purpose** for that subject, not only
  reset tokens.
- **Never bypass the second factor** (ASVS 5.0 V6.4.3). This is the most commonly
  broken requirement in the set, and breaking it converts "attacker controls the
  mailbox" into full account takeover.
- **Send the link to the STORED verified address**, never to an address the
  request supplied.

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

- **One cookie per account** — `__Host-sid.<opaque-ref>` — so revoking one cannot
  affect another, and overwriting one cannot clobber another.

  This used to add "and no single cookie contains a joinable set of identities",
  which **does not follow and must not be relied on**. The browser sends every
  matching cookie on every request, so the server receives the joinable set
  regardless of how it is split; splitting hides nothing from anyone who can see
  one request. The real justification is the one above — independent revocation
  and independent overwrite — and it is sufficient on its own. The wrong reason
  is called out rather than quietly deleted because someone who later refutes it
  might "optimise" back to a single cookie, having disproved an argument that was
  never load-bearing.

- A separate `active-account` selector cookie names which ref is current, and it
  is a **UI hint with no authority**. The request MUST name the account it acts
  on; the server resolves that name against the cookies actually presented.
  Trusting the selector as the sole authority makes **cookie tossing** an account
  switch: any subdomain — including one served by a third party, or taken over —
  can set a cookie the parent domain will send, and the victim then acts on an
  attacker-chosen account. The selector therefore also carries `__Host-` (which
  forbids `Domain=`, so a subdomain cannot write it), and the CSRF token is
  validated against the account the REQUEST names, not the one the cookie points
  at.

- The ring is **capped**. An uncapped ring is an unbounded `Cookie` header on
  every single request, which is a self-inflicted request-size problem that grows
  with how much someone uses the product.

- Adding an account runs a full authentication flow **without disturbing existing
  sessions**.
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

> **NOT BUILT.** There is no federated linking in this module today — no RPC, no
> use case, no event. That absence is the only reason C8's **trojan identifier**
> variant is currently unreachable, and it expires the moment linking is written.
>
> **On arrival, linking MUST obey §4.4.** Specifically: a federated link attached
> to an account the linking party has not proven control of is a trojan
> identifier — the attacker attaches their own provider identity to the victim's
> account and it survives every later recovery, because a reset changes the
> password and leaves the link alone. So a link may only be created by a session
> that has proven the account (never by an unauthenticated callback alone), and
> any password reset or recovery MUST void links not proven by the acting party.

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
  **`last_used_at` is a coalesced projection write, at most once per key per
  minute, and is NOT an event** — see §13. It is deliberately approximate: the
  screen answers "is this key still in use?", which a minute's resolution
  settles.
- Secret shown exactly once at creation.
- Revocation is immediate — API keys have no cached-token equivalent.
- Leak response: revoke, then produce the audit trail of everything that key
  touched. **That trail is `compliance`'s, not this module's** — it is sized and
  retained for request volume, which the event log is not (§13).

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

  **NOT BUILT** — no RPC, no use case, no event — and that absence is the only
  reason C8's **unexpired email change** variant is unreachable today. On
  arrival it MUST obey §4.4, in both directions:

  - Re-verifying the new address runs through `VerifyEmail`, which already voids
    every session for the subject. That is what defeats the *unexpired session*
    variant here, and it is already enforced rather than pending.
  - A password reset or recovery MUST void any PENDING change. Otherwise an
    attacker queues a change to their own address, the victim recovers the
    account believing they have secured it, and the queued change completes
    afterwards and hands it back.
- Verification tokens: **looked up by `SHA-256(token)`, never stored in the
  clear**; single-use, expiring, invalidated on email change.

  This previously said "constant-time lookup", which is not implementable and
  hid the rule that matters. You cannot do a constant-time lookup through a
  B-tree index and you do not need to: the token is 256 bits of uniform
  randomness, so there is nothing to guess and no candidate list to search.
  A **fast** hash is therefore correct here, and is not something to "harden"
  into a KDF later — ASVS 5.0 V6.5.2 settles it ("a standard hash function can
  be used if the secret has 112 bits of entropy or more"), and a slow KDF on a
  token lookup is pure denial-of-service surface for no security gain.

  Single-use is enforced by a single `DELETE … WHERE digest = $1 AND purpose =
  $2 AND expires_at > $3 RETURNING subject_id` (`ConsumeToken`), not by
  read-then-write: two simultaneous clicks of one link would otherwise both find
  it valid. The expiry is checked in that same statement so an expired token is
  indistinguishable from an unknown one — reporting "valid but expired" would
  confirm that the address it was sent to has an account.

### 12.1 Resending a verification link

A verification link lives 24 hours, is single-use, and every issuance revokes
every earlier one. Without a resend path a person who lost the mail, waited a
day, or clicked a link a later issuance had already voided is locked out of an
account they cannot re-register — the address is claimed by the account they
cannot reach. `ResendEmailVerification` closes that.

**It is public.** A Pending account holds no session (§1), so requiring one would
make the call unavailable to every account that needs it. The cost of being
public is paid by the two controls below rather than by an authentication.

**It appends an event, it does not send mail.** `ResendEmailVerification` writes
`EmailVerificationRequested` to the account's own stream and returns. The
verification reactor mints the token, revokes every outstanding one and sends the
link, exactly as it does after a registration — so there is one code path for "a
link was sent", one place the revoke-first ordering is written down, and no
request handler ever holds a plaintext token.

**Five outcomes, one response.** No account claims the address; the account is
Pending and a request was appended; the account has already verified; the account
is deactivated or suspended; a concurrent write won the stream. Only the second
appends anything, and all five return the same zero bytes. The residual
distinction is **timing** — the appending path performs one store round trip the
others do not — and it is bounded by the per-address ceiling rather than closed:
separating a few milliseconds from network jitter needs many samples of the same
address, and the ceiling permits three an hour.

**Revoking somebody else's live link is a bounded nuisance, not a takeover.**
Anyone who knows a Pending address can trigger an issuance, and that issuance
voids the link already in the victim's mailbox. The replacement is mailed to the
same mailbox, so no attacker gains anything redeemable; what they gain is the
ability to invalidate a link the victim was about to click, at most three times
an hour. The alternative — not revoking — leaves two live links for one address,
which is the property `identity.md §7 rule 7` forbids and is strictly worse.

**Rate limited on two axes, both spent before the account is looked up.** Per
address, keyed by the blind index (never the address itself — a cache is a
projection with a shorter life, and ADR-002 applies to it unchanged). Per caller,
keyed by the caller's network address (below). Both counters are consumed whether
or not an account exists, so the ceiling itself is not an oracle, and the caller's
budget is spent first so a sweep cannot exhaust a thousand victims' budgets on its
way to being refused. The numbers live in `cmd/api/identity.go`; the ceiling
**fails open** and says so, because failing closed would turn a Valkey blip into
permanent account loss for everyone who registered during it.

#### Which address the per-caller ceiling counts against

The connection's peer address, plus as much of `X-Forwarded-For` as the operator
has declared trustworthy. `API_TRUSTED_PROXY_HOPS` is that declaration and it
**defaults to 0**, which means the header is not read at all — an unconfigured
deployment behaves exactly as one with no such setting. The rules are owned by
`internal/platform/clientip` and are, in full:

- **Entries are counted from the RIGHT.** With N trusted hops the client is the
  Nth entry from the end, because the rightmost entries were appended by our own
  infrastructure and everything to the left of them was written by the caller.
  Taking the leftmost entry — the classic implementation — takes the value the
  attacker chose.
- **Too few entries falls back to the peer address**, never leftward. A caller
  who sends a short or absent header must not get a better outcome than one who
  sends none.
- **A malformed entry falls back to the peer address.** Each hop is parsed as an
  IP (bare, bracketed, or carrying a port); a hostname, a `for=` fragment or a
  CIDR block is not an address and buys nothing.
- **IPv6 is bucketed by its /64.** The smallest allocation anybody receives is a
  /64, so keyed on the full address a 20-per-hour ceiling is defeated at zero cost
  by anyone with an ordinary VPS. IPv4 is used whole.

**Deployment contract — set it to the number of proxies that APPEND to
`X-Forwarded-For`, and no more.** Neither mistake has a runtime symptom, and they
are not symmetric:

| Mistake | Consequence |
| --- | --- |
| Left at `0` behind a terminating proxy | Every caller shares one bucket; the per-caller rule becomes a global ceiling of 20 resends an hour for the whole deployment, and legitimate users are refused at random as traffic grows. Never exploitable. |
| Set above the real hop count | The selected entry is one the CALLER wrote. An attacker mints a fresh bucket per request to evade the ceiling, or borrows a victim's address to burn their budget. |

The value is refused above 8 at boot and logged at startup as
`trusted_proxy_hops`. See INFRA §13.1 for the topology table.

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
`ApiKeyCreated` · `ApiKeyRotated` · `ApiKeyRevoked` ·
`ServiceAccountCreated` · `UserDeactivated` · `UserSuspended` ·
`UserDeletionRequested`

**Every one carries `SubjectID` pseudonyms only** — no email, no IP, no device
name, no user agent in the payload (ADR-002). Those live in the PII vault,
joined at projection time.

### There is deliberately no `ApiKeyUsed`

It was listed here beside `ApiKeyCreated` and `ApiKeyRevoked`, and it does not
belong with them. Those record a **state change**; a key being used is not one.

Under ADR-013 the event log is permanent and is replayed in full on every
projection rebuild, so an event per API *request* makes the log grow with
**traffic rather than with state**. A single busy integration key would then
dominate the stream it shares with every account, credential and session event in
the system, and rebuild time — which is the recovery procedure for every
projection — would grow with last month's request volume. The cost is not paid at
write time, where it would be noticed, but at rebuild time, when it is least
affordable.

The two things `ApiKeyUsed` was reaching for are both real, and each has a home
that is sized for request volume:

- **`last_used_at`** (§13's key-management screen) is a **coalesced projection
  write** — at most once per key per minute, debounced through Valkey. It is
  derived, approximate by construction, and rebuildable from nothing because
  nobody needs its history. "Last used about a minute ago" is the whole product
  requirement.
- **The audit trail** §10 promises belongs in `compliance`, which is append-only
  storage designed for exactly this shape and retained on its own schedule. An
  audit record is not an aggregate's decision input, and putting it in the
  aggregate's stream conflates "what the system must replay to know the truth"
  with "what an auditor must be able to read".

Deleting it is free today because API keys are not built. It stops being free the
moment the first key exists, because by then the events are in a log that ADR-013
does not permit rewriting.

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

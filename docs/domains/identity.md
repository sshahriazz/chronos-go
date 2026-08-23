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

### 1.1 The lifecycle — BUILT, and how the reversal avoids a deadlock

`pending -> active -> deactivated -> suspended -> erased` is the state list. Some
transitions are reachable through the API and the rest are not; which is which is
a decision rather than an omission.

| Transition | Reached by | Notes |
| --- | --- | --- |
| deactivate | `DeactivateAccount`, AAL2, self-scoped | one atomic append: the account and every session on it |
| reactivate | **a completed sign-in**, not an RPC | the reversal identity.md §1 promises the holder |
| suspend | nothing, deliberately | `domain.User.Suspend` is built and tested; it acquires a caller when `operator` exists |
| deletion request | `RequestAccountDeletion`, AAL2, self-scoped | appends the event and stops; `compliance` does not exist |
| erased | nothing | `compliance` owns it (ADR-002) |

#### Deactivation is one atomic append, not two

`UserDeactivated` and every `SessionRevoked` it produces go into a single
`AppendToMany`. The two sequential orderings both fail and neither fails safe:

- **Revoke, then deactivate.** A failure leaves every session dead and the account
  on — a full sign-out the person did not ask for and nothing in the log explains.
- **Deactivate, then revoke.** A failure leaves the account off in the log and a
  live session in whoever's hands held it. **Nothing in the request pipeline reads
  an account's state** — `GetSessionByToken` joins `user_view` only to read the
  `enrolment` column — so that session keeps full API access while the person who
  switched their account off has been told it is off.

The password reset can choose an order because its two writes have a safe
direction (§4.5). A deactivation has no granting half, so there is no safe
direction and the write is indivisible instead.

**Measured, because the obvious test for this is wrong.** A `MultiStreamAppend`
returns ONE log position for the whole append, and the events read back out of
their own streams carry DIFFERENT `$all` positions — 695823 for the account event
beside 696384 and 697023 for two revocations, from one atomic write. The reported
position is the transaction's, not each event's, so "same commit position" is not
a property of atomicity and asserting it fails against a correct implementation.
What atomicity does guarantee is CONTIGUITY in `$all`, and that is what
`TestADeactivationAndItsRevocationsAreContiguousInTheLog` asserts.

The revocation spares **nothing**, including the session that asked. An account
switched off everywhere except on the device that switched it off is not what was
asked for. It does **not** sweep outstanding tokens — that is the reset's rule
(§4.4) and it belongs to a flow that exists because control may have been lost;
voiding the verification token of an account that deactivated mid-signup would
destroy the only route back into it, to defend against nothing.

A repeated deactivation records nothing on the account and **still sweeps the
sessions**, because a login whose ceremony began before the first deactivation
committed can mint a session the first sweep's work list never saw.

**The residual window, stated rather than hidden.** A deactivation racing a login
has one outcome the append cannot prevent: a login that had already loaded the
account can mint its session AFTER the revocation's work list was taken. Closing
it exactly would need a cross-stream precondition on a stream the login writes no
event to, and `AppendToMany` refuses an entry carrying only a precondition — so
the window is real. It is not a privilege gap under this design, because that
session grants nothing the same credentials could not obtain by signing in a
second later, which reactivates the account and mails the holder about it. It is
an incoherence, and the recoveries are the next `DeactivateAccount` (which is why
the idempotent path still sweeps), `RevokeAllSessions`, and the session's own
idle deadline. `TestADeactivationRacingALoginDoesNotTear` measures it and logs
the count rather than asserting one, because both answers are legal.

#### Reactivation is a sign-in, and why it cannot be an RPC

`CanAuthenticate` refused a deactivated account; every authenticated RPC needs a
session; a session needs an authentication. A `ReactivateAccount` RPC would
therefore have exactly one precondition — a session — that **its own subject can
never satisfy**, and "reversible by the holder" would be a sentence in this
document with no code behind it. That is the shape of the enrolment deadlock
(§2's bootstrap carve-out), and it is closed the same way: by admitting one more
state into the authentication, narrowly.

`domain.User.NeedsReactivation` is that admission — deactivated **and** the
address proven. Three properties bound it:

- **The ceremony is not shortened.** Every factor the account holds is still
  demanded. A deactivated account presenting a password alone is *challenged* for
  its second factor exactly as an active one is, so a stolen password cannot undo
  the step a worried owner took.
- **No session for a deactivated account is ever minted.** The bootstrap
  carve-out's mechanism cannot be reused here, because what it bounds is a
  *level* and this account's problem is a *state* — an AAL2 session on a
  deactivated account passes every declared floor in the system. So the
  reactivation is recorded in the **same atomic append** as
  `AuthenticationSucceeded`, and the account is Active before the session exists.
  The window in which the two disagree does not exist rather than being small.
- **The account stream carries a precondition.** Two simultaneous logins produce
  exactly one `UserReactivated`; the loser's whole append — its
  `AuthenticationSucceeded` included — is rolled back, and it retries against the
  reloaded stream. Bounded at three attempts, for §4.5's reason.

An **active** account writes nothing to its own stream on a successful login. An
event per login would make the account stream grow with *traffic* rather than
with state, which is why §13 refuses to record `ApiKeyUsed`.

**One state the reversal cannot reach, and why it is not reachable either.**
`domain.User.Deactivate` accepts a Pending account, and a Pending account that
deactivated before enrolling a second factor would be admitted by
`CanAuthenticate` and then refused for offering no second factor —
`NeedsFirstSecondFactor` requires Pending, so the bootstrap carve-out does not
apply to it. That account would be stuck. It is unreachable through the API:
`DeactivateAccount` declares AAL2 with no bootstrap floor, and a Pending account
cannot reach AAL2. The domain stays permissive because the operator path that
will eventually call it is not this one; the day it exists, this is the case it
must refuse.

The compensating control for "an attacker who has the credentials can undo the
deactivation" is the one the notification catalogue already anticipated:
`identity.account_reactivated`, Security class, to the subject — added on the
reasoning that "deactivation is reversible by the holder, so an attacker who has
an account's credentials can undo the very step a worried owner took."

#### Suspension has no RPC, and must not acquire one

identity.md §1 makes suspension administrative and explicitly not reversible by
the holder. Every method on `IdentityService` is reached by the account holder
acting on their own account — `api.callerSubject` refuses an API-key and a
service-account principal outright — so an RPC here could only ever be a
**self-suspension**. One call and the account is unreachable by every route this
module has: `Reactivate` refuses Suspended, `RequestPasswordReset` refuses it,
`ResendEmailVerification` refuses it, and there is no operator surface anywhere
in the repository to undo it. The authz annotation would also have to read
`relation: "self"`, which literally says "the holder may do this" — the opposite
of the rule.

`domain.User.Suspend` therefore stays built, tested and reachable by nothing, and
`TestNoRpcSuspendsOrReactivatesAnAccount` fails if a method whose name contains
`suspend` or `reactivate` is ever added to the service.

#### The deletion request stops at the handoff

`RequestAccountDeletion` appends `UserDeletionRequested` — a pseudonym, an actor,
the request time and the deadline — and does nothing else. It revokes no session,
deliberately: the grace period exists so the person can change their mind, and
signing them out of an account that still works would teach them the request took
effect immediately. It is idempotent and the **first** deadline stands, because
that is the date NOTIFICATIONS §4 says the person was mailed.

The account keeps every capability it had. There is no `deleted` state and
`user_view.state` does not move; two nullable columns
(`deletion_requested_at`, `deletion_scheduled_for`) carry it, and `GetUser`
renders them as timestamps rather than as a lifecycle position.

**What is unbuilt on the other side of the handoff**, in full:

- no `compliance` module, so no erasure and no key destruction;
- no `AccountDeletionWorkflow` (§16), so nothing runs the 30-day clock;
- no notification catalogue entry, so the "deletion scheduled for *date* —
  cancel" mail of NOTIFICATIONS §4 is not sent — and `cmd/worker`'s completeness
  guard fails until one is added;
- no cancellation command and no `UserDeletionCancelled` event, so the "cancel"
  the mail would offer has nothing behind it;
- nothing reads `deletion_scheduled_for`, so a deadline passing has no effect.

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
  by whoever follows the link that was mailed to that address. See §4.3. A reset
  cannot substitute for that link: it changes an existing password and refuses an
  account that has none.

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

**The password reset is now built, and it obeys this rule in full** — see §4.5.
That is the first flow to make the three variants reachable, and it closes all
three at the point they become reachable: it voids every session with no
exception, every outstanding token of every purpose, and any pending identifier
change, in the same command as the credential change.

**The email change is now built too, and it obeys the rule in both directions** —
see §12. Completing a change voids every session with no exception, and a
password reset voids any pending change on the aggregate as well as by killing
its token. That was the last of the three variants to become reachable: it could
not be tested before the flow existed, and it is tested end to end now.

Federated linking is the one flow that still does not exist in this module: no
RPC, no use case, no event. That is not a mitigation, it is an absence, and it
expires the day it is built. It carries the requirement in its own section (§7)
rather than only here, because a rule recorded far from the code that must obey
it is a rule that gets missed.

### 4.5 Password reset — BUILT, and what it does

Two RPCs, both public, both reached by somebody who cannot sign in:
`RequestPasswordReset` takes an address and answers nothing, and `ResetPassword`
takes the emailed token and the new password and answers nothing. The
implementation is `internal/modules/identity/app/passwordreset.go`; the reasoning
behind the three decisions the specification below did not settle is ADR-053.

The five rules this section demanded before the flow existed, and where each one
now lives:

- **Void every session for the subject**, including the one performing the reset.
  `RevokeAllSessions` with a zero `Except`, under
  `RevokeReasonPasswordReset`. Unlike `VerifyEmail`'s call this one is not a
  no-op: a resettable account has a password and can therefore have sessions.
- **Void every pending identifier change.**
  `domain.User.VoidPendingIdentifierChange` is called on every reset and records
  nothing, because no flow in this module can create a pending change yet — the
  same reason `VerifyEmail`'s revocation was written before any session could
  exist. What actually enforces it today is the next rule: a pending change
  cannot be completed without its live verification token.
- **Void every outstanding token of every purpose** for that subject, not only
  reset tokens. One statement scoped by the subject
  (`RevokeAllTokensForSubject`), never a loop over the known purposes — a loop is
  correct until somebody adds a purpose and forgets it, and the symptom is a live
  token that survives a reset with nothing to say so.
- **Never bypass the second factor** (ASVS 5.0 V6.4.3). `ResetPasswordResponse`
  is empty: no session, no bearer token, no identifiers. The reset changes one
  credential; the caller then signs in normally, presenting whatever factors the
  account has, unchanged. It does not disable TOTP, consume a recovery code,
  activate a Pending account, or re-enable a locked-out authenticator.
- **Send the link to the STORED verified address**, never one the request
  supplied. The request's address is a LOOKUP key and nothing else: the appended
  `PasswordResetRequested` carries a `SubjectID` pseudonym and a blind index, and
  the issuer resolves the address from the vault at send time. Nothing in the
  request path can address mail at all.

**The credential compare-and-set is the flow's only serialization point.** Two
reset links can be redeemed at the same instant and both consume their own token
successfully, because they are different digests in different rows. Exactly one
wins the `ResetCredentialPassword` update, and the loser writes nothing and
appends nothing.

**Order of destruction.** Tokens, sessions, then the verifier, then the event.
Revoking first means a failure leaves the password unchanged and nothing granted;
the opposite order can leave a new password live beside the attacker's surviving
session. The verifier moves before the event for the same reason in the other
direction — appending first and failing to write would leave the OLD password
working after the log and the user were both told it was replaced. A failure
between the two is visible: §4.2's reconciliation reports a verifier the log
cannot account for, and the append itself retries a lost expected-revision race
three times before giving up, because a login writing to the same account stream
is an ordinary event.

**Enumeration.** Five outcomes — no account, resettable, passwordless,
deactivated, suspended — produce byte-identical responses. Both mail ceilings are
spent BEFORE the account lookup, so the request at which a caller is refused says
nothing about which addresses have accounts, and the per-address counter is the
SAME one verification mail spends (NOTIFICATIONS.md §4: "an hourly ceiling per
address across all classes").

**What is still missing.** Nothing consumes `PasswordResetRequested`. The
reset-mail issuer is the component the verification reactor was before
`cmd/worker` grew one: the token cannot travel in an event (ADR-002), so whoever
sends the mail must mint it. Until that reactor is registered, a reset link is
appended to the log and never delivered.

**Known gap.** A password credential that has been locked out by consecutive
failures (`AuthenticatorDisabled`) cannot be reset — the statement requires
`disabled_at IS NULL`, and `UsablePasswordCredential` skips it. Re-enabling a
locked-out authenticator belongs to §11's anomaly response, not to a flow reached
by anyone who can trigger mail to the address.

### 4.6 The public username — BUILT, and where it attaches

Every account has a **username**: a public, human-chosen handle used for
mentions, profile URLs and anywhere the product names a person to other people.
It is **mandatory**, not an optional profile field, and ADR-051 settles what it
is. This section settles the one thing the ADR leaves open — *where in the
signup flow it is claimed* — and records the rules the implementation enforces.

#### It is claimed at `VerifyEmail`, beside the password

`VerifyEmailRequest` carries `token`, `password` **and** `username`. All three
are mandatory. `RegisterRequest` does not carry a handle and must never gain
one.

Three placements were possible. The reasoning that decided between them is §4.3's
applied to a second durable choice, plus one argument that is specific to this
field and is on its own sufficient.

**At `Register`** — rejected, decisively, because it reopens the
account-existence oracle §11 exists to close. `RegisterResponse` is empty
precisely so that "the address was free" and "the address was taken" are the same
answer. Pair the address with a freshly-invented handle and they stop being the
same answer: register, then ask the public availability RPC about the handle. Taken
means the registration went through, which means the address was free; free means
it did not, which means an account already exists for that address. **One extra
unauthenticated call, and the leak is back — through a field rather than through a
message.** The obvious repair, claiming the handle even when the address is
taken, is worse: it orphans handles on behalf of accounts that do not exist, and
makes an unauthenticated endpoint an unbounded handle-burning vector.

It is also squattable. An unverified address claim lapses after
`DefaultReservationLease`, which is what bounds the squat §4.3 leaves open; a
handle is claimed **permanently** and, once tombstoned, cannot be reissued even in
principle. So a handle at `Register` would let a script sweep every desirable name
with addresses it never proves, and every name it took would be gone for good.

**A separate `SetUsername` before activation** — rejected because it creates the
one state "mandatory" cannot survive: an account that is verified, has a password,
can authenticate, and has no handle. Closing that window needs a whole new gate —
a session restricted to a single endpoint, like `RequiresCredentialRotation` — to
stop the account being used before it has a name. That is a large mechanism bought
to solve a problem the placement below does not have.

**At `VerifyEmail`** — chosen. It is §4.3's rule extended: the party that has just
proven the mailbox is the party entitled to make the account's durable choices,
and the handle is claimed in the same atomic append as the proof and the first
password. Each squatted handle then costs the attacker one mailbox they actually
control. And the window in which an account has no handle is exactly the window in
which the account can do nothing at all — Pending, passwordless, unreachable by any
authentication — so "every usable account has a handle" is true by construction
rather than by a gate.

**What it costs, and how that is paid.** A handle cannot be *confirmed* available
until the link is clicked. `CheckUsernameAvailability` is public so a person picks
and checks at the form, and the check is advisory by construction — any
check-then-claim is racy, and the append's precondition is the authority. If the
handle is taken by the time the link is followed, the refusal happens **before the
token is consumed**, so the link survives and the person picks another name. That
placement follows §4.3's password-screening argument, with a different
justification: handle availability is not a function of the caller's own bytes, but
it is *public and free to query*, so refusing early costs an attacker nothing and
saves a legitimate user their only route into the account.

#### The refusal is deliberately specific, and that is the one exception

Every other refusal in this module is undifferentiated (ADR-036). "That username
is not available" is not, and must not be made so: a handle is published by
design, its availability is served by a public RPC whose entire purpose is to
answer this question, and a vague refusal would tell the person nothing while
telling an attacker nothing they could not already read.

The one distinction that is **not** drawn is between a handle somebody holds and a
handle that was **tombstoned**. That merge is a privacy control rather than
tidiness: "this handle belonged to an account that was erased" is a fact about a
person, and the tombstone exists to protect that person.

#### Normalisation, and what it deliberately does not do

The canonical form names a KurrentDB stream, permanently, so these rules are a
schema rather than a preference. `domain.NormalizeUsername` is the single
definition; the protovalidate rules on the wire mirror it and are never stricter.

| Rule | Value | Why |
| --- | --- | --- |
| Character set | `[a-z0-9_]`, ASCII only | validated, never mapped |
| Case | folded to lower; only the folded form is stored | `@Alice` and `@alice` must be one handle |
| Length | 3–30 bytes | a short space is exhaustible; a stream name is permanent |
| First character | a letter | a leading digit or `_` reads as a generated id |
| Underscore | may not lead, trail or repeat | each position multiplies near-duplicates for free |
| Hyphen | **refused** | `NewStreamID` rejects a dash in a key: KurrentDB derives a category from everything before the first one |

The fold is ASCII-only and not `strings.ToLower`, which is not a micro-detail:
`ToLower` maps `İ` to `i` plus a combining mark, turning input the character-set
rule refuses into input it accepts.

**Confusables.** The ASCII-only set eliminates the entire *cross-script* homoglyph
class outright — there is no Cyrillic `а`, no Greek `ο`, no fullwidth `ａ`, because
there is no non-ASCII input at all. That is the class that matters, because those
handles are byte-different and pixel-identical.

What remains is the *within-ASCII* class — `0`/`o`, `1`/`l`, `rn`/`m` — and the
system deliberately does **not** fold it. Folding is worse than the problem:
`0→o` makes `@bob` and `@b0b` one handle, so the first registrant silently denies
a whole family of names to everyone else; the mapping is not invertible, so a
refusal cannot be explained after the fact; and the composition of `rn`/`m`,
`vv`/`w`, `cl`/`d` collapses a fraction of the handle space that nobody can
enumerate in review. The residual risk is answered at the **rendering** layer,
where the reader is: a font that distinguishes `0` from `o`, and never presenting a
handle as proof of who somebody is.

**Reserved names** are refused on the normalized form, so `Admin`, `ADMIN` and
`admin` are one refusal. Two families, refused for unrelated reasons:

- **Role impersonation** — `admin`, `support`, `billing`, `security`, `noreply`,
  `postmaster`… A handle that reads as the operator is a phishing primitive that
  needs no technical compromise: "@support asked me to confirm your password" is a
  complete attack, and the only defence is that `@support` cannot exist.
- **Route collision** — `login`, `settings`, `api`, `new`, `about`… A profile path
  built from the handle makes a colliding route ambiguous forever, and it cannot be
  repaired later without taking a name away from somebody other people have linked
  to.

The list is exact rather than a prefix match (`admin2` is allowed), generous
rather than minimal (a name added later cannot be reclaimed from whoever holds
it), and static rather than runtime-editable (an editable list makes "is this
claimable" a question whose answer changes under a claim already checked).

#### Uniqueness, erasure, and login

- **Uniqueness** is a `UsernameReservation` aggregate on
  `reservation_username-<handle>`, contended with `NoStream`, exactly as an
  address is (ADR-044) — with the stream named by the handle **in the clear**,
  because hiding a published value buys nothing and costs log readability
  (ADR-051). `user_view.username` carries a partial unique index as a **backstop**;
  it asserts exactly what the domain guarantees and no more (ADR-052's lesson).
- **There is no lease and no release.** A handle is claimed by an account that has
  already proven its mailbox, so there is nothing unproven to expire. The one
  terminal transition is the tombstone.
- **Erasure DELETES the handle and tombstones it forever.** `user_view.username` is
  the one cleartext personal-data column in this system, so key destruction does
  nothing to it. The tombstone carries the handle and nothing else — no subject, no
  actor — which is what makes retaining it after an erasure lawful. The producer is
  `compliance` and does not exist yet; the *mechanism* — the aggregate transition,
  the event, the projector's deletion, and the refusal every future claim inherits
  — is built and tested.
- **It is NOT a login identifier.** `Authenticate` and `CreateSession` take the
  address only, and there is deliberately no `GetUserByUsername` query. A public
  handle accepted for login is an enumerable target list to spray and turns the
  lockout ceiling into a denial of service aimed at anyone whose handle is readable.

#### A username change does not exist

No RPC, no use case, no event, and its absence is a decision rather than a gap: a
change must **burn** the old handle rather than free it, or every old mention
re-points at whoever takes it next. `domain.User.AssignUsername` therefore refuses
a second, different handle. When the flow is built it inherits §4.4's revocation
rule and ADR-051's tombstone rule together.

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

### 11.1 There is no email-availability RPC, and there will not be one

`CheckUsernameAvailability` exists. `CheckEmailAvailability` does not, and its
absence is a decision rather than a gap somebody forgot to close (ADR-055).

The two look symmetrical and are not. A **username is published by design**
(ADR-051): `@alice` appears in mentions, in profile URLs and in mail other people
already received, so "that handle is taken" is readable from any profile page and
no endpoint changes what is knowable. It is deliberately the one piece of
user-supplied text this system publishes, and it sits in a projection column in
the clear. The availability check is therefore an enumeration oracle *by design*,
and the ceiling on it in `cmd/api/identity.go` says in its own comment that it is
a RESOURCE control and explicitly not an information control.

An **address is not published**. It is personal data, it lives in the PII vault
behind a blind index (ADR-012), and no projection may hold it (compliance.md §1).
An availability endpoint for it would hand any unauthenticated caller a precise,
unlimited answer to the exact question registration, login, reset and invitation
are all shaped to refuse — faster and more cheaply than any of the four.

An authenticated variant does not rescue it: scoped to the caller's own address
it answers a question the caller can already answer, and scoped to any address it
is the same oracle with a login in front of it.

The product pressure is real — a signup form wants to say "you already have an
account" before the user submits. **That answer is given, and it is given to the
mailbox.** See §11.2. The form's honest text remains "if that address can be
registered, we have sent it a link", which is true on both branches.

### 11.2 A registration on a claimed address answers the MAILBOX

`Register` returns the same empty response whether the address was free or
already claimed, and integration tests compare the two as marshalled bytes. That
is right and it is not enough on its own: until ADR-055 the taken branch sent
nothing anywhere, so the screen said "check your email" and no mail arrived — and
that branch is the one a returning user hits most often.

When a **verified** account already holds the address, identity appends
`identity.DuplicateRegistrationAttempted.v1` to that address's reservation stream
and the notification catalogue mails the holder: somebody tried to register with
your address, here is where to sign in, here is where to set a new password, and
if it was not you there is nothing to do. Nothing reaches the caller.

- **The disclosure line.** The message goes to the address, and reading it
  already requires controlling the address — the same proof the verification link
  demands. So "an account exists here" is the intended disclosure. Everything
  beyond that single fact is withheld: no handle, no creation date, no account
  state, no second-factor status, and **nothing about whoever made the attempt**,
  who is unauthenticated and whose IP or client string would be attacker-chosen
  text repeated into a victim's inbox.
- **An unverified claim gets nothing.** Nobody has proven they can read mail
  there, so sending is unsolicited mail to a person who never asked (NOTIFICATIONS
  §5). The pending registrant already holds a link, and §12.1 issues another.
- **Two ceilings.** The shared per-address and per-caller triggered-mail budgets
  (`mailAddressRules`, `mailCallerRules` — 3/hour and 10/day per address, shared
  with resend and reset so alternating between endpoints cannot double the mail),
  and a floor derived from the reservation stream itself
  (`domain.MaxDuplicateNoticesPerHour`) that holds while the shared counter is
  unwired, degraded or flushed. The shared budget is spent on **both** branches:
  spending only on the refused one would make the ceiling readable as the answer
  through a later resend refusal.
- **A refused ceiling suppresses the notice, never the registration.** A
  `RATE_LIMITED` only the taken branch can produce is the oracle again, and it
  would let an attacker block an address from being claimed by probing it.

---

## 12. Identifier and email lifecycle

- Email normalized (lowercase, Unicode NFC) with a uniqueness constraint on the
  normalized form; plus-addressing preserved, never stripped.
- The email itself is **personal data**: PII vault, blind index for lookup
  (ADR-012).
- **Email change** verifies the *new* address before switching, notifies the
  *old* address, and allows a revert window — otherwise an attacker with a
  hijacked session silently takes ownership.

  **BUILT.** Four RPCs: `RequestEmailChange` and `CancelEmailChange` (AAL2, see
  §4.3), `ConfirmEmailChange` and `RevertEmailChange` (public — both are reached
  from a mailbox, and after §4.4 runs there is no session to reach them with).
  The use case is `internal/modules/identity/app/emailchange.go`; the three
  messages are sent by identity's own reactor, on its own subscription group.

  Both directions of §4.4 are enforced and both are tested end to end:

  - Completing the change VOIDS every session for the subject, sparing none —
    including the one that requested it, because the party who requested it may
    be an attacker. That defeats the *unexpired session* variant at the instant
    the identifier moves.
  - A password reset VOIDS any pending change, twice over: the reset already
    revoked every outstanding token of every purpose, and
    `domain.User.VoidPendingIdentifierChange` now records the cancellation on the
    aggregate as well. Building this flow is what made C8's **unexpired email
    change** variant reachable at all, so it is closed in the same slice.

  Three decisions the paragraph above does not settle:

  - **The old address is DEMOTED, not released.** It becomes an unverified claim
    expiring at the revert deadline, so it stays unavailable to everybody for the
    window and is then freed by the ordinary lapsed-reservation sweep. Releasing
    it at the moment of the change is an attack rather than a simplification:
    whoever performed the change could re-register the freed address immediately
    and leave the revert with nowhere to go back to.
  - **The previous address lives in the vault**, as `previous_email`. The revert
    has to restore it and the log cannot hold it (ADR-002). `SubjectAddresses` is
    four MOVES and no reads, so the values never cross back into this module.
  - **The revert mail resolves a NON-PRIMARY address.** The dispatcher reads the
    vault at send time, which by then holds the address the account moved TO — so
    a notice on `EmailChanged` addressed to the primary would mail the undo link,
    with its live token, to the attacker. `notify.Spec` carries an address choice
    for this one message, and the vault adapter REFUSES to fall back to the
    primary when no previous address is recorded.

  The warning sent to the current address at REQUEST time carries no link, no
  token and not even the new address. It goes to the mailbox an attacker may
  already be reading, so a credential in it would make the warning itself the
  attack.
- Verification tokens: **looked up by `SHA-256(token)`, never stored in the
  clear**; single-use, expiring, invalidated on email change.

  Four purposes exist — `email_verification`, `password_reset`, `email_change`
  and `email_change_revert` — and the purpose is mixed INTO the digest rather
  than stored beside it. That binding is a control, not bookkeeping: without it,
  anybody who can cause a verification mail to be sent (by registering an address
  they own) would hold a token that completes a change on somebody else's
  account. A CHECK constraint on `identity_token.purpose` is the second,
  independent guard, and it earned its keep — it refused the new purposes until
  migration 00029 widened it, which is a failure at issuance rather than a link
  that is dead on arrival with nothing to say so.

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

`UserRegistered` · `DuplicateRegistrationAttempted` ·
`EmailVerificationRequested` · `EmailVerified` ·
`EmailChangeRequested` · `EmailChangeCancelled` · `EmailChanged` ·
`EmailChangeReverted` · `EmailReservationDemoted` ·
`PasswordSet` · `PasswordChanged` ·
`PasswordResetRequested` · `PasskeyRegistered` · `PasskeyRemoved` ·
`TotpEnabled` · `TotpDisabled` · `RecoveryCodesGenerated` ·
`RecoveryCodeConsumed` · `FederatedIdentityLinked` · `FederatedIdentityUnlinked`
· `AuthenticationSucceeded` · `AuthenticationFailed` ·
`SecondFactorChallenged` · `SecondFactorSucceeded` · `SessionCreated` ·
`SessionElevated` · `SessionRevoked` · `SessionExpired` ·
`SessionCompromiseDetected` · `DeviceRegistered` · `DeviceTrusted` ·
`ApiKeyCreated` · `ApiKeyRotated` · `ApiKeyRevoked` ·
`ServiceAccountCreated` · `UserDeactivated` · `UserReactivated` ·
`UserSuspended` · `UserDeletionRequested` · `UsernameReserved` ·
`UsernameAssigned` · `UsernameTombstoned`

**Every one carries `SubjectID` pseudonyms only** — no email, no IP, no device
name, no user agent in the payload (ADR-002). `DuplicateRegistrationAttempted`
goes further and carries no ACTOR either, in the payload or in the metadata: the
party it records is unauthenticated, so anything attributed to them would be
attacker-chosen text living forever in the log, and the metadata default — actor
equals subject — would assert that the account holder tried to register their own
address (ADR-055). Those live in the PII vault,
joined at projection time.

**The three username events are the one stated exception**, and it is ADR-051's:
a public handle is *published by design*, so the vault cannot protect it —
crypto-shredding does nothing to a value that was published — and there is
nothing for a pseudonym to stand in for. They carry the handle in the clear, and
`UsernameTombstoned` carries the handle and **nothing else**: no subject, no
actor, no timestamp tied to a person. That emptiness is what makes a tombstone
lawful to retain after an erasure.

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
| `user_view` | profile, status, public handle | `(email_index) WHERE email_released_at IS NULL` unique; `(username) WHERE username IS NOT NULL` unique |
| `auth_method_view` | the security settings screen | `(user_id, method_type)` |
| `session_view` | device list | `(user_id, status, last_seen_at DESC)` |
| `linked_account_view` | connected providers | `(issuer, subject)` unique |
| `api_key_view` | key management | `(key_id)` unique, `(owner_id, status)` |
| `login_history_view` | "recent activity" | `(user_id, occurred_at DESC)` |
| `auth_attempt_counter` | rate limiting (Valkey, TTL) | — |

`user_view.email_index` is unique among **current holders only**, and the
qualifier is load-bearing rather than a detail of the index. An unverified claim
lapses (§4.3), `EmailReservation.Reserve` takes it over, and the previous
holder's `Pending` account survives its own lapsed claim — so two accounts
legitimately carry one email index, at different times. `email_released_at`
records which of them stopped holding it, written by the account projection from
`EmailReleased`; a bare `UNIQUE` here asserted a property the domain never
promised and stopped the projector the first time the designed squat-recovery
path ran. See ADR-052.

The same column is why `GetUserByEmailIndex` filters on
`email_released_at IS NULL`: without it the login lookup can resolve an address
to the abandoned account instead of the one that holds it.

`user_view.username` is the **one personal-data column in any projection in this
system**, and its uniqueness index is a real backstop rather than an over-claim:
a handle is claimed permanently, never released and never reissued, so "at most
one account ever holds a handle" is precisely what the domain promises (§4.6,
ADR-051). It is `NULL` for an account that has not verified yet and `NULL` again
after an erasure — the erasure DELETES it, because key destruction does nothing
to cleartext.

There is deliberately **no `GetUserByUsername`**. Adding one would be the whole of
making a public handle a login identifier, so its absence is where that property
is kept.

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
| `AccountDeletionWorkflow` | grace period, then hand off to `compliance` erasure — **not built**; `UserDeletionRequested` is appended and nothing consumes it (§1.1) |

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

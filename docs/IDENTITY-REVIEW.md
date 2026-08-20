# Identity Review — 2026-08-11

> **Status: decisions closed, findings open.** All six blocking decisions are
> answered (Part A). The findings in Parts B–D are the implementation backlog.
> Nothing in `identity` is written yet, which is the point — every finding below
> is cheaper to settle now than after the first user row exists.

Pre-implementation review of `docs/domains/identity.md` against the live RFC,
NIST, W3C and vendor text, plus a package-selection pass. Everything
version-dependent was fetched on **2026-08-11**; claims that could not be
verified are marked as such rather than filled in.

Findings are graded by when they hurt, matching `REVIEW.md`:

- 🔴 **Bites hard later** — expensive or impossible to retrofit.
- 🟡 **Fix during the domain** — cheap now, annoying later.
- 🟢 **Note** — record it, act when it matters.

Status markers: `[ ]` open · `[x]` resolved · `[~]` accepted deviation.

---

## Part A — Decisions that block writing code

These are product or architecture calls, not research questions. Each changes
what gets built.

### [x] D1 🔴 — Is Chronos an OAuth authorization server?

> **DECIDED 2026-08-11: No — consumer only.** We consume Google, GitHub, Apple
> and Microsoft. Third parties do not integrate with us. **Take the three hedges
> anyway** (below): they cost almost nothing now and are expensive to retrofit if
> this is ever revisited.

The spec covers *consuming* Google, GitHub, Apple and Microsoft. Nothing anywhere
defines whether third parties integrate with **us** — "Sign in with Chronos", API
access on a user's behalf. A grep across every doc returns nothing either way.

| Choice | Consequence |
| --- | --- |
| **No** — consumer only | Identity stays roughly its current size. |
| **Yes** | Client registration, consent records, scope grants, token + introspection + revocation endpoints, RFC 8414 discovery. Roughly doubles the module and adds a permanent public security surface. |

The endpoints are the small part. The large parts are the **consent model**, the
**scope catalogue as a permanent public API**, the **OpenFGA intersection
semantics** (a token's authority must be the intersection of the granting user's
authority and the granted scopes, re-evaluated at use time), and the **ongoing
anti-consent-phishing operations**. It is a new domain module, not an extension
of `identity` — it answers "what may this *application* do on this user's
behalf", which is neither `identity`'s question nor `access`'s.

**Three hedges cost almost nothing now and are expensive to retrofit**, and are
worth taking even if the answer is "no for now": make the access token RFC
9068-shaped from day one, keep the grant model family-based (ADR-018 already
does), and reserve the `/.well-known/` paths.

### [x] D2 🟡 — Enterprise SSO: OIDC only, or SAML too?

> **DECIDED 2026-08-11: OIDC per TENANT — i.e. per `organization`, never per
> `workspace`.** SAML is out of scope; if ever revisited it is its own project,
> not a checkbox.
>
> **The boundary matters and is not cosmetic (ADR-020).** An identity provider is
> a property of the *company*, not of a room inside it. A person authenticates
> once against their organization's IdP and then reaches every workspace they
> belong to; a workspace cannot have its own IdP, cannot override the
> organization's, and cannot opt out of it.
>
> **Consequences to carry into the build:**
> - The IdP configuration — issuer, client id, client secret, allowed domains,
>   JIT provisioning policy — is an `organization` aggregate concern. `workspace`
>   never stores or reads it directly.
> - The dependency stays one-directional: `workspace → organization`, never the
>   reverse. `organization` must not learn what a workspace is in order to
>   support SSO, and a cycle here means the split has failed.
> - Domain verification is therefore also organization-level, which is what makes
>   the "verified domain" trusted-link state below coherent — the *organization*
>   owns `corp.com`, so it is the organization that may vouch for
>   `alice@corp.com`.
> - A person in two organizations that both use SSO has two federated links, one
>   per issuer, converging on one `User` aggregate. That is the normal case, not
>   an edge case, and §7's `(issuer, subject)` uniqueness already permits it.

`FEATURES.md` lists "OIDC/SAML per organization, JIT provisioning" and SCIM as
P2; `identity.md` specifies neither.

OIDC-per-org is a modest extension of the social-login work — same libraries,
same flows, per-org issuer config. SAML is not: different threat model, XML
signature wrapping and canonicalization attacks, and a materially weaker Go
library ecosystem. Treat SAML as its own project, not a checkbox.

Note the one case where auto-linking on email **is** defensible: a
domain-verified organisation (`hd=corp.com` on Google Workspace), because the
domain owner vouches. Worth designing the trusted-list mechanism to accommodate
"verified domain" as a third state now rather than retrofitting.

### [x] D3 🔴 — Password-alone at AAL1, or require a second factor?

> **DECIDED 2026-08-11: require a second factor.** Password-alone is removed as
> an authentication path, which permits the 8-character floor NIST allows for
> multi-factor use. This resolves the §3.1.1.2 conflict by removing the case it
> applies to, and it aligns the default with the passkey-first posture in §5.
>
> **Consequences to carry into the build:** §2's AAL table must drop
> "password alone" from AAL1; registration must enrol a second factor before the
> account reaches `active`; and §4's minimum becomes 8 with a **64-character
> maximum floor** (verifiers SHALL permit at least 64).

**SP 800-63B-4 §3.1.1.2 makes 15 characters a SHALL** for passwords used as
single-factor authentication — not a SHOULD. Passwords used only as part of
multi-factor may be 8. `identity.md` §2 permits password-alone at AAL1 and sets
no minimum at all.

| Choice | Consequence |
| --- | --- |
| **A** — enforce 15 characters | Real signup-conversion cost. |
| **B** — drop password-alone; require a second factor | Permits an 8-character floor. The passkey-first posture in §5 makes this more attractive than it first looks. |

Also absent and required: §4 says nothing about the **64-character maximum
floor** (verifiers SHALL permit at least 64). A system that rejects a 40-char
passphrase because of a `varchar` is a common and embarrassing violation.

### [x] D4 🟡 — The 100-attempt hard ceiling

> **DECIDED 2026-08-11: comply. Adopt a ceiling at 100 consecutive failures,
> scoped per AUTHENTICATOR rather than per account.**
>
> **D3 removed the objection.** §11's reasoning — that a hard lock is "a trivial
> account-denial vector" — was correct *while password-alone existed*, because
> disabling the password disabled the only way in. With a second factor now
> mandatory, disabling a user's password authenticator after 100 consecutive
> failures does not deny them the account: they authenticate with the other
> factor and rebind the password. What NIST calls "rebinding" is a flow we need
> anyway.
>
> That is the whole decision, and it is worth noticing that it was not available
> until D3 was settled — the two interact, and taking D4 in isolation would have
> produced the wrong answer.
>
> **Consequences to carry into the build:**
> - The counter is per `(user, authenticator)`, never per account. Burning the
>   password counter must leave TOTP and passkeys untouched.
> - A successful authentication resets that authenticator's counter (NIST SHOULD).
> - Progressive delay stays as the primary control. The ceiling is the backstop
>   NIST requires, not a replacement for it.
> - Disabling emits an event and notifies the verified address — otherwise the
>   user discovers it at the worst moment.
> - **The remaining denial vector is a user whose only factors are password +
>   TOTP, where an attacker burns the password counter.** They recover through the
>   verified-email reset path. That is a recovery flow, not a lockout, and it is
>   exactly what "rebind" means. Accept it and say so.

`identity.md` §11: progressive delay is "**deliberately *not* a hard lock** —
that is a trivial account-denial vector."

**SP 800-63B-4 §3.2.2 SHALL** limit consecutive failed attempts on a single
account to no more than **100** by disabling the authenticator, with recovery by
**rebinding**, not a timer.

The product reasoning is sound and the position is non-compliant as written.
NIST permits progressive delay as a *supplement*, not a substitute. The DoS
objection is also weaker than §11 assumes, because NIST says a successful
authentication SHOULD reset the counter — a legitimate user clears it.

Either adopt a ceiling at ≤100, or record an accepted deviation with reasoning.

### [x] D5 🟡 — Is a FIPS 140 boundary anywhere in the roadmap?

> **DECIDED 2026-08-11: no FIPS boundary planned. Argon2id stands.** Nothing in
> the scope — workspace, teams, invitations for a general multi-tenant SaaS —
> implies FedRAMP or a US federal customer, and no doc mentions one. Designing
> around a hypothetical FIPS requirement would cost real security today (PBKDF2
> is not memory-hard) for a benefit nobody has asked for.
>
> **Both escape hatches were verified rather than assumed**, which is what makes
> this a cheap decision to reverse:
>
> 1. **The KDF migration is tractable.** The algorithm and parameters are stored
>    with each hash, and `NeedsRehash` already triggers on an algorithm mismatch
>    (Part B, C5). Migrating Argon2id → PBKDF2 is therefore the same mechanism as
>    a parameter bump — lazy, per-user, on next login — not a flag day. The batch
>    re-encryption path built for pepper rotation covers the accounts that never
>    log in.
> 2. **The token format is NOT at risk.** This was the expensive half, and it is
>    resolved: `crypto/internal/fips140/ed25519` exists in the Go 1.26 tree, so
>    **Ed25519 is inside Go's FIPS 140-3 module** and ADR-018's EdDSA choice
>    survives `GODEBUG=fips140=on` unchanged. `crypto/internal/fips140/pbkdf2`
>    is likewise present, so the fallback KDF needs no new dependency.
>
> **Revisit only on a named customer requirement**, not on a roadmap rumour. If
> that day comes, the work is: flip the KDF policy, let rehash-on-login drain,
> run the batch job for dormant accounts, and turn on FIPS mode. No wire-format
> change, no forced password reset.

**Argon2 is not FIPS-approved and will not be soon.** SP 800-132 remains at its
**December 2010** version; NIST's Crypto Publication Review Board decided in May
2023 to revise it to approve a memory-hard KDF, and **as of August 2026 no draft
has been published** — no IPD, no FPD.

Argon2id is fully SP 800-63B-4 compliant (rev 4 deleted the algorithm name and
iteration count, requiring only "a suitable password hashing scheme" with salt
≥32 bits). It is simply not FIPS-approved. If a FIPS boundary is ever required,
PBKDF2-HMAC-SHA-256 at ≥600,000 iterations is the only option — and that changes
now, not later. Do not plan around imminent Argon2 approval.

Related: Go 1.24+ ships a FIPS 140-3 mode via `GODEBUG=fips140=on`. Whether
EdDSA (ADR-018's choice) is permitted in that mode is **unverified** and worth
checking early, because it would be a wire-format migration.

### [x] D6 🔴 — How is the email reservation stream named, and can that key rotate?

> **DECIDED 2026-08-11: a dedicated, never-rotated reservation key in OpenBao.**
> `k_res` protects only the email-to-stream-name linkage, so its blast radius is
> narrow: compromise permits offline enumeration against *guessed* addresses, and
> nothing else. It is never rotated and never destroyed — which must be stated in
> the ADR as an accepted permanent key, because it is the one key in the system
> that erasure cannot revoke.

See **C1**. The fix is to HMAC the address into the stream name. The unresolved
part is that stream names are immutable, so the key can never be rotated without
renaming every reservation stream, which is impossible in place.

| Option | Consequence |
| --- | --- |
| **A** | A dedicated, never-rotated reservation key in OpenBao, accepted as permanent. |
| **B** | Rotation means writing new reservation streams and leaving the old as tombstones. |

Neither is free. This blocks the uniqueness implementation.

---

## Part B — Where the spec conflicts with the standards

### [ ] C1 🔴 — A raw email address in a KurrentDB stream name

`docs/EVENT-SOURCING.md:163`, propagated into **ADR-044** as the worked example
for `MultiStreamAppend`, and into `internal/platform/eventsourcing/store.go:49`
as a comment:

```
stream:  reservation_email-alice@example.com
```

This puts personal data permanently into the event log, against **ADR-002**.
**Crypto-shredding cannot cover it — there is no ciphertext.** Stream names
persist in the `$streams` index and in `$ce-reservation_email` category streams
(this deployment runs `RUN_PROJECTIONS=System`, so those exist), surface in
metrics labels and client logs, and KurrentDB deletion is a **soft delete**.
Erasure would release the reservation while the address stays readable forever.

Fix: `reservation_email-<hex(HMAC-SHA256(k_res, normalized_email))>`, plus D6.

**Status: docs and one comment only — not implemented, so still free to fix.**

> **The general lesson, worth more than the fix:** a privacy rule written about
> *payloads* must be re-checked against every identifier the system derives —
> stream names, cache keys, metrics labels, log fields, idempotency scopes.

### [ ] C2 🔴 — Microsoft is on the trusted-verification list. It must not be.

`identity.md` §7 rule 1 lists "Google and Microsoft qualify" for auto-linking on
a provider's verified email.

**Entra ID's `email` claim is not verified**, and Entra emits no trustworthy
`email_verified`. Anyone can create a free Entra tenant, set `mail` on a user
they own to the victim's address, and be handed the victim's account. This is
**nOAuth** (Descope, June 2023). The victim's MFA, conditional access and Zero
Trust provide **zero** protection, because the attack never touches their tenant.

Still live: Semperis found **9 of 104** Entra App Gallery apps vulnerable in
2025, plus 2 of 38 more in Oct–Nov 2025.

Fix: the identifier is **`tid` + `oid`** — never `sub` (pairwise per-app), never
`upn`, never `email`. Trust the email only when the optional **`xms_edov`** claim
is true; it must be configured on the app registration. Trusted list becomes:
Google (`email_verified=true`), and Entra only with `xms_edov=true`.

**As written, the spec sanctions an account-takeover path.**

### [ ] C3 🔴 — Credential-ID uniqueness is never checked

**WebAuthn L3 §7.1 step 27** requires verifying the credential ID is not already
registered *for any user*. The spec's own rationale: an attacker who obtains a
victim's credential ID and public key registers it as their own; if the RP
replaces the victim's registration and the credentials are discoverable, **the
victim is signed into the attacker's account** at their next attempt, and
anything they save there is the attacker's.

Absent from §5 and from §18's test plan. Needs a unique index **and** a
pre-insert check, plus a negative test that constructs the collision.

### [ ] C4 🔴 — The AAL3 definition cannot be satisfied by the mechanism given

`identity.md:58` defines AAL3 as "hardware-bound authenticator with attestation";
`identity.md:232` reaches it by requesting `attestation: direct`. Two independent
problems:

- **SP 800-63B-4 Appendix B: syncable authenticators SHALL NOT be used at AAL3** —
  sync requires an exportable key.
- **Apple and Google return no attestation statement for synced passkeys.**
  Requesting `direct` yields `fmt: "none"`, so the mechanism silently no-ops on
  the two platforms most users are on.

AAL3 also carries session obligations the spec never states — reauth every 12
hours / 15 minutes idle — which §3's state machine cannot currently satisfy.

Honest replacement, or delete the row rather than ship an undefendable claim:

| Level | Satisfied by |
| --- | --- |
| AAL1 | password alone · federated link alone · passkey with `UV=false` |
| AAL2 | password + TOTP · password + WebAuthn · passkey with `UV=true` (incl. synced) |
| AAL3 | `UV=true` **and** `BE=0` **and** AAGUID on an allow-list verified against FIDO MDS **and** a real attestation statement. Reauth 12h / 15min idle. |

`BE=0` is the machine-checkable proxy for "non-exportable" that WebAuthn actually
gives you. It is not a cryptographic proof — state that limitation rather than
implying one.

**Related:** §2 must also say that **AAL is computed from the `UV` flag actually
returned on that assertion**, never from the credential type. §5 registers with
`userVerification: preferred`, which may return `UV=false` and still succeed — so
inferring "is a passkey ⇒ AAL2" is a silent downgrade.

### [ ] C5 🟡 — The pepper construction cannot be rotated

`identity.md` §4 specifies `argon2id(password ‖ pepper)`.

HMAC- and concatenation-based peppering are **one-way**: rotating requires the
plaintext password, which you only hold at login. OWASP states it plainly —
changing a pepper means forcing every user to reset. It also cannot live in
OpenBao, because concatenation needs the secret in process memory on every hash,
so in practice it becomes an env var: a second key-custody system beside the one
ADR-028 exists to be.

```
digest = argon2id(NFC(password), salt, m, t, p)
stored = AES-256-GCM(pepper_key_v, nonce, digest,
                     AAD = user_id ‖ credential_id)
```

Reversible, so rotation is decrypt-with-`v` / encrypt-with-`v+1` as a batch job —
no plaintext, no forced reset. This is the **ADR-041 pattern** (transit-wrapped
key, cached in-process under a capped TTL), which the spec already establishes
and §4 does not use.

The AAD closes a second hole. §4.2 claims an attacker with `INSERT`/`UPDATE` on
the credential table "cannot construct a hash that will verify" — but they need
not forge anything. They can **copy their own valid credential row onto the
victim's** and log in with a password they chose. Binding the ciphertext to the
row identity is what actually prevents that; §4.2 asserts the guarantee without
stating its precondition.

**Destroying the old transit key before the batch job reports zero rows at the
old version permanently locks out every un-migrated user.** Gate destruction on a
query, not a calendar.

### [ ] C6 🟡 — Password normalization is undefined, and it is baked into every hash

§4 says "Unicode allowed" and stops. §12 defines NFC for **emails** only. A
password typed on macOS (NFD-decomposed) will not verify against a hash created
on Windows or Linux (NFC). This is a known production failure class.

The standards now **agree**, which removes the ambiguity: SP 800-63B-4 §3.1.1.2
narrowed to **NFC** (rev 3 said "NFKC or NFKD"), matching **RFC 8265 §4**'s
`OpaqueString` profile — NFC, width-mapping, and explicitly **no case mapping**,
because folding a password reduces entropy and causes false accepts.

Must be decided before the first hash is written; changing it later invalidates
every stored credential.

### [ ] C7 🟡 — Truncated blind index and a UNIQUE constraint are mutually exclusive

§14 puts a `UNIQUE` constraint on `normalized_email_blind_index`. The standard
defence for a blind index is **truncation** — deliberately inducing collisions so
that an index match stops proving a plaintext match. You cannot have both: a
unique constraint on a truncated index rejects legitimate distinct users on a
coincidence.

Uniqueness is genuinely needed here (email is the identity key and the
reservation stream depends on it), so truncation is off the table — but it
currently reads as an oversight rather than a decision. **Write it down as a
decision, with the enumeration risk being accepted explicitly.**

**Also missing: no key-version columns exist anywhere.** `blind_index_key_version`
on `user_view` and `pepper_key_version` on the credential table. Without them
neither key can ever be rotated; rotation becomes a flag-day outage. Both are one
column.

Rotation of the blind index requires recomputing from plaintext, which the vault
permits — but note the collision with erasure: a **shredded subject cannot be
re-indexed**. Rotation must treat "cannot decrypt" as "skip, mark tombstone", or
the first rotation after the first erasure halts.

### [x] C8 🟡 — Pre-hijacking by unverified registration is CLOSED; three variants remain

> **Variant status verified 2026-08-16, by reading the RPC surface and the
> aggregates rather than by inference.**
>
> | Variant | Status | What makes it so |
> | --- | --- | --- |
> | Classic-federated merge | Covered | §7.5 "prove control of both" |
> | Pre-hijack via unverified registration | **CLOSED** | No credential exists before the proof (§4.3); attack test asserts the refusal |
> | Unexpired session | **Enforced, currently a no-op** | `VerifyEmail` calls `RevokeAllSessions` with no `Except` before appending |
> | Trojan identifier | **Unreachable — flow absent** | No federated linking: no RPC, no use case, no event |
> | Unexpired email change | **Unreachable — flow absent** | No email-change flow: no RPC, no use case, no event |
>
> **Two of the three "remaining" variants are unreachable because the flows they
> attack DO NOT EXIST**, and that is an absence rather than a mitigation — it
> expires the day either is built. So the rule is written into the sections those
> flows will be built in (§4.4, §4.5, §7, §12), not only recorded here.
>
> The third — unexpired session — is now ENFORCED: `VerifyEmail` voids every
> session for the subject, before the append, with no exception. Today it revokes
> nothing, because a pre-verification account has no credential and therefore no
> session; that is the argument for writing it now rather than against, since it
> is free while it is a no-op and expensive to retrofit once it is not.
> `TestVerifyEmailVoidsEverySessionEstablishedBeforeTheProof` asserts the call is
> MADE — not that the result is empty, which would pass with the call deleted.
>
> **The squat is self-clearing at the lease, and NOT dependent on the sweep** —
> checked because a broken sweep would have turned a bounded 48h denial into a
> permanent one, which is a materially worse finding than the one recorded.
> `EmailReservation.Available` returns true once `expiresAt` has passed, and
> `Reserve` takes over a lapsed claim directly, recording `EmailReleased` and then
> the new `EmailReserved`. So the real owner can claim the address at expiry even
> if the sweep never ran; the sweep is housekeeping that keeps the projection
> tidy, not the mechanism that frees the address. Covered by
> `domain/reservation_test.go`.

> **Resolved 2026-08-16 by option (a): registration creates no credential.**
> `Register` takes an address and nothing else; `VerifyEmail` takes the token and
> the password and creates the credential in the same request as the proof. The
> premise of the attack — a credential that exists before the proof — is gone,
> so there is nothing for the mailbox owner's click to activate.
>
> Enforced at three independent layers: `RegisterRequest` has no password field
> and field 2 is reserved; `domain.User.SetPassword` refuses a password while the
> address is unproven; a passwordless account has no usable credential for the
> bootstrap carve-out to admit.
>
> `internal/adapter/identityit/prehijack_integration_test.go` still executes the
> full attack sequence over real HTTP and now asserts the refusal. Its central
> assertion is that a registration leaves ZERO credential rows, and it also
> asserts that the victim's own password works — without that half, a
> `VerifyEmail` that stored nothing would refuse the attacker too and the test
> would pass against a broken flow.
>
> Option (b) — ship reset first, then void on verification — was considered and
> rejected: voiding a password with no reset flow locks out every legitimate
> registrant.
>
> **What it does NOT fix, stated rather than glossed:** an attacker can still
> claim an address they do not own and deny it to its real owner until the
> reservation lapses (48h), and registration's indistinguishability means the
> owner is told nothing actionable. That is a bounded, self-clearing denial of
> service on one identifier — strictly less than takeover, and not zero.
>
> Downgraded to 🟡 rather than closed outright: the three OTHER variants in the
> table below (unexpired session, trojan identifier, unexpired email change) are
> untouched by this change and still need the one rule at the end of this entry.
>
> The original 🔴 entry follows, unedited.

> **Escalated to 🔴 on 2026-08-15: the attack was EXECUTED against the running
> system and it succeeded end to end.**
> `internal/adapter/identityit/prehijack_integration_test.go` performs it over
> real HTTP and is committed asserting the CURRENT (vulnerable) behaviour, so the
> fix cannot land silently — when it does, that test fails and is rewritten as
> the refusal, exactly as `TestEnrolmentDeadlock` was retired.
>
> The sequence needs no credential of the victim's and no mailbox access:
>
>  1. The attacker registers the VICTIM's address with a password of their own
>     choosing. The account sits Pending.
>  2. The victim receives a verification mail they never requested — an ordinary
>     mail from a real service — and clicks it, believing they are finishing
>     their own signup.
>  3. Verification proves control of the MAILBOX. It does not prove that whoever
>     set the password controls that mailbox, and here they are different people.
>  4. The attacker signs in with the password only they know. The **bootstrap
>     carve-out** admits them at AAL1 (verified address, no second factor), and
>     that session may enrol a first factor — so they confirm their own
>     authenticator and the account activates.
>
> Outcome: an active account bearing the victim's address, with the attacker's
> password and the attacker's TOTP. The victim cannot start again — the address
> is claimed, and registration's indistinguishability (correct on its own terms)
> means they are told nothing actionable.
>
> Note the interaction: the bootstrap carve-out did not CREATE this — the paper
> predates it — but it removed the step that used to stall the attack, because
> before it no session could be minted for a factorless account at all. The two
> features are individually defensible and jointly exploitable.
>
> **This needs a decision, not a patch.** The paper's rule — on verification,
> void every session and every credential not proven by the verifying party —
> cannot be applied as written today: there is no password-reset flow, so voiding
> the password locks every legitimate user out. The realistic options are (a)
> don't create the credential until the link is clicked, supplying the password
> at that point, which reshapes registration and the reservation stream; or (b)
> ship reset first, then void on verification. (a) is the stronger fix and the
> larger change.

Sudhodanan & Paverd, *Pre-hijacked accounts*, **USENIX Security 2022**: roughly
**half of 75 popular services** tested were vulnerable to at least one variant.

| Variant | Status |
| --- | --- |
| Unverified-registration pre-hijack | **Closed** — registration creates no credential (identity.md §4.3) |
| Classic-federated merge | **Covered** — §7.5's "prove control of both" is the best-designed part of the doc |
| Unexpired session | **Open** — attacker keeps a live session across the victim's reset |
| Trojan identifier | **Open** — attacker pre-attaches their own email or federated link; survives the reset |
| Unexpired email change | **Partly** — §12 has a revert window, but nothing voids a pending change on reset |
| Non-verifying IdP | Covered in principle, **broken in practice** by C2 |

One rule closes all three: **when an identifier becomes verified — and on any
password reset or recovery — void every session, every pending identifier change,
and every identifier not proven by the acting party.**

### [x] C9 🟡 — `ApiKeyUsed` makes the event log grow with request volume

> **RESOLVED 2026-08-16 by deleting the event from the spec**, which is free
> today and would not have been later: API keys are not built, so there is no
> stream to rewrite and ADR-013 would have forbidden rewriting one.
>
> `identity.md` §13 now carries a "There is deliberately no `ApiKeyUsed`" section
> stating the reasoning, so the event cannot reappear as an obvious-looking
> addition beside `ApiKeyCreated`/`Revoked`. The two real needs are routed to
> storage sized for request volume: `last_used_at` is a coalesced projection
> write (≤1/key/minute via Valkey, approximate by construction), and the audit
> trail is `compliance`'s. §13's API-key bullets now say both inline, because
> that is where somebody implementing keys will be reading.
>
> The argument worth keeping: the cost of an event-per-request is not paid at
> write time where it would be noticed, but at REBUILD time — the recovery
> procedure for every projection — where it is least affordable.

§13 lists it beside `ApiKeyCreated`/`Revoked`. Under **ADR-013** every event is
permanent and replayed on every projection rebuild. An event per API *request*
means the log grows with **traffic, not state changes**.

`last_used_at` is a coalesced projection write (once per key per minute, via
Valkey). The audit trail §10 promises belongs in `compliance`, which is
append-only storage sized for request volume.

### [x] C10 🟡 — "Constant-time token lookup" is not implementable, and hides the real rule

> **Verified 2026-08-15 — the code already does the right thing; the SPEC wording
> is what still needs the fix.** `internal/modules/identity/adapter/token/token.go:130`
> hashes with `crypto/sha256` — a fast hash, which is the correct choice here for
> exactly the ASVS reason given below, and not something to "improve" into a KDF
> later. `db/query/identity/guard.sql:52` (`ConsumeToken`) is a single
> `DELETE … WHERE digest = $1 AND purpose = $2 AND expires_at > $3 RETURNING
> subject_id`, so single-use is atomic rather than read-then-write, and an expired
> token is indistinguishable from an unknown one because the expiry is checked in
> the same statement. `TestIdentitySliceEndToEnd` exercises the replay refusal
> over HTTP.
>
> Remaining: reword §4 and §12, which still say "constant-time lookup". The reset
> flow itself does not exist yet, so C11's reset-specific bullets stay open.

§4 and §12 both specify it. You cannot do a constant-time lookup through a B-tree
index, and you do not need to.

What the spec never says is the part that matters: **store `SHA-256(token)`,
never the raw token.** This is the single most common real-world reset-flow bug
and it is absent.

A **fast** hash is correct here, and worth writing down so nobody "fixes" it
later: against 256 bits of uniform randomness there is nothing to guess, so a
slow KDF per token lookup is pure DoS surface with zero security gain. ASVS 5.0
V6.5.2 settles it — "a standard hash function can be used if the secret has 112
bits of entropy or more."

Reword to: *lookup by `SHA-256(token)`, then constant-time compare; the raw token
is never stored.*

### [ ] C11 🟢 — Missing from the reset flow

- **Referer / URL-logging leak.** Not addressed anywhere. RFC 9110 §10.1.3 and
  §17.9 are the citations. Required: `Referrer-Policy: no-referrer` on the reset
  landing page, no third-party scripts on it, token scrubbed from access logs.
  Best pattern: the emailed GET link is consumed once by a handler that exchanges
  the token for a short-lived server-side reset session and **302s to a
  token-free URL** — exactly the redirect RFC 9110 §17.9 recommends. Works
  without JS.
- **Email link prefetching** by security gateways (Proofpoint/Mimecast/Defender)
  will **consume a single-use token before the user clicks it**. Real
  availability bug, not theoretical.
- **Single-use must be an atomic conditional update**, not read-then-write.
  `UPDATE … WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
  RETURNING …`, treating zero rows as failure.
- **Never build the reset URL from the `Host` header** — password-reset poisoning.
- **Reset must not bypass MFA** (ASVS 5.0 V6.4.3) — the most commonly broken
  requirement in the set, and it converts "attacker controls the mailbox" into
  full account takeover.
- **Dummy-hash on unknown user.** §11 requires identical response *and timing*
  and §18 asserts it as a test, but the mechanism is absent. With Argon2id, the
  delta between "user exists → 250ms hash" and "user missing → 0ms" is the
  loudest possible oracle. State it, or §18's test will be written to pass
  against a broken implementation.

---

## Part C — Two traps that would pass every test

Both are the failure class this repo has already hit repeatedly: code that looks
correct, tests that pass, and the property silently absent.

### [ ] T1 🔴 — `go-webauthn`'s clone detection is dead code by default

```go
func (a *Authenticator) UpdateCounter(authDataCount uint32) {
	if authDataCount <= a.SignCount && (authDataCount != 0 || a.SignCount != 0) {
		a.CloneWarning = true
		return
	}
	a.SignCount = authDataCount
}
```

On a counter regression it sets a flag and **returns no error** — `FinishLogin`
succeeds. If the application never inspects
`credential.Authenticator.CloneWarning`, clone detection does nothing and every
test still passes. Make it an assertion in §18.

The zero/zero no-op is correct per spec, not a bug: synced passkey providers
report `signCount = 0` permanently because there is no coherent place to keep a
monotonic counter across N devices. **Never fail a login on 0/0.** On a genuine
regression, emit a warning event and require step-up rather than hard-denying —
the spec itself lists an out-of-order race as a benign cause, and §6/§9 make
concurrent sessions a live possibility rather than a theoretical one.

### [ ] T2 🔴 — A TOTP secret-generation flaw with no CVE

`pquerna/otp` **below v1.5.0** generated secrets with a short `Read` instead of
`io.ReadFull` — a partial RNG read left part of the secret as zero bytes,
silently reducing entropy (PR #100).

**No CVE or GHSA was ever filed**, so `govulncheck` and every other scanner will
not catch it. Only an explicit version pin will.

---

## Part D — Architectural collisions

### [ ] A1 🔴 — TOTP replay prevention needs mutable state a handler may not write

**RFC 6238 §5.2** is unambiguous: *"The verifier MUST NOT accept the second
attempt of the OTP after the successful validation has been issued for the first
OTP."* **No Go library provides this** — `pquerna/otp` has no used-code store and
no last-accepted counter.

It requires recording the last accepted time-step **in the same transaction as
the login**. Our write model forbids that: handlers append events, projectors
write Postgres. An event → projector round trip is far too slow, and the gap
between them *is* the replay window.

The PII vault is precedent — "the only mutable system of record". A second small,
explicitly carved-out mutable table is probably right, and it covers single-use
recovery codes too. **Needs an ADR, not a decision made in passing.**

### [x] A2 🟢 — The revocation-epoch pattern fits sessions, but only half of it

Assessed against `internal/platform/authz`'s existing per-principal epoch.

**Right for "log out everywhere".** A `sver` claim compared against the user's
current version makes it O(1) instead of enumerating and denylisting N sessions —
the same argument access.md §6.2 makes for authz, holding for the same reason.

**Wrong for per-session revocation**, and the reason is a failure-mode inversion
worth recording: in authz, an epoch read failure yields "an epoch nothing can
match" → cache skipped → round trip to OpenFGA → still correct, costing latency.
On a session hot path the same failure must fail **closed**, so **a Valkey blip
logs out every user simultaneously.** The authz design has no such cliff; copying
it onto sessions would import one.

Per-session revocation is a Valkey denylist keyed by `sid` with **TTL =
access-token lifetime**, so its steady state is "revocations in the last 10
minutes" — naturally tiny. Keep the documented 10-minute window; do not add a
lookup to every request chasing instant revocation.

`sver` must be **Postgres-authoritative** with a Valkey hot copy, per the repo's
own rule that `FLUSHALL` must be survivable.

### [ ] A3 🟡 — Our own RPC framework opens a CSRF surface

> **Verified 2026-08-15 — real, but not yet exploitable, and the trigger is
> precise.** Four identity RPCs are `NO_SIDE_EFFECTS` and therefore GET-routable
> (`GetUser`, `ListSessions`, `ListMethods`, `ListLoginHistory`,
> `identity.proto:1063-1108`). There is no `Sec-Fetch-Site` or `Origin` check
> anywhere in `internal/server/`. **But CSRF needs credentials the browser
> attaches by itself, and this server has none:** `grep` for `Cookie`,
> `SetCookie` and `http.Cookie` across `internal/server/`,
> `internal/modules/identity/` and `cmd/api/` returns nothing. Authentication is
> `Authorization: Bearer` only, and a cross-site navigation does not carry it.
>
> So the finding is a **precondition, not a live hole**. It becomes live the
> moment a session cookie exists — which is exactly what the Apple `form_post`
> flow below requires. Whoever introduces the first cookie owns this control, and
> it must land in the same change, not after it. A `Sec-Fetch-Site` check is not
> written today because a control with no threat to stop cannot be tested against
> one, and untested security machinery is how a false sense of coverage starts.

ConnectRPC serves **GET** routes for RPCs marked `IdempotencyLevel =
NO_SIDE_EFFECTS`. Those are top-level navigable, and `SameSite=Lax` permits
cross-site top-level GET.

So **marking an RPC `NO_SIDE_EFFECTS` is a security decision, not a performance
annotation**, and belongs in review. Worth a line in `CONVENTIONS.md`, and an
owner for the gate.

The good news: ConnectRPC already requires a `Connect-Protocol-Version` header,
which cannot be set cross-origin without triggering a preflight the server
refuses. That is a solid CSRF defence obtained free from the mandated stack. Add
a `Sec-Fetch-Site` check (browser-set, unforgeable) as the primary control, with
an `Origin` check as fallback.

**Also: Sign in with Apple returns via cross-site POST** (`form_post`, forced
whenever scopes are requested), and `SameSite=Lax` does **not** send cookies on
cross-site POST. The Apple flow needs its own short-lived, single-purpose
`SameSite=None; Secure` state cookie — never the session cookie. This is the most
common Apple integration failure and it is not in the spec.

### [ ] A4 🟡 — Breach re-checking has no offline answer

§4.1's third detection point — "on new corpus publication, re-screening over
`password_screened_at` watermarks" — **cannot work as written.** You hold only a
salted, peppered Argon2id digest; there is no offline test.

Every major vendor agrees. Okta documents it plainly ("doesn't retroactively
check"); Auth0, Cognito and Chrome all check at sign-in, sign-up and reset only.
The two designs that *do* re-scan either keep **recoverable plaintext** (Enzoic
on the customer's own DC; password managers by construction) or **bring the
corpus to the hash** — hashing newly leaked plaintexts under each matched user's
stored salt, which only works for *credential-pair* corpora, not password-only
lists like HIBP. That is Entra ID Protection's `leakedCredentials` and
Facebook's 2016 program.

**Do not store a truncated fast hash alongside the Argon2id digest.** No vendor
does this. A plain truncated SHA-1 is directly joinable against the public HIBP
corpus, handing an attacker with the DB a candidate set per user instantly and
offline — rebuilding exactly the efficient oracle the KDF exists to prevent.

The watermark's real value is **invalidating the clean verdict** so the *next
login* re-screens. Rewrite the row to say so. Dormant accounts — the actual
credential-stuffing target — are covered by the **identity track** instead: a
breach notification keyed on the email raises a risk event and needs no password
material at all.

Measured against the live API on 2026-08-11: HIBP is **~2.06 billion hashes**
(~81 GB raw, ~46 GB gzipped), and its own documentation is stale — it claims
~800 records per range response; **measured ~1,970**. The 800-record padding
floor is now unreachable and inert, leaving only the 0–200 jitter, which is
narrower than natural inter-prefix variance. `Add-Padding: true` also bypasses
the Cloudflare edge cache entirely, so padded requests hit origin.

### [~] A5 🟢 — Smaller contradictions

> **Partially resolved 2026-08-16 — two bullets were settled by the CODE, and the
> spec was the thing that had drifted. The rest stand.** Marked `[~]` rather than
> `[x]`: what remains is real, and the §6 cookie-tossing item is the one with
> teeth.
>
> **Idle timeout — settled, and neither document said it.** The implementation
> uses TWO windows, not one: `DefaultIdleWindow = 14 * 24h` and
> `DefaultAbsoluteWindow = 30 * 24h` (`app/authentication.go:80-87`), with the
> idle deadline pushed forward on each authenticated request and **clamped to the
> absolute deadline**. So §3's "idle > 14d" is right, and ADR-018's "30 days
> sliding" describes the absolute ceiling while calling it sliding — which is the
> one thing it is not. A session here cannot outlive 30 days however active it
> is. ADR-018's table wording is the remaining inaccuracy; ADRs are settled by
> policy, so this is flagged rather than edited.
>
> **`Elevated` as attributes — already true in the code.** `session_view` carries
> `aal`, `elevated_scope` and `elevated_until` as columns, and `ElevateSession`
> clamps with `LEAST($4::timestamptz, absolute_expires_at)`
> (`db/query/identity/session.sql:157`). So elevation is scoped and time-boxed
> exactly as this bullet asked, and it is §3's state-machine diagram — which
> draws `Elevated` as a peer state of `Active` — that is now the stale artifact.
> The review's own warning applies to the diagram, not to the build.
- **§3's `Elevated` should be attributes, not a state** — `(aal, elevated_until,
  elevation_scope)` on `Active`. A single state cannot express "elevated to AAL2
  but this action needs AAL3", and elevation must be scoped to the ceremony that
  produced it (elevating to change an email should not authorize deleting the
  account). Do **not** carry `elevated_until` in the access token: a 10-minute
  token holding a 5-minute elevation outlives its own window.
- **§3's diagram contradicts its table** — the diagram draws `Compromised`
  reachable only from `Elevated`; the table correctly says any state.
- **§6's session-ring rationale is wrong.** ✅ **Corrected 2026-08-16.** The
  false claim is now stated and refuted in place rather than deleted, so the
  refutation cannot be rediscovered as an argument for collapsing to one cookie.
  "No single cookie contains a joinable set of identities" does not follow — the
  browser sends every matching cookie on every request, so the server receives the
  joinable set regardless. Splitting buys independent revocation and independent
  overwrite, which is sufficient justification.
- **§6's account selector is trusted as authority.** ✅ **Specified 2026-08-16**
  — §6 now states all three requirements (request names the account, `__Host-` on
  the selector, CSRF validated against the named account) and names cookie
  tossing as the attack. Still UNBUILT: no cookie exists in the server today
  (auth is bearer-only), so this is a contract for whoever adds the first one. Invariant 1 rejects a
  request naming two accounts but does not require a request to name one. If the
  selector cookie is the sole authority, **cookie tossing** from any subdomain
  flips it. Required: the request MUST name the account explicitly (the cookie is
  a UI hint only), the selector MUST also carry `__Host-`, and the CSRF token
  must be validated against the account the request names.
- **§6 has no ring-size cap.** ✅ **Stated 2026-08-16** as a requirement with its
  reason. The NUMBER is still unchosen — it wants a real answer about how many
  accounts one person plausibly holds, not a guess written into a doc.
- **§10's key format has no checksum**, which is what makes a secret-scanning
  partner pattern viable at an acceptable false-positive rate. Also: `<keyid>`
  must be random and never derived from the org ID — the AWS `AKIA` lesson is
  that a leaked key should not disclose which customer it belongs to.
- **§10 vs ADR-007.** "API keys have no cached-token equivalent" is true only
  because every API-key request performs a lookup, which contradicts "no database
  read on the hot path". Both can hold simultaneously, but say so, or the first
  person optimising API-key auth will add a cache and silently delete the
  immediate-revocation property.
- **§11 has no aggregate breaker.** Per-identifier and per-IP counters both
  structurally miss credential stuffing from residential proxy networks — each IP
  makes one request, each account is hit once. The best cheap signal is the
  **ratio of failures against non-existent accounts**; a stuffing list contains
  emails you have never had. Count it server-side while keeping the *response*
  enumeration-safe.
- **IPv6 rate limiting must bucket at /64 minimum.** Per-/128 is defeated for
  free by incrementing. This is the most commonly shipped bug in the area.
- **§9's "mark device trusted"** should be a first-party `HttpOnly` device cookie
  you mint, not a fingerprint. EDPB Guidelines 2/2023 place fingerprinting inside
  the ePrivacy consent requirement; a security cookie sits far more comfortably in
  the exemption and is more reliable besides.
- **§8's device grant** omits RFC 8628's two abuse controls: `slow_down`/
  `authorization_pending` polling discipline (§3.5) and user-code entropy plus
  brute-force limiting (§5.2). Add a binding confirmation screen naming the
  device, or a user can be phished into approving an attacker's.
- **§7 is missing RFC 9207 (`iss`).** Chronos federates to four authorization
  servers from one client — exactly the multi-AS mix-up condition where RFC 9700
  §4.4.2 says the client MUST bind the intended issuer to the user agent.
- **§15's `FederatedIdentity.EmailVerified` must be tri-state**, not a bool.
  Entra and GitHub-noreply are "not asserted", which is not the same as `false`.
- **§15's `FederatedProvider` port cannot express a correct flow.**
  `AuthorizeURL / Exchange / Identity` has nowhere to put `nonce`, `state`,
  `verifier` or `expected_iss`. `AuthorizeURL` must return that tuple for the
  caller to persist and `Exchange` must take it back.
- **§16 has no Apple client-secret rotation workflow.** Apple's `client_secret`
  is an ES256 JWT with a **maximum 6-month expiry** that must be regenerated on a
  schedule, or every Apple login breaks at once with no warning. This is a
  natural Temporal cron entry and it is absent.
- **§13 has no `FederatedIdentityRevokedByProvider` event**, which Apple's
  server-to-server notifications require.

---

## Part E — Package selections

Versions and maintenance status verified 2026-08-11. "What goes wrong" is the
column that matters.

| Need | Choice | Status | What goes wrong |
| --- | --- | --- | --- |
| Password hashing | `x/crypto/argon2`, wrapped ourselves | official | Provides `IDKey()` and nothing else — no salt, no PHC encoding, no constant-time verify, no version check. We need custom encoding anyway to carry `pepper_key_version`, which no library models. **Reject Argon2 version != `0x13`** on parse. |
| WebAuthn | `go-webauthn/webauthn` | v0.17.4, 2026-05-22 | Only credible option (`duo-labs` is archived). 0.x with breaking changes — v0.17.0 changed credential JSON. **Pin exactly; store credentials in our own columns, never its marshalled JSON.** See T1. |
| TOTP | `pquerna/otp` | v1.5.0, frozen | Pin ≥ v1.5.0 (T2). **No replay prevention** — ours to build (A1). Last commit 2025-08-07; budget for vendoring. |
| WebAuthn testing | `descope/virtualwebauthn` | v1.0.5, 2026-05-10 | Test dependency. Will not produce counter regressions, BE flips, or credential-ID collisions — hand-build those fixtures. |
| OAuth client | `golang.org/x/oauth2` | v0.36.0, 2026-02-11 | PKCE built in (`GenerateVerifier`, `S256ChallengeOption`). Does **not** validate ID tokens, `state`, `nonce`, or `iss` — all four are ours. `TokenSource` refreshing concurrently issues N refreshes, which trips reuse detection; wrap with `singleflight` per session. |
| OIDC | `coreos/go-oidc/v3` | v3.20.0, 2026-07-08 | **Active** — the "unmaintained" reputation is out of date. Alg confusion is structurally closed (`jose.ParseSigned` enforces the allowlist before the payload is touched). Does **not** check `nonce`, `at_hash`, `c_hash`, `azp` — three fail silently. Reuse one `RemoteKeySet` per issuer for the process lifetime; its unknown-`kid` refresh is a DoS lever needing a rate limit. |
| JWT issuance | `golang-jwt/jwt/v5` | v5.3.1 | Already a direct dep. **Always pass `jwt.WithValidMethods([]string{"EdDSA"})`** — without it `Parse` honours the token's own `alg` header and you have hand-rolled alg confusion. Add a lint rule; a rule beats a convention. |
| PRECIS / usernames | `x/text/secure/precis` | v0.40.0, 2026-07-08 | Self-declared "under construction". Does **not** implement RFC 8265's zero-length check (golang/go#64531, open since 2023) — wrap it. **CVE-2026-56851** (Nickname profile panic) is fixed upstream but **in no released version**; avoid that profile on untrusted input until a release carries it. |
| IDNA / domains | `x/net/idna` | v0.57.0, 2026-07-08 | De facto stable. Use `idna.Lookup` for inbound validation, `idna.Registration` when claiming. |
| Confusables (UTS #39) | **build it ourselves** | — | Four libraries are the same ~200-line skeleton copied around; three untouched since 2020–21 with Unicode 13 tables. The only one claiming restriction levels and mixed-script detection has 6 stars. `go:generate` from the current `confusables.txt` is ~a day and removes the stale-table risk. |
| Blind index | **build it ourselves** | — | ~60 lines over `hkdf` + `hmac`. The only Go port is a v0.1.x single-maintainer package — not a dependency for a login path. |
| Rate limiting | **GCRA in Lua on `valkey-go`** | — | `x/time/rate` is in-process only: with N replicas the effective limit is N×, and an unbounded per-key map is itself a DoS. `redis_rate` would add a second Redis client library. ~40 lines of Lua. |

**Argon2id starting parameters**, to be tuned by measurement on the target
hardware, never a laptop: `m = 65536 KiB (64 MiB)`, `t = 1`, `p = 1`, salt 128
bits, tag 256 bits. RFC 9106's SECOND RECOMMENDED with `p` reduced to 1, because
a login server optimises *throughput under concurrency* rather than single-hash
latency. RFC 9106 §7.3: one pass maximises attack cost for constant defender
time — so raise `m` to the ceiling your throughput math allows first, and only
then spend leftover latency budget on `t`.

Note RFC 9106's FIRST RECOMMENDED (2 GiB) is scoped to a single-user-at-a-time
verifier and is **out of scope for a login endpoint**. OWASP's numbers (46 MiB /
19 MiB) are a **floor**, not a target.

**Bound the hasher.** At 64 MiB/hash, 200 concurrent logins is 12.8 GiB of GC
churn — memory-hard hashing is a self-inflicted amplification vector. A
semaphore at `min(NumCPU, RAM_budget / m)` with a short acquisition timeout
shedding 503. Note the **CPU ceiling** usually decides before memory does: at 250
ms of single-core work, one core sustains 4 logins/s, so an 8-core box tops out
near 32/s. Benchmark with `b.RunParallel`, not `time.Since` — Argon2 is
memory-bandwidth bound and degrades superlinearly under concurrency.

---

## Open questions carried forward

Beyond the six decisions in Part A:

1. **Memory budget for the hash pool**, in GiB, on the production instance.
   Everything downstream derives from this and nobody has stated it.
2. **Reset token TTL** — 15 minutes recommended; some orgs demand 60.
3. **Registration enumeration.** Registration cannot be fully enumeration-safe
   while enforcing unique emails synchronously. Accept the leak, or move to an
   always-"check your email" flow — which conflicts with the reservation
   stream's current hard 400 on collision. Decide before it is built.
4. **Ring size cap**, and whether "add account" is reachable without an existing
   session.
5. **Rate-limiter fallback when Valkey is down.** Failing closed on login is a
   total outage; failing open removes stuffing protection at exactly the moment
   an attacker may have caused the outage. Recommendation: degrade to a strict
   in-process limiter rather than choosing.
6. **Apple: single developer team?** If not, `sub` is not stable across teams and
   merge becomes mandatory.
7. **Apple private relay** addresses as the account's contact address — accept,
   or require a separately-verified deliverable address? Relay addresses are
   revocable and then bounce permanently.
8. **AAL3 in scope for v1 at all?** If aspiration, delete the row (C4).
9. **Who curates the AAGUID allow-list** — operator-global or per-org?

---

## What was verified, and what was not

Verified against primary sources on 2026-08-11: W3C WebAuthn L3 (CR snapshot, 26
May 2026), NIST SP 800-63B-4, RFC 9106, RFC 9700 (BCP 240), RFC 7636, RFC 8252
(BCP 212), RFC 9207, RFC 9068, RFC 6238/4226, RFC 8264/8265, RFC 5321/5322, RFC
6530/6531, RFC 9110, UTS #39 rev. 32 and UTS #46 rev. 35 (Unicode 17.0.0),
Chromium source for SameSite behaviour, the Go module proxy, and live
measurements against `api.pwnedpasswords.com`.

**Not verified, and not guessed at:**

- Whether `go-webauthn/metadata` verifies the FIDO MDS BLOB signature against a
  pinned root. **Read `metadata/const.go` and `decode.go` before relying on MDS
  for an AAL3 gate.**
- SP 800-63B-4 Appendix B's clause-level syncable-authenticator requirements were
  summarized, not read verbatim. Read them directly before defending the AAL
  policy to an auditor.
- GitHub's exact API-key checksum algorithm, width and encoding. Confirm before
  freezing the key format — it cannot change afterwards.
- Whether Go 1.26 ships a stdlib Argon2, and whether EdDSA is permitted under
  `GODEBUG=fips140=on`.
- Machine-to-machine tiering (client credentials / `private_key_jwt` / mTLS) was
  researched but its brief was cut short by a session limit; the recommendation —
  API keys now, `private_key_jwt` when an enterprise review asks, mTLS only for a
  named regulated customer — is recorded here without its full supporting detail.

A published version of this review is at
`https://claude.ai/code/artifact/f966b77d-3e9b-4847-a207-44913d64de57`.

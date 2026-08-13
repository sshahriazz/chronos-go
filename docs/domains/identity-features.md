# Identity — the complete feature plane

What `identity` does when it is finished. Capability surface only — no rationale,
no findings, no research. Decisions are recorded in `IDENTITY-REVIEW.md` Part A;
the reasoning behind each behaviour lives in `identity.md`.

Scope boundaries, stated once: identity answers **"who is this?"**. It never
answers "what may they do" (`access`), "what did they buy" (`entitlement`), "are
they a member" (`organization` / `workspace`), or "send this email"
(`notification`).

---

## 1. Registration and account lifecycle

- Register with email + password, or with a passkey, or with a federated provider
- **A second authentication factor is required before an account becomes
  `active`** — password-alone is not an authentication path
- Email verification by single-use token; unverified accounts cannot authenticate
- Resend verification, rate-limited
- Enumeration-safe responses at every entry point: registration, login, reset,
  invitation — identical body, identical status, identical timing
- Account states: `pending → active → deactivated → suspended → erased`
- Self-service deactivate and reactivate
- Deletion request → handed to `compliance` for erasure
- Erasure is a key destruction; the account's history remains replayable with the
  subject unreadable

## 2. Authentication methods

Every method below is an entity inside the `User` aggregate, so the
"at least one usable method" invariant spans all of them.

| Method | Count | Primary factor |
| --- | --- | --- |
| Password | 0..1 | yes |
| Passkey / WebAuthn | 0..n | yes |
| Federated link | 0..n | yes |
| TOTP | 0..1 | second factor only |
| Recovery codes | 0..1 set | second factor only |

- **`AtLeastOneUsableMethod`** — an active user always retains ≥1 primary method;
  removal that would breach it fails with a named error, never a lockout
- **`NoSilentDowngrade`** — an attempt may not use a method weaker than the
  account's strongest unless the user explicitly elects the fallback; every such
  use is rate-limited, notified, and recorded as a risk signal
- Method strength is ordered and is a first-class domain concept
- Adding a password to a passwordless account requires step-up, notification, and
  is treated as a risk event

## 3. Passwords

- Argon2id, parameters stored per hash, tuned by measurement
- Digest encrypted under a transit-wrapped pepper key, bound to the credential row
- Unicode NFC normalization at set and at verify
- 8-character minimum (second factor is mandatory), 64-character floor accepted
- No composition rules, no periodic rotation, paste and password managers allowed
- Transparent rehash on next successful login when algorithm, parameters, or key
  version fall below current policy
- Breach screening at registration, at change, and at successful login
- A breached credential does not block the login; it produces a session marked
  `RequiresCredentialRotation`, restricted to profile and credential endpoints
- Password change requires the current password or step-up
- Password reset by single-use, hashed, short-lived token, delivered only to the
  stored verified address
- Reset never bypasses an enrolled second factor
- Reset invalidates all sessions, all other outstanding reset tokens, and any
  pending email change
- Failed-attempt ceiling per authenticator, with progressive delay as the primary
  control and recovery by rebinding

## 4. Passkeys and WebAuthn

- Registration and authentication ceremonies, fully verified server-side
- Discoverable credentials by default; **conditional UI / autofill** login with
  no username typed
- Cross-device authentication over hybrid transport (QR + BLE proximity)
- Multiple passkeys per user, each independently named, listed, and revocable
- Per-credential record: public key, sign count, AAGUID-derived provider label,
  transports, backup eligibility and backup state, UV status, created and last
  used
- Synced-versus-device-bound is surfaced to the user in plain language
- Prompts driven by backup state: "add a second credential" when a credential is
  single-device, "you can remove your password" when it is backed up
- Clone signal on counter regression → step-up and notification, never a silent
  lockout
- Optional per-organization policy: require attested authenticators from an
  allow-list
- Signal to password managers when a credential is deleted server-side, so it
  disappears from the user's list

## 5. Second factors and recovery

- TOTP enrollment with QR provisioning, verified by a live code before it is
  enabled
- TOTP replay prevention — a validated code cannot be used a second time
- TOTP disable requires step-up
- Recovery codes: a fixed set, single-use, shown once, hashed at rest
- Remaining-code count surfaced; warning as the set runs low
- Regeneration replaces the whole set atomically and notifies the account holder
- Using the last code forces an interstitial: new set issued, additional
  credential encouraged

## 6. Sessions

- Session per device, listed with device name, platform, coarse location, current
  and last-seen
- Idle and absolute timeouts, both enforced
- Revoke one session, revoke all others, revoke everything
- Revocation propagates to the API, to realtime connections, and to refresh
- **Session ring** — several accounts signed in simultaneously in one browser,
  each independently authenticated, elevated, and revocable
- Every request names its account explicitly; nothing is shared across the ring
- Step-up elevation, time-boxed and scoped to the ceremony that produced it
- Elevation required for: password change, MFA disable, credential removal, email
  change, API key creation, account deletion, ownership transfer
- Compromise detection on refresh-token replay → whole family revoked, session
  marked compromised, user notified
- Trusted-device marking, so a known device is challenged less often

## 7. Federated identity

Consumers only — Chronos is not an authorization server. Third parties do not
integrate with Chronos.

- **Google, GitHub, Apple, Microsoft Entra**
- Authorization code with PKCE, `state`, `nonce`, and issuer binding
- Identity is always `(issuer, subject)` — never email
- Linking an additional provider to an existing account requires step-by-step
  proof: fresh re-authentication, explicit confirmation naming the provider
- Auto-link only where the provider's email verification is trustworthy
- Unlink requires step-up and leaves the account with a usable method
- Provider-initiated revocation is honoured
- Connected providers listed and managed by the user

## 8. Enterprise SSO — per tenant

- **OIDC per organization**, configured by the organization, inherited by every
  workspace inside it
- Domain verification, after which the organization may vouch for addresses on
  its domain
- JIT provisioning on first successful SSO login
- Per-organization policy: require SSO, disable password enrollment
- A person in several SSO organizations holds one account with several federated
  links

## 9. Native, mobile and headless clients

- System browser only — embedded webviews refused
- Claimed HTTPS redirects on mobile, loopback on desktop
- Device authorization grant for CLI and TV, with a confirmation screen naming
  the device
- Tokens stored in platform keychains
- Every device registers a name and platform and appears in the session list

## 10. Machine-to-machine

- **API keys** — prefixed, checksummed, scoped, expiring, rotatable with overlap
- Keys are bound to one organization and can never exceed the granting
  principal's authority
- Rotation issues a new key and retires the old on a schedule, with last-used
  visible so traffic can be confirmed moved
- Immediate revocation; automatic revocation when the granting member leaves
- Last-used timestamp and IP, per key
- **Service accounts** — non-human principals owned by an organization, with
  their own lifecycle
- Full audit trail of what each key touched, in `compliance`
- Secret-scanning partner format, so leaked keys are caught and revoked
  automatically

## 11. Risk, abuse and notification

- Rate limiting per identifier, per network, and in aggregate
- Credential-stuffing detection
- Impossible-travel and new-device signals → notify, optionally step up
- Security notifications to the verified address for: new sign-in from an unknown
  device, password change, method added or removed, email change, session
  revocation, recovery-code use, key creation
- Every authentication outcome is an event; the login history is a read model
- Account activity view: recent sign-ins, active sessions, connected providers,
  registered methods

## 12. Recovery and edge cases

- Forgotten password → verified-address reset
- Lost second factor → recovery code
- Lost everything → last-resort recovery: organization-admin initiated,
  cancellable delay, all factors invalidated, re-enrolment required
- Duplicate accounts → merge, requiring proof of control of both sides
- Email change → verify new, notify old, revert window
- Identifier reuse after erasure

---

## What identity publishes

`UserRegistered` · `EmailVerificationRequested` · `EmailVerified` ·
`EmailChangeRequested` · `EmailChanged` · `PasswordSet` · `PasswordChanged` ·
`PasswordResetRequested` · `PasswordRehashed` · `CredentialCompromiseDetected` ·
`PasskeyRegistered` · `PasskeyRemoved` · `PasskeyBackupStateChanged` ·
`PasskeyCloneWarning` · `TotpEnabled` · `TotpDisabled` ·
`RecoveryCodesGenerated` · `RecoveryCodeConsumed` · `RecoveryCodesExhausted` ·
`FederatedIdentityLinked` · `FederatedIdentityUnlinked` ·
`FederatedIdentityRevokedByProvider` · `AuthenticationSucceeded` ·
`AuthenticationFailed` · `AuthenticatorDisabled` · `SecondFactorChallenged` ·
`SecondFactorSucceeded` · `SessionCreated` · `SessionElevated` ·
`SessionRevoked` · `SessionExpired` · `SessionCompromiseDetected` ·
`DeviceRegistered` · `DeviceTrusted` · `ApiKeyCreated` · `ApiKeyRotated` ·
`ApiKeyRevoked` · `ServiceAccountCreated` · `UserDeactivated` · `UserSuspended` ·
`UserDeletionRequested`

Every one carries `SubjectID` pseudonyms only — no email, no IP, no device name,
no user agent.

## Read models

`user_view` · `auth_method_view` · `session_view` · `linked_account_view` ·
`api_key_view` · `login_history_view` · `sso_config_view` ·
`auth_attempt_counter`

---

## Build order

Each slice is independently shippable and leaves the system in a working state.

| Slice | Contains | Unblocks |
| --- | --- | --- |
| **1** | `User` aggregate, registration, email verification, password, TOTP, recovery codes, first session | The authn gate — every non-public RPC is refused until this exists |
| **2** | Passkeys, conditional UI, method management, step-up | Passwordless as a first-class path |
| **3** | Full session surface: ring, device list, revocation, trusted devices, risk signals | Multi-account, and the security-settings screen |
| **4** | Federated providers, linking, merge | Social login |
| **5** | API keys, service accounts | The public API |
| **6** | OIDC per organization, domain verification, JIT provisioning | Enterprise |

Slice 1 is the one that matters most: until it lands, `authn` has no
implementation and the interceptor pipeline refuses everything that is not public.

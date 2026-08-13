# Identity slice 1 — build log and handoff

State of the `User` aggregate slice: what is built, what it decided, and what is
left. Feature surface is in [domains/identity-features.md](domains/identity-features.md);
open findings are in [IDENTITY-REVIEW.md](IDENTITY-REVIEW.md).

**Gate status:** `make check` exit 0. `govulncheck ./...` reports 0
vulnerabilities affecting this code.

---

## Done

| # | Package | What it is |
| --- | --- | --- |
| S1-01 | `platform/ids` | `Credential` kind, prefix `cred` |
| S1-02 | `modules/identity/contract` | 29 events, `MethodKind`, `EmailIndex`, `AssuranceLevel`, `FailureReason` |
| S1-02 | `modules/identity/module.go` | codec + schema registration, one place for three binaries |
| S1-03 | `domain/method.go` | role, strength ordering, `AALFor` |
| S1-04 | `domain/user.go` | `User` aggregate, lifecycle, `AtLeastOneUsableMethod`, `NoSilentDowngrade` |
| S1-05 | `domain/password.go` | RFC 8265 `OpaqueString` profile |
| S1-06 | `domain/user.go` | two-step TOTP enrolment, recovery-code set |
| S1-07 | `domain/session.go` | `Session` aggregate, two deadlines, scoped elevation |
| S1-10 | `domain/email.go` | RFC 5321 normalization, IDNA, one deliberate RFC deviation |
| S1-09 | `adapter/argon2id` | peppered, AAD-bound, rotatable, concurrency-bounded |
| S1-10 | `adapter/blindindex` | full-width keyed email index |
| S1-11 | `domain/reservation.go` | `EmailReservation`, lease-then-confirm |
| S1-12 | `adapter/totp` | RFC 6238 with a mandatory replay guard |
| S1-13 | `adapter/token` | single-use verification and reset secrets |
| S1-14 | `adapter/hibp` | breach screening, k-anonymity, fail-open |
| S1-15 | `platform/ratelimit` + `adapter/valkey` | multi-window attempt ceiling |
| S1-16 | `cmd/migrate/migrations/00008_identity.sql` | eight system-scoped tables, constraints probed live |
| S1-17 | `db/query/identity/*.sql` + `adapter/postgres` | 30 sqlc queries; `Guards` implements both single-use ports |
| S1-18 | `identity/projection` | user, session and reservation projectors; all three wired into `cmd/projector` |

Ports declared in `app/ports.go` and not yet implemented: `PasswordHasher`
(done), `TOTPReplayGuard`, `TokenStore`, `BreachChecker`.

---

## Decisions that are not obvious from the code

**Identity read models are system-scoped, not tenant-scoped.** A user exists
before any organization, so there is no `workspace_id` to `SET LOCAL`. They are
reached through `db.SystemTX` only — the same path the PII vault uses. The cost
is a second access path that has to be audited separately from RLS.

**Session tokens are opaque, hashed, and resolved per request.** Not JWTs. A JWT
has a window in which a revoked session still works, which contradicts the
tombstone discipline in ADR-045.

**Slice 1 ships TOTP as the only second factor.** D3 makes a second factor
mandatory before an account activates; passkeys are slice 2. So registration is:
email + password → verify → enrol TOTP → recovery codes → active.

**Breach screening is real in slice 1 and fails open.** An unreachable corpus
allows the login and records a named signal. Blocking would let an outage at a
third party lock every user out.

**One blind-index key, never rotated, no version column.** The index names a
KurrentDB stream and stream names are immutable, so rotation orphans every
reservation ever written and uniqueness silently stops being enforced for
everything registered before it. IDENTITY-REVIEW C7 asked for a version column;
it is deliberately absent, because a column that can never change advertises a
capability that does not exist. C7's other half — truncation — is fixed: the
index is the full 32 bytes.

**The password pepper is held unwrapped in process memory.** The stronger option
is a transit round trip per verify so the pepper never exists here, but
`crypto.KeyRing` is `Wrap`/`Unwrap` with no additional-data parameter, and
without AAD the verifier cannot be bound to its row. The binding prevents a live
account takeover from one table write; pepper-in-memory only raises the cost of
an offline attack that already requires the database.

**Argon2id parameters are measured, not copied.** 32 MiB / 3 passes / 1 lane =
51 ms on an 11-core arm64 dev machine. Memory is capped for an operational
reason: each concurrent hash holds its full working set.

**Password hashing is concurrency-bounded at `GOMAXPROCS`.** Measured:
throughput saturates at the core count and then declines, while memory and
latency grow linearly. 128 concurrent logins is 4 GiB spent to do less work than
16. Over capacity, callers queue 2 s then get `RATE_LIMITED`.

**The attempt ceiling fails OPEN; TOTP replay fails CLOSED.** The two look
inconsistent and are not. Rate limiting failing closed would make a Valkey
outage a total authentication outage, and its damage is bounded by two other
controls: the hasher's concurrency limit caps memory however many attempts
arrive, and a second factor is mandatory so guessing a password alone produces
no session. **That second dependency is load-bearing — if password-only
authentication ever becomes reachable, this decision must be revisited**, because
unthrottled guessing would then be sufficient on its own. TOTP replay has no such
backstop: accepting a replayed code IS the compromise.

**`credential` is the one identity table NOT rebuildable from the log.** Password
verifiers and TOTP secrets cannot enter events — an event is permanent, so a
verifier in one survives the password change, survives erasure of everything
else, and stays offline-crackable forever. The log records THAT a password was
set; the table holds what verifies it. The accepted consequence: a rebuild from
position zero reconstructs every other identity table and not this one. Losing it
means every user resets their password, which is recoverable; putting its
contents in the log is not.

**`totp_replay`'s primary key IS the replay guard.** Not a backstop for
application logic. `SELECT` then `INSERT` races two presentations of the same
code and both win — exactly the concurrency a relaying attacker produces.
Verified live: eight concurrent `INSERT ... ON CONFLICT DO NOTHING` for one step
produced exactly **one** winner and one row.

**One rule decides which table is a projection: is the value in the log?**

| In the log | Not in the log |
| --- | --- |
| PROJECTION — truncated and replayed on rebuild | AUTHORITATIVE — never truncated, never reconstructed |
| `user_view`, `session_view`, `login_history_view` | `credential`, `recovery_code`, `identity_token`, `session_token`, `totp_replay` |

Secrets are never in the log — a digest in an event outlives what it protects.
Values that move on every request are never in the log either — recording each
idle-deadline refresh would make every authenticated read a write. Both belong on
the authoritative side.

Two migrations exist only because 00008 got this wrong, and both were found by
writing the code that had to live with it:

- **00009** drops the foreign keys from `credential`, `recovery_code`,
  `identity_token` and `login_history_view` to `user_view`. With them, a routine
  projection rebuild cascades into every password verifier in the system, and no
  replay can bring them back. Found while writing `Reset` — there was no version
  of it that was both correct and safe.
- **00010** splits `session_token` out of `session_view`. `SessionCreated`
  carries no digest, so a projector could not populate a `NOT NULL` column, and a
  rebuild would have destroyed every live session's secret. A session now resolves
  only when BOTH halves exist. The cost is stated rather than hidden: rebuilding
  the session projection signs everyone out for its duration. That buys the
  ability to fix a session-projection bug by replaying the log.

**Tokens use SHA-256, passwords use Argon2id.** The rule is where the entropy
came from: slow hash when a human chose the secret, fast hash when `crypto/rand`
did. Argon2id on a 256-bit token would add 50 ms per link click and buy nothing.

---

## Verification discipline used here

Rate-limit windows are FIXED, not sliding, and the boundary burst is real: a
caller can spend a full window at the end of one and again at the start of the
next, so the true worst case is 2x the stated limit. Stated rather than papered
over — the number is a deterrent, not a guarantee.

Every package got a mutation pass — a deliberate defect planted one at a time,
with the requirement that a *named* test fails. Counts: domain 16/16, argon2id
21/21, blindindex + email 14/14, reservation 13/13, totp 14/14, token 9/9,
hibp 13/13, ratelimit + counter 7/7.

Seven defects were found this way. They are listed because the pattern repeats,
not for their own sake:

1. **Recovery codes satisfied the mandatory-second-factor rule.** Password + a
   printed sheet activated the account.
2. **`IsDowngrade` fired on every ordinary login.** It compared the primary
   factor against the strongest of *all* methods, so password-vs-your-own-TOTP
   read as a downgrade. The signal would have been noise within a week.
3. **The session idle deadline could never move.** Held as a fixed instant with
   nothing able to advance it, so every session died one idle window after
   creation regardless of use.
4. **`decode` left `KeyLen` at zero**, so `NeedsRehash` returned true for every
   verifier forever and every login rehashed.
5. **A released reservation reported "available" for the wrong reason** — the
   zero deadline, not the dropped claim. A broken release looked identical.
6. **`make(chan struct{}, -1)` panicked inside an option** before `New` could
   validate it. An option that can panic cannot be validated.
7. **A sub-millisecond rate-limit window deleted its own key.** `PEXPIRE 0`
   removes a key, so the counter would be created and destroyed on every call,
   every attempt would read 1, and the limiter would silently permit everything.
   Rounding up to 1 ms was the first fix and was worse — a 1 ms key may or may
   not survive to the next assertion, so the guard could not be verified.
   Refusing sub-millisecond windows is both safer and checkable.

Five tests of mine were vacuous or misreported and had to be repaired:

- **NFC fixtures were byte-identical.** Typing both the composed and decomposed
  forms as literals produces the same bytes — the editor normalizes as you type.
  They would have passed against a build with no normalization at all. Now
  written with explicit `\u` escapes and verified distinct.
- **A "catch" was a compile error.** Deleting `norm.NFC.String(...)` left `norm`
  unused, so the compiler failed rather than the test. Re-run with a
  substitution that keeps the import live.
- **An entropy assertion followed its own constant.** `len(raw) != token.Bytes`
  is satisfied by halving `token.Bytes`. Now an absolute floor as well.
- **A `User-Agent` assertion could not fail.** It checked for non-empty, but Go's
  HTTP client sets its own default — so deleting the header still passed. Now
  asserts the exact value.
- **A "catch" was a build failure, twice more.** Removing a Lua script left a
  variable unused; a non-atomic substitution did the same. Both reported as
  caught until re-run with mutations that compile. The real result: a client-side
  read-modify-write turns 200 concurrent increments into a final count of **3**.

Four pieces of dead code were removed after probing rather than reasoning:

- `strings.ToLower(domain)` — `idna.Lookup.ToASCII` already case-folds
- `norm.NFC.String(domain)` — it NFC-normalizes too
- a post-punycode length recheck — punycode *shrinks* UTF-8 (251 → 179 bytes),
  so the branch was unreachable and its comment claimed a hazard that does not
  exist
- `Skew: 0` in `ValidateOpts` when *generating* a code — only consulted when
  validating

---

## Left to build

Order matters: 16–18 unblock 19–22, which unblock 23–25.

| # | Task | Notes |
| --- | --- | --- |
| S1-19 | Registration commands | `Register` claims the reservation; `VerifyEmail` confirms it. Two aggregates, two streams, **not atomic** — order settled below |
| S1-20 | Second-factor commands | |
| S1-21 | Authentication commands | |
| S1-22 | Queries | keyset via `platform/page` |
| S1-23 | `proto/chronos/identity/v1` | Every method needs full policy annotations or the server refuses to start |
| S1-24 | Connect handlers | `domain/` must not import `gen/proto` |
| S1-25 | `interceptor.Authenticator` | **The point of the slice.** Until it exists every non-public RPC is refused |
| S1-26 | Revocation → tombstones | Reuses the ADR-045 kernel |
| S1-27 | `cmd/api` wiring + composition-root test | |
| S1-28 | Integration tests | |
| S1-29 | Final mutation pass | |

---

## What S1-18 turned up

**Identity was wired into no binary.** `cmd/projector` registered notification
events and notification projections only, so all three identity projections would
have run nowhere and `user_view` would have stayed empty with every test passing.
This is the same failure as the three unwired notification adapters, one layer
down. Two composition-root tests now cover it: `TestEveryProjectionIsRegistered`
(every projection is in the registry, names are unique, filters validate) and
`TestTheProjectorDecodesEveryIdentityEvent`, which compares the projector's codec
against a codec built from `identity.RegisterEvents` rather than against a list —
a second list is a second place to forget an event. Both were checked with
compiling mutations.

**The reservation projection filters by stream prefix, unlike its two siblings.**
`user` and `session` filter on the `identity.` event-type prefix because their
events span two categories. Reservations are one whole category, so a stream
prefix resolves to a single category and rebuilds read `$ce-reservation_email`
instead of scanning `$all`. The `$et-` shortcut was the obvious alternative and
does not apply: the runner takes it only when a filter names exactly one event
type, and this projection handles three.

**Two SQL guards are provably redundant and were kept anyway.** A mutation
removing `NOT verified` from the sweep survives, because confirmation also clears
`expires_at` and NULL never satisfies the comparison; the same is true of
`released_at IS NOT NULL` in the retention delete. Both stay — the sweep's partial
index is defined on that exact predicate and a query that does not match it does
not use it, and freeing a verified address should take two mistakes rather than
one. Both survivals are recorded in the SQL so the next reader does not "simplify"
them.

---

## Settled: the registration ordering

`Register` writes to two aggregates on two streams, and KurrentDB has no
cross-stream transaction, so one of them lands first and the process can die
between them. **The order is reserve first, then register**, and the reason is
which crash is recoverable rather than which is likelier.

Reserve-then-register leaves, on a crash, a lease with no account. That lease
lapses on its own: `expires_at` plus the sweep over `email_reservation_view` is
machinery that already exists, and the address frees itself. The cost is bounded
— the address is unusable until the lease runs out.

Register-then-reserve leaves an account holding an address it has no claim on.
Nothing sweeps that. A second registration for the same address then wins the
reservation, and two accounts point at one identifier while `GetUserByEmailIndex`
— the login lookup — resolves to whichever row landed. No existing mechanism
repairs it.

Retrying is safe because `EmailReservation.Reserve` is idempotent for the same
subject and does **not** extend the lease: a client retrying after a crash
re-reserves its own claim and continues, rather than colliding with its own
orphan. That property was built for this case and is what makes the choice cheap.

The dependency this creates is worth stating: **registration is not shippable
until the lapse sweep runs.** Without it an abandoned registration holds an
address permanently, which is the attack `email_reservation_view` exists to stop.
The sweep is a Temporal schedule reading `ListLapsedReservations` and issuing
releases **against the stream** — it never writes the view, so a stale row costs
one wasted aggregate load and never a wrong release.

**`GOMAXPROCS` is not the container's CPU limit.** Under a CFS quota it reports
the host's core count, so the hashing bound could be sized several times too
high in production. Resolve at S1-27, when config is wired.

**Increment-plus-expiry atomicity is not testable.** Breaking it needs a process
death between two round trips. Swapping the Lua script for INCR-then-PEXPIRE
passes the entire suite. The script is chosen because it removes the failure
mode, not because anything demonstrates its absence — noted in the test file so
the next reader does not mistake coverage for proof.

**The concurrency property is unproven.** Two simultaneous registrations for one
address contending on one stream — the entire justification for the reservation
design — can only be shown against live KurrentDB. It is explicitly part of
S1-28 and no unit test implies coverage of it.

**`pquerna/otp` is stable rather than actively developed.** Latest is v1.5.0 and
it is the de-facto standard, but it is ~40 lines of RFC 6238 wrapped in base32
and URI handling. If it goes unmaintained, replacement is contained. Its
transitive `boombuler/barcode` was pinned at a 2019 pseudo-version and has been
bumped to v1.1.0 explicitly — it links into the binary (5 symbols) even though
the QR-image path is never called.

---

## Still open in IDENTITY-REVIEW

Fixed: C1, C2, C5, C6, C7 (truncation half), T2, **A1** TOTP replay state — the
decision is now recorded as ADR-049 (authoritative in PostgreSQL, atomic claim,
fails closed), which also notes that the sweep and the authenticator's wiring are
still outstanding.

Outstanding and landing with slice 2: **C3** credential-ID uniqueness, **C4**
AAL3 undeliverable (`contract.AAL3` exists and `AssuranceLevel.Valid()`
deliberately rejects it), **T1** go-webauthn `CloneWarning`.

**ADR-048 is cited but unwritten.** Both ADR-044's text and
`internal/platform/eventsourcing/store.go:53` reference it for the rule that a
reservation stream is named by a keyed HMAC because a stream name is permanent
and has no ciphertext for erasure to destroy. Nothing in `DECISIONS.md` carries
that number, so the citation resolves to nothing and the next ADR written will
collide with it — the TOTP ADR did, and was renumbered to 049. Writing ADR-048 is
outstanding.

Outstanding and unscheduled: **C8** remaining pre-account-takeover variants,
**C9** `ApiKeyUsed` as a domain event, **C10** constant-time token lookup,
**C11** reset-flow gaps, **A3** ConnectRPC `NO_SIDE_EFFECTS` CSRF surface,
**A4** breach re-checking offline, **A5** smaller contradictions.

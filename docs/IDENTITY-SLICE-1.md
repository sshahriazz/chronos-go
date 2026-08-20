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
| S1-19 | `app/registration.go` | `Register` + `VerifyEmail`, one atomic two-stream append. `Register` takes NO password and creates NO credential; `VerifyEmail` takes the token AND the password and creates the account's first credential in the same request as the proof (IDENTITY-REVIEW C8, identity.md §4.3) |
| S1-19 | `app/credentials.go` + `adapter/postgres` | `PasswordCredentials`; rehash is a compare-and-set |
| S1-19 | `app/sweep.go` + `adapter/temporal` | lapsed-reservation sweep, a 15-minute Temporal schedule |
| S1-20 | `app/secondfactor.go` | `EnrollTotp`, `ConfirmTotp`, `GenerateRecoveryCodes`, `ConsumeRecoveryCode` |
| S1-20 | `adapter/totpseal` | AES-256-GCM sealing for TOTP secrets, AAD-bound, versioned |
| S1-21 | `app/authentication.go` | `Authenticate`, `CreateSession`, `RevokeSession`, `RevokeAllSessions` |
| S1-22 | `app/queries.go` + `adapter/postgres` | account, devices, methods, activity — keyset-paginated |
| S1-23 | `proto/chronos/identity/v1` | 13 RPCs, full policy annotations, protovalidate rules |
| S1-24 | `identity/api` | Connect handlers; the caller comes from the principal, never the request |
| S1-25 | `interceptor.SessionAuthenticator` | bearer token → live session → principal; self-scoped authz |
| S1-26 | revocation → epoch bump | a revoked session invalidates every decision cached for that principal |
| S1-27 | `cmd/api` | `IdentityService` registered and gated; four app services and a dozen adapters wired |
| — | `app/keyreseal.go` + `adapter/temporal` | credential key re-sealing, hourly, both key kinds |
| — | `platform/config` | retired-key sets, so a rotation does not lock every user out |
| — | `app/retention.go` + `adapter/temporal` | daily retention schedule running the five orphaned sweep statements |
| — | `adapter/temporal/scheduleprobe.go` | health probes for both schedules |
| — | `platform/obs` + `server/health` | probe results exported to Prometheus, with a panel and six alert rules |

Migrations since: **00012** grants `TRUNCATE` on identity's projections (without it
no identity rebuild could run), **00013** corrects `credential.verifier`'s comment
in the database.

Also landed alongside: the gRPC documentation surface was removed in favour of a
single REST/OpenAPI reference, and **protovalidate** — mandated by ADR and absent
— was added, so the constraints the spec documents are now enforced by an
interceptor rather than by prose.

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

## `SessionAuthenticator` stays in `internal/server/interceptor`

It resolves a bearer token against `session_token ⋈ session_view`, so it imports
`gen/sqlc/identity`, `identity/app` and `pgx` from a package that is otherwise
pure transport. That reads like a layering mistake, and it was raised as one.

It is not, and the reason is worth recording so it is not "fixed" twice. The
depguard contract constrains three things — the kernel, `domain/`, and `app/` —
and `internal/server` is not among them; nothing in `.golangci.yml` denies this
import, so there is no contract being violated. What moving it would cost is
worse than what it buys: `Authenticator` and `Principal` are declared by their
CONSUMER (ADR-001, CONVENTIONS §2), which is the interceptor, so an implementation
living in `identity/adapter/postgres` would make an identity adapter import the
transport layer. Trading "transport knows a query" for "a module knows the HTTP
gates" is not an improvement.

The version that would genuinely be better splits it in two: identity owns
"resolve a token digest to session facts" and returns its own type; the
interceptor owns "turn session facts into a Principal". That is a real
refactor of ~1,000 lines including tests, it changes no behaviour, and it is
worth doing only when a second module needs an authenticator — at which point
the shape is forced rather than chosen.

---

## Left to build

| # | Task | Notes |
| --- | --- | --- |
| S1-28 | Integration tests | end-to-end register→verify→enrol→login→authenticated call; concurrent registration; rebuild preserves credentials |
| S1-29 | Final mutation pass | |

Everything from S1-01 to S1-27 is built, wired and gated: `cmd/api` registers
`IdentityService` behind the gate pipeline, and `cmd/worker` runs the sweep,
retention and key re-sealing schedules.

### Closed after the verification reactor landed

Two gaps were left open when `identity/reactor` shipped and are now closed.

**Resend.** `VerifyEmail`'s own refusal has always told the user to "request a new
one", and until now nothing could. `ResendEmailVerification` is a PUBLIC RPC
(`internal/modules/identity/api/public.go`) over `app.ResendVerification`. It
appends `EmailVerificationRequested` and nothing else — the existing reactor
mints, revokes and mails — so there is one code path for "a link was sent" and no
plaintext token in a request handler. Five outcomes render as the same zero bytes;
`identity.md §12.1` carries the argument, including the residual timing
distinction and why it is bounded rather than closed.

**Rate limiting.** Two `ratelimit.Limiter`s over the SAME Valkey counter the
attempt ceiling uses, built at the composition root beside `authnRules`: per
address (blind index, 3/hour and 10/day) and per caller (connection peer address,
20/hour and 100/day). Enforced inside `app.ResendVerification`, before the account
lookup, so the ceiling cannot be skipped by any caller and cannot itself become an
existence oracle. No new platform package was needed — `internal/platform/ratelimit`
already carried the multi-window fixed-window limiter and the `Counter` port.

Both were mutation tested (18 mutants, 18 killed) and asserted at the composition
root: a resend with no ceiling behind it works perfectly and passes every unit
test, so `cmd/api/mailceiling_wiring_test.go` is the only thing that can tell
"configured" from "never wired".

The per-caller axis carries a deployment constraint recorded in `identity.md §12.1`:
the scope is the connection's peer address, so behind a terminating proxy every
caller collapses into one bucket. That must be resolved — by plumbing a trusted
client address — before this runs behind an ingress at scale.

---

## Open concerns, carried deliberately

These are known, none of them is a mystery, and each is written down because the
failure mode is silent. In rough order of what would hurt first.

**Nothing has ever run end to end.** Every layer has unit and adapter tests and
`make check` is green, but no registration has completed through the real HTTP
stack against real infrastructure. S1-28 is that test, and the honest expectation
is that it finds something — this is the first time the pieces meet.

**`ActiveOrg` has no producer.** `enforce` passes the principal by value to
`Org.Resolve`, which returns only a context, so nothing can populate
`principal.Context.ActiveOrg` before `resourceIDFor` reads it. Every ORG-SCOPED
method therefore fails closed. Identity is unaffected because its methods are
self-scoped, which means the self-scoped path is currently the only one that can
succeed — worth knowing before anyone concludes from a green identity run that the
gates work in general.

**Self-scoping is keyed on the relation string `"self"`.** `policy.SelfScoped()`
recognises non-public + relation `self` + type `user` + no resource-id field, and
`policy.Load` refuses malformed declarations at startup. It should be a structural
marker on `chronos.options.v1.Authz` — `bool self = 4` or a scope enum — so the
convention is not carried by a string. One predicate to repoint when the proto
gains it.

**Three schedule-creation mutations survive.** Deleting `d.scheduleSweep`,
`d.scheduleRetention` or `d.scheduleReseal` leaves every test green: the workflows
are still registered and no test without a live Temporal can see that no schedule
exists. The `ScheduleProbe`s report it at runtime and the alert rules fire on it,
which is containment rather than a fix. An integration test against live Temporal
closes it for all three.

**Schedules only exist when `TEMPORAL_ENABLED=true`.** Mail has an inline
fallback in that mode; the sweep, retention and re-sealing have none. The probes
report it and the alerts fire on it.

**The observer link is held by a convention, not the compiler.**
`d.authObserver` is read from the deps struct that is passed to
`app.NewAuthentication`, so the composition-root assertion cannot drift from what
the service received — but nothing enforces that pairing. `app` exposes no
accessor for the observer, so a test cannot assert from outside the package that
the service got the one that was recorded.

**`SessionAuthenticator`'s placement** is decided and documented above; it is a
structural preference, not a contract violation, and the better split is worth
doing when a second module needs an authenticator.

**`totp_replay` rows expire in ~90 seconds** while retention runs daily. That is
deliberate — the table is small and the sweep is cheap — but it means row count is
a poor health signal for that table specifically.

**A rotation is now completable but has never been run.** The retired-key config
exists, the re-sealing job exists, and `CountCredentialsAtKeyVersion` is the done
check. Nobody has performed a rotation against real data, and the ordering it
depends on — add the new key while keeping the old, re-seal to zero, then destroy —
is enforced by documentation alone.

---

## Four things that were broken and looked fine

Each of these passed every test in the repository and would have failed in
production, at the moment it was needed.

**Identity projections could never have been rebuilt.** `Projection.Reset` is a
`TRUNCATE`; the app connects as `chronos_app`, never the owner (ADR-011); and
00008 granted identity's tables `SELECT, INSERT, UPDATE, DELETE` and no
`TRUNCATE`, while every notification projection had it. Probed live rather than
inferred: `ERROR: permission denied for table login_history_view`. This is the
expensive shape of failure — invisible until somebody rebuilds, which only
happens *after* a projector bug is found, so the recovery path fails exactly when
it is needed and reports a permissions error that reads like infrastructure.
Migration 00012 grants it on the four projections and deliberately withholds it
from `credential`, `recovery_code`, `identity_token`, `session_token` and
`totp_replay` — verified those still refuse.

**The pepper rotation work list could not see TOTP secrets.**
`ListCredentialsAtPepperVersion` hardcoded `kind = 'password'`, which was correct
until S1-20 sealed TOTP secrets into the same column. Proven with two planted
rows: the old query returned 1 of 2. The failure mode is the worst one a rotation
can have — the job reports zero rows while every TOTP secret still depends on the
old key, an operator reads that as "safe to destroy", and every second factor in
the system stops opening at once. Now `ListCredentialsAtKeyVersion(kind, …)`, per
kind because each has its own key set and its own version sequence, plus
`CountCredentialsAtKeyVersion` — reading an empty *page* as "finished" is a
separate mistake, since a page can be empty because the last pass hit its limit.

**Identity was wired into no binary.** `cmd/projector` registered notification
events and projections only, so all three identity projections would have run
nowhere and `user_view` would have stayed empty with every component test green.
Two composition-root tests now cover it, both checked with compiling mutations.

**Probe results reached no dashboard.** The `health.Registry` — every probe, its
criticality, its impact string — exported nothing. Dashboards showed
`up{job="postgres"}`, which is whether *Prometheus can scrape us*, not whether the
dependency works; the two diverge exactly when it matters, since a Postgres that
accepts connections and rejects our credentials is `up=1` and probe-DOWN. That
also meant the two schedule probes — the only signal that the sweep and retention
will ever run — were visible only to somebody opening the status endpoint by hand.
Now exported, panelled, and alerted on, with `Registry.Exports()` and a
composition-root test per binary so the observer cannot silently come unwired
again.

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

Closed since: **C8**'s main variant — the pre-hijacking takeover — is fixed by
moving the first password to `VerifyEmail`, so registration leaves no credential
for a stranger's click to activate; `internal/adapter/identityit/prehijack_integration_test.go`
executes the attack and asserts the refusal. **C9** is resolved by deleting
`ApiKeyUsed` from the spec before any key exists. **C10** was already satisfied
in code (`SHA-256` digest, atomic `DELETE … RETURNING`); the spec wording was
what needed the fix.

Outstanding and unscheduled: **C8**'s three other variants (unexpired session,
trojan identifier, unexpired email change), **C11** reset-flow gaps, **A3**
ConnectRPC `NO_SIDE_EFFECTS` CSRF surface — verified inert today because the
server holds no cookie and authenticates by bearer alone, and live the moment a
session cookie exists — **A4** breach re-checking offline, **A5** smaller
contradictions.

Also outstanding, and not from the review: an attacker can still CLAIM an address
they do not own and deny it to its owner until the reservation lapses (48h). That
is bounded, self-clearing and strictly less than takeover, and it is asserted at
the end of the pre-hijack test rather than left as prose.

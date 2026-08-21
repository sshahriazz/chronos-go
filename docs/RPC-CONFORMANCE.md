# RPC conformance matrix

Every RPC the server exposes, driven over real HTTP against live infrastructure —
not in-process handler calls. Each cell is a property asserted on the wire by
`internal/adapter/protocolit`.

| | |
| --- | --- |
| RPCs | 30 across 4 services (identity 19, notification 7, profile 3, system 1) |
| Subtests passing | 260 |
| Failing | 0 |
| Wall clock | 21.9s |
| Command | `go test ./internal/adapter/protocolit/ -tags=integration -count=1` |

**Every dimension is complete.** `OK` asserted on the wire · `--` not applicable.
A `--` is a claim in itself, and each one is justified below.

## Coverage by dimension

| Dimension | Covered | What it asserts |
| --- | --- | --- |
| Success | **30/30** | a happy-path call answered, and its response asserted |
| Validation | **24/24** | a declared protovalidate rule refused on the wire |
| Anonymous | **21/21** | an unauthenticated caller refused |
| AAL floor | **7/7** | the declared assurance floor enforced |
| Idempotency required | **20/20** | refused without an `Idempotency-Key` |
| Idempotency semantics | **30/30** | replay / body-collision / key-ignored, per applicability |
| GET route | **29/29** | documented GET works, or a mutation has none |
| Protocols | **30/30** | same answer over connect / grpc / grpc-web x h2c / http1.1 |
| Reason code | **29/29** | a machine-readable reason on every refusal |

## The matrix

| RPC | Kind | Success | Valid | Anon | AAL | Idem-req | Idem-sem | GET | Proto | Reason |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **IdentityService** | |  |  |  |  |  |  |  |  |  |
| `Authenticate` | public write | OK | OK | -- | -- | OK | OK | OK | OK | OK |
| `CheckUsernameAvailability` | public read | OK | OK | -- | -- | -- | OK | -- | OK | OK |
| `ConfirmTotp` | write | OK | OK | OK | OK | OK | OK | OK | OK | OK |
| `CreateSession` | public write | OK | OK | -- | -- | OK | OK | OK | OK | OK |
| `DeactivateAccount` | write | OK | -- | OK | OK | OK | OK | OK | OK | OK |
| `EnrollTotp` | write | OK | -- | OK | OK | OK | OK | OK | OK | OK |
| `GenerateRecoveryCodes` | write | OK | OK | OK | OK | OK | OK | OK | OK | OK |
| `GetUser` | read | OK | -- | OK | -- | -- | OK | OK | OK | OK |
| `ListLoginHistory` | read | OK | OK | OK | -- | -- | OK | OK | OK | OK |
| `ListMethods` | read | OK | -- | OK | -- | -- | OK | OK | OK | OK |
| `ListSessions` | read | OK | OK | OK | -- | -- | OK | OK | OK | OK |
| `Register` | public write | OK | OK | -- | -- | OK | OK | OK | OK | OK |
| `RequestAccountDeletion` | write | OK | OK | OK | OK | OK | OK | OK | OK | OK |
| `RequestPasswordReset` | public write | OK | OK | -- | -- | OK | OK | OK | OK | OK |
| `ResendEmailVerification` | public write | OK | OK | -- | -- | OK | OK | OK | OK | OK |
| `ResetPassword` | public write | OK | OK | -- | -- | OK | OK | OK | OK | OK |
| `RevokeAllSessions` | write | OK | OK | OK | OK | OK | OK | OK | OK | OK |
| `RevokeSession` | write | OK | OK | OK | OK | OK | OK | OK | OK | OK |
| `VerifyEmail` | public write | OK | OK | -- | -- | OK | OK | OK | OK | OK |
| **NotificationService** | |  |  |  |  |  |  |  |  |  |
| `GetNotificationPreferences` | read | OK | OK | OK | -- | -- | OK | OK | OK | OK |
| `GetUnreadCount` | read | OK | OK | OK | -- | -- | OK | OK | OK | OK |
| `ListNotifications` | read | OK | OK | OK | -- | -- | OK | OK | OK | OK |
| `MarkNotificationsRead` | write | OK | OK | OK | -- | OK | OK | OK | OK | OK |
| `RegisterPushSubscription` | write | OK | OK | OK | -- | OK | OK | OK | OK | OK |
| `RemovePushSubscription` | write | OK | OK | OK | -- | OK | OK | OK | OK | OK |
| `SetNotificationPreferences` | write | OK | OK | OK | -- | OK | OK | OK | OK | OK |
| **ProfileService** | |  |  |  |  |  |  |  |  |  |
| `CreateAvatarUpload` | write | OK | OK | OK | -- | OK | OK | OK | OK | OK |
| `GetProfile` | read | OK | -- | OK | -- | -- | OK | OK | OK | OK |
| `UpdateProfile` | write | OK | OK | OK | -- | OK | OK | OK | OK | OK |
| **SystemService** | |  |  |  |  |  |  |  |  |  |
| `GetStatus` | public read | OK | -- | -- | -- | -- | OK | OK | OK | -- |

Column key: **Success** happy path · **Valid** validation rule refused ·
**Anon** anonymous caller refused · **AAL** assurance floor · **Idem-req** key required ·
**Idem-sem** replay/collision/ignored · **GET** GET-route behaviour ·
**Proto** cross-protocol equivalence · **Reason** machine-readable reason code.

## Why every `--` is a `--`

A not-applicable cell is an assertion that the property does not exist for that RPC,
and each one rests on a specific fact about the code rather than on convenience.

| Cell | Applies to | Why not, elsewhere |
| --- | --- | --- |
| Validation | 6 RPCs whose request declares no rule | `GetUser`, `ListMethods`, `EnrollTotp`, `DeactivateAccount`, `GetProfile`, `GetStatus` have no `buf.validate` rule to break. A case would assert the absence of a rule, not its enforcement. |
| Anonymous | the 9 public RPCs | `(chronos.options.v1.public) = true` means there is no credential to withhold. |
| AAL floor | RPCs declaring no `min_aal` | Only 7 declare one, and all 7 are asserted. |
| Idempotency required | the 10 reads | The gate returns on `!p.Mutating()`. A read carrying a key is covered under Idem-sem instead. |
| GET route | `CheckUsernameAvailability` | `OPERATION_CLASS_READ` but no `NO_SIDE_EFFECTS`, so connect-go publishes no GET route to test. It is POST-only by design. |
| Reason code | `GetStatus` | Public, read-only, and it has no refusal path of its own reachable from this suite. |

## The idempotency contract is not uniform, and the matrix reflects that

`Idem-sem` covers three different properties, because three different things are true
depending on the RPC. Collapsing them into one column would have hidden the reasoning.

**The 13 authenticated mutations** get the full contract: a replay with the same key and
body returns the stored response byte-for-byte, and the same key with a different valid
body returns `CONFLICT`. The byte comparison matters most on the destructive ones — a
second *execution* of `DeactivateAccount` answers `changed:false`, so a byte-identical
`changed:true` can only have come from the store.

**Two of those replay through a gate instead of the store, and that is correct.**
`ConfirmTotp` activates the account, which ends the `bootstrap_min_aal = AAL1` exemption
its own session depended on; `DeactivateAccount` revokes every session including the
caller's. The gate pipeline runs *before* `Idempotency.Do`, so both replays are refused —
403 and 401 — rather than answered from the store. Reading a stored response is still
reading a response, and a caller who may no longer make the request may no longer read
its answer. The test asserts the refusal, which is what pins the ordering.

**Three have no collision case**, because no second valid body exists:
`DeactivateAccountRequest` declares no fields, `RequestAccountDeletion.confirmation` must
be the literal `DELETE`, and `EnrollTotpRequest`'s only field is `deprecated = true` and
slated for removal — building a test on it would fail for an unrelated reason the day it goes.

**The 7 public mutations get no stored replay at all.** `gates.go` returns at
`if p.Public { return next(ctx, req) }` before `Idempotency.Do`, and the scope is
`(principal, method, key)` — a public caller has no principal. Their key is still
required, enforced by the handler, and gives the command a stable identity. That absence
is *proved* rather than asserted in prose: `TestAPublicMutationHasNoStoredReplay` sends
two different bodies under one key and requires the second not to be a `CONFLICT`. If a
future change moved the public branch below the gate, public mutations would silently
acquire a store scoped to no principal, and one caller's key could refuse another's.

**The 10 reads ignore the key**, which the gate does on `!p.Mutating()`.

## Cross-protocol equivalence covers refusals as well as answers

Success-equivalence is inherently a representative test: driving all 20 mutations over 6
transports would mean 120 real executions, and `DeactivateAccount` cannot be run six
times against anything worth keeping. So the success path runs on the reads plus two
cheap-to-repeat mutations.

Refusal-equivalence has no such limit, and it exercises the *harder* path. A successful
response is a message in the body on every protocol; an error is not — Connect puts it in
a JSON body, gRPC in a `grpc-status-details-bin` trailer, and gRPC-Web in that trailer
encoded inside the body. All 20 mutations are driven to a deterministic keyless refusal
over all 6 combinations and required to answer with the same code and reason.

## Defects found and fixed

Every one was found by calling the RPC, not by reading the code. Each fix carries a test
that was proved to fail before it.

### 1. Two modules' events were never registered

`cmd/api` registered identity's events only, while serving notification and profile too. An aggregate could be written ONCE — an empty stream decodes zero events — and was then unloadable forever. `cmd/projector` has its own codec and registers all six modules, so every read kept answering and every dashboard stayed green.

Guarded by `cmd/api/eventregistration_test.go`.

### 2. The session authenticator ran a second clock

`SessionAuthenticatorDeps.Now` was left unset in `cmd/api/gates.go`, so session deadlines were written by the injected clock and enforced against the wall clock. Correct in production, untestable through ADR-054's movable clock.

Guarded by `internal/adapter/protocolit/auth_test.go`.

### 3. Validation refusals carried no reason

connectrpc.com/validate builds its own `connect.Error`, so a schema refusal arrived carrying `buf.validate.Violations` and no `chronos.errors.v1.ErrorDetail`. CONVENTIONS 5.1 has clients branch on the reason. The fix re-raises it as `VALIDATION_FAILED` and carries the violations across, rather than trading one gap for the other.

Guarded by `internal/server/interceptor/validationreason.go`.

### 4. The published error catalogue disagreed with the wire

Four of eleven reasons. `CONFLICT` was documented `aborted` and sent `already_exists`; `PLAN_UPGRADE_REQUIRED`, `QUOTA_EXCEEDED` and `ORG_SUSPENDED` were documented `failed_precondition`/412 and sent `permission_denied`/403, `resource_exhausted`/429 and `permission_denied`/403.

Guarded by `internal/server/connect/catalogue_test.go`.

### 5. Sign-up and sign-in were undocumented

All seven public mutations require an `Idempotency-Key`, and the spec declared it on none of them. Worse, `checkopenapi`'s gate asserted the OPPOSITE rule — public methods must NOT declare it — so it would have rejected the correction. A client generated from the published spec could not register or authenticate anyone.

Guarded by `internal/tools/checkopenapi/spec.go`.

### 6. `base64` was published as a boolean

connect-go compares the query value against the literal string `"1"`, so `true` is not merely unsupported — it is silently OFF, and the still-encoded payload reaches the parser as literal JSON. The published example was `false`, a value with no meaning to the server either.

Guarded by `internal/tools/fixopenapi/main_test.go`.

### 7. One row carried two clocks

`TouchSession` stamped `last_seen_at` with PostgreSQL's `now()` while every other timestamp on a session comes from the injected clock. A session reported a `lastSeenAt` 28 seconds BEFORE its own `createdAt`. This was originally misdiagnosed as the unset `Now` above — that was a real defect and is fixed, but it was never what wrote this column.

Guarded by `db/query/identity/session.sql`.

Two behaviours, verified against the running server rather than inferred:

```
GET  /chronos.system.v1.SystemService/GetStatus?message=e30&base64=true   400  invalid value e30
GET  /chronos.system.v1.SystemService/GetStatus?message=e30&base64=1      200
POST /chronos.identity.v1.IdentityService/Register   (no header)          400  VALIDATION_FAILED
POST /chronos.identity.v1.IdentityService/Register   (with header)        200  {}
```

## Primitives the gaps turned out to need

Most of the missing coverage was not an oversight but a missing fixture. Naming them is
worth more than the tests themselves, because the next gap will need the same ones.

- **`disposableAccount`** — a fresh, fully-activated AAL2 account per test. Ten RPCs had no
  happy path mainly because `DeactivateAccount`, `RequestAccountDeletion` and
  `RevokeAllSessions` end the account, and the suite's order is not fixed.
- **`bootstrapAccount`** — verified, with no second factor. The only state from which
  `EnrollTotp` and `ConfirmTotp` can be driven, since both *are* the bootstrap.
- **`mintResetToken`** — short-circuits the delivery of a reset token, never its meaning;
  minted through the same `token.New()` and `guards.Issue()` the server uses.
- **`seedNotification`** — appends a real `notification.Created.v1` event and waits for the
  projector. The first version wrote the feed row directly and the server correctly refused
  the result: `app/inbox.go` appends with `Expected: StreamExists()` because "a read event on
  a stream with no created event is a fact about nothing".
- **`keyless`** — a request builder that deliberately omits the `Idempotency-Key`. `authed()`
  always sets one, so a test written to observe a keyless refusal silently observed a success
  it had caused.

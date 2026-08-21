# Domain: profile

**Presentation, not identity.**

It answers *how a person is shown to other people and spoken to by the system* —
their display name, the language and timezone their mail is rendered in, and
their avatar. It answers nothing about who they are: no credential, no session,
no lifecycle state, no username.

Governed by ADR-002 (nothing personal in an event or a projection), ADR-013 (no
business meaning in an object key; objects are immutable), ADR-020 (the reasoning
that makes this a separate module), ADR-051 (why the username stays in identity)
and ADR-055 (the two-call upload, and why the prefix is the authorization).

---

## 1. Why it is not part of identity

Identity's aggregate guards authentication. Every attribute added to it widens
the thing that stands between an attacker and an account, and a display name is
not a credential — it is a label rendered next to somebody's words.

This is the same split ADR-020 made between `organization` and `workspace`, and
for the same reason: two concerns whose growth directions differ end up as one
concern where everything lands. Identity grows toward *proof* — passkeys,
step-up, device binding, federation. Profile grows toward *presentation* —
pronouns, a job title, a pronunciation clip, a header image. Fused, a
translation-tag validator would sit beside the TOTP replay guard.

**The dependency is one-directional and thinner than workspace→organization:**

```
profile ──────► the pseudonym (ADR-002)
                      ▲
identity ─────────────┘
```

Profile imports nothing from identity. It is keyed by `SubjectID`, which is a
kernel primitive, and identity never learns this module exists.

**The username is deliberately NOT here.** It is a public handle with a
reservation aggregate, a tombstone that outlives the account and an erasure rule
of its own (ADR-051). It is an identity concern that happens to be human-readable,
and duplicating it here would give one value two owners.

---

## 2. Where each field lives, and why

| Field | Event | `profile_view` | PII vault |
| --- | --- | --- | --- |
| display name | marker only | `display_name_set` | **the value** |
| locale | marker only | `locale_set` | **the value** |
| timezone | marker only | `timezone_set` | **the value** |
| avatar object key | **the value** | `avatar_object_key` | — |
| avatar content type / size | **the value** | two columns | — |

**The three vault fields are personal data**, and `internal/platform/pii` says so
in its own words — including for locale and timezone, which read as preferences
and are not: combined with other fields they narrow down who somebody is.

They go to the vault and to nowhere else, which buys three properties at once:

1. **Erasure stays a key deletion.** Destroying the subject key makes all three
   unreadable in one operation, with no projection to update and no event to
   rewrite (ADR-002).
2. **There is one answer, not two.** `internal/platform/notify` resolves `Name`,
   `Locale` and `Timezone` from the vault immediately before every message it
   sends. A second copy in a projection would be a second answer, and the one a
   person actually sees in their inbox would be the vault's.
3. **No projection gains a personal-data column** (compliance.md §1). The
   username remains the single deliberate exception in this system.

**The avatar's object key is not personal data.** It is a random name under a
digest prefix; it identifies bytes rather than a person. It travels in the event
because the projection has to be rebuildable from the log alone.

### What the projection stores instead

`profile_view` holds the *fact* that each vault field is set. A boolean answers
"has this person configured a timezone?" for support and for the settings screen
without decrypting anything, and it survives erasure honestly: the key is
destroyed, the value becomes unreadable, and the row still records that something
was configured without saying what.

---

## 3. One event, sparse

There is exactly one stored type: `profile.ProfileUpdated.v1`.

```go
type ProfileUpdated struct {
    SubjectID   string
    DisplayName *Change       // nil ⇒ this update did not mention it
    Locale      *Change
    Timezone    *Change
    Avatar      *AvatarChange // nil ⇒ unchanged
    UpdatedAt   time.Time
}
```

**A nil pointer means UNCHANGED. `Cleared` means EMPTIED.** They are different
requests — "leave my timezone alone" and "remove my timezone" — and a shape that
cannot tell them apart turns a settings screen which renders one field into one
that silently erases the other three.

That distinction is enforced at three layers, in the same shape at each:

| Layer | How it is expressed |
| --- | --- |
| wire | `optional` fields — explicit presence |
| event | pointer per field |
| SQL | a nullable parameter per column, `COALESCE($n, current)` |

The SQL is where it is load-bearing. Dropping one `COALESCE` does not fail to
compile and does not fail a unit test; it makes every partial save erase the
fields it did not mention.

### Why one event and not one per field

Adding "pronouns" later is a proto field, a pointer field and a column. **No new
event type, no notification-catalogue entry, no schema bump and no upcaster** —
because the payload's SHAPE does not change when a field is added to it, only its
contents, and a payload written before the field existed decodes with that
pointer nil, which already means "not mentioned".

A version bump is still required if a field is renamed, retyped or removed.

### Clearing a vault field is refused, and that is honest rather than incidental

`internal/platform/pii` can destroy a subject's KEY and cannot delete one field —
crypto-shredding is all-or-nothing by design — and `pii.Validate` refuses an
empty value precisely so a vault row cannot mean "present but blank". So there is
no operation this system could perform to empty a display name, and sending an
empty one is **refused with that reason** rather than silently treated as "leave
it alone". A caller that meant to clear it gets an error instead of a save that
appeared to work.

The event's shape already expresses `Cleared` for all four fields, so the day
`pii.Vault` gains a per-field delete, the name follows with no event change.

---

## 4. The avatar: two calls, and no bytes

```
browser                    API                      SeaweedFS
   │  CreateAvatarUpload     │                          │
   ├────────────────────────►│  GrantUpload             │
   │                         ├─────────────────────────►│
   │  url + fields + key     │◄─────────────────────────┤
   │◄────────────────────────┤    signed POST policy    │
   │                         │                          │
   │  POST the image ────────┼─────────────────────────►│   ← the API is not
   │                         │                          │     on this path
   │  UpdateProfile(key)     │                          │
   ├────────────────────────►│  Verify(key)  (HEAD)     │
   │                         ├─────────────────────────►│
   │                         │◄─────────────────────────┤
   │                         │  append ProfileUpdated   │
```

**No image touches an event, a database row or a request body.** There is no
bytes field anywhere in `chronos.profile.v1` and there must not be one. An image
arriving through the API would have to be held in memory by every replica that
could receive it, would put a client-controlled decoder on the request path, and
would make the request-size limit a product setting rather than a bound enforced
by storage.

### What the signed policy pins

| Pinned | What it prevents |
| --- | --- |
| bucket | the grant being redirected somewhere else |
| exact key | overwriting another object by naming it |
| `content-length-range` | storing more than was declared — **enforced by the store**, which is why it is a POST and not a presigned PUT |
| `Content-Type` | the stored object claiming to be something else |
| expiry | a leaked capability working forever |

### The second call takes a client-supplied key, and that is safe

The confirm call receives a key the CLIENT chose to send. The control is not that
the key is unguessable; it is that **the key's prefix is derived from the caller's
own pseudonym**:

```go
func AvatarPrefix(subjectID string) string   // sha256("chronos.profile.avatar\x00" + subjectID)[:16]
```

`GrantUpload` only ever signs a policy for a key the SERVER chose under the
CALLER's prefix, and `ParseAvatarKey` recomputes the same prefix from the same
session-derived pseudonym. There is no key a caller can name outside their own
namespace that will be accepted — even one they legitimately hold, which
`TestOneSubjectCannotConfirmAnothersUpload` proves against a real stored object.

The prefix check runs **before** the object store is contacted. Reversed, this
endpoint would be an existence oracle for the whole bucket.

Three alternatives were considered and each is worse:

- **A table of outstanding grants.** A write to PostgreSQL from a request handler,
  which this system does not do (ADR-019), plus its own expiry sweep.
- **An HMAC-signed grant token.** It works, and it introduces key material to
  configure, rotate and keep out of logs — to buy a property the prefix gives for
  free.
- **A key derived from the subject with no random part.** Re-uploading would
  OVERWRITE the stored object, and objects here are immutable: a new version is a
  new key plus a new event (ADR-013).

### What is verified, and whose word counts

`Verify` is a HEAD against the store. The content type and size recorded in the
event are **the store's answer**, never the uploader's claim, and the domain
refuses an empty object, one over the ceiling, and anything outside
`{image/png, image/jpeg, image/webp}`.

**SVG is deliberately absent.** It is a document format that executes script, and
serving one from an origin a session cookie is scoped to is stored cross-site
scripting with a picture frame around it.

### Reading it back

`GetProfile` signs a fresh download URL on every call, valid for ten minutes. It
is never stored: a saved URL outlives its signature, and a bucket that served
anonymous reads would have moved authorization to whoever holds the link.

---

## 5. Concurrency

One stream per person, `profile-<subject id>`, so the consistency boundary and
the concurrency boundary are the same thing. The aggregate is saved under the
revision it was loaded at, so two browser tabs saving at once collide: one wins,
the other is told `CONFLICT` and retries against the winner's state.

`CONFLICT` is returned rather than retried server-side. A retry would re-apply
values against a state the person did not see, and quietly undoing somebody
else's change is worse than asking for the button to be pressed again.

**Proved against the event log, never a projection.** ADR-052 is why that
distinction earns its own test helper: a unique index in a read model can conceal
a duplicate and stall the projector, so an assertion about "how many changes
happened" that counts rows can be satisfied by a table that is quietly wrong.
`TestConcurrentUpdatesAreNotLost` reads the stream, asserts one event per writer
at contiguous revisions, and **fails if no writer was ever told `CONFLICT`** —
because an append with `AnyRevision` would produce the right count while silently
losing decisions.

---

## 6. The two writes, in order

A save touches two stores: the PII vault and the event log, in that order.

If the append fails after the vault write, the value is stored and the log has
not yet recorded that it changed; the client's retry carries the same idempotency
key, the vault write is an idempotent upsert, and the append then lands — the two
converge.

Reversed, the log would assert a change the vault never received, and every email
from then on would render the old name while the history said otherwise. **A
system of record that disagrees with its own log is the worse failure**, so the
vault goes first.

---

## 7. API surface

Three RPCs, all self-scoped. `relation: "self"`, `resource_type: "user"`, no
`resource_id_field`, no entitlement — so no method here needs a gate `cmd/api`
leaves nil.

| RPC | Class | What it does |
| --- | --- | --- |
| `GetProfile` | READ | the caller's own profile; vault resolved and URL signed per call |
| `UpdateProfile` | WRITE | one sparse change; appends one event |
| `CreateAvatarUpload` | WRITE | mints a signed POST target |

**No request message names a subject, an org, or an account.** A profile is
global to a person exactly as their account is — one display name across every
organization they belong to — so there is no tenant field to accept and none to
forget to check. `TestNoRequestMessageCanNameASubject` asserts that against the
descriptor rather than by reading the file.

`CreateAvatarUpload` is a mutation rather than a read, deliberately: it issues a
capability. As a read, a double-clicked button would mint two grants and abandon
an object; as a mutation the idempotency gate returns the same grant.

---

## 8. Storage

`profile_view` carries **no `org_id` and no row-level security**, the same shape
as identity's `user_view` and for the same reason: a profile is not
tenant-scoped. Isolation is by pseudonym — every statement is filtered by the
caller's own `subject_id`, which the authn gate supplies and no request can name.

One projection, one table, one event type. Rebuildable from position zero, and
`TestTheProjectionRebuildsFromZero` truncates and replays to prove it rather than
asserting it.

A `CHECK` constraint requires the avatar's three columns to move together. It
earns its place: it is what turns a dropped `COALESCE` on one of them from silent
data loss into a stopped projector.

---

## 9. Notifications

`profile.ProfileUpdated.v1` is **Security class, to the subject**.

That is a stronger class than a display name first suggests, and the reason is
impersonation rather than vanity. The name and picture are how colleagues
recognise a person in a mention, a comment and an invitation email. An attacker
holding a session who changes them is impersonating the holder to everyone the
holder works with, and the holder is the only person who can notice. Security
class also means no preference can switch the alert off, which is correct for a
takeover tripwire.

The template data names the FIELDS that changed and never their values — a value
there would be personal data on its way into a template through an event.

---

## 10. What this module does not do

- **It does not own the username.** ADR-051, in identity.
- **It does not delete objects.** Reclaiming abandoned uploads and the objects of
  erased subjects is a sweep's job, running against the bucket with
  `profile_view` as its reference list — not something a request handler does
  inline, where a failure would either fail a save that already succeeded or leak
  an object silently.
- **It does not resize, crop or re-encode.** No image decoder runs in this
  process, which is the property the whole two-call upload exists to preserve.

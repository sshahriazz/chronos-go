# Versioning and the changelog

Three things in this system are versioned, they move at different speeds, and
conflating any two of them breaks something. This document names each one, says
who owns it, and gives the procedure.

| Axis | Question it answers | Where it lives | Who changes it |
| --- | --- | --- | --- |
| **Build identity** | which build is this process? | git tag → `-ldflags` → `internal/platform/buildinfo` | the build, automatically |
| **Product version** | what shipped, and when? | git tags, `CHANGELOG.md`, `.changes/` | `make release` |
| **Wire contract** | what may a client depend on? | `chronos.<domain>.v1` proto packages | a new package version, never an edit |

---

## 1. The wire contract is not the product version

`chronos.identity.v1` does **not** become `v2` because the product reached
`2.0.0`. They are independent, and they must stay independent: a customer's
generated client is pinned to a proto package, and renaming that package on a
marketing cadence would break every integration for no reason.

The proto version changes exactly once per genuine incompatibility, and it
cannot change quietly — `buf breaking` runs in `make check` and in CI, so
removing a field, renaming an RPC or changing a type inside a published `v1`
package fails the build. A real break is a new package (`v2`) served alongside
`v1` until `v1` is retired, which is a deprecation with a date, announced
through the changelog.

The published bounds are part of the contract too (CONVENTIONS §7.2). Loosening
a `maxLength` is additive; tightening one rejects requests that used to succeed
and is a breaking change, whatever the proto compiler says about it.

## 2. Build identity: one symbol, every binary

`internal/platform/buildinfo` is the single answer to "which build is this?".
It replaced three copies of `var version = "dev"` in `cmd/api`, `cmd/worker` and
`cmd/projector`, each documenting an `-ldflags` invocation that no build passed
— so all three reported `dev`, in their logs, in their `service.version` trace
attribute, and in the `GetStatus` response the operator console reads. A
version that is always the same string cannot attribute a latency regression to
a release or a customer report to the build that served it.

The Makefile stamps it once:

```make
VERSION ?= $(shell git describe --tags --always --dirty)
COMMIT  ?= $(shell git rev-parse HEAD)
LDFLAGS := -X …/buildinfo.version=$(VERSION) -X …/buildinfo.commit=$(COMMIT)
```

`--dirty` matters: a binary built from uncommitted code must not claim to be the
tag it was cut from. That is how a bug gets attributed to a release that never
contained it.

An **unstamped** build still answers usefully. `go build` from inside a checkout
records the VCS state, and Go turns it into a pseudo-version — so `air` and a
bare `go build` already report the commit and whether the tree was modified.
`go run` does not stamp, which is why `make run`, `make worker` and `make
projector` pass the same LDFLAGS. Only a build with neither link-time flags nor
VCS data — a `go test` binary, or a build from an extracted tarball — reports
`dev`, and there it is true rather than a default nobody noticed.

```bash
make version   # what this tree would build as, and what it would release as
make build     # stamped binaries into bin/
```

## 3. Product version: semver, derived from what changed

Tags are `vMAJOR.MINOR.PATCH`. The number is **not** chosen on release day — it
is computed from the unreleased fragments, so it is a consequence of the work
rather than a judgement about it:

| Fragment kind | Bumps |
| --- | --- |
| `Removed` | major |
| `Added`, `Changed`, `Deprecated` | minor |
| `Fixed`, `Security` | patch |

`BUMP=` overrides the computation for a release whose number is a decision. The
first one usually is: with no prior version a lone `Fixed` fragment computes
`v0.0.1`, and `make release BUMP=v0.1.0` says what was meant.

### The product is an unstable alpha, and says so in the version

Every release carries a prerelease marker: `v0.1.0-alpha.1`, `v0.1.0-alpha.2`,
and so on. `PRERELEASE ?= alpha.1` in the Makefile is what puts it there, and
`make version` prints the channel so nobody has to infer it:

```
  channel   UNSTABLE — every release is tagged -alpha.1
```

The marker is not decoration. Semver orders `v0.1.0-alpha.1` BELOW `v0.1.0`, so
no dependency resolver, container tag policy or upgrade check will pick up an
alpha build as though it were a supported one — and a bare `v0.2.0` cannot be
cut by accident while the default stands.

What it promises: nothing. Any behaviour may change between alpha releases,
including behaviour you depend on. There is no upgrade path guarantee, and the
changelog records what changed rather than committing to keeping it.

**Leaving alpha is a decision, not a cleanup.** Emptying `PRERELEASE` — with
`make release PRERELEASE=` or by removing the default — is the act of declaring
the product beta or stable. Do it deliberately, and say so in the changelog.
While the major version is still `0` after that, minor bumps may change public
behaviour; reaching `v1.0.0` is a further promise on top.

### The Go module major-version rule

Go encodes the major version in the import path from v2 onwards: `v2.0.0`
requires `module github.com/chronos/chronos-go/v2` and rewrites every import in
the tree. Chronos is a service, not a library, so nothing external is pinned to
that path — but the rule still applies to anything that imports it, and it is a
real reason not to reach for a major bump casually.

## 4. The changelog is written at release time, from the diffs

Nobody writes changelog entries while working. At release, `/release` reads
every commit since the last tag, opens the diff of each one that touched
something a customer can observe, and writes the entries.

**This is a trade, and it is worth naming.** Writing entries at change time is
more faithful to intent — the author knows what they meant; a reader of the diff
infers it. An earlier version of this repository enforced exactly that, with a
gate that failed any pull request touching a module without a fragment. It was
traded for a workflow where the changelog costs nothing until somebody wants a
release.

What pays for the trade is the rule that the entries come from **diffs, never
commit subjects**. Subjects here are written for engineers on purpose —
*"half of every API key minted could never authenticate"* is right for `git log`
and wrong for a customer — and a changelog made of reworded subjects is the
failure this whole document exists to avoid.

The procedure is `.claude/skills/release/SKILL.md`. Its shape:

```bash
make release-input      # every commit since the last tag, sorted by what it touched
git show <sha>          # for each one that needs an entry — the diff, not the subject
make changelog-new KIND=Added DOMAIN=billing BODY="…"   # one entry per CHANGE, not per commit
make changelog-preview  # read it as a customer, then approve it
```

The fragments are an intermediate artifact now rather than a per-change
obligation, but they are still where entries live before a release, and
`make check` still validates any that exist.

```yaml
# .changes/unreleased/Added-20260827-163518.yaml
kind: Added
body: Export your organization's data as a signed, downloadable bundle.
time: 2026-08-27T16:35:18+06:00
custom:
    Domain: compliance
```

One file per entry, named by timestamp, so two releases prepared in parallel
touch two different files.

### What earns an entry

**Write one when a customer can observe the difference**: a new capability, a
changed behaviour or limit, a fixed defect they could hit, a security change,
anything that alters a request or a response.

**Do not write one otherwise.** A refactor, a test, a generated file, a
dashboard, an internal tool and the whole operator plane are invisible from
outside, and padding a public changelog with them makes it useless.

**One entry per CHANGE, not per commit.** A feature built over five commits is
one entry. A fix and its test are one entry.

### What you owe the release while working

One trailer, on any commit a customer cannot observe:

```
Changelog: none
```

`make release-input` sorts the range by it. A commit without one that touched
`proto/chronos/`, `internal/modules/`, `internal/server/`, a service binary or a
migration is a commit the release stops and reads. The trailer is not
decoration: it is the record that somebody decided, sitting in the history next
to the change it applies to.

`make changelog-check` validates fragments against `.changie.yaml` itself — an
unknown kind, an unknown domain, an empty body or a pasted commit subject fails
in `make check` and in CI, rather than at `make release` with somebody waiting.
`make release` additionally refuses to cut a release that describes nothing
while observable work went into the range.

### Writing the body

- Address the reader as *you*, describe what they can now do or no longer
  suffer. Not what the code does.
- One sentence, ending in a full stop. 20–400 characters, enforced.
- No internal vocabulary: no stream names, table names, ADR numbers, projector
  or reactor names. If the sentence cannot be written without them, the change
  is probably not customer-visible.
- Never any personal data, and never a customer's name (ADR-002 applies to a
  published document at least as strongly as to a log line).

## 5. Cutting a release

Ask for one: **`/release`**. The procedure is `.claude/skills/release/SKILL.md`
and it runs these, stopping twice — once for you to approve the wording, once
before pushing:

```bash
make release-input                    # every commit since the last tag
git show <sha>                        # the diff behind each one that needs an entry
make changelog-new KIND=… DOMAIN=… BODY="…"
make changelog-preview                # the notes the current fragments would produce
make release                          # batch into .changes/vX.Y.Z-alpha.1.md, rebuild CHANGELOG.md
make release BUMP=v0.1.0              # a number that is a decision, not a consequence
make release PRERELEASE=alpha.2       # the next alpha
make release PRERELEASE=              # leave alpha — a decision, see §3
git diff                              # read it as a customer would
make release-tag                      # commit + annotated tag; does NOT push
git push origin main --follow-tags
```

`make release` refuses a dirty tree — a release is assembled from committed
code. Pushing the tag is the only irreversible step, and it is deliberately a
separate command you type yourself.

## 6. What the website reads

`CHANGELOG.md` is the whole public changelog; `.changes/vX.Y.Z.md` is one
release, standalone, with its own heading. A release page renders the per-version
file; an "all changes" page renders `CHANGELOG.md`. There is no second copy to
drift, and no publishing step that can be forgotten.

The running system reports its own version at `chronos.system.v1.SystemService/GetStatus`
and in every log line and trace, so "which release is serving me?" is answerable
from the outside and from the dashboards without asking anyone.

## 7. Related, and deliberately separate

- **Migrations** are numbered by Goose and append-only. That sequence is not the
  product version and never appears in it.
- **Key versions** (`IDENTITY_PASSWORD_PEPPER_VERSION`, TOTP seal keys, the
  OpenBao KEK) are rotation counters. Unrelated to everything here.
- **Event schema evolution** is upcast-on-read (ADR-029). A new event version is
  not a product version bump; it is usually invisible from outside and earns no
  changelog entry.

# Working rules

These are not style preferences. Every rule below exists because its absence
produced a concrete, verified failure in this repository — the failure is named
alongside the rule so the rule can be argued with rather than merely obeyed.

---

## 1. Tooling: what to reach for, and in what order

| Need | Use | Not |
| --- | --- | --- |
| Locate or understand code | `codegraph explore` (one call) | grep + read loop |
| Shell output | `rtk <cmd>` (hook rewrites automatically) | raw command |
| A decision from a previous session | `memcp_recall` / `memcp_search` | guessing, or re-deriving |
| Reply to the user | terse; substance intact | narration, praise, recap |

**CodeGraph before files.** One `codegraph_explore` call returns verbatim
line-numbered source, the call paths among the symbols, and the blast radius. A
grep/read exploration of the same question costs dozens of calls and still
misses dynamic-dispatch hops. Treat returned source as already read — do not
re-open those files.

**CodeGraph before wiring claims.** It is the only cheap way to answer "is this
actually connected?". It found three adapters — `inapp`, `webpush`, `seaweedfs`
— that were fully built, fully tested, and constructed by no binary at all.
Every component test passed while three notification channels delivered nothing.

**Prefer the shell binary when the MCP tool is unavailable.** `codegraph serve
--mcp` can sit in "pending approval" for a whole session; `codegraph explore`
does not care. Falling back to grep because the MCP call failed gives up the
tool for a reason that has nothing to do with the tool.

**rtk for shell.** Cuts up to 90% of command output. The hook rewrites commands
transparently, so this costs nothing to comply with.

**memcp for continuity.** Before re-deriving a decision, search for it. A
decision re-litigated is a decision that can come out differently the second
time. Record what cost real work and is not recoverable from the repository —
measured numbers with their conditions, probe results, dead ends — and delete
memories that turn out to be wrong rather than leaving them to be recalled as
current. `claude-mem` is installed too and overlaps; keep memcp primary so the
two cannot disagree.

---

## 2. Anti-hallucination rules

Each of these was violated in this repository, with the consequence recorded.

### Probe the system; do not recall it

Assertions about infrastructure behaviour must come from a probe against the
running service, not from training data.

- `$ce-` category streams were documented as "unavailable — ✅ Verified". They
  were unavailable because `RUN_PROJECTIONS=None` was set in our own compose
  file. The doc verified our misconfiguration and enshrined it as a property of
  KurrentDB. Enabling `System` made them work — and 14.8× faster than the
  filtered `$all` scan they had been replaced with.
- `MultiStreamAppend` was assumed absent. It exists and is genuinely atomic:
  failing one stream's precondition rolled the other back. That changes how
  cross-aggregate writes get designed.

Before writing "X is not supported", run a probe. Delete the probe afterwards or
promote it to a test; do not leave it in `internal/tools/`.

### A passing test is not a passing guarantee

Ask what the test would do if the feature were removed. If the answer is "still
pass", the test is decoration.

- The batch-atomicity test used a bad column name. That fails at **prepare**
  time, before any statement executes — it proved nothing about rollback. A
  `CHECK` violation, which fails at execution, was the real test.
- The push-payload privacy test asserted against `capture.plain`, which was
  never assigned. It compared against `""` and passed unconditionally.

For any test asserting a **security** property, mutate the implementation and
confirm the test fails. Two mutations proved the security-suppression and
position-zero guards; both would otherwise have been false confidence.

### Test the composition root, not only the components

Component tests construct their subject directly, so they pass whether or not
any binary constructs it. Assert the wiring itself.

A nil `Preferences` port is **permissive** — the dispatcher skips the check.
Per-user channel toggles therefore did nothing, with no error anywhere.
`cmd/worker/wiring_test.go` now asserts every channel is present and both
optional ports are non-nil.

### Never widen a rule to fit the code

sqlc was mandated and never configured. Raw SQL went everywhere, and then a
carve-out was written **into CONVENTIONS.md** to excuse it. That is worse than
the violation: it converts a known gap into documented policy.

If code violates a stated rule, either fix the code or raise the conflict
explicitly. Do not edit the rule to match.

### Verify a claim before repeating it

Numbers, capabilities and states get repeated across turns and harden into
assumptions.

- "29× faster" was measured against *client-side* filtering, which is not what
  ships. Server-side, the honest figure is 14.8×.
- Every performance claim in this repo names its measurement conditions,
  because "808 µs/event" was 63% Docker Desktop's VM boundary, not the system.

---

## 3. Verification gates

Nothing is "done" until `make check` passes. It runs:

```
fmt-check         formatting is VERIFIED, never rewritten — a check that fixes checks nothing
proto-lint        COMMENTS category: an undocumented field fails the build
proto-breaking    against main
api-validate      the OpenAPI spec is non-empty and complete
migrate-check     migrations are append-only
sqlc-check        generated query code is current AND matches the schema
sql-check         no SQL in Go outside the kernel carve-out
changelog-check   unreleased changelog fragments satisfy .changie.yaml
lint              golangci-lint, including the depguard import contract
test              go test ./... -race
```

Integration tests need the stack: `make up` (which also bootstraps OpenBao
transit), then `go test -tags=integration ./... -race`.

`-race` always. The projector and reactor runners are concurrent by design; a
data race there corrupts a read model rather than crashing.

### The changelog is not checked here, and that is a trade

`changelog-check` in `make check` validates fragments that exist. It does NOT
require one: entries are written at RELEASE time, from the diffs, by whoever
runs `/release`. Nobody has to think about the changelog while working.

The cost is that intent gets reconstructed from a diff weeks later, so the
release procedure pays it back — it reads `git show` for every commit that
touched something observable, never the subject line. Commit subjects here are
written for engineers on purpose, and a changelog made of them leaks internal
detail or reads as noise.

What you owe the release, while working, is one trailer:

```
Changelog: none
```

on any commit a customer cannot observe — a refactor, a test, generated code, an
internal tool, the operator plane. `make release-input` sorts the range by that
trailer, so a commit without one is a commit the release has to stop and read.
See docs/VERSIONING.md.

---

## 4. Committing

**Commit as soon as one thing is done and green.** Not at the end of a session,
not when the user asks. In this repository that is a standing instruction: when
a change compiles, its tests pass and it is one complete thought, commit it.
Pushing is different — never push without being asked.

A session that ends with twenty files staged is a session whose history cannot
be read, bisected or reverted. The compliance work that produced
`v0.1.0-alpha.1` was four commits — the billing join, the dead export deleted,
the racing tests fixed, the docs caught up — and each of those is separately
revertable. As one commit it would have been none of those things.

**One commit is one reason to change.** Never mix:

- a dependency bump with a behaviour change,
- generated code with the source that generated it *and* an unrelated fix,
- formatting with anything at all.

**Every commit builds and its tests pass.** If a change needs two files to
compile, those two files are one commit. `git bisect` is worthless the moment
that stops being true.

### The message

Conventional Commits, with this repository's voice in the subject:

```
type(scope): what changed, as a statement about the system

Why it changed. What was wrong before, or what was impossible. The body
is for the reasoning a reader will not recover from the diff — not a
restatement of it. Wrap at 72.

Changelog: none

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
```

- `type` is one of `feat fix refactor test docs chore perf build ci`.
- `scope` is the module or domain: `identity`, `billing`, `compliance`,
  `projections`, `api`, `deps`. Omit it when the change is genuinely global.
- The subject is prose, not a label. `fix(identity): half of every API key
  minted could never authenticate` says what was wrong. `fix(identity): fix key
  bug` says nothing. No trailing full stop; aim for 72 characters.
- `Changelog: none` when nothing a customer can observe changed. The release
  procedure reads that trailer (§ `docs/VERSIONING.md`), so it is not decoration
  — it is the record that somebody decided.

---

## 5. Reporting

State what was measured and what was assumed, separately. Report failures with
the output. If part of a task was skipped, say which part and why.

When correcting an earlier statement, correct it plainly and move on — no
tallying, no self-criticism beyond what changes the reader's decisions.

---

## 6. Environment notes

- `head` on this machine is an HTTP tool, not coreutils. Use `/usr/bin/head`.
- The shell is zsh. `$var(...)` is glob syntax there; scripts destined for CI
  must be tested under `bash`, which is what GitHub Actions runs.
- Docker Desktop's VM boundary adds ~113 µs to every Postgres round trip.
  Native is 47 µs. Never quote a local latency number without saying which.

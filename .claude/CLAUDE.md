<!-- CODEGRAPH_START -->
## CodeGraph

In repositories indexed by CodeGraph (a `.codegraph/` directory exists at the repo root), reach for it BEFORE grep/find or reading files when you need to understand or locate code:

- **MCP tool** (when available): `codegraph_explore` answers most code questions in one call — the relevant symbols' verbatim source plus the call paths between them, including dynamic-dispatch hops grep can't follow. Name a file or symbol in the query to read its current line-numbered source. If it's listed but deferred, load it by name via tool search.
- **Shell** (always works): `codegraph explore "<symbol names or question>"` prints the same output.

If there is no `.codegraph/` directory, skip CodeGraph entirely — indexing is the user's decision.
<!-- CODEGRAPH_END -->

## Tooling

Four tools are installed and expected to be used. Each replaces a default
behaviour rather than supplementing it, so reaching for the default instead is a
regression, not a stylistic choice.

| Need | Use | Instead of |
| --- | --- | --- |
| Locate or understand code | `codegraph explore "<names or question>"` | grep + read loop |
| Any shell command | `rtk <cmd>` — the hook rewrites it automatically | raw command |
| A decision or finding from an earlier session | `memcp_recall` / `memcp_search` | re-deriving it |
| Every reply | caveman style, already enforced by hook | prose padding |

### CodeGraph — before files, and before wiring claims

One `codegraph explore` call returns verbatim line-numbered source, the call
paths among the symbols, and the blast radius. Treat that source as already
read; do not re-open those files. A grep/read exploration of the same question
costs dozens of calls and still misses dynamic-dispatch hops.

It is also the only cheap way to answer "is this actually connected?". It found
three adapters — `inapp`, `webpush`, `seaweedfs` — fully built, fully tested,
and constructed by no binary. Every component test passed while three
notification channels delivered nothing.

The MCP tool `codegraph_explore` is equivalent when connected. The shell binary
always works, including when the MCP server is pending approval, so prefer it
when a call has just failed for that reason rather than falling back to grep.

### rtk — the shell proxy

Cuts up to 90% of command output. A hook rewrites commands transparently, so
compliance costs nothing. `rtk gain` reports what it saved; `rtk proxy <cmd>`
runs a command unfiltered when the filtering itself is what needs debugging.

### memcp — cross-session memory

Persistent memory over 24 MCP tools. The ones that matter day to day:

- `memcp_recall` / `memcp_search` — retrieve before re-deriving. A decision
  re-litigated is a decision that can come out differently the second time.
- `memcp_remember` — record findings that cost real work to establish and are
  NOT recoverable from the repository: measured numbers with their conditions,
  probe results against running infrastructure, dead ends and why they were dead.
- `memcp_forget` — delete a memory that turned out to be wrong. Use it. A stale
  fact recalled as current is worse than no memory at all.

Do not store what the code, git history or the docs already record. Everything
recalled reflects what was true when written — if it names a file, flag or
metric, verify that still exists before acting on it.

Note `claude-mem` is also installed and does the same job. Prefer `memcp` as the
primary so two memory stores cannot disagree.

### caveman — reply style

Active by default at `full`. Compresses replies, never technical substance:
error strings, numbers, units, negations, code blocks and API names stay exact.
Files written to disk — code, comments, commits, docs, this file — are normal
prose. Style commands: `/caveman <level>`, `/caveman-stats`, `/caveman-init`.

## Working rules

Read [WORKFLOW.md](WORKFLOW.md) before starting work. It carries the tooling
order (CodeGraph before files, rtk for shell, memcp for prior decisions),
the anti-hallucination rules, and the verification gates — each tied to a
specific failure that happened in this repository.

Four that matter most, in short:

1. **Probe the system, do not recall it.** "$ce- is unavailable" was verified
   documentation of our own misconfiguration.
2. **Ask what a test would do if the feature were deleted.** Two security tests
   here passed unconditionally — one failed at prepare time, one compared
   against an empty string.
3. **Test the composition root.** Three adapters were built, tested, and wired
   into nothing; every component test passed.
4. **Never widen a rule to fit the code.** A carve-out was written into
   CONVENTIONS.md to excuse raw SQL rather than configuring the mandated sqlc.

## Versioning and the changelog

Read [docs/VERSIONING.md](../docs/VERSIONING.md) before cutting a release or
deciding whether a change needs a changelog entry. The short form:

**Entries are written at release time, by you, from the diffs.** Nobody writes
them while working. When the user asks for a release, invoke `/release` and
follow it: `make release-input` lists every commit since the last tag, and you
open `git show` on each one that touched something observable.

**Never write an entry from a commit subject.** Subjects here are written for
engineers on purpose — "half of every API key minted could never authenticate"
belongs in `git log` and nowhere near a customer. Reading the diff is what pays
for writing entries late; skipping it makes the whole arrangement worse than
having no changelog.

**One entry per change, not per commit.** A feature built over five commits is
one entry.

**What you owe the release while working is one trailer.** On any commit a
customer cannot observe — a refactor, a test, generated code, an internal tool,
the operator plane:

```
Changelog: none
```

`make changelog-check` (part of `make check`, and a CI job) validates the
entries that exist against `.changie.yaml`: unknown kind or domain, empty body,
or a pasted commit subject fails there.

**Do not hand-edit `CHANGELOG.md` or `.changes/vX.Y.Z.md`.** Both are assembled
by `make release` from the fragments. Editing them is the same class of mistake
as editing a generated dashboard.

**Do not add a `var version` to a `main` package.** `internal/platform/buildinfo`
is the one place a binary learns which build it is; three per-`main` copies
existed and all three reported `dev` forever.

**Chronos is an unstable alpha.** Releases are tagged `vX.Y.Z-alpha.N`. Do not
remove the `PRERELEASE` default in the Makefile as tidying — emptying it is how
the product is declared beta or stable.

**Never bump `chronos.*.v1` to match a product version.** They are independent
axes; see docs/VERSIONING.md §1.

## Committing

**Commit as soon as one thing is done and green** — not at the end of a session,
and without waiting to be asked. In this repository that is a standing
instruction. Pushing is different: never push without being asked.

One commit is one reason to change. Every commit builds and its tests pass.
Never mix a dependency bump, generated code and a behaviour change.

Conventional Commits, subject in this repository's voice — a statement about the
system, not a label:

```
fix(identity): half of every API key minted could never authenticate
```

The body carries the reasoning a reader will not recover from the diff. Add
`Changelog: none` when a customer cannot observe the change; the release
procedure reads it. Full rules: [WORKFLOW.md](WORKFLOW.md) §4.

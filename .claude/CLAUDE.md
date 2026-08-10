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

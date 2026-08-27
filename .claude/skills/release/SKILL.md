---
name: release
description: Cut a Chronos release — read every commit since the last tag, write the customer-facing changelog from the diffs, assemble, tag, and stop before pushing. Use when the user asks to release, cut a version, tag a release, or update the changelog.
---

# Cutting a release

The changelog is written **here**, at release time, from the diffs of every
commit since the last tag. Nobody writes fragments while working; that is the
whole point of this procedure, and it is also its weakness. Compensate by
reading diffs, never commit subjects.

Full reference: `docs/VERSIONING.md`. This file is the procedure.

## Before anything

```bash
git status --porcelain     # must be empty; a release is assembled from committed code
git branch --show-current  # releases are cut from main
make version               # what the last tag was, and what channel we are on
```

If the tree is dirty, stop and ask. Do not stash, do not commit unrelated work
into the release.

Run the suite. A tag is a claim that this code works:

```bash
go build ./... && go test ./... -count=1
```

## 1. Read the range

```bash
make release-input
```

It prints every commit since the last tag, split three ways: **NEEDS AN ENTRY**
(touched something a customer can observe), **DECLINED** (the commit says
`Changelog: none`), and a count of the rest.

## 2. Read the diffs — not the subjects

For every commit under NEEDS AN ENTRY:

```bash
git show <sha>
```

This is the step that cannot be skipped and cannot be delegated to the subject
line. Commit subjects in this repository are written for engineers on purpose:
*"half of every API key minted could never authenticate"* is correct for
`git log` and wrong for a customer. A changelog assembled from subjects either
leaks internal detail or reads as noise — which is exactly the failure this
procedure trades a per-change gate away for, so it has to be paid for here.

Read for one thing: **what can somebody outside this system now do, or no
longer suffer, that was not true before?**

If the answer is "nothing" — a refactor with identical behaviour, a test, a
generated file — it gets no entry. Say so in the summary; do not invent one.

## 3. Group, then write

**One entry per customer-visible change, not per commit.** A feature built
across five commits is one entry. A fix and its test are one entry. Two
unrelated fixes in one commit are two entries.

```bash
make changelog-new KIND=<kind> DOMAIN=<domain> BODY="<one sentence>"
```

`KIND` decides the version bump, so pick it for what happened, not for the
number you want:

| Kind | Bump | For |
| --- | --- | --- |
| `Added` | minor | a capability that did not exist |
| `Changed` | minor | different behaviour, same capability |
| `Deprecated` | minor | still works, going away, with a date |
| `Removed` | **major** | gone |
| `Fixed` | patch | it was broken and now is not |
| `Security` | patch | a security-relevant change |

`DOMAIN` is one of the enum in `.changie.yaml`. Read that file rather than
guessing; it is the list the validator checks against.

The body:

- Addresses the reader as **you**, and says what they can do or no longer
  suffer. Not what the code does.
- One sentence, ends in a full stop, 20–400 characters. Enforced.
- No internal vocabulary: no stream, table, projector, reactor or type names,
  no ADR numbers, no file paths.
- No personal data and no customer names. ADR-002 applies to a published
  document at least as hard as to a log line.
- Never a commit subject. `make changelog-new` rejects one that starts
  `feat(...)`, `fix(...)` and so on, but it cannot catch a subject reworded
  just enough to pass.

**A tightened bound is a `Changed`, not a nothing.** Lowering a `maxLength` or a
numeric ceiling rejects requests that used to succeed, and `buf breaking` will
not flag it (CONVENTIONS §7.2).

## 4. Show the user before tagging

```bash
make changelog-preview
```

Print it and say which commits produced which entry, and which commits you
judged invisible. **Wait for the user to approve the wording.** They are the
only one who knows whether an entry describes what they meant to ship.

## 5. Assemble, tag

```bash
make release                       # auto bump from the fragment kinds
make release BUMP=v0.2.0           # when the number is a decision, not a consequence
make release PRERELEASE=alpha.3    # the alpha counter; see below
```

`make release` refuses a dirty tree and refuses a release that describes nothing
while observable work went into the range.

Then read what it wrote — `git diff` — and tag:

```bash
make release-tag                   # commits CHANGELOG.md + .changes/, annotated tag, no push
git cat-file tag <version>         # confirm the notes actually landed in the annotation
```

The tag carries the notes in its own annotation, not just in the commit it
points at. Check it — this failed silently once: `git tag -F` defaults to
`--cleanup=strip`, which deletes every line starting with `#`, so Markdown
headings were eaten and the tag read as one bare bullet.

## 6. Stop

**Do not push.** `git push origin main --follow-tags` publishes to GitHub and
fires `.github/workflows/release.yml`, which creates a public release with those
notes and attaches four binaries. That is outward-facing and irreversible in
practice. Report what was tagged and offer the command.

## The alpha channel

`PRERELEASE ?= alpha.1` in the Makefile puts a prerelease marker on every
release. **Bump the counter each release** — `make release PRERELEASE=alpha.2`,
then `alpha.3` — or two releases carry the same marker.

Emptying it (`make release PRERELEASE=`) declares the product beta or stable.
That is the user's decision and it must be asked for explicitly. Never do it as
tidying.

## When there is no prior tag

`make release-input` reports the whole history. Do not describe all of it —
describe the state of the product as something a new reader can act on, and say
in the summary that the first release was summarised rather than enumerated.
`BUMP=v0.1.0` is usually right: a lone `Fixed` from nothing computes `v0.0.1`.

## What must not happen

- A release whose entries are reworded commit subjects.
- An entry for work no customer can observe, added to make the release look
  bigger.
- A tag pushed without the user asking.
- `CHANGELOG.md` or `.changes/vX.Y.Z.md` edited by hand. Both are generated; fix
  the fragment and re-run `make release`.
- The `PRERELEASE` default removed as part of an unrelated change.

#!/usr/bin/env bash
# Migrations are append-only.
#
# This replaces the checksum verification we gave up by moving off Atlas
# (ADR-011). Goose records which versions were applied but does not hash their
# contents, so an edit to an already-applied migration is invisible: the file
# says one thing, the database contains another, and a fresh environment built
# from the same repo diverges from production silently.
#
# The rule: a migration file may be ADDED. It may never be modified, renamed or
# deleted once it exists on the base branch.
#
# Exits non-zero on violation.
set -uo pipefail
cd "$(dirname "$0")/.."

DIR="cmd/migrate/migrations"
BASE="${MIGRATION_BASE_REF:-}"
G="\033[32m"; R="\033[31m"; Y="\033[33m"; X="\033[0m"

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo -e "  ${Y}skip${X}  not a git repository"
  exit 0
fi

# Pick a base to compare against: an explicit ref, else origin/main, else main.
if [ -z "$BASE" ]; then
  for candidate in origin/main origin/master main master; do
    if git rev-parse --verify "$candidate" >/dev/null 2>&1; then BASE="$candidate"; break; fi
  done
fi
if [ -z "$BASE" ]; then
  echo -e "  ${Y}skip${X}  no base branch yet (first commit?) — nothing to compare"
  exit 0
fi

echo "migration append-only check (against $BASE)"

changes=$(git diff --name-status "$BASE" -- "$DIR" 2>/dev/null)
if [ -z "$changes" ]; then
  echo -e "  ${G}OK${X}    no migration changes"
  exit 0
fi

violations=0
while IFS=$'\t' read -r status file rest; do
  [ -z "$status" ] && continue
  case "$status" in
    A)   echo -e "  ${G}OK${X}    added    $file" ;;
    M)   echo -e "  ${R}FAIL${X}  MODIFIED $file"
         echo "        An applied migration must never change. Add a new one instead."
         violations=$((violations + 1)) ;;
    D)   echo -e "  ${R}FAIL${X}  DELETED  $file"
         echo "        Removing a migration desynchronises every environment that ran it."
         violations=$((violations + 1)) ;;
    R*)  echo -e "  ${R}FAIL${X}  RENAMED  $file -> $rest"
         echo "        Renaming changes the version Goose recorded."
         violations=$((violations + 1)) ;;
    *)   echo -e "  ${Y}?${X}     $status $file" ;;
  esac
done <<< "$changes"

# Versions must also be unique, or ordering is undefined.
dupes=$(ls "$DIR" 2>/dev/null | sed -n 's/^\([0-9]\{1,\}\)_.*/\1/p' | sort | uniq -d)
if [ -n "$dupes" ]; then
  echo -e "  ${R}FAIL${X}  duplicate migration versions: $dupes"
  violations=$((violations + 1))
fi

echo
if [ "$violations" -eq 0 ]; then
  echo -e "${G}migrations are append-only${X}"
  exit 0
fi
echo -e "${R}${violations} violation(s)${X}"
exit 1

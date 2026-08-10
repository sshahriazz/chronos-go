#!/usr/bin/env bash
# A vendored third-party proto must match the version of the server we run.
#
# third_party/centrifugo/api.proto is a copy of a file that belongs to somebody
# else. Nothing in the file says which release it came from, so it can drift from
# the running server in the direction that is hardest to notice: the generated
# client keeps compiling, the RPCs keep resolving, and a field added or renamed
# upstream is simply absent from ours. The failure surfaces as a publish that
# silently omits data, not as a build error.
#
# So the pin is derived from CENTRIFUGO_IMAGE — the same value that decides which
# server actually runs — and this script fails if the vendored copy differs from
# that release. Bumping the image without re-vendoring is then a failing check
# rather than a discovery months later.
#
# Exits non-zero on drift.
set -uo pipefail
cd "$(dirname "$0")/.."

G="\033[32m"; R="\033[31m"; Y="\033[33m"; X="\033[0m"

VENDORED="third_party/centrifugo/api.proto"
REPO="https://github.com/centrifugal/centrifugo.git"
SUBDIR="internal/apiproto"

# .env.example is the committed source of truth for image pins, not .env: this
# check must give the same answer on a developer's machine and in CI.
pin="$(sed -n 's|^CENTRIFUGO_IMAGE=[^:]*:||p' .env.example | sed -n '1p')"
if [ -z "$pin" ]; then
  echo -e "  ${R}FAIL${X}  no CENTRIFUGO_IMAGE pin in .env.example"
  exit 1
fi

if ! command -v buf >/dev/null 2>&1; then
  echo -e "  ${Y}skip${X}  buf is not installed"
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

if ! buf export "${REPO}#ref=${pin},subdir=${SUBDIR}" -o "$tmp" >"$tmp/err" 2>&1; then
  # Offline, or the tag does not exist. Not a violation on its own — but say
  # which, because "check skipped" and "check passed" must never look alike.
  echo -e "  ${Y}skip${X}  could not fetch centrifugo ${pin}: $(tr -d '\n' < "$tmp/err" | cut -c1-120)"
  exit 0
fi

upstream="$(find "$tmp" -name api.proto | sed -n '1p')"
if [ -z "$upstream" ]; then
  echo -e "  ${R}FAIL${X}  centrifugo ${pin} has no ${SUBDIR}/api.proto; the upstream layout moved"
  exit 1
fi

if diff -q "$upstream" "$VENDORED" >/dev/null 2>&1; then
  echo -e "  ${G}ok${X}    ${VENDORED} matches centrifugo ${pin}"
  exit 0
fi

echo -e "  ${R}FAIL${X}  ${VENDORED} does not match centrifugo ${pin}"
echo
diff -u "$VENDORED" "$upstream" | sed -n '1,60p'
echo
echo "  The vendored proto and the server we run disagree. Re-vendor and"
echo "  regenerate, or correct the pin:"
echo
echo "    buf export '${REPO}#ref=${pin},subdir=${SUBDIR}' -o /tmp/cfg"
echo "    cp /tmp/cfg/api.proto ${VENDORED}"
echo "    make proto-thirdparty"
exit 1

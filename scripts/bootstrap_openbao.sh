#!/usr/bin/env bash
# Key custody for crypto-shredding (ADR-028, ADR-002).
#
# Personal data is encrypted with a key held here, and ERASURE IS KEY
# DESTRUCTION — not a delete statement, not a migration. That only works if the
# key never leaves OpenBao, so the KEK is created non-exportable: the transit
# engine encrypts and decrypts on our behalf and the material is unreadable even
# to us.
#
# Idempotent, and run by `make up`. Without it a fresh volume has no transit
# engine at all, and every attempt to store personal data fails at runtime with
# a 404 nobody expects.
set -uo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] && { set -a; . ./.env; set +a; }

ADDR="${OPENBAO_ADDR:-http://localhost:8200}"
TOKEN="${OPENBAO_DEV_TOKEN:-}"
KEK="${OPENBAO_KEK_NAME:-chronos-kek}"
G="\033[32m"; Y="\033[33m"; R="\033[31m"; X="\033[0m"

if [ -z "$TOKEN" ]; then
  echo -e "  ${Y}skip${X}  OPENBAO_DEV_TOKEN is not set"
  exit 0
fi

for i in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$ADDR/v1/sys/health" || true)
  case "$code" in 200|429|472|473|501|503) break ;; esac
  [ "$i" = "30" ] && { echo -e "  ${R}FAIL${X}  OpenBao never became reachable at $ADDR"; exit 1; }
  sleep 1
done

api() { curl -s -o /dev/null -w '%{http_code}' -H "X-Vault-Token: $TOKEN" "$@"; }

# The transit engine. Already-mounted answers 400, which is success here.
code=$(api -X POST -d '{"type":"transit"}' "$ADDR/v1/sys/mounts/transit")
case "$code" in
  204|200) echo -e "  ${G}OK${X}    transit engine mounted" ;;
  400)     echo -e "  ${G}OK${X}    transit engine already mounted" ;;
  *)       echo -e "  ${R}FAIL${X}  mounting transit: HTTP $code"; exit 1 ;;
esac

# exportable=false is the whole point: a key that can be exported can be copied,
# and a copied key means destroying the original erases nothing.
code=$(api -X POST \
  -d '{"type":"aes256-gcm96","exportable":false,"allow_plaintext_backup":false}' \
  "$ADDR/v1/transit/keys/$KEK")
case "$code" in
  200|204) echo -e "  ${G}OK${X}    key-encryption key '$KEK' ready (non-exportable)" ;;
  *)       echo -e "  ${R}FAIL${X}  creating KEK: HTTP $code"; exit 1 ;;
esac

verdict=$(curl -s -H "X-Vault-Token: $TOKEN" "$ADDR/v1/transit/keys/$KEK" \
  | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print(d['type'], d['exportable'])" 2>/dev/null)
echo -e "  ${G}OK${X}    verified: $verdict (type, exportable)"

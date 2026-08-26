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
KV="${OPENBAO_KV_MOUNT:-secret}"
STRIPE_PATH="${OPENBAO_STRIPE_PATH:-chronos/stripe}"
G="\033[32m"; Y="\033[33m"; R="\033[31m"; X="\033[0m"

# Where the unseal key and root token live once this installation is initialised.
#
# Gitignored, and beside the data it unseals — which is exactly what production
# must never do and exactly what a laptop needs. See infra/openbao/config.hcl.
CREDS="infra/openbao/.bao-credentials.json"

for i in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$ADDR/v1/sys/health" || true)
  # 501 = not initialised, 503 = sealed. Both mean reachable, and both are
  # states this script exists to move out of.
  case "$code" in 200|429|472|473|501|503) break ;; esac
  [ "$i" = "30" ] && { echo -e "  ${R}FAIL${X}  OpenBao never became reachable at $ADDR"; exit 1; }
  sleep 1
done

# ---------------------------------------------------------------------------
# Initialise once, unseal on every start
# ---------------------------------------------------------------------------
#
# With file storage the server comes up SEALED and stays that way until somebody
# hands it the unseal key — which is the whole point of a seal and the reason
# dev mode skips it. One share and a threshold of one, because the alternative
# is a developer splitting a key three ways on their own laptop.
initialised=$(curl -s "$ADDR/v1/sys/init" | grep -o '"initialized":[a-z]*' | cut -d: -f2)

if [ "$initialised" = "false" ]; then
  if [ -f "$CREDS" ]; then
    # Credentials for a store that no longer exists. Refused rather than
    # overwritten: the volume was destroyed and the KEK with it, so every
    # subject's personal data is already unreadable — and silently minting a new
    # key here is what turns that into a system that looks fine.
    echo -e "  ${R}FAIL${X}  OpenBao is uninitialised but $CREDS exists."
    echo    "        The storage volume was destroyed and the key-encryption key with"
    echo    "        it, so anything already encrypted is unreadable. If that is"
    echo    "        expected — after \`make nuke\` — delete $CREDS and the kek_canary"
    echo    "        row, then run this again."
    exit 1
  fi
  out=$(curl -s -X POST -d '{"secret_shares":1,"secret_threshold":1}' "$ADDR/v1/sys/init")
  key=$(echo "$out" | grep -o '"keys":\["[^"]*' | cut -d'"' -f4)
  root=$(echo "$out" | grep -o '"root_token":"[^"]*' | cut -d'"' -f4)
  if [ -z "$key" ] || [ -z "$root" ]; then
    echo -e "  ${R}FAIL${X}  initialising OpenBao: $out"; exit 1
  fi
  mkdir -p "$(dirname "$CREDS")"
  umask 077
  printf '{"unseal_key":"%s","root_token":"%s"}\n' "$key" "$root" > "$CREDS"
  echo -e "  ${G}OK${X}    initialised; unseal key and root token written to $CREDS"
fi

if [ ! -f "$CREDS" ]; then
  echo -e "  ${R}FAIL${X}  OpenBao is initialised and $CREDS is missing, so nothing here"
  echo    "        can unseal it. If the credentials are lost the data is unreadable."
  exit 1
fi

UNSEAL=$(grep -o '"unseal_key":"[^"]*' "$CREDS" | cut -d'"' -f4)
TOKEN=$(grep -o '"root_token":"[^"]*' "$CREDS" | cut -d'"' -f4)

sealed=$(curl -s "$ADDR/v1/sys/seal-status" | grep -o '"sealed":[a-z]*' | cut -d: -f2)
if [ "$sealed" = "true" ]; then
  curl -s -X POST -d "{\"key\":\"$UNSEAL\"}" "$ADDR/v1/sys/unseal" >/dev/null
  sealed=$(curl -s "$ADDR/v1/sys/seal-status" | grep -o '"sealed":[a-z]*' | cut -d: -f2)
  [ "$sealed" = "true" ] && { echo -e "  ${R}FAIL${X}  OpenBao would not unseal"; exit 1; }
  echo -e "  ${G}OK${X}    unsealed"
fi

# The app reads the token from .env, so the one this script minted has to land
# there. Rewritten in place rather than appended, so repeated runs do not stack
# stale tokens that shadow each other.
if [ -f .env ] && ! grep -q "^OPENBAO_DEV_TOKEN=$TOKEN$" .env; then
  tmp=$(mktemp)
  grep -v '^OPENBAO_DEV_TOKEN=' .env > "$tmp"
  printf 'OPENBAO_DEV_TOKEN=%s\n' "$TOKEN" >> "$tmp"
  mv "$tmp" .env
  echo -e "  ${G}OK${X}    OPENBAO_DEV_TOKEN updated in .env"
fi

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

# Read the key back and ASSERT the two properties erasure depends on, rather
# than printing whatever the server said.
#
# This used to pipe the response through a scripting-runtime one-liner and echo
# the result beside a hardcoded "OK". Where that runtime was absent the pipeline
# produced an empty string and the line still said OK — so the one check standing
# between "erasure destroys the key" and "erasure destroys a copy of the key"
# reported success without ever looking. It now fails.
#
# Matched as whole literals rather than extracted: `"mount_type":"transit"` also
# ends in `type`, so pulling a value out with sed would read the wrong field,
# while asking whether the exact expected pair is present cannot.
detail=$(curl -s -H "X-Vault-Token: $TOKEN" "$ADDR/v1/transit/keys/$KEK")
if [ -z "$detail" ]; then
  echo -e "  ${R}FAIL${X}  could not read '$KEK' back from $ADDR"; exit 1
fi
case "$detail" in
  *'"exportable":false'*) ;;
  *) echo -e "  ${R}FAIL${X}  '$KEK' is EXPORTABLE — a key that can be copied means destroying the original erases nothing (ADR-002)"; exit 1 ;;
esac
case "$detail" in
  *'"type":"aes256-gcm96"'*) ;;
  *) echo -e "  ${R}FAIL${X}  '$KEK' is not aes256-gcm96"; exit 1 ;;
esac
echo -e "  ${G}OK${X}    verified: aes256-gcm96, exportable=false"

# ---------------------------------------------------------------------------
# The KV engine, for APPLICATION SECRETS — a different job from the KEK above.
# ---------------------------------------------------------------------------
# The transit engine holds a key that never leaves OpenBao. This holds values
# that must leave it: a Stripe API key is useless unless the process can send it
# to Stripe. So this is custody, not secrecy-in-use — the secret is read once at
# startup over an authenticated channel instead of sitting in every process's
# environment, in `docker inspect`, in a crash dump and in the shell history of
# whoever last deployed.
#
# BILLING-PLAN.md §7 requires it for the Stripe key and the webhook signing
# secrets. KV v2 rather than v1 because v2 versions writes, which is what makes
# the overlap window in billing.md §5 case 26 auditable: after a rotation you can
# see which secret was current when.
code=$(api -X POST -d '{"type":"kv","options":{"version":"2"}}' "$ADDR/v1/sys/mounts/$KV")
case "$code" in
  204|200) echo -e "  ${G}OK${X}    kv v2 engine mounted at '$KV'" ;;
  400)     echo -e "  ${G}OK${X}    kv v2 engine already mounted at '$KV'" ;;
  *)       echo -e "  ${R}FAIL${X}  mounting kv: HTTP $code"; exit 1 ;;
esac

# Seed the Stripe secrets from .env, FOR DEVELOPMENT ONLY.
#
# This is the one place the two worlds meet, and it runs only because a dev
# machine's .env is already the source of truth there. In production nothing
# seeds anything: the secrets are written by whoever holds them, and this script
# would find them already present.
#
# Absent values are skipped rather than written empty. An empty Stripe key in
# custody is worse than none: the process starts, reads it, and fails on the
# first call to Stripe with an authentication error that looks like a revoked
# key rather than a missing one.
seed=""
add_seed() {
  [ -n "${2:-}" ] || return 0
  [ -n "$seed" ] && seed="$seed,"
  seed="$seed\"$1\":\"$2\""
}
add_seed api_key "${STRIPE_SECRET_KEY:-}"
add_seed webhook_secret "${STRIPE_WEBHOOK_SECRET:-}"
add_seed webhook_secret_previous "${STRIPE_WEBHOOK_SECRET_PREVIOUS:-}"

if [ -z "$seed" ]; then
  echo -e "  ${Y}skip${X}  no STRIPE_* values in .env to seed into '$KV/$STRIPE_PATH'"
else
  code=$(api -X POST -d "{\"data\":{$seed}}" "$ADDR/v1/$KV/data/$STRIPE_PATH")
  case "$code" in
    200|204) echo -e "  ${G}OK${X}    stripe secrets seeded at '$KV/$STRIPE_PATH'" ;;
    *)       echo -e "  ${R}FAIL${X}  seeding stripe secrets: HTTP $code"; exit 1 ;;
  esac
fi

#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Smoke test: prove every piece of infrastructure is actually answering.
# Exits non-zero if anything is down.
# -----------------------------------------------------------------------------
set -uo pipefail

cd "$(dirname "$0")/.."
[ -f .env ] && set -a && . ./.env && set +a

fails=0

check() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    printf '  \033[32mOK\033[0m    %s\n' "$name"
  else
    printf '  \033[31mFAIL\033[0m  %s\n' "$name"
    fails=$((fails + 1))
  fi
}

http() { curl -fsS --max-time 5 "$1"; }

echo "chronos infrastructure smoke test"
echo

grpc() { nc -z localhost "$1"; }

echo "-- services"
check "postgres            (5432)"  docker compose exec -T postgres pg_isready -U "${POSTGRES_USER:-chronos}"
check "valkey              (6379)"  docker compose exec -T valkey valkey-cli ping
check "kurrentdb health    (2113)"  http "http://localhost:${KURRENTDB_PORT:-2113}/health/live"
check "openfga http        (8080)"  http "http://localhost:${OPENFGA_HTTP_PORT:-8080}/healthz"
check "centrifugo health   (8000)"  http "http://localhost:${CENTRIFUGO_PORT:-8000}/health"
check "temporal frontend   (7233)"  docker compose exec -T temporal tctl --address temporal:7233 cluster health
check "temporal ui         (8233)"  http "http://localhost:${TEMPORAL_UI_PORT:-8233}/"
check "seaweedfs master    (9333)"  http "http://localhost:${SEAWEEDFS_MASTER_PORT:-9333}/cluster/status"
check "seaweedfs filer     (8888)"  http "http://localhost:${SEAWEEDFS_FILER_PORT:-8888}/"
check "seaweedfs s3        (8333)"  http "http://localhost:${SEAWEEDFS_S3_PORT:-8333}/status"
check "mailpit api         (8025)"  http "http://localhost:${MAILPIT_UI_PORT:-8025}/api/v1/info"

echo
echo "-- gRPC listeners"
check "kurrentdb grpc     (2113)"   grpc "${KURRENTDB_PORT:-2113}"
check "openfga grpc       (8081)"   grpc "${OPENFGA_GRPC_PORT:-8081}"
check "temporal grpc      (7233)"   grpc "${TEMPORAL_PORT:-7233}"
check "centrifugo grpc   (10000)"   grpc "${CENTRIFUGO_GRPC_PORT:-10000}"
check "seaweedfs master  (19333)"   grpc "${SEAWEEDFS_MASTER_GRPC_PORT:-19333}"
check "seaweedfs filer   (18888)"   grpc "${SEAWEEDFS_FILER_GRPC_PORT:-18888}"
check "seaweedfs s3      (18333)"   grpc "${SEAWEEDFS_S3_GRPC_PORT:-18333}"

echo
echo "-- metrics endpoints"
check "kurrentdb metrics  (2113)"   http "http://localhost:${KURRENTDB_PORT:-2113}/metrics"
check "openfga metrics    (2112)"   http "http://localhost:${OPENFGA_METRICS_PORT:-2112}/metrics"
check "centrifugo metrics (8000)"   http "http://localhost:${CENTRIFUGO_PORT:-8000}/metrics"
check "temporal metrics   (9091)"   http "http://localhost:${TEMPORAL_METRICS_PORT:-9091}/metrics"
check "seaweedfs metrics  (9327)"   http "http://localhost:${SEAWEEDFS_METRICS_PORT:-9327}/metrics"
check "mailpit metrics    (8025)"   http "http://localhost:${MAILPIT_UI_PORT:-8025}/metrics"
check "postgres exporter  (9187)"   http "http://localhost:${POSTGRES_EXPORTER_PORT:-9187}/metrics"
check "valkey exporter    (9121)"   http "http://localhost:${VALKEY_EXPORTER_PORT:-9121}/metrics"

echo
echo "-- telemetry"
check "prometheus         (9090)"   http "http://localhost:${PROMETHEUS_PORT:-9090}/-/healthy"
check "grafana            (3001)"   http "http://localhost:${GRAFANA_PORT:-3001}/api/health"
check "tempo              (3200)"   http "http://localhost:${TEMPO_PORT:-3200}/ready"
check "otel collector otlp(4317)"   grpc "${OTLP_GRPC_PORT:-4317}"
check "otel collector http(4318)"   grpc "${OTLP_HTTP_PORT:-4318}"
check "otel collector mtrx(8889)"   http "http://localhost:${OTEL_COLLECTOR_METRICS_PORT:-8889}/metrics"
# These two checks used to sit behind a `command -v` guard on a scripting
# runtime, which meant they did not run at all where it was absent — silently,
# reporting neither pass nor fail. They now always run: the Go toolchain is not
# optional in this repository, and a check that can vanish is a check nobody can
# rely on.
#
# Pairing a scrape target's health with its job label needs a JSON parser, so it
# is a Go program; counting provisioned dashboards does not, so it is grep.
down=$(go run ./internal/tools/obsprobe -down targets 2>/dev/null)
if [ -z "${down:-}" ]; then
  printf '  \033[32mOK\033[0m    all prometheus targets up\n'
else
  printf '  \033[31mFAIL\033[0m  prometheus targets down: %s\n' "$down"
  fails=$((fails + 1))
fi

# One "uid" per dashboard in Grafana's search response, and the query is already
# filtered to dash-db, so a count of the key is a count of the dashboards.
expected=$(find infra/grafana/dashboards -name '*.json' | wc -l | tr -d ' ')
dash=$(curl -fsS --max-time 5 -u "${GRAFANA_ADMIN_USER:-admin}:${GRAFANA_ADMIN_PASSWORD:-chronos_dev_grafana}" \
  "http://localhost:${GRAFANA_PORT:-3001}/api/search?type=dash-db" 2>/dev/null \
  | grep -o '"uid"' | wc -l | tr -d ' ')
if [ "${dash:-0}" -ge "${expected:-1}" ]; then
  printf '  \033[32mOK\033[0m    %s grafana dashboards provisioned\n' "$dash"
else
  printf '  \033[31mFAIL\033[0m  only %s grafana dashboards provisioned (expected %s)\n' "${dash:-0}" "$expected"
  fails=$((fails + 1))
fi

echo
if [ "$fails" -eq 0 ]; then
  printf '\033[32mall services healthy\033[0m\n'
else
  printf '\033[31m%d service(s) failing\033[0m\n' "$fails"
fi
exit "$fails"

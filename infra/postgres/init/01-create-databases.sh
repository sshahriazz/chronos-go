#!/bin/bash
# -----------------------------------------------------------------------------
# Runs once, on first boot of an empty postgres-data volume.
#
# Creates the OpenFGA database. Temporal creates its own (temporal,
# temporal_visibility) via the auto-setup image, so they are not created here.
# -----------------------------------------------------------------------------
set -euo pipefail

create_db() {
  local db="$1"
  echo "==> ensuring database '${db}'"
  psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER}" --dbname "${POSTGRES_DB}" <<-EOSQL
	SELECT 'CREATE DATABASE ${db}'
	WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${db}')\gexec
	EOSQL
}

create_db "${OPENFGA_DB:-openfga}"

echo "==> chronos: database bootstrap complete"

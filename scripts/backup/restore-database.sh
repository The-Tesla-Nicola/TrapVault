#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Restore a PostgreSQL backup into a running Docker Compose stack.
# Usage:  ./scripts/backup/restore-database.sh backups/honeypot_20240115_030000.sql.gz
# ---------------------------------------------------------------------------
set -euo pipefail

BACKUP_FILE="${1:-}"

if [[ -z "${BACKUP_FILE}" ]]; then
  echo "Usage: $0 <backup-file.sql.gz>"
  exit 1
fi

if [[ ! -f "${BACKUP_FILE}" ]]; then
  echo "Error: backup file not found: ${BACKUP_FILE}"
  exit 1
fi

echo "WARNING: This will overwrite the current database. Press Ctrl-C within 5 seconds to abort."
sleep 5

echo "Dropping and recreating database schema…"
docker compose exec -T postgres \
  psql \
    --username "${POSTGRES_USER:-honeypot}" \
    --dbname   "${POSTGRES_DB:-honeypot}" \
    -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"

echo "Restoring from ${BACKUP_FILE}…"
gunzip -c "${BACKUP_FILE}" | docker compose exec -T postgres \
  psql \
    --username "${POSTGRES_USER:-honeypot}" \
    --dbname   "${POSTGRES_DB:-honeypot}"

echo "Restore complete."

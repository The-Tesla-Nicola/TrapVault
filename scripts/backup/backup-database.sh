#!/usr/bin/env bash
# Backup PostgreSQL database from a running Docker Compose stack.
# Usage: ./scripts/backup/backup-database.sh

set -euo pipefail

BACKUP_DIR="./backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
FILENAME="trapvault_${TIMESTAMP}.sql.gz"

mkdir -p "${BACKUP_DIR}"

echo "Creating backup: ${BACKUP_DIR}/${FILENAME}"

docker compose exec -T postgres \
  pg_dump \
    --username "${POSTGRES_USER:-honeypot}" \
    --no-password \
    "${POSTGRES_DB:-honeypot}" \
  | gzip > "${BACKUP_DIR}/${FILENAME}"

echo "Backup complete: ${BACKUP_DIR}/${FILENAME}"

find "${BACKUP_DIR}" -name "trapvault_*.sql.gz" -mtime +30 -delete
echo "Old backups pruned."

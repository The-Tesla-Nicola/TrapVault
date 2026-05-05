#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Obtain and install a Let's Encrypt TLS certificate using Certbot.
# Usage:  ./scripts/deployment/setup-ssl.sh yourdomain.com admin@yourdomain.com
# ---------------------------------------------------------------------------
set -euo pipefail

DOMAIN="${1:-}"
EMAIL="${2:-}"

if [[ -z "${DOMAIN}" || -z "${EMAIL}" ]]; then
  echo "Usage: $0 <domain> <email>"
  exit 1
fi

# Install certbot if not present
if ! command -v certbot &>/dev/null; then
  echo "Installing certbot…"
  apt-get update -qq && apt-get install -y -qq certbot python3-certbot-nginx
fi

echo "Obtaining certificate for ${DOMAIN}…"
certbot --nginx \
  --non-interactive \
  --agree-tos \
  --email "${EMAIL}" \
  -d "${DOMAIN}"

echo "Certificate installed. Reloading nginx…"
docker compose exec nginx nginx -s reload

echo "SSL setup complete for ${DOMAIN}."

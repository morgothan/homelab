#!/usr/bin/env bash
# Exports all secrets from Infisical and imports them into OpenBao KV v2.
# Run once during migration: ./bin/migrate-infisical-to-openbao.sh
# Requires: .env.infisical, .env.openbao (with BAO_ADMIN_TOKEN set)
#           infisical CLI on PATH, jq on PATH

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
DOCKER_DIR="${SCRIPT_DIR}/.."

source "${DOCKER_DIR}/.env.infisical"
source "${DOCKER_DIR}/.env.openbao"

: "${INFISICAL_MACHINE_CLIENT_ID:?Missing from .env.infisical}"
: "${INFISICAL_MACHINE_CLIENT_SECRET:?Missing from .env.infisical}"
: "${INFISICAL_PROJECT_ID:?Missing from .env.infisical}"
: "${INFISICAL_ENV:?Missing from .env.infisical}"
: "${BAO_ADDR:?Missing from .env.openbao}"
: "${BAO_ADMIN_TOKEN:?Missing BAO_ADMIN_TOKEN from .env.openbao — add it (Task 2 Step 12)}"

INFISICAL_CLI_URL="${INFISICAL_LOCAL_URL:-${INFISICAL_SITE_URL}}"

echo "=== Step 1: Authenticate with Infisical ==="
INFISICAL_BIN="$(command -v infisical || echo "${HOME}/.local/bin/infisical")"
INFISICAL_TOKEN="$("${INFISICAL_BIN}" login \
    --method=universal-auth \
    --client-id="${INFISICAL_MACHINE_CLIENT_ID}" \
    --client-secret="${INFISICAL_MACHINE_CLIENT_SECRET}" \
    --domain="${INFISICAL_CLI_URL}" \
    --plain --silent)"
echo "Infisical: authenticated."

echo "=== Step 2: Export all secrets from Infisical ==="
ALL_SECRETS_JSON=$(curl -sf \
    "${INFISICAL_CLI_URL}/api/v3/secrets/raw?environment=${INFISICAL_ENV}&workspaceId=${INFISICAL_PROJECT_ID}&expandSecretReferences=true&recursive=true" \
    -H "Authorization: Bearer ${INFISICAL_TOKEN}")

SECRET_COUNT=$(echo "${ALL_SECRETS_JSON}" | jq '.secrets | length')
echo "Exported ${SECRET_COUNT} secrets from Infisical."

echo "=== Step 3: Group secrets by service path ==="
# Groups secrets into per-service buckets under kv/docker/{service}.
# Grouping rules (first match wins):
#   AUTHELIA_*, AUTH_*, OIDC_*  → authelia
#   CF_*, CLOUDFLARE_*          → cloudflare
#   SMTP_*                      → smtp
#   GF_*, GRAFANA_*             → grafana
#   *POSTGRES*, *DATABASE*,
#   *_DB_*, *DB_HOST*, REDIS_*,
#   *_REDIS_*                   → db
#   everything else              → misc
GROUPED=$(echo "${ALL_SECRETS_JSON}" | jq '
  .secrets |
  map({
    key:     .secretKey,
    value:   .secretValue,
    service: (
      .secretKey |
      if   test("^(AUTHELIA_|AUTH_|OIDC_)")                          then "authelia"
      elif test("^(CF_|CLOUDFLARE_)")                                then "cloudflare"
      elif test("^SMTP_")                                            then "smtp"
      elif test("^(GF_|GRAFANA_)")                                   then "grafana"
      elif test("(POSTGRES|DATABASE|_DB_PASSWORD|^DB_|_REDIS_|^REDIS_)") then "db"
      else "misc"
      end
    )
  }) |
  group_by(.service) |
  map({ (.[0].service): (map({key: .key, value: .value}) | from_entries) }) |
  add // {}
')

echo "Secret distribution:"
echo "${GROUPED}" | jq 'to_entries[] | "\(.key): \(.value | keys | length) secrets"' -r

echo ""
echo "=== Step 4: Import into OpenBao KV v2 ==="
echo "${GROUPED}" | jq -r 'keys[]' | while read -r service; do
    secrets_obj=$(echo "${GROUPED}" | jq --arg s "$service" '.[$s]')
    curl -sf -X POST \
        -H "X-Vault-Token: ${BAO_ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{\"data\": ${secrets_obj}}" \
        "${BAO_ADDR}/v1/kv/data/docker/${service}" > /dev/null
    count=$(echo "${secrets_obj}" | jq 'keys | length')
    echo "  ✓ kv/docker/${service}: ${count} secrets imported"
done

echo ""
echo "=== Done ==="
echo "Total secrets exported: ${SECRET_COUNT}"
echo "Next: Open ${BAO_ADDR}/ui to review groupings and move any miscategorized secrets."
echo "Then: run Task 6 to rewrite dc.sh."

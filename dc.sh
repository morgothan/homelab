#!/usr/bin/env bash
# dc.sh — wrapper for docker compose that injects secrets from OpenBao
#
# Usage: ./dc.sh <docker compose args>
# Example: ./dc.sh up -d
#          ./dc.sh restart authelia
#          ./dc.sh config
#          ./dc.sh down --full      # bring down main stack + openbao stack
#          ./dc.sh up -d --full     # bring up openbao stack (if down) + main stack
#
# Reads AppRole credentials from .env.openbao (same directory as this script),
# authenticates with OpenBao, fetches all secrets from kv/${BAO_KV_PREFIX}/*, and runs
# docker compose with all secrets injected into the environment.
#
# If OpenBao is unreachable, dc.sh auto-starts the openbao stack and waits.
# --full: for 'down', also brings down the openbao stack after the main stack.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env.openbao"

if [[ ! -f "${ENV_FILE}" ]]; then
    echo "Error: ${ENV_FILE} not found." >&2
    echo "Create it with BAO_ADDR, BAO_ROLE_ID, BAO_SECRET_ID defined." >&2
    exit 1
fi

# shellcheck source=.env.openbao
source "${ENV_FILE}"

: "${BAO_ADDR:?Missing BAO_ADDR in ${ENV_FILE}}"
: "${BAO_ROLE_ID:?Missing BAO_ROLE_ID in ${ENV_FILE}}"
: "${BAO_SECRET_ID:?Missing BAO_SECRET_ID in ${ENV_FILE}}"
BAO_KV_PREFIX="${BAO_KV_PREFIX:-docker}"

BAO_COMPOSE="${SCRIPT_DIR}/docker-compose.openbao.yml"

# ── Strip --full flag (handle both stacks) ───────────────────────────────────
FULL=false
ARGS=()
for arg in "$@"; do
    [[ "${arg}" == "--full" ]] && FULL=true || ARGS+=("${arg}")
done
set -- "${ARGS[@]+"${ARGS[@]}"}"

# ── Auto-start OpenBao stack if unreachable ──────────────────────────────────
if ! curl -sf --max-time 2 "${BAO_ADDR}/v1/sys/health" >/dev/null 2>&1; then
    echo "OpenBao not reachable — starting openbao stack..."
    docker compose -f "${BAO_COMPOSE}" up -d
    echo -n "Waiting for OpenBao to be ready..."
    for i in $(seq 1 30); do
        if curl -sf --max-time 2 "${BAO_ADDR}/v1/sys/health" >/dev/null 2>&1; then
            echo " ready."
            break
        fi
        echo -n "."
        sleep 2
        if [[ "${i}" -eq 30 ]]; then
            echo ""
            echo "Error: OpenBao did not become ready in time." >&2
            exit 1
        fi
    done
fi

# ── Wait for unsealed state ───────────────────────────────────────────────────
health_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    "${BAO_ADDR}/v1/sys/health" 2>/dev/null || echo "000")
if [[ "${health_code}" == "503" ]]; then
    echo -n "OpenBao is sealed, waiting for auto-unseal..."
    for i in $(seq 1 30); do
        health_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
            "${BAO_ADDR}/v1/sys/health" 2>/dev/null || echo "000")
        if [[ "${health_code}" == "200" ]]; then
            echo " unsealed."
            break
        fi
        echo -n "."
        sleep 2
        if [[ "${i}" -eq 30 ]]; then
            echo ""
            echo "Error: OpenBao did not unseal in time." >&2
            exit 1
        fi
    done
fi

# ── Authenticate with AppRole ─────────────────────────────────────────────────
BAO_TOKEN=$(curl -sf --max-time 5 \
    -X POST \
    -H "Content-Type: application/json" \
    -d "{\"role_id\":\"${BAO_ROLE_ID}\",\"secret_id\":\"${BAO_SECRET_ID}\"}" \
    "${BAO_ADDR}/v1/auth/approle/login" \
    | jq -r '.auth.client_token')

if [[ -z "${BAO_TOKEN}" || "${BAO_TOKEN}" == "null" ]]; then
    echo "Error: Failed to authenticate with OpenBao AppRole." >&2
    exit 1
fi

# ── List service paths ────────────────────────────────────────────────────────
PATHS=$(curl -sf --max-time 5 \
    -H "X-Vault-Token: ${BAO_TOKEN}" \
    "${BAO_ADDR}/v1/kv/metadata/${BAO_KV_PREFIX}?list=true" \
    | jq -r '.data.keys[] | rtrimstr("/")')

if [[ -z "${PATHS}" ]]; then
    echo "Error: No secret paths found at kv/${BAO_KV_PREFIX}/ in OpenBao." >&2
    exit 1
fi

# ── Fetch and export all secrets ─────────────────────────────────────────────
while IFS= read -r service; do
    secret_data=$(curl -sf --max-time 5 \
        -H "X-Vault-Token: ${BAO_TOKEN}" \
        "${BAO_ADDR}/v1/kv/data/${BAO_KV_PREFIX}/${service}" \
        | jq -r '.data.data | to_entries[] | "\(.key)=\(.value)"') \
        || { echo "Error: failed to fetch kv/${BAO_KV_PREFIX}/${service} from OpenBao" >&2; exit 1; }

    while IFS= read -r kv; do
        if [[ -n "${kv}" ]]; then
            key="${kv%%=*}"
            value="${kv#*=}"
            if [[ "${key}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
                export "${key}=${value}"
            fi
        fi
    done <<< "${secret_data}"
done <<< "${PATHS}"

if [[ "${FULL}" == "true" && "${1:-}" == "down" ]]; then
    docker compose "$@"
    docker compose -f "${BAO_COMPOSE}" down
else
    exec docker compose "$@"
fi

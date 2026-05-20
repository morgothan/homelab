#!/usr/bin/env bash
# dc.sh — wrapper for docker compose that injects secrets from Infisical
#
# Usage: ./dc.sh <docker compose args>
# Example: ./dc.sh up -d
#          ./dc.sh restart authelia
#          ./dc.sh config
#
# Reads auth credentials from .env.infisical (in the same directory as this
# script), authenticates with Infisical, then runs docker compose with all
# secrets injected into the environment.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env.infisical"

if [[ ! -f "${ENV_FILE}" ]]; then
    echo "Error: ${ENV_FILE} not found." >&2
    echo "Create it with INFISICAL_MACHINE_CLIENT_ID, INFISICAL_MACHINE_CLIENT_SECRET," >&2
    echo "INFISICAL_PROJECT_ID, INFISICAL_ENV, and INFISICAL_SITE_URL defined." >&2
    exit 1
fi

# shellcheck source=.env.infisical
source "${ENV_FILE}"

: "${INFISICAL_MACHINE_CLIENT_ID:?Missing INFISICAL_MACHINE_CLIENT_ID in ${ENV_FILE}}"
: "${INFISICAL_MACHINE_CLIENT_SECRET:?Missing INFISICAL_MACHINE_CLIENT_SECRET in ${ENV_FILE}}"
: "${INFISICAL_PROJECT_ID:?Missing INFISICAL_PROJECT_ID in ${ENV_FILE}}"
: "${INFISICAL_ENV:?Missing INFISICAL_ENV in ${ENV_FILE}}"
: "${INFISICAL_SITE_URL:?Missing INFISICAL_SITE_URL in ${ENV_FILE}}"

# Prefer local URL for CLI auth so this works even when the main stack (Traefik/tunnel) is down
INFISICAL_CLI_URL="${INFISICAL_LOCAL_URL:-${INFISICAL_SITE_URL}}"

# If the local Infisical endpoint isn't up, start the infisical stack and wait for it
if ! curl -sf --max-time 2 "${INFISICAL_CLI_URL}/api/status" >/dev/null 2>&1; then
    INFISICAL_COMPOSE="${SCRIPT_DIR}/docker-compose.infisical.yml"
    echo "Infisical not reachable — starting infisical stack..."
    docker compose -f "${INFISICAL_COMPOSE}" --env-file "${ENV_FILE}" up -d
    echo -n "Waiting for Infisical to be ready..."
    for i in $(seq 1 30); do
        if curl -sf --max-time 2 "${INFISICAL_CLI_URL}/api/status" >/dev/null 2>&1; then
            echo " ready."
            break
        fi
        echo -n "."
        sleep 2
        if [[ "${i}" -eq 30 ]]; then
            echo ""
            echo "Error: Infisical did not become ready in time." >&2
            exit 1
        fi
    done
fi

if [[ -n "${INFISICAL_BIN:-}" ]]; then
    # Caller provided an explicit path
    if [[ ! -x "${INFISICAL_BIN}" ]]; then
        echo "Error: INFISICAL_BIN=${INFISICAL_BIN} is not executable." >&2
        exit 1
    fi
elif command -v infisical &>/dev/null; then
    INFISICAL_BIN="$(command -v infisical)"
elif [[ -x ~/.local/bin/infisical ]]; then
    INFISICAL_BIN=~/.local/bin/infisical
else
    echo "Error: infisical CLI not found. Install it or set INFISICAL_BIN." >&2
    exit 1
fi

INFISICAL_TOKEN="$("${INFISICAL_BIN}" login \
    --method=universal-auth \
    --client-id="${INFISICAL_MACHINE_CLIENT_ID}" \
    --client-secret="${INFISICAL_MACHINE_CLIENT_SECRET}" \
    --domain="${INFISICAL_CLI_URL}" \
    --plain --silent)"

if [[ -z "${INFISICAL_TOKEN}" ]]; then
    echo "Error: Failed to obtain Infisical token." >&2
    exit 1
fi

export INFISICAL_TOKEN

exec "${INFISICAL_BIN}" run \
    --projectId="${INFISICAL_PROJECT_ID}" \
    --env="${INFISICAL_ENV}" \
    --domain="${INFISICAL_CLI_URL}" \
    --recursive \
    -- docker compose "$@"

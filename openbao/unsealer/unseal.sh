#!/bin/sh
# Polls OpenBao every 30s and unseals it whenever the sealed state is detected.
# Reads UNSEAL_KEY from /bao-unseal-key (KEY=VALUE format, one per line).
#
# NOTE: Requires OpenBao initialized with -key-shares=1 -key-threshold=1.
# With threshold > 1, each restart requires multiple unseal calls — this
# script only sends one key per 503 cycle and will not fully unseal.

BAO_ADDR="http://openbao:8200"
KEY_FILE="/bao-unseal-key"

[ -f "$KEY_FILE" ] || {
  echo "[unsealer] Waiting for $KEY_FILE to appear (create it during bootstrap)..."
  until [ -f "$KEY_FILE" ]; do sleep 10; done
  echo "[unsealer] $KEY_FILE found."
}

UNSEAL_KEY=""
while IFS='=' read -r k v; do
  [ "$k" = "UNSEAL_KEY" ] && UNSEAL_KEY="$v"
done < "$KEY_FILE"

[ -n "$UNSEAL_KEY" ] || { echo "[unsealer] ERROR: UNSEAL_KEY not found in $KEY_FILE"; exit 1; }

echo "[unsealer] Waiting for OpenBao TCP on openbao:8200..."
until nc -z openbao 8200 2>/dev/null; do
  sleep 3
done
echo "[unsealer] OpenBao is listening. Starting seal monitor."

# Short pause to let OpenBao finish its internal startup
sleep 2

check_and_unseal() {
  code=$(wget -S -O/dev/null "$BAO_ADDR/v1/sys/health" 2>&1 \
         | awk '/HTTP\//{print $2}' | tail -1)
  case "$code" in
    200|429|473)
      ;; # active or standby — nothing to do
    503)
      echo "[unsealer] Sealed (HTTP 503) — sending unseal key..."
      wget -qO/dev/null \
        --post-data="{\"key\":\"$UNSEAL_KEY\"}" \
        --header="Content-Type: application/json" \
        "$BAO_ADDR/v1/sys/unseal" \
        && echo "[unsealer] Unseal request sent." \
        || echo "[unsealer] WARNING: unseal request failed."
      ;;
    *)
      echo "[unsealer] Status HTTP $code — waiting."
      ;;
  esac
}

check_and_unseal

while true; do
  sleep 30
  check_and_unseal
done

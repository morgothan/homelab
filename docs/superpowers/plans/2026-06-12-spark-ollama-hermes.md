# DGX Spark: Ollama + Hermes Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Set up Docker-based Ollama (GPU-accelerated) and native Hermes Agent (Signal gateway + web dashboard) on the DGX Spark, migrate all models from the existing Ollama LXC, and expose the Hermes dashboard externally via Authelia.

**Architecture:** Ollama runs as a Docker container on `spark.hirschnet` with NVIDIA GPU access via the Container Toolkit; secrets are fetched from OpenBao at `http://openbao.hirschnet` by a copy of `dc.sh`. Hermes Agent is installed natively via the NousResearch installer and runs as two systemd services (gateway + dashboard); a bootstrap script (`hermes-secrets-sync.sh`) fetches Hermes secrets from OpenBao and writes `~/.hermes/.env` before each gateway start. The main Traefik on `traefik.hirschnet` routes `hermes.<DOMAIN>` to the Spark's dashboard port (9119) behind Authelia 2FA.

**Tech Stack:** Docker Compose (Ollama), NVIDIA Container Toolkit, signal-cli (Java 17+, HTTP daemon mode), Hermes Agent (Python/Node, NousResearch installer), OpenBao (AppRole secrets), Traefik file provider, Authelia OIDC.

---

## File Map

### New files — `spark.hirschnet`

| Path | Purpose |
|------|---------|
| `/home/nat/docker/docker-compose.yml` | Ollama service definition |
| `/home/nat/docker/.env` | Non-secret vars: `DOCKERDIR` |
| `/home/nat/docker/.env.openbao` | AppRole creds for OpenBao (gitignored on Spark) |
| `/home/nat/docker/dc.sh` | Copied from `traefik.hirschnet`; manages Ollama compose with OpenBao secrets |
| `/etc/systemd/system/signal-cli.service` | signal-cli HTTP daemon |
| `/etc/systemd/system/hermes-dashboard.service` | Hermes dashboard web UI |
| `/home/nat/bin/hermes-secrets-sync.sh` | Fetches Hermes + Ollama secrets from OpenBao → `~/.hermes/.env` |

### Modified files — `spark.hirschnet`

| Path | Change |
|------|--------|
| Hermes gateway systemd unit (created by installer) | Add `ExecStartPre` for secrets sync |

### New files — `traefik.hirschnet`

| Path | Purpose |
|------|---------|
| `traefik/configs/site-spark-hermes.yml` | Routes `hermes.<DOMAIN>` → `spark.hirschnet:9119` |

### Modified files — `traefik.hirschnet`

| Path | Change |
|------|--------|
| `docker-compose.yml` | Update `open-webui` `OLLAMA_BASE_URL` and add `OLLAMA_API_KEY` |

### OpenBao secrets (new)

| Path | Keys |
|------|------|
| `kv/spark/ollama` | `OLLAMA_API_KEY` |
| `kv/spark/hermes` | `SIGNAL_HTTP_URL`, `SIGNAL_ACCOUNT`, `SIGNAL_ALLOWED_USERS`, `SIGNAL_HOME_CHANNEL` |

---

## Task 1: Install NVIDIA Container Toolkit

**Host:** `spark.hirschnet`

The DGX Spark ships with `nvidia-smi` working but Docker does not have the NVIDIA runtime configured. Without this task, `docker compose up` will start Ollama on CPU only.

- [ ] **Step 1.1: Verify GPU is visible but runtime is missing**

```bash
ssh spark.hirschnet
nvidia-smi | grep "NVIDIA GB10"
docker info 2>/dev/null | grep -i runtime
```

Expected: `nvidia-smi` shows `NVIDIA GB10`. `docker info` shows only `runc`, no `nvidia`.

- [ ] **Step 1.2: Install NVIDIA Container Toolkit**

```bash
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
  | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg

distribution=$(. /etc/os-release; echo ${ID}${VERSION_ID})
curl -sL "https://nvidia.github.io/libnvidia-container/${distribution}/libnvidia-container.list" \
  | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
  | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list

sudo apt-get update
sudo apt-get install -y nvidia-container-toolkit
```

- [ ] **Step 1.3: Configure Docker to use NVIDIA runtime and restart**

```bash
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker
```

- [ ] **Step 1.4: Verify NVIDIA runtime is registered**

```bash
docker info 2>/dev/null | grep -i runtime
```

Expected: output includes `nvidia` in the Runtimes list.

- [ ] **Step 1.5: Smoke-test GPU passthrough**

```bash
docker run --rm --gpus all nvcr.io/nvidia/cuda:12.8.0-base-ubuntu24.04 nvidia-smi
```

Expected: `nvidia-smi` output showing `NVIDIA GB10` inside the container.

---

## Task 2: Create OpenBao Secrets and Spark AppRole

**Host:** `traefik.hirschnet` (or OpenBao web UI at `https://openbao.<DOMAIN>`)

This task adds all secrets needed by Ollama and Hermes. It also creates a dedicated AppRole for the Spark so its credentials are isolated from the main host's AppRole.

- [ ] **Step 2.1: Generate a strong random OLLAMA_API_KEY**

```bash
openssl rand -hex 32
```

Copy the output — this is `OLLAMA_API_KEY`. Keep it for Steps 2.2 and 2.4.

- [ ] **Step 2.2: Create `kv/spark/ollama` secret in OpenBao**

Log in to `https://openbao.<DOMAIN>` → Secrets → `kv/docker/` → Create secret at path `ollama`.

Add key: `OLLAMA_API_KEY` = `<value from Step 2.1>`

- [ ] **Step 2.3: Create `kv/spark/hermes` secret in OpenBao**

Create secret at path `hermes`. Add these keys (fill in your actual values):

| Key | Value |
|-----|-------|
| `SIGNAL_HTTP_URL` | `http://127.0.0.1:8080` |
| `SIGNAL_ACCOUNT` | Your Signal phone number in E.164 format (e.g. `+15551234567`) |
| `SIGNAL_ALLOWED_USERS` | Comma-separated E.164 numbers allowed to message the bot (your number) |
| `SIGNAL_HOME_CHANNEL` | Same as `SIGNAL_ALLOWED_USERS` if only one user |

- [ ] **Step 2.4: Create a dedicated AppRole for the Spark**

On `traefik.hirschnet` (where OpenBao's local API is accessible):

```bash
# Get a root/admin token first (see openbao_admin_process.md if needed)
BAO_TOKEN=<admin-token>
BAO_ADDR=http://localhost:8200

# Create a policy that allows the Spark to read its secrets
curl -sf -X PUT \
  -H "X-Vault-Token: ${BAO_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"policy":"path \"kv/data/spark/ollama\" { capabilities = [\"read\"] }\npath \"kv/data/spark/hermes\" { capabilities = [\"read\"] }\npath \"kv/metadata/spark\" { capabilities = [\"list\"] }\npath \"kv/metadata/spark/*\" { capabilities = [\"list\"] }"}' \
  "${BAO_ADDR}/v1/sys/policies/acl/spark-policy"

# Create AppRole for spark
curl -sf -X POST \
  -H "X-Vault-Token: ${BAO_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"policies":["spark-policy"],"token_ttl":"1h","token_max_ttl":"4h"}' \
  "${BAO_ADDR}/v1/auth/approle/role/spark"

# Get role_id
curl -sf \
  -H "X-Vault-Token: ${BAO_TOKEN}" \
  "${BAO_ADDR}/v1/auth/approle/role/spark/role-id" | jq -r '.data.role_id'

# Get secret_id (run this once; copy the value)
curl -sf -X POST \
  -H "X-Vault-Token: ${BAO_TOKEN}" \
  "${BAO_ADDR}/v1/auth/approle/role/spark/secret-id" | jq -r '.data.secret_id'
```

Save both the `role_id` and `secret_id` — needed in Task 3.

- [ ] **Step 2.5: Verify policy works**

```bash
# Authenticate as the Spark AppRole
SPARK_TOKEN=$(curl -sf -X POST \
  -H "Content-Type: application/json" \
  -d "{\"role_id\":\"<role_id>\",\"secret_id\":\"<secret_id>\"}" \
  "${BAO_ADDR}/v1/auth/approle/login" | jq -r '.auth.client_token')

# Read the ollama secret
curl -sf \
  -H "X-Vault-Token: ${SPARK_TOKEN}" \
  "${BAO_ADDR}/v1/kv/data/spark/ollama" | jq '.data.data'
```

Expected: JSON with `OLLAMA_API_KEY`.

---

## Task 3: Set Up dc.sh and Env Files on Spark

**Host:** `spark.hirschnet`

- [ ] **Step 3.1: Copy dc.sh from traefik.hirschnet**

```bash
scp traefik.hirschnet:/home/nat/docker/dc.sh /home/nat/docker/dc.sh
chmod +x /home/nat/docker/dc.sh
```

- [ ] **Step 3.2: Create `/home/nat/docker/.env`**

```bash
cat > /home/nat/docker/.env << 'EOF'
DOCKERDIR=/home/nat/docker
EOF
```

- [ ] **Step 3.3: Create `/home/nat/docker/.env.openbao`**

```bash
cat > /home/nat/docker/.env.openbao << 'EOF'
BAO_ADDR=http://openbao.hirschnet
BAO_ROLE_ID=<role_id from Task 2>
BAO_SECRET_ID=<secret_id from Task 2>
BAO_KV_PREFIX=spark
EOF
chmod 600 /home/nat/docker/.env.openbao
```

- [ ] **Step 3.4: Verify dc.sh can reach OpenBao and fetch secrets**

```bash
cd /home/nat/docker
./dc.sh config
```

Expected: docker compose config output (no errors about missing secrets, shows `OLLAMA_API_KEY` resolved).

---

## Task 4: Write Ollama docker-compose.yml and Start

**Host:** `spark.hirschnet`

- [ ] **Step 4.1: Create `/home/nat/docker/docker-compose.yml`**

```bash
cat > /home/nat/docker/docker-compose.yml << 'EOF'
services:
  ollama:
    image: ollama/ollama:latest
    container_name: ollama
    restart: unless-stopped
    ports:
      - "11434:11434"
    volumes:
      - ${DOCKERDIR}/ollama:/root/.ollama
    environment:
      - OLLAMA_HOST=0.0.0.0
      - OLLAMA_API_KEY=${OLLAMA_API_KEY}
      - OLLAMA_KEEP_ALIVE=-1
      - OLLAMA_NUM_PARALLEL=3
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
EOF
```

- [ ] **Step 4.2: Start Ollama**

```bash
cd /home/nat/docker
./dc.sh up -d
```

Expected: pulls `ollama/ollama:latest`, starts container.

- [ ] **Step 4.3: Verify GPU is in use**

```bash
docker logs ollama 2>&1 | head -20
```

Expected: log line containing `CUDA` or `nvidia` — no "CPU only" warnings.

```bash
docker exec ollama ollama --version
curl -sf http://localhost:11434/api/version | jq .
```

Expected: version JSON response.

- [ ] **Step 4.4: Verify API key auth is enforced**

```bash
# Should get 401 without key
curl -s -o /dev/null -w "%{http_code}" http://localhost:11434/api/tags
```

Expected: `401`

```bash
# Should succeed with key
OLLAMA_API_KEY=$(grep -oP 'OLLAMA_API_KEY=\K.*' /home/nat/docker/.env.openbao 2>/dev/null || \
  source /home/nat/docker/.env.openbao && \
  TOKEN=$(curl -sf -X POST -H "Content-Type: application/json" \
    -d "{\"role_id\":\"${BAO_ROLE_ID}\",\"secret_id\":\"${BAO_SECRET_ID}\"}" \
    "${BAO_ADDR}/v1/auth/approle/login" | jq -r '.auth.client_token') && \
  curl -sf -H "X-Vault-Token: ${TOKEN}" \
    "${BAO_ADDR}/v1/kv/data/spark/ollama" | jq -r '.data.data.OLLAMA_API_KEY')

curl -sf -H "Authorization: Bearer ${OLLAMA_API_KEY}" http://localhost:11434/api/tags | jq .
```

Expected: JSON with empty `models` array (no models pulled yet).

---

## Task 5: Pull Models and Create ha-assistant

**Host:** `spark.hirschnet`

Models are pulled into the Ollama container. The `ha-assistant` model is a custom model built from `llama3.2:3b` with a specific Modelfile. All pulls use the API key.

- [ ] **Step 5.1: Pull base models (these are large — run in a tmux session)**

```bash
# Set the API key (or source it from your environment)
OLLAMA_API_KEY=<value from OpenBao>

for model in qwen2.5-coder:14b llama3.2:3b "qwen2.5:7b-instruct-q4_0" gemma3:12b "gemma4:E4B"; do
  echo "Pulling ${model}..."
  docker exec -e OLLAMA_API_KEY="${OLLAMA_API_KEY}" ollama ollama pull "${model}"
done
```

Total download: ~43 GB. Monitor with `docker exec ollama ollama list`.

- [ ] **Step 5.2: Create the ha-assistant Modelfile**

```bash
cat > /tmp/Modelfile.ha << 'EOF'
FROM llama3.2:3b

PARAMETER num_thread 8
PARAMETER num_ctx 8192

SYSTEM "You are a smart home voice assistant. Be concise — responses will be spoken aloud. One to two sentences maximum."
EOF
```

Note: `num_thread 8` matches the LXC tuning. Tune this after benchmarking on the GB10 — the Spark has different CPU topology. Start with 8, increase if voice response latency is acceptable.

- [ ] **Step 5.3: Build ha-assistant model**

```bash
docker exec -e OLLAMA_API_KEY="${OLLAMA_API_KEY}" ollama \
  ollama create ha-assistant -f /dev/stdin < /tmp/Modelfile.ha
```

- [ ] **Step 5.4: Verify all models are present**

```bash
docker exec ollama ollama list
```

Expected: 6 models — `qwen2.5-coder:14b`, `llama3.2:3b`, `qwen2.5:7b-instruct-q4_0`, `gemma3:12b`, `gemma4:E4B`, `ha-assistant:latest`.

- [ ] **Step 5.5: Test inference on GPU**

```bash
docker exec -e OLLAMA_API_KEY="${OLLAMA_API_KEY}" ollama \
  ollama run gemma3:12b "Reply with just: OK"
```

Expected: responds "OK" within ~5 seconds (model load may take up to 30s on first run). Check GPU memory usage: `nvidia-smi | grep MiB` should show non-zero GPU memory used.

---

## Task 6: Install signal-cli

**Host:** `spark.hirschnet`

signal-cli is a Java application. Java 8 is installed but signal-cli requires Java 17+. We install `default-jre` (Java 21 on Ubuntu 24.04) and the latest signal-cli release.

- [ ] **Step 6.1: Install Java 21**

```bash
sudo apt-get install -y default-jre
java -version
```

Expected: `openjdk version "21..."`

- [ ] **Step 6.2: Install signal-cli**

```bash
VERSION=$(curl -Ls -o /dev/null -w "%{url_effective}" \
  https://github.com/AsamK/signal-cli/releases/latest \
  | sed 's|.*/v||')
echo "Installing signal-cli ${VERSION}"

curl -L -O "https://github.com/AsamK/signal-cli/releases/download/v${VERSION}/signal-cli-${VERSION}.tar.gz"
sudo tar xf "signal-cli-${VERSION}.tar.gz" -C /opt
sudo ln -sf "/opt/signal-cli-${VERSION}/bin/signal-cli" /usr/local/bin/signal-cli
rm "signal-cli-${VERSION}.tar.gz"

signal-cli --version
```

Expected: prints `signal-cli <version>`

- [ ] **Step 6.3: Link your Signal account (interactive — requires your phone)**

```bash
signal-cli link -n "HermesAgent"
```

This prints a `sgnl://` URI and a QR code. On your phone:
1. Open Signal → Settings → Linked Devices → Link New Device
2. Scan the QR code (or paste the URI if using Signal Desktop)

The command will complete after you scan. You'll see: `Associated with: <your number>`.

- [ ] **Step 6.4: Note your linked phone number**

```bash
signal-cli listAccounts
```

Expected: shows your phone number (E.164 format, e.g. `+15551234567`). This is the value you stored as `SIGNAL_ACCOUNT` in OpenBao (Task 2.3). Confirm they match.

- [ ] **Step 6.5: Test receiving messages**

```bash
SIGNAL_ACCOUNT=<your-number>
signal-cli --account "${SIGNAL_ACCOUNT}" receive
```

Expected: exits cleanly (or shows any pending messages). No Java errors.

- [ ] **Step 6.6: Create the signal-cli systemd service**

Replace `+15551234567` with your actual phone number:

```bash
sudo tee /etc/systemd/system/signal-cli.service << 'EOF'
[Unit]
Description=signal-cli HTTP daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nat
ExecStart=/usr/local/bin/signal-cli --account +15551234567 daemon --http 127.0.0.1:8080
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable signal-cli
sudo systemctl start signal-cli
```

- [ ] **Step 6.7: Verify signal-cli daemon is healthy**

```bash
sudo systemctl status signal-cli
curl -sf http://127.0.0.1:8080/api/v1/check | jq .
```

Expected: service is `active (running)`. Curl returns JSON with `versions.signal-cli`.

---

## Task 7: Write hermes-secrets-sync.sh

**Host:** `spark.hirschnet`

This script is called as `ExecStartPre` in the Hermes gateway unit. It fetches secrets from OpenBao and writes them to `~/.hermes/.env`, ensuring OpenBao is the source of truth on every service start.

- [ ] **Step 7.1: Create the `bin` directory and write the script**

```bash
mkdir -p /home/nat/bin

cat > /home/nat/bin/hermes-secrets-sync.sh << 'SCRIPT'
#!/usr/bin/env bash
# Fetches Hermes + Ollama secrets from OpenBao and writes ~/.hermes/.env
set -euo pipefail

ENV_FILE="/home/nat/docker/.env.openbao"
HERMES_ENV="${HOME}/.hermes/.env"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "hermes-secrets-sync: ${ENV_FILE} not found" >&2
  exit 1
fi

source "${ENV_FILE}"
: "${BAO_ADDR:?}"
: "${BAO_ROLE_ID:?}"
: "${BAO_SECRET_ID:?}"

BAO_TOKEN=$(curl -sf --max-time 10 \
  -X POST \
  -H "Content-Type: application/json" \
  -d "{\"role_id\":\"${BAO_ROLE_ID}\",\"secret_id\":\"${BAO_SECRET_ID}\"}" \
  "${BAO_ADDR}/v1/auth/approle/login" \
  | jq -r '.auth.client_token')

if [[ -z "${BAO_TOKEN}" || "${BAO_TOKEN}" == "null" ]]; then
  echo "hermes-secrets-sync: OpenBao authentication failed" >&2
  exit 1
fi

fetch_secret() {
  local path="$1"
  curl -sf --max-time 10 \
    -H "X-Vault-Token: ${BAO_TOKEN}" \
    "${BAO_ADDR}/v1/kv/data/${path}" \
    | jq -r '.data.data | to_entries[] | "\(.key)=\(.value)"'
}

mkdir -p "$(dirname "${HERMES_ENV}")"
{
  fetch_secret "docker/hermes"
  fetch_secret "docker/ollama"
} > "${HERMES_ENV}"

chmod 600 "${HERMES_ENV}"
echo "hermes-secrets-sync: wrote ${HERMES_ENV}"
SCRIPT

chmod +x /home/nat/bin/hermes-secrets-sync.sh
```

- [ ] **Step 7.2: Run the script and verify output**

```bash
/home/nat/bin/hermes-secrets-sync.sh
cat ~/.hermes/.env
```

Expected: `hermes-secrets-sync: wrote /home/nat/.hermes/.env`. File contains `SIGNAL_HTTP_URL`, `SIGNAL_ACCOUNT`, `SIGNAL_ALLOWED_USERS`, `SIGNAL_HOME_CHANNEL`, `OLLAMA_API_KEY` — one per line.

Note: `~/.hermes/` will be created by the script if it doesn't exist yet (created by Hermes installer in Task 8, but `mkdir -p` handles the case where this runs first).

---

## Task 8: Install Hermes Agent

**Host:** `spark.hirschnet` — **must be an interactive terminal session**

- [ ] **Step 8.1: Run the hermes-secrets-sync script first so the API key is available**

```bash
/home/nat/bin/hermes-secrets-sync.sh
```

- [ ] **Step 8.2: Run the Hermes installer**

```bash
curl -fsSL https://raw.githubusercontent.com/NousResearch/hermes-agent/main/scripts/install.sh | bash
```

Answer the prompts as follows:

| Prompt | Answer |
|--------|--------|
| Install ripgrep + ffmpeg? | `Y` (Enter) |
| How would you like to set up Hermes? | **Quick setup** |
| Select Provider | **Custom endpoint (enter URL manually)** |
| API base URL | `http://localhost:11434/v1` |
| API key | Paste `OLLAMA_API_KEY` value from `~/.hermes/.env` |
| Model selection | Select `gemma3:12b` |
| Context length | Enter (auto-detect) |
| Display name | `Spark Ollama (localhost:11434)` |
| Connect a messaging platform? | **Set up messaging now** |
| Select platforms | **Skip for now** — Signal setup is done separately in Task 9 |
| Launch hermes chat now? | `Y` — type `hello`, verify response, then `/exit` |
| Install gateway as background service? | `Y` |

- [ ] **Step 8.3: Install web extras required for the dashboard**

```bash
source ~/.bashrc
export PATH="$HOME/.local/bin:$PATH"
pip install 'hermes-agent[web,pty]'
```

- [ ] **Step 8.4: Verify Hermes CLI works**

```bash
source ~/.bashrc
export PATH="$HOME/.local/bin:$PATH"
which hermes
hermes -z "Reply exactly HERMES_OK"
```

Expected: prints `HERMES_OK`.

- [ ] **Step 8.5: Reload shell and confirm PATH**

```bash
source ~/.bashrc
which hermes
```

Expected: `/home/nat/.local/bin/hermes`

---

## Task 9: Configure Signal Gateway

**Host:** `spark.hirschnet` — signal-cli must be running (Task 6 complete)

- [ ] **Step 9.1: Confirm signal-cli is reachable**

```bash
curl -sf http://127.0.0.1:8080/api/v1/check | jq .
```

Expected: JSON with `versions.signal-cli`.

- [ ] **Step 9.2: Run the Signal gateway setup wizard**

```bash
hermes gateway setup
```

Select **Signal**. The wizard will:
1. Check for signal-cli → confirm it's reachable at `http://127.0.0.1:8080`
2. Ask for HTTP URL → Enter (accept `http://127.0.0.1:8080`)
3. Ask for account phone number → enter `SIGNAL_ACCOUNT` value (e.g. `+15551234567`)
4. Ask for allowed users → enter your number(s) from `SIGNAL_ALLOWED_USERS`
5. Ask for home channel → enter your number from `SIGNAL_HOME_CHANNEL`

If the wizard skips prompts or shows "setup complete" immediately, configure manually:

```bash
source ~/.hermes/.env
hermes config set signal.http_url "${SIGNAL_HTTP_URL}"
hermes config set signal.account "${SIGNAL_ACCOUNT}"
```

- [ ] **Step 9.3: Test Signal gateway from your phone**

Send "hello" in Signal to the linked account. Expected: Hermes replies within ~10 seconds.

---

## Task 10: Set Up Hermes Systemd Services

**Host:** `spark.hirschnet`

The Hermes installer created a gateway service in Task 8. We add `ExecStartPre` to it for secrets sync, then create a separate dashboard service.

- [ ] **Step 10.1: Find the gateway service unit name**

```bash
systemctl list-units --type=service --all | grep -i hermes
```

Note the exact service name (commonly `hermes-gateway.service` or similar containing `hermes` and `gateway`).

- [ ] **Step 10.2: Add ExecStartPre to the gateway unit**

```bash
GATEWAY_UNIT=<name from Step 10.1>
sudo systemctl edit "${GATEWAY_UNIT}"
```

This opens a drop-in override editor. Add:

```ini
[Service]
ExecStartPre=/home/nat/bin/hermes-secrets-sync.sh
```

Save and close (`Ctrl+X` if nano, `:wq` if vim).

- [ ] **Step 10.3: Reload and restart the gateway**

```bash
sudo systemctl daemon-reload
sudo systemctl restart "${GATEWAY_UNIT}"
sudo systemctl status "${GATEWAY_UNIT}"
```

Expected: `active (running)`. Check that `hermes-secrets-sync.sh` ran in journal:

```bash
sudo journalctl -u "${GATEWAY_UNIT}" -n 20 --no-pager | grep hermes-secrets-sync
```

Expected: `hermes-secrets-sync: wrote /home/nat/.hermes/.env`

- [ ] **Step 10.4: Create the dashboard systemd service**

```bash
sudo tee /etc/systemd/system/hermes-dashboard.service << 'EOF'
[Unit]
Description=Hermes Agent Dashboard
After=network.target

[Service]
Type=simple
User=nat
Environment="PATH=/home/nat/.local/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/home/nat/.local/bin/hermes dashboard --host 0.0.0.0 --port 9119 --no-open --insecure
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable hermes-dashboard
sudo systemctl start hermes-dashboard
```

- [ ] **Step 10.5: Verify dashboard is accessible on LAN**

```bash
sudo systemctl status hermes-dashboard
curl -sf -o /dev/null -w "%{http_code}" http://localhost:9119/
```

Expected: service `active (running)`, curl returns `200` or `302`.

From `traefik.hirschnet` (to confirm LAN reachability):

```bash
curl -sf -o /dev/null -w "%{http_code}" http://spark.hirschnet:9119/
```

Expected: `200` or `302`.

---

## Task 11: Add Traefik Routing for Hermes Dashboard

**Host:** `traefik.hirschnet`

- [ ] **Step 11.1: Create `traefik/configs/site-spark-hermes.yml`**

Replace `<DOMAIN>` with the value of `${DOMAIN}` from `.env` (do not commit the actual domain value):

```bash
cat > /home/nat/docker/traefik/configs/site-spark-hermes.yml << 'EOF'
http:
  routers:
    hermes-https:
      entryPoints:
        - "https"
      rule: Host(`hermes.<DOMAIN>`)
      middlewares:
        - chain-authelia-nowaf@file
      service: hermes-svc
      tls:
        certresolver: letsencrypt
        domains:
          - main: "<DOMAIN>"
            sans:
              - "*.<DOMAIN>"

  services:
    hermes-svc:
      loadBalancer:
        servers:
          - url: "http://spark.hirschnet:9119"
EOF
```

Traefik watches `traefik/configs/` and hot-reloads on file changes — no restart needed.

- [ ] **Step 11.2: Verify Traefik picked up the new route**

```bash
docker logs traefik 2>&1 | tail -20 | grep -i "hermes\|error"
```

Expected: log entry showing the `hermes-https` router was loaded. No errors.

- [ ] **Step 11.3: Verify Authelia-protected access**

Open `https://hermes.<DOMAIN>` in a browser. Expected: Authelia 2FA login page. After authenticating: Hermes dashboard loads.

---

## Task 12: Update Open WebUI to Use Spark Ollama

**Host:** `traefik.hirschnet`

- [ ] **Step 12.1: Find and update OLLAMA_URL in OpenBao**

Log in to OpenBao. Find the path where `OLLAMA_URL` is stored (search `kv/docker/` paths — likely `kv/docker/misc` or `kv/docker/homelab-news`). Update its value to `http://spark.hirschnet:11434`.

- [ ] **Step 12.2: Add OLLAMA_API_KEY to the open-webui environment in docker-compose.yml**

```bash
cd /home/nat/docker
```

In `docker-compose.yml`, locate the `open-webui` service environment block. Add the `OLLAMA_API_KEY` line:

```yaml
    environment:
      - OAUTH_CLIENT_ID=${OIDC_OPENWEBUI_CLIENT_ID}
      - OAUTH_CLIENT_SECRET=${OPENWEBUI_OIDC_CLIENT_SECRET}
      - OPENID_PROVIDER_URL=https://authelia.${DOMAIN}/.well-known/openid-configuration
      - OAUTH_PROVIDER_NAME=Authelia
      - OAUTH_SCOPES=openid profile email groups
      - ENABLE_OAUTH_SIGNUP=True
      - OAUTH_MERGE_ACCOUNTS_BY_EMAIL=True
      - ENABLE_LOGIN_FORM=False
      - ENABLE_OAUTH_ROLE_MANAGEMENT=True
      - OAUTH_ROLES_CLAIM=groups
      - OAUTH_ADMIN_ROLES=openwebui-admin
      - OAUTH_DEFAULT_ROLE=user
      - OLLAMA_BASE_URL=${OLLAMA_URL}
      - OLLAMA_API_KEY=${OLLAMA_API_KEY}      # ← add this line
      - WEBUI_SECRET_KEY=${OPEN_WEBUI_SECRET_KEY}
```

- [ ] **Step 12.3: Store OLLAMA_API_KEY in OpenBao for the main host**

Log in to OpenBao → add `OLLAMA_API_KEY` to the same path where `OLLAMA_URL` lives (the path dc.sh fetches it from). Set the value to the same key generated in Task 2.1.

- [ ] **Step 12.4: Restart open-webui**

```bash
cd /home/nat/docker
./dc.sh pull open-webui
./dc.sh up -d open-webui
```

- [ ] **Step 12.5: Verify Open WebUI connects to Spark Ollama**

Open `https://ai.<DOMAIN>` → Admin → Settings → Connections. The Ollama URL should show `http://spark.hirschnet:11434` and the status indicator should be green.

If the status is red or models don't appear, the `OLLAMA_API_KEY` env var may not be supported by this Open WebUI version. In that case: Admin → Settings → Connections → set the Ollama API key field manually via the UI.

---

## Task 13: Migrate Home Assistant to Spark Ollama

**Host:** Home Assistant (`homeassistant.iot.hirschnet`)

The existing HA Ollama conversation integration points at the old LXC IP. Update it to the Spark.

- [ ] **Step 13.1: Add Spark Ollama API key to HA Secrets**

In `homeassistant/secrets.yaml` (or via HA → Settings → System → Edit secrets):

```yaml
ollama_api_key: <OLLAMA_API_KEY value from Task 2.1>
```

- [ ] **Step 13.2: Update the Ollama integration in HA**

Go to Settings → Devices & Services → Ollama → Configure.

- URL: `http://spark.hirschnet:11434`
- API Key: `!secret ollama_api_key`

If the integration doesn't have an API key field in the UI (older HA version), use the config entry override in `configuration.yaml`:

```yaml
ollama:
  host: spark.hirschnet
  port: 11434
  api_key: !secret ollama_api_key
```

- [ ] **Step 13.3: Reload the Ollama integration**

Settings → Developer Tools → YAML → Reload Integrations, or restart HA.

- [ ] **Step 13.4: Test voice assistant response**

Trigger the HA voice assistant (say "Hey Jarvis" or equivalent wake word). Verify:
1. HA sends the query to Spark Ollama
2. Response comes back within ~5 seconds
3. The reply is voiced aloud

Check HA logs for any Ollama connection errors: Settings → System → Logs → search "ollama".

---

## Task 14: Decommission the Ollama LXC

**Host:** `pve.hirschnet` (Proxmox) — only after Task 13 is verified

- [ ] **Step 14.1: Verify HA is working against Spark for at least 24 hours**

No steps — just wait and monitor. Check HA logs for any Ollama errors during normal use.

- [ ] **Step 14.2: Stop Ollama on the LXC**

```bash
ssh root@192.168.107.219 "systemctl stop ollama && systemctl disable ollama"
ssh root@192.168.107.219 "systemctl is-active ollama || echo 'confirmed stopped'"
```

Expected: `inactive` or `confirmed stopped`

- [ ] **Step 14.3: Verify nothing broke**

Wait 30 minutes. Check:
- HA voice assistant still responds (uses Spark)
- Open WebUI still works (uses Spark)
- Hermes Signal replies still work

- [ ] **Step 14.4: Shut down the LXC**

On `pve.hirschnet`:

```bash
/usr/sbin/pct stop 120
```

Keep the LXC in stopped state for 1 week as rollback insurance. After that, it can be deleted:

```bash
# Only after 1 week of stable operation
/usr/sbin/pct destroy 120
```

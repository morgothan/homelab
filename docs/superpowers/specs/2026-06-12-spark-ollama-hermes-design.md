# DGX Spark: Ollama + Hermes Agent Setup

**Date:** 2026-06-12
**Status:** Approved

## Overview

Set up the NVIDIA DGX Spark (`spark.hirschnet`) as the new primary GPU inference host. Ollama runs in Docker with NVIDIA GPU access. Hermes Agent (NousResearch) runs natively as two systemd services: gateway (Signal messenger bridge) and dashboard (web UI). The existing Ollama LXC (CT 120, `192.168.107.219`) is decommissioned after migration.

## Goals

- Replace the existing Ollama LXC with a Docker-based Ollama on the DGX Spark (NVIDIA GB10, CUDA 13.0, aarch64)
- Migrate all models including `ha-assistant`; update HA to point at the Spark
- Install Hermes Agent natively on the Spark, connected to local Ollama and accessible via Signal
- Expose the Hermes dashboard externally via Traefik + Authelia OIDC (`hermes.sketchyasfuckistan.net`)
- All secrets stored in OpenBao as the source of truth; no plaintext secrets in config files or the repo

## Non-Goals

- No Traefik route for the Ollama API (LAN-only access)
- No Open WebUI instance on the Spark (existing Open WebUI on traefik.hirschnet continues, updated to use Spark's Ollama)
- No change to Authelia, Traefik, or OpenBao configuration beyond adding one file provider entry and updating Open WebUI env vars

---

## Architecture

### Components

#### On `spark.hirschnet` — `/home/nat/docker/`

| Component | Type | Notes |
|-----------|------|-------|
| `ollama` | Docker container | `ollama/ollama`, NVIDIA GPU, port 11434 |
| `dc.sh` | Script | Copied from traefik.hirschnet; `BAO_ADDR=http://openbao.hirschnet` |
| `.env.openbao` | Gitignored credentials | AppRole creds for Spark (separate from main host) |
| `.env` | Gitignored config | `DOCKERDIR`, non-secret vars |

#### On `spark.hirschnet` — native systemd services

| Service | Description |
|---------|-------------|
| `signal-cli.service` | signal-cli HTTP daemon on `127.0.0.1:8080`; system service |
| `hermes-gateway.service` | Hermes gateway (Signal bridge); user service |
| `hermes-dashboard.service` | Hermes web UI on `0.0.0.0:9119`; user service |

Hermes data dir: `~/.hermes/` (not in Docker; owned by `nat`)
signal-cli session: `~/.local/share/signal-cli/` (not in Docker)

#### On `traefik.hirschnet`

| Change | Details |
|--------|---------|
| New file: `traefik/configs/site-spark-hermes.yml` | Routes `hermes.${DOMAIN}` → `spark.hirschnet:9119` behind `chain-authelia-nowaf` |
| Update `docker-compose.yml` (open-webui) | `OLLAMA_BASE_URL=http://spark.hirschnet:11434`, add `OLLAMA_API_KEY` |

### Network Flow

```
User (Signal) → signal-cli daemon (127.0.0.1:8080) → Hermes gateway
                                                           ↓
                                              Ollama (localhost:11434)
                                                      (CUDA GPU)

Browser → Cloudflare Tunnel → Traefik (traefik.hirschnet)
          → Authelia (2FA) → spark.hirschnet:9119 (Hermes dashboard)

Open WebUI (traefik.hirschnet) → spark.hirschnet:11434 (Ollama API + key)

Home Assistant (192.168.107.12) → spark.hirschnet:11434 (Ollama API + key)
```

---

## Secrets

### OpenBao paths

| Path | Key | Description |
|------|-----|-------------|
| `kv/docker/ollama` | `OLLAMA_API_KEY` | Ollama API authentication key |
| `kv/docker/hermes` | `SIGNAL_HTTP_URL` | `http://127.0.0.1:8080` |
| `kv/docker/hermes` | `SIGNAL_ACCOUNT` | Signal phone number (E.164, e.g. `+15551234567`) |
| `kv/docker/hermes` | `SIGNAL_ALLOWED_USERS` | Comma-separated E.164 numbers allowed to message Hermes |
| `kv/docker/hermes` | `SIGNAL_HOME_CHANNEL` | Default delivery target for Hermes cron jobs |

### Secret bootstrap for Hermes

Hermes reads secrets from `~/.hermes/.env`. Since it runs natively (not via dc.sh), a bootstrap script (`~/bin/hermes-secrets-sync.sh`) fetches `kv/docker/hermes` from OpenBao and writes `~/.hermes/.env`. This script runs as a `ExecStartPre` in the Hermes gateway service unit so secrets are refreshed on every service start. OpenBao is the source of truth; `~/.hermes/.env` is a derived artifact.

### Spark `.env.openbao`

```
BAO_ADDR=http://openbao.hirschnet
BAO_ROLE_ID=<spark-role-id>
BAO_SECRET_ID=<spark-secret-id>
BAO_KV_PREFIX=docker
```

A dedicated AppRole for the Spark should be created in OpenBao with read-only access to `kv/docker/ollama` and `kv/docker/hermes`. This keeps the Spark's credentials isolated from the main host's AppRole.

---

## Ollama Docker Configuration

```yaml
# /home/nat/docker/docker-compose.yml on spark.hirschnet
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
```

`OLLAMA_API_KEY` is injected by `dc.sh` from `kv/docker/ollama`.

---

## signal-cli Setup

### Installation (on spark.hirschnet)

1. Install Java 17+: `sudo apt install -y default-jre`
2. Download latest signal-cli release from GitHub and install to `/opt/signal-cli-<version>/`; symlink to `/usr/local/bin/signal-cli`
3. **Link account** (interactive, requires physical phone):
   ```bash
   signal-cli link -n "HermesAgent"
   ```
   Scan the printed QR code in Signal → Settings → Linked Devices → Link New Device.
4. Verify: `signal-cli --account +<number> receive`

### systemd service (`/etc/systemd/system/signal-cli.service`)

```ini
[Unit]
Description=signal-cli HTTP daemon
After=network-online.target

[Service]
Type=simple
User=nat
ExecStart=/usr/local/bin/signal-cli --account +<number> daemon --http 127.0.0.1:8080
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

The phone number (`SIGNAL_ACCOUNT`) is baked into this unit (not a secret in the security sense — it's the bot's registered number).

---

## Hermes Agent Setup

### Installation

```bash
curl -fsSL https://raw.githubusercontent.com/NousResearch/hermes-agent/main/scripts/install.sh | bash
```

Interactive setup choices:
- Provider: **Custom endpoint** → `http://localhost:11434/v1`
- API key: enter `OLLAMA_API_KEY` value at the prompt (Ollama requires a Bearer token since it's running with `OLLAMA_API_KEY` set; the key is written to `~/.hermes/.env` by the bootstrap script before install runs, or set post-install via `hermes config set model.api_key <key>`)
- Default model: `gemma3:12b` (or `qwen2.5:7b-instruct-q4_0` for faster responses)
- Messaging: **Signal** (configured via `hermes gateway setup` after signal-cli is running)
- Gateway install: **System service** (`sudo hermes gateway install --system --run-as-user nat`)

### `~/.hermes/.env` (written by hermes-secrets-sync.sh)

```bash
SIGNAL_HTTP_URL=http://127.0.0.1:8080
SIGNAL_ACCOUNT=+<number>
SIGNAL_ALLOWED_USERS=+<your-number>
SIGNAL_HOME_CHANNEL=+<your-number>
OLLAMA_API_KEY=<key>  # Hermes uses this when calling the local Ollama endpoint
```

### hermes-secrets-sync.sh

A script at `~/bin/hermes-secrets-sync.sh` on the Spark that:
1. Reads `.env.openbao` for AppRole creds
2. Authenticates with OpenBao at `http://openbao.hirschnet`
3. Fetches `kv/docker/hermes` and `kv/docker/ollama`
4. Writes the relevant keys to `~/.hermes/.env`

This script is called as `ExecStartPre` in the Hermes gateway systemd unit.

### systemd units

Hermes installs its own systemd units via `hermes gateway install --system`. The `ExecStartPre` for the `hermes-secrets-sync.sh` call is added to the unit file after installation.

The dashboard requires extras not installed by default:
```bash
pip install 'hermes-agent[web,pty]'
```

Hermes dashboard runs as a user service. There is no `hermes dashboard install` CLI — use a manual systemd unit file. The `--insecure` flag is required when binding to a non-localhost address:
```bash
hermes dashboard --host 0.0.0.0 --port 9119 --no-open --insecure
```
The `--insecure` flag suppresses the binding-to-network warning; Authelia provides the actual auth layer.

---

## Traefik: site-spark-hermes.yml

```yaml
# traefik/configs/site-spark-hermes.yml (on traefik.hirschnet)
http:
  routers:
    hermes-https:
      entryPoints:
        - "https"
      rule: Host(`hermes.sketchyasfuckistan.net`)
      middlewares:
        - chain-authelia-nowaf@file
      service: hermes-svc
      tls:
        certresolver: letsencrypt
        domains:
          - main: "sketchyasfuckistan.net"
            sans:
              - "*.sketchyasfuckistan.net"

  services:
    hermes-svc:
      loadBalancer:
        servers:
          - url: "http://spark.hirschnet:9119"
```

The literal domain is used directly in the file. Traefik's file provider does not expand env vars. This is consistent with other `site-*.yml` files (e.g. `site-openbao.yml`) which are committed to git with hardcoded domain names in standard `Host()` rules.

---

## Model Migration

### Models to pull on Spark (via `./dc.sh exec ollama ollama pull <model>`)

| Model | Size | Notes |
|-------|------|-------|
| `qwen2.5-coder:14b` | 9.0 GB | |
| `llama3.2:3b` | 2.0 GB | |
| `qwen2.5:7b-instruct-q4_0` | 4.4 GB | |
| `gemma3:12b` | 8.1 GB | |
| `gemma4:E4B` | 9.6 GB | |
| `ha-assistant` | 2.0 GB | Custom Modelfile; see below |

### ha-assistant Modelfile

Recreate from the existing LXC config:

```
FROM llama3.2:3b

PARAMETER num_thread 8
PARAMETER num_ctx 8192

SYSTEM "You are a smart home voice assistant. Be concise — responses will be spoken aloud. One to two sentences maximum."
```

Note: `num_thread` in the Modelfile is the only effective way to set thread count for this model (env var is unreliable). On the DGX Spark the thread parameter should be tuned after testing — the GB10 has different CPU topology than the LXC.

### HA Update

After all models are pulled and verified on the Spark, update Home Assistant's Ollama integration:
- Endpoint: `http://spark.hirschnet:11434`
- API key: `OLLAMA_API_KEY` (store in HA Secrets)
- Model: `ha-assistant`

### Decommission LXC

After HA is verified working against the Spark:
1. Stop Ollama service on the LXC: `ssh root@192.168.107.219 systemctl stop ollama`
2. Disable autostart: `ssh root@192.168.107.219 systemctl disable ollama`
3. LXC can be kept powered off initially as a rollback option, then deleted once stable

---

## Open WebUI Update (traefik.hirschnet)

In `docker-compose.yml`, update the `open-webui` service environment:

```yaml
- OLLAMA_BASE_URL=http://spark.hirschnet:11434
- OLLAMA_API_KEY=${OLLAMA_API_KEY}
```

`OLLAMA_API_KEY` is already in `kv/docker/ollama` and will be injected by dc.sh on traefik.hirschnet. Open WebUI uses the `OLLAMA_API_KEY` env var natively to authenticate against Ollama.

---

## Implementation Order

1. **OpenBao**: Create `kv/docker/ollama` and `kv/docker/hermes` secrets; create dedicated Spark AppRole
2. **Spark dc.sh + .env.openbao**: Copy and configure dc.sh; create `.env.openbao` pointing at `http://openbao.hirschnet`
3. **Ollama Docker**: Write `docker-compose.yml`, run `./dc.sh up -d`, verify GPU access
4. **Pull models**: Pull all models; recreate ha-assistant from Modelfile
5. **signal-cli**: Install Java, install signal-cli, link account interactively, install systemd service
6. **hermes-secrets-sync.sh**: Write and test the bootstrap script
7. **Hermes install**: Run installer, configure model endpoint + API key, run `hermes gateway setup` for Signal
8. **Hermes systemd**: Add `ExecStartPre` to gateway unit; install and start dashboard service
9. **Traefik**: Add `site-spark-hermes.yml` on traefik.hirschnet; verify `hermes.${DOMAIN}` resolves through Authelia
10. **Open WebUI**: Update `OLLAMA_BASE_URL` + `OLLAMA_API_KEY`, restart open-webui on traefik.hirschnet
11. **HA migration**: Update HA Ollama integration to Spark, verify ha-assistant responds
12. **Decommission LXC**: Stop + disable Ollama on the LXC after HA verification

---

## Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| GB10 GPU not recognized by Ollama container | Verify with `docker run --rm --gpus all nvidia/cuda:12.0-base nvidia-smi` before pulling models |
| signal-cli aarch64 binary not available | signal-cli ships pre-built JARs (Java, not native binary) — runs on any arch with Java 17+ |
| ha-assistant performance different on GB10 vs Arc iGPU | Tune `num_thread` in Modelfile after benchmarking; GB10 should be significantly faster |
| Hermes dashboard `hermes dashboard install` CLI not available | Fall back to manual systemd unit file |
| OpenBao unreachable from Spark during service startup | hermes-secrets-sync.sh has retry logic; on failure, gateway will not start (safe failure mode) |

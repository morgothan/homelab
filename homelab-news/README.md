# Homelab News

A self-hosted daily intelligence digest for your homelab, rendered as a newspaper. Pulls data from Docker, Loki, Prometheus, and optional integrations, then uses a local LLM (via Ollama) to write AP wire-style articles about what happened.

## What it does

| Page | What it shows | Refresh |
|------|---------------|---------|
| **Front Page** | Full-day edition — Docker + Loki logs from midnight to now, LLM-generated articles | Hourly |
| **Current Events** | Rolling 6-hour window, same sources | Every 15 min |
| **Police Blotter** | All active Cloudflare-blocked IPs with geo/ASN/abuse intel, attack categories, probe paths | 60s live fetch |
| **Archive** | Daily snapshots, infinite retention, grouped by month | — |
| **Trends** | LLM-synthesised weekly, monthly, and yearly digests identifying patterns across periods | — |

Articles are grouped into six sections: **City Hall** (container health, updates), **Public Safety** (bans, scanners), **Weather** (UPS/power), **City Archives** (backups), **Arts & Entertainment** (media pipeline), and **Public Works** (DNS, networking). The most important article of the day is promoted to a full-width **Lead Story**.

## Requirements

- Docker
- **Ollama** with a capable model (tested with `gemma4:e4b`; needs good instruction-following and JSON output)
- **Loki** — log aggregation (Promtail or alloy feeding Docker container logs)
- **Prometheus** — for UPS, disk, and service metrics (optional but recommended)
- The Docker socket mounted read-only for local container inspection
- SSH key for remote Docker hosts over SSH (optional)

## Architecture

Five [supervisord](http://supervisord.org/) workers run inside a single container alongside a FastAPI web server:

| Worker | Role | Schedule |
|--------|------|----------|
| `today` | Generates the front-page edition from midnight to now | Hourly |
| `rolling` | Generates the current-events edition for the last 6 hours | Every 15 min |
| `daily` | Snapshots `today.json` into the daily archive at 00:01 UTC | Nightly |
| `updates` | Checks Docker images for updates, fetches GitHub release notes, runs LLM changelog summaries | Hourly |
| `periodic` | Generates weekly/monthly/yearly trend digests | Sun/1st/Jan 1 at 00:01 UTC |

Data is persisted to `/data` (bind-mounted from the host):

```
data/
  today.json            # current front-page edition
  rolling.json          # current rolling edition
  archive/              # one YYYY-MM-DD.json per day, infinite retention
    index.json          # lightweight index (date, headline, issue count) for fast listing
  periodic.json         # weekly/monthly/yearly digests
  context.md            # optional homelab context fed to the LLM
  ip_intel.json         # geo/ASN/abuse cache (7-day TTL)
```

## Configuration

All configuration is via environment variables. Set them in your `docker-compose.yml` or `.env` file.

### Core

| Variable | Description | Default |
|----------|-------------|---------|
| `SITE_NAME` | Publication name shown in the masthead and page title | `Homelab News` |
| `OLLAMA_URL` | Ollama API base URL | `http://ollama:11434` |
| `OLLAMA_MODEL` | Model to use | `gemma4:e4b` |
| `LOKI_URL` | Loki HTTP API base URL | `http://loki:3100` |

### Docker / container health

| Variable | Description |
|----------|-------------|
| `REMOTE_DOCKER_HOSTS` | Comma-separated Docker host URLs to check for container health. Supports `tcp://host:2375` and `ssh://user@host`. Local Docker socket is always checked. |
| `SSH_KEY` | Path inside the container to the SSH private key used for `ssh://` remote hosts (default: `/root/.ssh/id_ed25519`) |

### Monitoring integrations (optional)

| Variable | Description | Default |
|----------|-------------|---------|
| `PROMETHEUS_URL` | Prometheus HTTP API base URL | `http://prometheus:9090` |
| `NODE_EXPORTER_INSTANCE` | Node exporter instance label used for disk/load checks | — |
| `BESZEL_URL` | Beszel PocketBase URL for host health data | — |
| `BESZEL_EMAIL` | Beszel login email | — |
| `BESZEL_PASS` | Beszel login password | — |
| `KOPIA_URL` | Kopia WebUI URL for backup health | `https://kopia-webui:5151` |
| `KOPIA_USER` | Kopia server username | — |
| `KOPIA_PASS` | Kopia server password | — |
| `TAUTULLI_URL` | Tautulli base URL for Plex activity | `http://tautulli:8181` |
| `TAUTULLI_KEY` | Tautulli API key | — |
| `HOMEASSISTANT_URL` | Home Assistant base URL | — |
| `HOMEASSISTANT_TOKEN` | Home Assistant long-lived access token | — |

### Remote SSH checks (optional)

These enable OS-level update checks via `midclt` / `apt` over SSH. The SSH key must be authorised on the target hosts.

| Variable | Description |
|----------|-------------|
| `PVE_SSH_HOST` | SSH target for Proxmox VE apt update checks (e.g. `root@pve.local`) |
| `TRUENAS_SSH_HOST` | SSH target for TrueNAS SCALE OS update checks (e.g. `admin@truenas.local`) |
| `BESZEL_SSH_HOST` | SSH target for reading the Beszel container image version (e.g. `user@beszel.local`) |
| `PLEX_LXC_ID` | Proxmox LXC container ID hosting Plex — used to fetch the Plex version via PVE API |

### DNS / AdGuard (optional)

| Variable | Description |
|----------|-------------|
| `ADGUARD_PRIMARY_URL` | AdGuard Home base URL for the primary DNS instance |
| `ADGUARD_KIDS_URL` | AdGuard Home base URL for a secondary (e.g. filtered) DNS instance |

### Police blotter / IP intel (optional)

| Variable | Description |
|----------|-------------|
| `ABUSEIPDB_KEY` | [AbuseIPDB](https://www.abuseipdb.com/) API key — enables abuse confidence scores on the blotter |
| `CROWDSEC_KEY` | [CrowdSec](https://www.crowdsec.net/) CTI API key — enriches blotter IPs with threat intelligence |

IPs are geo/ASN enriched via ip-api.com regardless of whether these keys are set.

The blotter reads ban state from `cf-fail2ban`'s state file (`traefik/monitor/fail2ban-state.json`). If that file is absent it falls back to reconstructing bans from the Traefik access log.

### Notifications (optional)

| Variable | Description |
|----------|-------------|
| `GOTIFY_URL` | Gotify base URL — enables push notifications for critical update findings |
| `GOTIFY_TOKEN` | Gotify app token |

### GitHub (optional)

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | Personal access token — raises GitHub API rate limit from 60 to 5,000 req/hr for release note fetching |

## Homelab context file

Create `data/context.md` with a plain-text description of your homelab — service names, what's normal, what matters. This file is injected into every LLM prompt, which helps the model:

- Use your actual service names instead of generic ones
- Understand what "normal" looks like so it can focus on anomalies
- Flag breaking changes in Docker image updates that affect your specific setup

Example:
```markdown
Stack: Traefik reverse proxy, Authelia SSO, Jellyfin media server, *arr suite.
Media server is Jellyfin (not Plex). Authelia handles all external auth via OIDC.
Nightly backups via Kopia to Backblaze B2. UPS is APC Back-UPS 600.
High Loki error counts from traefik are usually scanner bots, not real issues.
```

## Prompt injection defenses

Log messages, release notes, and all other untrusted external text pass through `_sanitize_for_llm()` before being embedded in prompts — strips injection trigger phrases and enforces length limits. LLM output is validated by `_validate_articles()` which enforces field types, length caps, and a section whitelist before anything is stored or rendered.

## Backfill

To populate the archive from historical Loki data:

```bash
# Backfill from a specific date to yesterday
docker exec -it lab-monitor python /app/backfill.py --start 2026-01-01

# Preview without writing anything
docker exec -it lab-monitor python /app/backfill.py --start 2026-01-01 --dry-run

# Also regenerate weekly/monthly/yearly trend digests
docker exec -it lab-monitor python /app/backfill.py --start 2026-01-01 --trends

# Regenerate trends from existing archive without re-backfilling days
docker exec -it lab-monitor python /app/backfill.py --trends-only
```

Backfill is safe to interrupt and resume — already-processed dates are skipped automatically.

## Operations

```bash
# Restart a single worker without restarting the container
docker exec lab-monitor supervisorctl restart today
docker exec lab-monitor supervisorctl restart rolling
docker exec lab-monitor supervisorctl restart updates

# Check worker status
docker exec lab-monitor supervisorctl status

# View logs
docker compose logs -f lab-monitor
```

## First-run setup

The `/data` directory must be owned by uid `1001` on the host before starting:

```bash
mkdir -p homelab-news/data
sudo chown -R 1001:1001 homelab-news/data
```

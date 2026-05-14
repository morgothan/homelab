# Homelab News

A self-hosted daily intelligence digest for your homelab, rendered as a newspaper. Pulls data from Docker, Loki, Prometheus, and optional integrations, then uses a local LLM (via Ollama) to write AP wire-style articles about what happened.

## What it does

| Page | What it shows | Refresh |
|------|---------------|---------|
| **Front Page** | Full-day edition — Docker + Loki logs from midnight to now, LLM-generated articles | Hourly |
| **Current Events** | Rolling 6-hour window, same sources | Every 15 min |
| **Police Blotter** | All active Cloudflare-blocked IPs with geo/ASN/abuse intel, attack categories, probe paths | 60s live fetch |
| **Archive** | Daily snapshots going back as far as you've backfilled | — |
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
  archive.json        # daily editions (90-day rolling window)
  periodic.json       # weekly/monthly/yearly digests
  context.md          # optional homelab context fed to the LLM
  ip_intel.json       # geo/ASN/abuse cache (7-day TTL)
```

## Configuration

All configuration is via environment variables. Set them in your `docker-compose.yml` or `.env` file.

### Required

| Variable | Description |
|----------|-------------|
| `OLLAMA_URL` | Ollama API base URL (default: `http://ollama:11434`) |
| `OLLAMA_MODEL` | Model to use (default: `gemma4:e4b`) |
| `LOKI_URL` | Loki HTTP API base URL (default: `http://loki:3100`) |

### Docker / container health

| Variable | Description |
|----------|-------------|
| `REMOTE_DOCKER_HOSTS` | Comma-separated Docker host URLs to check for container health. Supports `tcp://host:2375` and `ssh://user@host`. Local Docker socket is always checked. |
| `SSH_KEY` | Path inside the container to the SSH private key used for `ssh://` remote hosts (default: `/root/.ssh/id_ed25519`) |

### Monitoring integrations (optional)

| Variable | Description | Default |
|----------|-------------|---------|
| `PROMETHEUS_URL` | Prometheus HTTP API base URL | `http://prometheus:9090` |
| `NODE_EXPORTER_INSTANCE` | Node exporter instance label for disk checks | `hostname:9100` |
| `BESZEL_URL` | Beszel PocketBase URL for host health data | `http://beszel:8090` |
| `BESZEL_EMAIL` | Beszel login email | — |
| `BESZEL_PASS` | Beszel login password | — |
| `KOPIA_URL` | Kopia WebUI URL for backup health | `https://kopia-webui:5151` |
| `KOPIA_USER` | Kopia server username | — |
| `KOPIA_PASS` | Kopia server password | — |
| `TAUTULLI_URL` | Tautulli base URL for Plex activity | `http://tautulli:8181` |
| `TAUTULLI_KEY` | Tautulli API key | — |

### Police blotter / IP intel (optional)

| Variable | Description |
|----------|-------------|
| `ABUSEIPDB_KEY` | [AbuseIPDB](https://www.abuseipdb.com/) API key — enables abuse confidence scores on the blotter. IPs are geo/ASN enriched via ip-api.com regardless. |

The blotter reads ban state from `cf-fail2ban`'s state file (`traefik/monitor/fail2ban-state.json`). If that file is absent it falls back to reconstructing bans from the Traefik access log.

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

# Backfill archive only (no trend digests)
docker exec -it lab-monitor python /app/backfill.py --start 2026-01-01

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

# Inject ABUSEIPDB_KEY without a container restart
docker exec lab-monitor sed -i 's/\[program:web\]/[program:web]\nenvironment=ABUSEIPDB_KEY="your-key-here"/' /app/supervisord.conf
docker exec lab-monitor supervisorctl update
docker exec lab-monitor supervisorctl restart web
```

## First-run setup

The `/data` directory must be owned by uid `1001` on the host before starting:

```bash
mkdir -p homelab-news/data
sudo chown -R 1001:1001 homelab-news/data
```

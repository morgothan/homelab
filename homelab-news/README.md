# Homelab News

A self-hosted operations digest that presents homelab activity as a newspaper. It gathers container state, logs, metrics, backup status, security events, media activity, and software updates, then uses an OpenAI-compatible local LLM endpoint to generate concise articles and trend reports.

The web server reads previously generated JSON files and does not depend on the LLM being available. If generation fails, the last successful edition remains visible and its timestamp is marked as potentially stale.

## Pages

| Page | What it shows | Default refresh |
|------|---------------|-----------------|
| **Front Page** | Current-day edition built from midnight to now | Generated hourly |
| **Current Events** | Rolling operational report and detailed source cards | Generated every 15 minutes |
| **Wire Reports** | Container-image and application update intelligence with LLM summaries | Generated hourly |
| **Police Blotter** | Active edge and CrowdSec decisions with optional geo, ASN, and abuse intelligence | Live API-backed view |
| **Arts & Entertainment** | One consolidated **New Library Additions** story from Seerr availability events, plus optional media-library scan results | Hourly snapshot |
| **Archive** | One snapshot per day, grouped by month | Daily |
| **Trends** | Hindsight-reflected operational intelligence plus weekly, monthly, and yearly reports | Reflected every 6 hours; reports scheduled |

Generated articles use newspaper-style sections such as **City Hall**, **Public Safety**, **Weather**, **City Archives**, **Arts & Entertainment**, and **Public Works**. The most important item can be promoted to a lead story.

## Architecture

A single container runs a FastAPI web server and background workers under Supervisor:

| Program | Role | Schedule |
|---------|------|----------|
| `web` | Serves HTML and JSON-backed views | Continuous |
| `today` | Builds the current-day front page | `UPDATE_INTERVAL` |
| `rolling` | Builds the rolling Current Events report | `REFRESH_INTERVAL` |
| `daily` | Copies the last successful edition into the archive | Daily at 00:01 local time |
| `updates` | Checks container images and supported applications and summarizes release information | `UPDATE_INTERVAL` |
| `periodic` | Builds weekly, monthly, and yearly reports and recovers missed schedules after downtime | Scheduled at 00:01 local time |
| `trends` | Reflects over Hindsight memories, verifies archive evidence, and caches trend intelligence | `TREND_REFRESH_INTERVAL` |

The news workers collect and persist raw observations before calling the LLM. During generation, the existing articles and successful-generation timestamp remain in place. A successful response replaces the edition; a failed response preserves it with `generation_status: stale`.

### Source organization

The application uses focused foundation modules beneath stable worker entry
points:

| Module | Responsibility |
|--------|----------------|
| `config.py` | Environment parsing, schedules, integration settings, and data paths |
| `storage.py` | UTF-8 JSON loading and atomic persistence |
| `articles.py` | Typed article contract and validation of untrusted LLM output |
| `runtime.py` | Failure-isolated, interval-aligned worker scheduling |
| `lib.py` | Compatibility facade for collectors, inference, security, and rendering |

The facade keeps existing imports and Supervisor commands compatible while
allowing cohesive areas to evolve independently. Development conventions and
the container-based validation workflow are documented in `DEVELOPMENT.md`.

## Requirements

- Docker Engine and Docker Compose
- An OpenAI-compatible local inference endpoint, such as vLLM
- Loki for aggregated logs
- Optional Prometheus metrics and the integrations described below
- A deliberately scoped way to inspect local and remote container state

The supplied image includes `skopeo` and an SSH client. The service expects its persistent data directory to be writable by user ID `1001`.

> **Security:** Access to the Docker API is equivalent to sensitive host access unless an authorization proxy restricts it. Prefer a least-privilege socket proxy or Docker over SSH. Do not publish an unauthenticated Docker API endpoint. Mount only a dedicated SSH key, not an entire personal SSH directory.

## Persistent data

The application stores state below `DATA_DIR`, which defaults to `/data`:

```text
data/
  today.json              # current-day edition and collection results
  rolling.json            # rolling edition and collection results
  updates.json            # image update state
  homelab_intel.json      # generated update intelligence
  periodic.json           # weekly, monthly, and yearly reports
  trend_intelligence.json # cached Hindsight reflection and deterministic window measurements
  context.md              # optional operator-supplied LLM context
  ip_intel.json           # cached IP intelligence
  media_events.json       # retained Seerr request and availability events
  recent_media.json       # hourly seven-day media list and resolved Jellyfin links
  archive/
    index.json            # lightweight archive index
    YYYY-MM-DD.json       # one archived edition per day
```

`archive.json` is a legacy format. The daily worker migrates it to per-day files at startup and renames the old file with a `.migrated` suffix.

## Configuration

All configuration is supplied through environment variables. Values containing credentials should come from a secret manager or Docker secrets and must not be committed.

### Runtime and LLM

| Variable | Description | Default |
|----------|-------------|---------|
| `SITE_NAME` | Publication name shown in the masthead | `Homelab News` |
| `DATA_DIR` | Persistent state directory | `/data` |
| `VLLM_URL` | Base URL of the OpenAI-compatible inference endpoint | Empty |
| `VLLM_MODEL` | Model identifier sent to the inference endpoint | Empty |
| `OLLAMA_TIMEOUT` | LLM request timeout in seconds; retained as a legacy variable name | `3600` |
| `REFRESH_INTERVAL` | Rolling-report interval in seconds | `900` |
| `UPDATE_INTERVAL` | Front-page and update-check interval in seconds | `3600` |
| `ROLLING_HOURS` | Lookback window for Current Events | `1` |
| `LOG_HOURS` | Labelled log window used by the UI | `1` |
| `HINDSIGHT_URL` | Optional Hindsight-compatible memory service | Empty |
| `HINDSIGHT_BANK` | Memory bank name | `homelab_news` |
| `HINDSIGHT_TIMEOUT` | Memory request timeout in seconds | `90` |
| `TREND_REFRESH_INTERVAL` | Hindsight trend-reflection interval in seconds | `21600` |

### Docker and update discovery

| Variable | Description | Default |
|----------|-------------|---------|
| `REMOTE_DOCKER_HOSTS` | Comma-separated remote targets. Each entry may use `label=url`; supported URL schemes include `ssh://`, `tcp://`, and `pct://` | Empty |
| `SSH_KEY` | Dedicated private key used for remote checks | `/root/.ssh/id_ed25519` |
| `DOCKER_AUTH_FILE` | Registry authentication file used by `skopeo` | `/root/.docker/config.json` |
| `SKOPEO_TIMEOUT` | Remote image-inspection timeout in seconds | `20` |
| `GITHUB_TOKEN` | Optional token that raises the release-information API rate limit | Empty |

Example using role-based, non-production names:

```yaml
environment:
  REMOTE_DOCKER_HOSTS: >-
    compute=ssh://monitor@compute.example.invalid,
    media=ssh://monitor@media.example.invalid
  SSH_KEY: /run/secrets/monitoring_ssh_key
```

### Logs, metrics, and backups

| Variable | Description | Default |
|----------|-------------|---------|
| `LOKI_URL` | Loki HTTP API base URL | `http://loki:3100` |
| `PROMETHEUS_URL` | Prometheus HTTP API base URL | `http://prometheus:9090` |
| `NODE_EXPORTER_INSTANCE` | Prometheus instance label used for host metrics | Empty |
| `KOPIA_URL` | Kopia server URL | `https://kopia-webui:5151` |
| `KOPIA_USER` | Kopia server username | `admin` |
| `KOPIA_PASS` | Kopia server password | Empty |
| `TRAEFIK_ACCESS_LOG` | Reverse-proxy access-log path | `/traefik/access.log` |
| `LIBRARY_SCAN_FILE` | Optional media-library scan result | `/traefik/monitor/library-dupe-scan.json` |

### Host and application checks

| Variable | Description |
|----------|-------------|
| `PVE_SSH_HOST` | SSH target used for virtualization-host update checks |
| `TRUENAS_SSH_HOST` | SSH target used for storage-host update checks |
| `BESZEL_SSH_HOST` | SSH target used for monitoring-host version checks |
| `SPARK_SSH_HOST` | SSH target used for compute-host version checks |
| `HERMES_SSH_HOST` | SSH target used for agent-host version checks |
| `ADGUARD_PRIMARY_URL` | Primary DNS service URL |
| `ADGUARD_KIDS_URL` | Optional secondary DNS service URL |
| `HOMEASSISTANT_URL` | Home Assistant API URL |
| `HOMEASSISTANT_TOKEN` | Home Assistant long-lived access token |
| `BESZEL_URL` | Beszel API URL |
| `BESZEL_EMAIL` | Beszel login identity |
| `BESZEL_PASS` | Beszel login password |
| `JELLYFIN_URL` | Jellyfin API URL |
| `JELLYFIN_KEY` | Jellyfin API key |
| `JELLYFIN_WEB_URL` | Public Jellyfin base URL used for media detail links |
| `RADARR_URL` | Radarr API URL used for net-new movie imports |
| `RADARR_API_KEY` | Radarr API key |
| `SONARR_URL` | Sonarr API URL used for net-new episode imports |
| `SONARR_API_KEY` | Sonarr API key |
| `SEERR_SETTINGS_FILE` | Optional read-only Seerr settings fallback for Arr connection details |
| `JELLYSTAT_URL` | Jellystat API URL |
| `JELLYSTAT_KEY` | Jellystat API key |

Unset optional integrations are skipped or reported as unconfigured.

### Security intelligence and media events

| Variable | Description | Default |
|----------|-------------|---------|
| `CF_FAIL2BAN_STATE` | Edge-ban state file | `/traefik/monitor/fail2ban-state.json` |
| `ABUSEIPDB_KEY` | Optional AbuseIPDB API key | Empty |
| `CROWDSEC_KEY` | Optional CrowdSec CTI API key | Empty |
| `CROWDSEC_LAPI_URL` | CrowdSec local API URL | `http://crowdsec:8080` |
| `CROWDSEC_LAPI_KEY` | CrowdSec local API key | Empty |
Recent library additions come from Radarr and Sonarr import history. Imports
paired with an upgrade deletion are excluded, and repeated imports are
deduplicated by movie or episode. Jellyfin is used as a fallback. Seerr events can
also be delivered directly to the newspaper at
`http://lab-monitor:8080/api/events/seerr`. Enable Seerr's Webhook notification
agent for request and availability event types. Events are retained in
`/data/media_events.json` and remain visible in the daily and rolling editions for
seven days as a fallback when Jellyfin is unavailable, independently of those
editions' shorter operational-log windows. Recent movies and episodes are grouped into one
deterministic **New Library Additions** story in Arts & Entertainment; the card
appears first in that section and lists all newly available items instead of
generating a separate story per item. The dedicated `/entertainment` page also
shows the same seven-day list above its media-library scan report.

Public IPs are enriched through a third-party geolocation API and cached for seven days. Consider the privacy and availability implications before enabling this feature.

### Trend retention

| Variable | Description | Default |
|----------|-------------|---------|
| `MAX_WEEKLY` | Maximum retained weekly reports | `16` |
| `MAX_MONTHLY` | Maximum retained monthly reports | `24` |

Yearly reports are retained without a configured cap.

## Homelab context

An optional `context.md` helps the LLM understand normal behavior, service roles, and which events deserve attention. Treat this file as private operational data: it is read at runtime and should not be committed to a public repository.

Sanitized example:

```markdown
The reverse proxy and identity provider are critical services.
The media stack runs on a separate host and brief maintenance restarts are normal.
Backups run nightly; any snapshot older than two days should be highlighted.
Routine internet scanner traffic should not be promoted unless it bypasses controls.
```

Do not include real domain names, internal hostnames, network addresses, account names, tokens, device identifiers, or unique topology details in public examples.

## Prompt and output handling

Log messages, release notes, and other untrusted text pass through `_sanitize_for_llm()` before being embedded in prompts. The sanitizer removes common prompt-injection phrases and applies length limits. Generated articles pass through `_validate_articles()`, which enforces field types, length limits, and a section allowlist before data is stored or rendered.

These controls reduce risk but do not make untrusted LLM input harmless. Keep the LLM endpoint and this application isolated from unnecessary management credentials.

## First run

Create the persistent directory and make it writable by the container application user:

```bash
mkdir -p homelab-news/data
sudo chown -R 1001:1001 homelab-news/data
```

Then build and start the service with your Compose configuration:

```bash
./dc.sh up -d --build lab-monitor
```

## Operations

```bash
# Worker state
docker exec lab-monitor supervisorctl status

# Restart one worker
docker exec lab-monitor supervisorctl restart today
docker exec lab-monitor supervisorctl restart rolling
docker exec lab-monitor supervisorctl restart updates

# Follow service logs
./dc.sh logs -f lab-monitor

# Health endpoint
docker exec lab-monitor python -c \
  'import urllib.request; print(urllib.request.urlopen("http://localhost:8080/health").read().decode())'
```

## Historical backfill

`backfill.py` queries historical Loki data and can generate daily, weekly, and monthly reports. Historical daily records contain Loki-derived data only; container health, current bans, and live metrics cannot be reconstructed.

```bash
# Preview the requested range without LLM calls or writes
docker exec -it lab-monitor python /app/backfill.py \
  --start YYYY-MM-DD --end YYYY-MM-DD --dry-run

# Generate daily reports for a range
docker exec -it lab-monitor python /app/backfill.py \
  --start YYYY-MM-DD --end YYYY-MM-DD

# Build weekly and monthly trends from the legacy archive
docker exec -it lab-monitor python /app/backfill.py --trends-only
```

The current backfill utility writes the legacy `archive.json` format. Restart the daily worker after a successful backfill so it migrates those entries into `archive/` and rebuilds the web index:

```bash
docker exec lab-monitor supervisorctl restart daily
```

Backfill skips dates already present in the legacy file and is safe to resume. Preserve a backup of `DATA_DIR` before a large backfill or migration.

## Public-repository checklist

Before committing documentation or configuration:

- Replace real domains and hostnames with names below `example.invalid`.
- Do not include network addresses, MAC addresses, tunnel IDs, account IDs, email addresses, usernames, or device serial numbers.
- Do not commit `context.md`, generated JSON state, logs, registry authentication, SSH material, database exports, or environment files.
- Use placeholders for all tokens and credentials; a redacted value should never resemble the real value.
- Scan the staged diff and Git history with a secret scanner.

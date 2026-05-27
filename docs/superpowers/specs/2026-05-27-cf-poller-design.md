# Cloudflare Analytics Poller — Design Spec

**Date:** 2026-05-27  
**Status:** Approved

---

## Overview

A new standalone container (`cf-poller`) that polls the Cloudflare GraphQL Analytics API every 5 minutes and feeds two sinks:

- **Prometheus** — aggregated request metrics (traffic, bandwidth, cache, HTTP status codes)
- **Loki** — individual firewall/WAF events as structured log entries

This surfaces data that does not exist anywhere in the current stack. The existing cloudflared dashboard (`V1SL92dVn`) covers tunnel daemon health metrics only; `cf-poller` adds zone-level visibility: who is hitting the site, from where, and what Cloudflare is blocking before requests ever reach Traefik.

---

## Cloudflare Plan Constraints

**Plan: Free**

| Dataset | Retention | Notes |
|---------|-----------|-------|
| `firewallEventsAdaptive` | 24 hours | Per-event detail; polled every 5 min to ensure no gaps |
| `httpRequestsAdaptiveGroups` | 7 days | Aggregated; used for Prometheus gauges |

Logpush, Logpull, and Grafana Alloy's `loki.source.cloudflare` are all Enterprise-only and are not used here.

---

## Credentials Required

Two new secrets in OpenBao at `kv/docker/cloudflare`:

| Variable | Description |
|----------|-------------|
| `CF_ANALYTICS_TOKEN` | New API token — `Zone:Analytics:Read` only, scoped to the homelab zone |
| `CF_ZONE_ID` | Zone ID — found on the domain's Overview page in the Cloudflare dashboard |

The token uses the narrowest possible permission scope (read-only analytics, single zone).

---

## Container Structure

```
cf-poller/
  app.py              # FastAPI app, background polling tasks, Prometheus metrics
  push_dashboard.py   # Creates Grafana dashboard on container startup
  requirements.txt
  Dockerfile
  data/               # Host-mounted volume
    state.json        # Cursor timestamps — survives restarts
```

Single Python process. No supervisord. FastAPI serves `/metrics` for Prometheus scraping. Two asyncio background tasks handle polling. `push_dashboard.py` is called once at startup via `app.py`'s startup event.

---

## Data Flow

### Task 1 — Firewall Events (every 5 min)

1. Read `last_firewall_ts` from `state.json` (default: now − 24h on first run)
2. Query `firewallEventsAdaptive` for events since that timestamp
3. For each event:
   - Push to Loki as a JSON log line (labels: `job="cloudflare"`, `type="firewall"`)
   - Increment `cf_firewall_events_total{action, source, country}`
4. Advance `last_firewall_ts` to the timestamp of the newest event seen
5. On Loki push failure: log error, do NOT advance cursor (retry next cycle)

**Loki log line fields:** `datetime`, `action`, `source`, `clientIP`, `clientCountryName`, `clientAsn`, `clientRequestPath`, `clientRequestQuery`, `userAgent`, `ruleId`

### Task 2 — Request Analytics (every 5 min)

1. Query `httpRequestsAdaptiveGroups` for the last 5-minute window
2. Update Prometheus gauges:

| Metric | Labels | Source field |
|--------|--------|--------------|
| `cf_requests_per_minute` | `country` (top 10 + "other") | `sum` |
| `cf_bandwidth_bytes_per_minute` | `country` | `sumEdgeResponseBytes` |
| `cf_cache_requests_total` | `cache_status` | `sum` grouped by `cacheStatus` |
| `cf_http_status_total` | `status` (2xx/3xx/4xx/5xx buckets) | `sum` grouped by `edgeResponseStatus` |
| `cf_unique_visitors` | — | `uniq(clientIP)` |

Gauges are not persisted across restarts (they are rates, not cumulative totals — a gap during restart is acceptable).

---

## Prometheus Metrics

```
# Firewall event counters (cumulative since container start)
cf_firewall_events_total{action="block", source="waf", country="RU"}
cf_firewall_events_total{action="managed_challenge", source="rateLimit", country="CN"}

# Request rate gauges (last 5-min window)
cf_requests_per_minute{country="US"}
cf_bandwidth_bytes_per_minute{country="US"}
cf_cache_requests_total{cache_status="hit"}
cf_http_status_total{status="2xx"}
cf_unique_visitors

# Poller health
cf_poller_last_success_timestamp_seconds{task="firewall"}
cf_poller_last_success_timestamp_seconds{task="requests"}
cf_poller_errors_total{task="firewall"}
cf_poller_errors_total{task="requests"}
```

---

## Grafana Dashboard

**UID:** `cloudflare-analytics`  
**Title:** Cloudflare Zone Analytics  
**Created by:** `push_dashboard.py` on container startup (same pattern as `rainsoft/push_dashboard.py`)

| Row | Panels |
|-----|--------|
| **Overview** | Total requests/min · Bandwidth/min · Unique visitors (1h) · Firewall events/min · Cache hit % |
| **Traffic Geography** | Geomap: requests by country · Bar chart: top 10 countries |
| **Security** | Time series: events by action (block/challenge/etc.) · Time series: events by source (waf/rateLimit/etc.) · Table: recent firewall events from Loki (time, IP, country, action, source, path) |
| **Cache & HTTP** | Bar/pie: cache status breakdown · Time series: HTTP status codes over time |
| **Bandwidth** | Time series: total bandwidth · Bar chart: bandwidth by top 5 countries |

The Loki table in the Security row uses LogQL: `{job="cloudflare", type="firewall"} | json` — filterable by country, action, or source from the dashboard.

---

## Error Handling

| Scenario | Behaviour |
|----------|-----------|
| Loki unreachable | Log error to stdout; do NOT advance cursor; retry next poll cycle |
| GraphQL API error (bad token, rate limit, 5xx) | Log error; skip cycle; keep container running |
| Missing `CF_ANALYTICS_TOKEN` or `CF_ZONE_ID` | Container exits at startup with a clear error message |
| First run (no `state.json`) | Backfill last 24 hours of firewall events |
| Container restart | Resume from `state.json` cursor; no duplicate events sent to Loki |

---

## Docker Compose Integration

New service in `docker-compose.yml`:

```yaml
cf-poller:
  build: ./cf-poller
  pull_policy: never
  container_name: cf-poller
  image: cf-poller:latest
  restart: unless-stopped
  volumes:
    - ${DOCKERDIR}/cf-poller/data:/data
  networks:
    - ${DOCKERNET}
  environment:
    - TZ=America/New_York
    - CF_ANALYTICS_TOKEN=${CF_ANALYTICS_TOKEN}
    - CF_ZONE_ID=${CF_ZONE_ID}
    - LOKI_URL=${LOKI_URL}
    - GRAFANA_URL=http://grafana:3000
    - GF_SECURITY_ADMIN_USER=${GF_SECURITY_ADMIN_USER}
    - GF_SECURITY_ADMIN_PASSWORD=${GF_SECURITY_ADMIN_PASSWORD}
  labels:
    - traefik.enable=false
```

New Prometheus scrape target added to `prometheus/etc/prometheus.yml`:

```yaml
- job_name: 'cf-poller'
  static_configs:
    - targets: ['cf-poller:8000']
```

---

## Dependencies

- Python 3.13-slim (same base image as other containers)
- `fastapi`, `uvicorn`, `httpx`, `prometheus-client`, `tzdata`
- Loki endpoint: `http://logger.hirschnet:3100` (existing, via `${LOKI_URL}`)
- Grafana: `http://grafana:3000` (existing, for dashboard push)
- No new infrastructure required

---

## Out of Scope

- Cloudflare Logpush / Logpull (Enterprise-only)
- Zero Trust / Access request logs (Enterprise ZT plan only)
- Raw per-request HTTP access logs (Enterprise-only)
- Automatic IP blocking from firewall event data (already handled by `cf-fail2ban` from Traefik layer)

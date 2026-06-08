"""Cloudflare GraphQL Analytics poller.

Polls firewallEventsAdaptive (→ Loki) and httpRequestsAdaptiveGroups
(→ Prometheus gauges) every POLL_INTERVAL seconds, across all zones
discovered automatically from the Cloudflare API.
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
log = logging.getLogger("cf-poller")

# ── Config ─────────────────────────────────────────────────────────────────────

def _require(var: str) -> str:
    val = os.getenv(var)
    if not val:
        log.error("Required environment variable %s is not set", var)
        sys.exit(1)
    return val

CF_ANALYTICS_TOKEN = _require("CF_ANALYTICS_TOKEN")
LOKI_URL           = os.getenv("LOKI_URL", "http://logger.hirschnet:3100")
GRAFANA_URL        = os.getenv("GRAFANA_URL", "http://grafana:3000")
GRAFANA_USER       = os.getenv("GF_SECURITY_ADMIN_USER", "admin")
GRAFANA_PASS       = os.getenv("GF_SECURITY_ADMIN_PASSWORD", "")
DATA_DIR           = Path(os.getenv("DATA_DIR", "/data"))
POLL_INTERVAL      = int(os.getenv("POLL_INTERVAL", "300"))
CF_GRAPHQL_URL     = "https://api.cloudflare.com/client/v4/graphql"
CF_REST_URL        = "https://api.cloudflare.com/client/v4"
TOP_N_COUNTRIES    = 10

# ── Zone discovery ─────────────────────────────────────────────────────────────

async def discover_zones() -> dict[str, str]:
    """Return {zone_id: zone_name} for every active zone the token can reach.

    Paginates through /v4/zones until all results are collected.
    Exits the process if the token lacks permission or no zones are returned.
    """
    zones: dict[str, str] = {}
    page = 1
    async with httpx.AsyncClient() as client:
        while True:
            resp = await client.get(
                f"{CF_REST_URL}/zones",
                headers={"Authorization": f"Bearer {CF_ANALYTICS_TOKEN}"},
                params={"page": page, "per_page": 50, "status": "active"},
                timeout=10,
            )
            if resp.status_code == 403:
                log.error(
                    "Token lacks permission to list zones. "
                    "Add Zone:Read to the API token in the Cloudflare dashboard."
                )
                sys.exit(1)
            resp.raise_for_status()
            body = resp.json()
            for z in body.get("result", []):
                zones[z["id"]] = z["name"]
            info = body.get("result_info", {})
            if info.get("page", 1) * info.get("per_page", 50) >= info.get("total_count", 0):
                break
            page += 1

    if not zones:
        log.error("No active zones found for this token. Check token scope.")
        sys.exit(1)

    log.info("Discovered %d zone(s): %s", len(zones), ", ".join(sorted(zones.values())))
    return zones

# ── State ──────────────────────────────────────────────────────────────────────

_DEFAULT_STATE_FILE = DATA_DIR / "state.json"


def load_state(path: Path = _DEFAULT_STATE_FILE) -> dict:
    """Load polling cursors from disk. Returns empty dict if missing or corrupt."""
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


_state_lock = asyncio.Lock()


def save_state(state: dict, path: Path = _DEFAULT_STATE_FILE) -> None:
    """Persist polling cursors to disk atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    tmp.replace(path)


async def save_state_key(key: str, value: str, path: Path = _DEFAULT_STATE_FILE) -> None:
    """Update a single cursor key, merging with whatever other zones already saved."""
    async with _state_lock:
        current = load_state(path)
        current[key] = value
        save_state(current, path)

# ── Firewall event parsing ─────────────────────────────────────────────────────

def parse_firewall_events(data: dict) -> list[dict]:
    """Extract event list from a firewallEventsAdaptive GraphQL response."""
    try:
        result = data["data"]["viewer"]["zones"][0]["firewallEventsAdaptive"]
        return list(result) if isinstance(result, list) else []
    except (KeyError, IndexError, TypeError):
        return []


def build_loki_payload(events: list[dict], zone_name: str) -> dict:
    """Convert firewall events to Loki /loki/api/v1/push format.

    Caller must ensure events is non-empty; Loki rejects empty values arrays.
    """
    values = []
    for ev in events:
        try:
            dt = datetime.fromisoformat(ev.get("datetime", "").replace("Z", "+00:00"))
            ns = str(int(dt.timestamp() * 1_000_000_000))
        except (ValueError, AttributeError):
            ns = str(int(datetime.now(timezone.utc).timestamp() * 1_000_000_000))
        values.append([ns, json.dumps(ev)])
    return {
        "streams": [
            {
                "stream": {"job": "cloudflare", "type": "firewall", "zone": zone_name},
                "values": values,
            }
        ]
    }

# ── Analytics parsers ──────────────────────────────────────────────────────────

# How many minutes the analytics query window covers. Used to convert
# window counts to per-minute rates stored in gauges.
_WINDOW_MINUTES = 6.0

# ── Prometheus metrics ─────────────────────────────────────────────────────────

fw_events_total = Counter(
    "cf_firewall_events_total",
    "Cloudflare firewall events since container start",
    ["action", "source", "country", "zone"],
)
requests_gauge = Gauge(
    "cf_requests_per_minute",
    "Cloudflare total requests per minute (last poll window)",
    ["zone"],
)
requests_by_country = Gauge(
    "cf_requests_by_country",
    "Cloudflare requests per minute by country (last poll window)",
    ["country", "zone"],
)
bandwidth_by_country = Gauge(
    "cf_bandwidth_bytes_by_country",
    "Cloudflare bandwidth bytes per minute by country (last poll window)",
    ["country", "zone"],
)
cache_gauge = Gauge(
    "cf_cache_requests",
    "Cloudflare requests per minute by cache status (last poll window)",
    ["cache_status", "zone"],
)
http_status_gauge = Gauge(
    "cf_http_status",
    "Cloudflare requests per minute by HTTP status bucket (last poll window)",
    ["status", "zone"],
)
last_success_gauge = Gauge(
    "cf_poller_last_success_timestamp_seconds",
    "Unix timestamp of last successful poll",
    ["task", "zone"],
)
errors_counter = Counter(
    "cf_poller_errors_total",
    "Total polling errors by task",
    ["task", "zone"],
)


def bucket_status_code(status: int) -> str:
    """Map an HTTP status integer to a 2xx/3xx/4xx/5xx/other bucket string."""
    if 200 <= status < 300:
        return "2xx"
    if 300 <= status < 400:
        return "3xx"
    if 400 <= status < 500:
        return "4xx"
    if 500 <= status < 600:
        return "5xx"
    return "other"


def _groups(data: dict) -> list:
    try:
        return data["data"]["viewer"]["zones"][0]["httpRequestsAdaptiveGroups"]
    except (KeyError, IndexError, TypeError):
        return []


def parse_country_analytics(
    data: dict,
) -> tuple[dict[str, float], dict[str, float], float]:
    """
    Returns (requests_per_min, bytes_per_min, unique_visitors_per_min).
    Countries ranked beyond TOP_N_COUNTRIES are merged into 'other'.
    All values are divided by _WINDOW_MINUTES to produce per-minute rates.
    """
    rows = _groups(data)
    req_by_country: dict[str, float] = {}
    bytes_by_country: dict[str, float] = {}
    unique_visitors: float = 0.0

    for i, row in enumerate(rows):
        country = (row.get("dimensions") or {}).get("clientCountryName") or "unknown"
        count = row.get("count", 0) / _WINDOW_MINUTES
        edge_bytes = ((row.get("sum") or {}).get("edgeResponseBytes", 0)) / _WINDOW_MINUTES

        if i < TOP_N_COUNTRIES:
            req_by_country[country] = count
            bytes_by_country[country] = edge_bytes
        else:
            req_by_country["other"] = req_by_country.get("other", 0.0) + count
            bytes_by_country["other"] = bytes_by_country.get("other", 0.0) + edge_bytes

        if i == 0:
            unique_visitors = ((row.get("uniq") or {}).get("uniques", 0)) / _WINDOW_MINUTES

    return req_by_country, bytes_by_country, unique_visitors


def parse_cache_analytics(data: dict) -> dict[str, float]:
    """Returns requests_per_min keyed by cache_status string."""
    return {
        ((row.get("dimensions") or {}).get("cacheStatus") or "unknown"): (
            row.get("count", 0) / _WINDOW_MINUTES
        )
        for row in _groups(data)
    }


def parse_status_analytics(data: dict) -> dict[str, float]:
    """Returns requests_per_min keyed by 2xx/3xx/4xx/5xx/other bucket."""
    buckets: dict[str, float] = {}
    for row in _groups(data):
        raw = (row.get("dimensions") or {}).get("edgeResponseStatus", 0)
        bucket = bucket_status_code(int(raw) if raw else 0)
        buckets[bucket] = buckets.get(bucket, 0.0) + row.get("count", 0) / _WINDOW_MINUTES
    return buckets

# ── GraphQL client ─────────────────────────────────────────────────────────────

_FIREWALL_QUERY = """
query FirewallEvents($zoneTag: String!, $after: Time!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      firewallEventsAdaptive(
        filter: {datetime_gt: $after}
        limit: 10000
        orderBy: [datetime_ASC]
      ) {
        action
        clientAsn
        clientCountryName
        clientIP
        clientRequestPath
        clientRequestQuery
        datetime
        source
        userAgent
        ruleId
      }
    }
  }
}
"""


async def _graphql(client: httpx.AsyncClient, query: str, variables: dict) -> dict:
    resp = await client.post(
        CF_GRAPHQL_URL,
        json={"query": query, "variables": variables},
        headers={"Authorization": f"Bearer {CF_ANALYTICS_TOKEN}"},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    if errors := data.get("errors"):
        raise ValueError(f"GraphQL errors: {errors}")
    return data


# ── Loki push ──────────────────────────────────────────────────────────────────

async def _push_loki(client: httpx.AsyncClient, payload: dict) -> None:
    resp = await client.post(
        f"{LOKI_URL}/loki/api/v1/push",
        json=payload,
        timeout=10,
    )
    resp.raise_for_status()


# ── Firewall event poller ──────────────────────────────────────────────────────

async def poll_firewall_events(state: dict, zone_id: str, zone_name: str) -> dict:
    """Fetch new firewall events for one zone, push to Loki, increment counters."""
    state_key = f"last_firewall_ts_{zone_id}"
    now = datetime.now(timezone.utc)
    default_after = (now - timedelta(hours=23, minutes=50)).strftime("%Y-%m-%dT%H:%M:%SZ")
    after = state.get(state_key, default_after)

    # CF rejects queries spanning > 1 day. If the cursor is stale, clamp it forward
    # and accept losing the gap (CF wouldn't return those events anyway).
    max_age = now - timedelta(hours=23, minutes=50)
    try:
        after_dt = datetime.fromisoformat(after.replace("Z", "+00:00"))
    except ValueError:
        after_dt = max_age
    if after_dt < max_age:
        log.warning(
            "[%s] Cursor too old (%s) — clamping to avoid CF 1d limit; events in gap are lost",
            zone_name, after,
        )
        after = max_age.strftime("%Y-%m-%dT%H:%M:%SZ")
        state = {**state, state_key: after}

    async with httpx.AsyncClient() as client:
        data = await _graphql(
            client, _FIREWALL_QUERY, {"zoneTag": zone_id, "after": after}
        )
        events = parse_firewall_events(data)

        if events:
            payload = build_loki_payload(events, zone_name)
            try:
                await _push_loki(client, payload)
            except Exception as e:
                # Do NOT advance cursor — retry on next cycle
                log.error("[%s] Loki push failed (%d events not sent): %s", zone_name, len(events), e)
                return state

            for ev in events:
                fw_events_total.labels(
                    action=ev.get("action", "unknown"),
                    source=ev.get("source", "unknown"),
                    country=ev.get("clientCountryName", "unknown"),
                    zone=zone_name,
                ).inc()

            state = {**state, state_key: events[-1]["datetime"]}
            log.info("[%s] Pushed %d firewall events to Loki", zone_name, len(events))
        else:
            # Advance cursor to now so inactive zones don't re-query the same window
            # and don't trigger the "cursor too old" warning every poll cycle.
            state = {**state, state_key: now.strftime("%Y-%m-%dT%H:%M:%SZ")}
            log.debug("[%s] No new firewall events since %s", zone_name, after)

    last_success_gauge.labels(task="firewall", zone=zone_name).set(
        datetime.now(timezone.utc).timestamp()
    )
    return state


# ── Request analytics poller ───────────────────────────────────────────────────

_COUNTRY_QUERY = """
query RequestsByCountry($zoneTag: String!, $start: Time!, $end: Time!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      httpRequestsAdaptiveGroups(
        filter: {datetime_geq: $start, datetime_leq: $end}
        limit: 30
        orderBy: [count_DESC]
      ) {
        count
        sum { edgeResponseBytes }
        dimensions { clientCountryName }
      }
    }
  }
}
"""

_CACHE_QUERY = """
query RequestsByCache($zoneTag: String!, $start: Time!, $end: Time!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      httpRequestsAdaptiveGroups(
        filter: {datetime_geq: $start, datetime_leq: $end}
        limit: 10
        orderBy: [count_DESC]
      ) {
        count
        dimensions { cacheStatus }
      }
    }
  }
}
"""

_STATUS_QUERY = """
query RequestsByStatus($zoneTag: String!, $start: Time!, $end: Time!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      httpRequestsAdaptiveGroups(
        filter: {datetime_geq: $start, datetime_leq: $end}
        limit: 10
        orderBy: [count_DESC]
      ) {
        count
        dimensions { edgeResponseStatus }
      }
    }
  }
}
"""


async def poll_request_analytics(state: dict, zone_id: str, zone_name: str) -> dict:
    """Fetch request analytics for one zone, update Prometheus gauges."""
    now = datetime.now(timezone.utc)
    end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    start = (now - timedelta(minutes=int(_WINDOW_MINUTES))).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    variables = {"zoneTag": zone_id, "start": start, "end": end}

    async with httpx.AsyncClient() as client:
        country_data, cache_data, status_data = await asyncio.gather(
            _graphql(client, _COUNTRY_QUERY, variables),
            _graphql(client, _CACHE_QUERY, variables),
            _graphql(client, _STATUS_QUERY, variables),
        )

    req_by_c, bw_by_c, _ = parse_country_analytics(country_data)
    requests_gauge.labels(zone=zone_name).set(sum(req_by_c.values()))
    for country, rate in req_by_c.items():
        requests_by_country.labels(country=country, zone=zone_name).set(rate)
    for country, rate in bw_by_c.items():
        bandwidth_by_country.labels(country=country, zone=zone_name).set(rate)

    for cs, rate in parse_cache_analytics(cache_data).items():
        cache_gauge.labels(cache_status=cs, zone=zone_name).set(rate)

    for bucket, rate in parse_status_analytics(status_data).items():
        http_status_gauge.labels(status=bucket, zone=zone_name).set(rate)

    last_success_gauge.labels(task="requests", zone=zone_name).set(now.timestamp())
    log.info("[%s] Updated request analytics gauges (window: %s → %s)", zone_name, start, end)
    return state


# ── Background loops ───────────────────────────────────────────────────────────

async def _firewall_loop(zone_id: str, zone_name: str) -> None:
    state_key = f"last_firewall_ts_{zone_id}"
    cursor = load_state().get(state_key)
    while True:
        try:
            # Pass a minimal dict so poll_firewall_events can read its key
            state_in = {state_key: cursor} if cursor else {}
            state_out = await poll_firewall_events(state_in, zone_id, zone_name)
            new_cursor = state_out.get(state_key)
            if new_cursor and new_cursor != cursor:
                await save_state_key(state_key, new_cursor)
                cursor = new_cursor
        except Exception as e:
            log.error("[%s] Firewall poll error: %s: %s", zone_name, type(e).__name__, e)
            errors_counter.labels(task="firewall", zone=zone_name).inc()
        await asyncio.sleep(POLL_INTERVAL)


async def _analytics_loop(zone_id: str, zone_name: str) -> None:
    while True:
        try:
            await poll_request_analytics({}, zone_id, zone_name)
        except Exception as e:
            log.error("[%s] Analytics poll error: %s: %s", zone_name, type(e).__name__, e)
            errors_counter.labels(task="requests", zone=zone_name).inc()
        await asyncio.sleep(POLL_INTERVAL)


# ── FastAPI app ────────────────────────────────────────────────────────────────

app = FastAPI()


@app.on_event("startup")
async def startup() -> None:
    try:
        import push_dashboard  # noqa: F401 — runs on import
    except Exception as e:
        log.error("Grafana dashboard push failed (non-fatal): %s", e)

    zones = await discover_zones()
    for zone_id, zone_name in zones.items():
        asyncio.create_task(_firewall_loop(zone_id, zone_name))
        asyncio.create_task(_analytics_loop(zone_id, zone_name))


@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/health")
async def health():
    return {"status": "ok"}

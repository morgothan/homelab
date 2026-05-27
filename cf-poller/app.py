"""Cloudflare GraphQL Analytics poller.

Polls firewallEventsAdaptive (→ Loki) and httpRequestsAdaptiveGroups
(→ Prometheus gauges) every POLL_INTERVAL seconds.
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
CF_ZONE_ID         = _require("CF_ZONE_ID")
LOKI_URL           = os.getenv("LOKI_URL", "http://logger.hirschnet:3100")
GRAFANA_URL        = os.getenv("GRAFANA_URL", "http://grafana:3000")
GRAFANA_USER       = os.getenv("GF_SECURITY_ADMIN_USER", "admin")
GRAFANA_PASS       = os.getenv("GF_SECURITY_ADMIN_PASSWORD", "")
DATA_DIR           = Path(os.getenv("DATA_DIR", "/data"))
POLL_INTERVAL      = int(os.getenv("POLL_INTERVAL", "300"))
CF_GRAPHQL_URL     = "https://api.cloudflare.com/client/v4/graphql"
TOP_N_COUNTRIES    = 10

# ── State ──────────────────────────────────────────────────────────────────────

_DEFAULT_STATE_FILE = DATA_DIR / "state.json"


def load_state(path: Path = _DEFAULT_STATE_FILE) -> dict:
    """Load polling cursors from disk. Returns empty dict if missing or corrupt."""
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(state: dict, path: Path = _DEFAULT_STATE_FILE) -> None:
    """Persist polling cursors to disk atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    tmp.replace(path)

# ── Firewall event parsing ─────────────────────────────────────────────────────

def parse_firewall_events(data: dict) -> list[dict]:
    """Extract event list from a firewallEventsAdaptive GraphQL response."""
    try:
        result = data["data"]["viewer"]["zones"][0]["firewallEventsAdaptive"]
        return list(result) if isinstance(result, list) else []
    except (KeyError, IndexError, TypeError):
        return []


def build_loki_payload(events: list[dict]) -> dict:
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
                "stream": {"job": "cloudflare", "type": "firewall"},
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
    ["action", "source", "country"],
)
requests_gauge = Gauge(
    "cf_requests_per_minute",
    "Cloudflare total requests per minute (last poll window)",
)
requests_by_country = Gauge(
    "cf_requests_by_country",
    "Cloudflare requests per minute by country (last poll window)",
    ["country"],
)
bandwidth_by_country = Gauge(
    "cf_bandwidth_bytes_by_country",
    "Cloudflare bandwidth bytes per minute by country (last poll window)",
    ["country"],
)
cache_gauge = Gauge(
    "cf_cache_requests",
    "Cloudflare requests per minute by cache status (last poll window)",
    ["cache_status"],
)
http_status_gauge = Gauge(
    "cf_http_status",
    "Cloudflare requests per minute by HTTP status bucket (last poll window)",
    ["status"],
)
unique_visitors_gauge = Gauge(
    "cf_unique_visitors",
    "Unique visitor IPs per minute (last poll window)",
)
last_success_gauge = Gauge(
    "cf_poller_last_success_timestamp_seconds",
    "Unix timestamp of last successful poll",
    ["task"],
)
errors_counter = Counter(
    "cf_poller_errors_total",
    "Total polling errors by task",
    ["task"],
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

async def poll_firewall_events(state: dict) -> dict:
    """Fetch new firewall events, push to Loki, increment Prometheus counters."""
    default_after = (
        datetime.now(timezone.utc) - timedelta(hours=24)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    after = state.get("last_firewall_ts", default_after)

    async with httpx.AsyncClient() as client:
        data = await _graphql(
            client, _FIREWALL_QUERY, {"zoneTag": CF_ZONE_ID, "after": after}
        )
        events = parse_firewall_events(data)

        if events:
            payload = build_loki_payload(events)
            try:
                await _push_loki(client, payload)
            except Exception as e:
                # Do NOT advance cursor — retry on next cycle
                log.error("Loki push failed (%d events not sent): %s", len(events), e)
                return state

            for ev in events:
                fw_events_total.labels(
                    action=ev.get("action", "unknown"),
                    source=ev.get("source", "unknown"),
                    country=ev.get("clientCountryName", "unknown"),
                ).inc()

            # Advance cursor only after successful Loki push
            state = {**state, "last_firewall_ts": events[-1]["datetime"]}
            log.info("Pushed %d firewall events to Loki", len(events))
        else:
            log.debug("No new firewall events since %s", after)

    last_success_gauge.labels(task="firewall").set(
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
        uniq { uniques }
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

_AGGREGATE_QUERY = """
query AggregateStats($zoneTag: String!, $start: Time!, $end: Time!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      httpRequestsAdaptiveGroups(
        filter: {datetime_geq: $start, datetime_leq: $end}
        limit: 1
      ) {
        count
        uniq { uniques }
      }
    }
  }
}
"""


async def poll_request_analytics(state: dict) -> dict:
    """Fetch request analytics, update all Prometheus gauges."""
    now = datetime.now(timezone.utc)
    end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    start = (now - timedelta(minutes=int(_WINDOW_MINUTES))).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    variables = {"zoneTag": CF_ZONE_ID, "start": start, "end": end}

    async with httpx.AsyncClient() as client:
        country_data, cache_data, status_data, agg_data = await asyncio.gather(
            _graphql(client, _COUNTRY_QUERY, variables),
            _graphql(client, _CACHE_QUERY, variables),
            _graphql(client, _STATUS_QUERY, variables),
            _graphql(client, _AGGREGATE_QUERY, variables),
        )

    # Aggregate totals
    agg_rows = agg_data["data"]["viewer"]["zones"][0]["httpRequestsAdaptiveGroups"]
    if agg_rows:
        requests_gauge.set(agg_rows[0].get("count", 0) / _WINDOW_MINUTES)
        unique_visitors_gauge.set(
            ((agg_rows[0].get("uniq") or {}).get("uniques", 0)) / _WINDOW_MINUTES
        )

    # By country
    req_by_c, bw_by_c, _ = parse_country_analytics(country_data)
    for country, rate in req_by_c.items():
        requests_by_country.labels(country=country).set(rate)
    for country, rate in bw_by_c.items():
        bandwidth_by_country.labels(country=country).set(rate)

    # Cache status
    for cs, rate in parse_cache_analytics(cache_data).items():
        cache_gauge.labels(cache_status=cs).set(rate)

    # HTTP status buckets
    for bucket, rate in parse_status_analytics(status_data).items():
        http_status_gauge.labels(status=bucket).set(rate)

    last_success_gauge.labels(task="requests").set(now.timestamp())
    log.info("Updated request analytics gauges (window: %s → %s)", start, end)
    return state


# ── Background loops ───────────────────────────────────────────────────────────

async def _firewall_loop() -> None:
    state = load_state()
    while True:
        try:
            state = await poll_firewall_events(state)
            save_state(state)
        except Exception as e:
            log.error("Firewall poll error: %s", e)
            errors_counter.labels(task="firewall").inc()
        await asyncio.sleep(POLL_INTERVAL)


async def _analytics_loop() -> None:
    state = load_state()
    while True:
        try:
            state = await poll_request_analytics(state)
            save_state(state)
        except Exception as e:
            log.error("Analytics poll error: %s", e)
            errors_counter.labels(task="requests").inc()
        await asyncio.sleep(POLL_INTERVAL)


# ── FastAPI app ────────────────────────────────────────────────────────────────

app = FastAPI()


@app.on_event("startup")
async def startup() -> None:
    # Push Grafana dashboard — log error and continue if Grafana isn't ready
    try:
        import push_dashboard  # noqa: F401 — runs on import
    except Exception as e:
        log.error("Grafana dashboard push failed (non-fatal): %s", e)

    asyncio.create_task(_firewall_loop())
    asyncio.create_task(_analytics_loop())


@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/health")
async def health():
    return {"status": "ok"}

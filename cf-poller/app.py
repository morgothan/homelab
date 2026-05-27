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

# FastAPI app — tasks added in startup event
app = FastAPI()

@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.get("/health")
async def health():
    return {"status": "ok"}

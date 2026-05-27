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

# FastAPI app — tasks added in startup event
app = FastAPI()

@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.get("/health")
async def health():
    return {"status": "ok"}

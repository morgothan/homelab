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

# FastAPI app — tasks added in startup event
app = FastAPI()

@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.get("/health")
async def health():
    return {"status": "ok"}

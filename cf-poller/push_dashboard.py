"""Push the Cloudflare Analytics Grafana dashboard.

Imported once at container startup from app.py's startup event.
If Grafana is unreachable, raises an exception (caught and logged by caller).
"""

import base64
import json
import os
import urllib.request

GRAFANA_URL = os.getenv("GRAFANA_URL", "http://grafana:3000")
USER = os.getenv("GF_SECURITY_ADMIN_USER", "admin")
PASS = os.getenv("GF_SECURITY_ADMIN_PASSWORD", "")
_AUTH = base64.b64encode(f"{USER}:{PASS}".encode()).decode()


def _api(path, data=None):
    url = f"{GRAFANA_URL}{path}"
    req = urllib.request.Request(url, data=data)
    req.add_header("Authorization", f"Basic {_AUTH}")
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)


# ── Discover datasource UIDs ───────────────────────────────────────────────────

sources = _api("/api/datasources")
prom_uid = next(
    (d["uid"] for d in sources if d["type"] == "prometheus" and d.get("isDefault")),
    next((d["uid"] for d in sources if d["type"] == "prometheus"), None),
)
loki_uid = next((d["uid"] for d in sources if d["type"] == "loki"), None)

if not prom_uid:
    raise RuntimeError("No Prometheus datasource found in Grafana")


def _prom(expr, legend="", instant=False, ref="A"):
    return {
        "datasource": {"type": "prometheus", "uid": prom_uid},
        "expr": expr, "legendFormat": legend, "instant": instant, "refId": ref,
    }


def _loki(expr, ref="A"):
    if not loki_uid:
        raise RuntimeError("No Loki datasource found")
    return {
        "datasource": {"type": "loki", "uid": loki_uid},
        "expr": expr, "refId": ref,
    }


# ── Panel helpers ──────────────────────────────────────────────────────────────

def _stat(id_, title, expr, x, y, w, h, unit="", decimals=0, thresholds=None,
          graph_mode="none", mappings=None):
    return {
        "id": id_, "type": "stat", "title": title,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "options": {
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "orientation": "auto", "textMode": "auto",
            "colorMode": "background", "graphMode": graph_mode,
        },
        "fieldConfig": {
            "defaults": {
                "unit": unit, "decimals": decimals,
                "thresholds": thresholds or {
                    "mode": "absolute",
                    "steps": [{"color": "green", "value": None}],
                },
                "mappings": mappings or [],
            },
            "overrides": [],
        },
        "targets": [_prom(expr, instant=True)],
    }


def _timeseries(id_, title, targets, x, y, w, h, unit=""):
    return {
        "id": id_, "type": "timeseries", "title": title,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "options": {
            "tooltip": {"mode": "multi", "sort": "none"},
            "legend": {"showLegend": True, "displayMode": "list", "placement": "bottom"},
        },
        "fieldConfig": {
            "defaults": {"unit": unit, "custom": {"lineWidth": 2}},
            "overrides": [],
        },
        "targets": targets,
    }


def _bar(id_, title, expr, x, y, w, h, unit="", legend="{{country}}"):
    return {
        "id": id_, "type": "barchart", "title": title,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "options": {
            "orientation": "horizontal",
            "legend": {"displayMode": "list", "placement": "bottom"},
        },
        "fieldConfig": {"defaults": {"unit": unit}, "overrides": []},
        "targets": [_prom(expr, legend=legend, instant=True)],
    }


def _row(id_, title, y):
    return {
        "id": id_, "type": "row", "title": title,
        "gridPos": {"x": 0, "y": y, "w": 24, "h": 1},
        "collapsed": False, "panels": [],
    }


def _logs(id_, x, y, w, h):
    return {
        "id": id_, "type": "logs", "title": "Recent Firewall Events",
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "options": {
            "dedupStrategy": "none", "showLabels": False,
            "showTime": True, "sortOrder": "Descending", "wrapLogMessage": False,
        },
        "targets": [_loki('{job="cloudflare", type="firewall"} | json')],
    }


# ── Dashboard panels ───────────────────────────────────────────────────────────

panels = [
    # ── Row 1: Overview ────────────────────────────────────────────────────────
    _row(1, "Overview", 0),

    _stat(2,  "Requests / min",    "cf_requests_per_minute",
          0,  1, 5, 4, decimals=1, graph_mode="area"),
    _stat(3,  "Bandwidth / min",   "sum(cf_bandwidth_bytes_by_country)",
          5,  1, 5, 4, unit="decbytes", decimals=1, graph_mode="area"),
    _stat(4,  "Unique Visitors / min", "cf_unique_visitors",
          10, 1, 5, 4, decimals=1),
    _stat(5,  "Firewall Events / min",
          'increase(cf_firewall_events_total[5m]) / 5',
          15, 1, 5, 4,
          thresholds={"mode": "absolute", "steps": [
              {"color": "green", "value": None},
              {"color": "yellow", "value": 1},
              {"color": "red",   "value": 10},
          ]}),
    _stat(6, "Cache Hit %",
          'sum(cf_cache_requests{cache_status="hit"}) / sum(cf_cache_requests) * 100',
          20, 1, 4, 4, unit="percent", decimals=1,
          thresholds={"mode": "absolute", "steps": [
              {"color": "red",    "value": None},
              {"color": "yellow", "value": 50},
              {"color": "green",  "value": 80},
          ]}),

    # ── Row 2: Traffic Geography ───────────────────────────────────────────────
    _row(7, "Traffic Geography", 5),

    _bar(8,  "Requests by Country",
         "topk(10, cf_requests_by_country)",
         0, 6, 12, 8, legend="{{country}}"),
    _bar(9,  "Bandwidth by Country",
         "topk(5, cf_bandwidth_bytes_by_country)",
         12, 6, 12, 8, unit="decbytes", legend="{{country}}"),

    # ── Row 3: Security ────────────────────────────────────────────────────────
    _row(10, "Security", 14),

    _timeseries(11, "Firewall Events by Action",
                [_prom('sum by (action)(increase(cf_firewall_events_total[5m]))',
                       legend="{{action}}")],
                0, 15, 12, 8),
    _timeseries(12, "Firewall Events by Source",
                [_prom('sum by (source)(increase(cf_firewall_events_total[5m]))',
                       legend="{{source}}")],
                12, 15, 12, 8),

    _logs(13, 0, 23, 24, 8),

    # ── Row 4: Cache & HTTP Status ─────────────────────────────────────────────
    _row(14, "Cache & HTTP Status", 31),

    _timeseries(15, "Cache Status Over Time",
                [_prom("cf_cache_requests", legend="{{cache_status}}")],
                0, 32, 12, 8),
    _timeseries(16, "HTTP Status Codes Over Time",
                [_prom("cf_http_status", legend="{{status}}")],
                12, 32, 12, 8),

    # ── Row 5: Bandwidth ───────────────────────────────────────────────────────
    _row(17, "Bandwidth", 40),

    _timeseries(18, "Total Bandwidth Over Time",
                [_prom("sum(cf_bandwidth_bytes_by_country)", legend="total")],
                0, 41, 24, 8, unit="decbytes"),
]

# ── Push dashboard ─────────────────────────────────────────────────────────────

dashboard = {
    "dashboard": {
        "id": None,
        "uid": "cloudflare-analytics",
        "title": "Cloudflare Zone Analytics",
        "tags": ["cloudflare", "security", "homelab"],
        "timezone": "browser",
        "schemaVersion": 38,
        "version": 1,
        "refresh": "5m",
        "time": {"from": "now-24h", "to": "now"},
        "panels": panels,
    },
    "folderId": 0,
    "overwrite": True,
}

payload = json.dumps(dashboard).encode()
result = _api("/api/dashboards/db", data=payload)
print(f"Dashboard pushed: uid={result.get('uid')} status={result.get('status')}")

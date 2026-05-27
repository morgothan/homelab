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
        "targets": [_loki('{job="cloudflare", type="firewall", zone=~"$zone"} | json')],
    }


# ── Dashboard panels ───────────────────────────────────────────────────────────

panels = [
    # ── Row 1: Overview ────────────────────────────────────────────────────────
    _row(1, "Overview", 0),

    _stat(2,  "Requests / min",
          'sum(cf_requests_per_minute{zone=~"$zone"})',
          0,  1, 6, 4, decimals=1, graph_mode="area"),
    _stat(3,  "Bandwidth / min",
          'sum(cf_bandwidth_bytes_by_country{zone=~"$zone"})',
          6,  1, 6, 4, unit="decbytes", decimals=1, graph_mode="area"),
    _stat(4,  "Zones Monitored",
          'count(count by (zone)(cf_requests_per_minute{zone=~"$zone"}))',
          12, 1, 6, 4, decimals=0),
    _stat(5,  "Firewall Events / min",
          'sum(rate(cf_firewall_events_total{zone=~"$zone"}[10m])) * 60',
          18, 1, 6, 4,
          thresholds={"mode": "absolute", "steps": [
              {"color": "green", "value": None},
              {"color": "yellow", "value": 1},
              {"color": "red",   "value": 10},
          ]}),

    # ── Row 2: Cache & Traffic ─────────────────────────────────────────────────
    _row(6, "Cache & Traffic", 5),

    _stat(7, "Cache Hit %",
          '(sum(cf_cache_requests{cache_status="hit", zone=~"$zone"}) or vector(0))'
          ' / sum(cf_cache_requests{zone=~"$zone"}) * 100',
          0, 6, 8, 4, unit="percent", decimals=1,
          thresholds={"mode": "absolute", "steps": [
              {"color": "red",    "value": None},
              {"color": "yellow", "value": 50},
              {"color": "green",  "value": 80},
          ]}),

    # ── Row 3: Traffic Geography ───────────────────────────────────────────────
    _row(8, "Traffic Geography", 10),

    _bar(9,  "Requests by Country",
         'topk(10, sum by(country)(cf_requests_by_country{zone=~"$zone"}))',
         0, 11, 12, 8, legend="{{country}}"),
    _bar(10, "Bandwidth by Country",
         'topk(5, sum by(country)(cf_bandwidth_bytes_by_country{zone=~"$zone"}))',
         12, 11, 12, 8, unit="decbytes", legend="{{country}}"),

    # ── Row 4: Security ────────────────────────────────────────────────────────
    _row(11, "Security", 19),

    _timeseries(12, "Firewall Events by Action",
                [_prom('sum by (action)(rate(cf_firewall_events_total{zone=~"$zone"}[10m]) * 60)',
                       legend="{{action}}")],
                0, 20, 12, 8),
    _timeseries(13, "Firewall Events by Source",
                [_prom('sum by (source)(rate(cf_firewall_events_total{zone=~"$zone"}[10m]) * 60)',
                       legend="{{source}}")],
                12, 20, 12, 8),

    _logs(14, 0, 28, 24, 8),

    # ── Row 5: Cache & HTTP Status ─────────────────────────────────────────────
    _row(15, "Cache & HTTP Status", 36),

    _timeseries(16, "Cache Status Over Time",
                [_prom('cf_cache_requests{zone=~"$zone"}', legend="{{cache_status}}")],
                0, 37, 12, 8),
    _timeseries(17, "HTTP Status Codes Over Time",
                [_prom('cf_http_status{zone=~"$zone"}', legend="{{status}}")],
                12, 37, 12, 8),

    # ── Row 6: Bandwidth ───────────────────────────────────────────────────────
    _row(18, "Bandwidth", 45),

    _timeseries(19, "Total Bandwidth Over Time",
                [_prom('sum(cf_bandwidth_bytes_by_country{zone=~"$zone"})', legend="total")],
                0, 46, 24, 8, unit="decbytes"),
]

# ── Template variable — zone picker ───────────────────────────────────────────

templating = {
    "list": [
        {
            "datasource": {"type": "prometheus", "uid": prom_uid},
            "definition": "label_values(cf_requests_per_minute, zone)",
            "hide": 0,
            "includeAll": True,
            "multi": False,
            "name": "zone",
            "label": "Zone",
            "options": [],
            "query": {
                "query": "label_values(cf_requests_per_minute, zone)",
                "refId": "StandardVariableQuery",
            },
            "refresh": 2,
            "regex": "",
            "sort": 1,
            "type": "query",
            "allValue": ".*",
            "current": {},
        }
    ]
}

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
        "templating": templating,
        "panels": panels,
    },
    "folderId": 0,
    "overwrite": True,
}

payload = json.dumps(dashboard).encode()
result = _api("/api/dashboards/db", data=payload)
print(f"Dashboard pushed: uid={result.get('uid')} status={result.get('status')}")

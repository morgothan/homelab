#!/usr/bin/env python3
"""Build and push the RainSoft Grafana dashboard."""
import json, os, sys, urllib.request, urllib.error

GRAFANA_URL = os.getenv("GRAFANA_URL", "http://grafana:3000")
USER = os.getenv("GF_SECURITY_ADMIN_USER") or os.environ["GRAFANA_USERNAME"]
PASS = os.getenv("GF_SECURITY_ADMIN_PASSWORD") or os.environ["GRAFANA_PASSWORD"]

def api(path):
    req = urllib.request.Request(f"{GRAFANA_URL}{path}")
    creds = base64.b64encode(f"{USER}:{PASS}".encode()).decode()
    req.add_header("Authorization", f"Basic {creds}")
    with urllib.request.urlopen(req) as r:
        return json.load(r)

import base64
DS_UID = os.getenv("GRAFANA_DATASOURCE_UID")
if not DS_UID:
    datasources = api("/api/datasources")
    prom = next((d for d in datasources if d["type"] == "prometheus" and d["isDefault"]), None) \
           or next((d for d in datasources if d["type"] == "prometheus"), None)
    if not prom:
        print("No Prometheus datasource found", file=sys.stderr)
        sys.exit(1)
    DS_UID = prom["uid"]

def ds(expr, instant=False, legend=""):
    return {
        "datasource": {"type": "prometheus", "uid": DS_UID},
        "expr": expr,
        "legendFormat": legend,
        "instant": instant,
        "refId": "A",
    }

def stat(id_, title, expr, x, y, w, h, unit="", decimals=0, thresholds=None,
         mappings=None, color_mode="background", graph_mode="none", legend=""):
    p = {
        "id": id_, "type": "stat", "title": title,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": {"type": "prometheus", "uid": DS_UID},
        "options": {
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "orientation": "auto", "textMode": "auto",
            "colorMode": color_mode, "graphMode": graph_mode,
        },
        "fieldConfig": {
            "defaults": {
                "unit": unit, "decimals": decimals,
                "thresholds": thresholds or {"mode": "absolute", "steps": [{"color": "green", "value": None}]},
                "mappings": mappings or [],
            },
            "overrides": [],
        },
        "targets": [ds(expr, instant=True, legend=legend)],
    }
    return p

def gauge(id_, title, expr, x, y, w, h, unit="", min_=0, max_=100, thresholds=None):
    return {
        "id": id_, "type": "gauge", "title": title,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": {"type": "prometheus", "uid": DS_UID},
        "options": {
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "orientation": "auto", "showThresholdLabels": False, "showThresholdMarkers": True,
        },
        "fieldConfig": {
            "defaults": {
                "unit": unit, "min": min_, "max": max_,
                "thresholds": thresholds or {
                    "mode": "absolute",
                    "steps": [
                        {"color": "red", "value": None},
                        {"color": "orange", "value": 25},
                        {"color": "yellow", "value": 50},
                        {"color": "green", "value": 75},
                    ],
                },
                "mappings": [],
            },
            "overrides": [],
        },
        "targets": [ds(expr, instant=True)],
    }

def timeseries(id_, title, targets, x, y, w, h, unit="", stacked=False, min_val="UNSET"):
    defaults = {"unit": unit, "custom": {"lineWidth": 2}}
    if min_val != "UNSET":
        defaults["min"] = min_val  # None → JSON null → Grafana auto-scales Y axis
    return {
        "id": id_, "type": "timeseries", "title": title,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": {"type": "prometheus", "uid": DS_UID},
        "options": {
            "tooltip": {"mode": "multi", "sort": "none"},
            "legend": {"showLegend": True, "displayMode": "list", "placement": "bottom"},
            "fillOpacity": 10 if not stacked else 40,
            "stacking": {"mode": "normal" if stacked else "none"},
        },
        "fieldConfig": {
            "defaults": defaults,
            "overrides": [],
        },
        "targets": targets,
    }

def row_panel(id_, title, y):
    return {
        "id": id_, "type": "row", "title": title,
        "gridPos": {"x": 0, "y": y, "w": 24, "h": 1},
        "collapsed": False, "panels": [],
    }

def info_table(id_, title, metric, fields, x, y, w, h):
    return {
        "id": id_, "type": "table", "title": title,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": {"type": "prometheus", "uid": DS_UID},
        "options": {"footer": {"show": False}, "showHeader": True, "cellHeight": "sm"},
        "fieldConfig": {
            "defaults": {"custom": {"align": "auto", "displayMode": "auto"}},
            "overrides": [
                {"matcher": {"id": "byName", "options": "Value"}, "properties": [{"id": "custom.hidden", "value": True}]},
                {"matcher": {"id": "byName", "options": "Time"},  "properties": [{"id": "custom.hidden", "value": True}]},
            ],
        },
        "transformations": [
            {"id": "labelsToFields", "options": {"mode": "columns"}},
            {"id": "filterFieldsByName", "options": {"include": {"names": fields}}},
        ],
        "targets": [ds(metric, instant=True)],
    }

def event_table(id_, x, y, w, h):
    return {
        "id": id_, "type": "table", "title": "Device Event History (codes are undocumented)",
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": {"type": "prometheus", "uid": DS_UID},
        "options": {"footer": {"show": False}, "showHeader": True, "cellHeight": "sm"},
        "fieldConfig": {
            "defaults": {"unit": "dateTimeAsLocal"},
            "overrides": [
                {"matcher": {"id": "byName", "options": "code"}, "properties": [{"id": "unit", "value": "string"}]},
            ],
        },
        "transformations": [
            {"id": "labelsToFields", "options": {"mode": "columns"}},
            {"id": "filterFieldsByName", "options": {"include": {"names": ["code", "Value"]}}},
        ],
        "targets": [ds("rainsoft_last_event_timestamp_seconds * 1000", instant=True)],
    }

panels = [
    # ── Row 1: Status ──────────────────────────────────────────────────────
    row_panel(1, "Status", 0),

    stat(2, "System Status", "rainsoft_system_status", 0, 1, 3, 3,
         color_mode="background",
         mappings=[{"type": "value", "options": {
             "0": {"text": "OK",    "color": "green", "index": 0},
             "1": {"text": "FAULT", "color": "red",   "index": 1},
         }}],
         thresholds={"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "red", "value": 1}]}),

    # Age in seconds since last contact — thresholds on seconds, not timestamp
    stat(3, "Last Contact", "time() - rainsoft_last_contact_timestamp_seconds", 3, 1, 4, 3,
         unit="s",
         thresholds={"mode": "absolute", "steps": [
             {"color": "green",  "value": None},
             {"color": "yellow", "value": 600},   # >10 min stale
             {"color": "red",    "value": 1800},  # >30 min stale
         ]}),

    # Multiply seconds → ms so Grafana dateTimeAsLocal interprets correctly
    stat(4, "Last Regeneration", "rainsoft_last_regen_timestamp_seconds * 1000", 7, 1, 9, 3,
         unit="dateTimeAsLocal",
         thresholds={"mode": "absolute", "steps": [{"color": "text", "value": None}]}),

    stat(5, "WiFi RSSI", "rainsoft_wifi_rssi_dbm", 16, 1, 3, 3,
         unit="dBm", decimals=0,
         thresholds={"mode": "absolute", "steps": [
             {"color": "red",    "value": None},
             {"color": "orange", "value": -80},
             {"color": "yellow", "value": -70},
             {"color": "green",  "value": -60},
         ]}),

    stat(6, "Vacation Mode", "rainsoft_vacation_mode", 19, 1, 3, 3,
         mappings=[{"type": "value", "options": {
             "0": {"text": "Off", "color": "green", "index": 0},
             "1": {"text": "ON",  "color": "blue",  "index": 1},
         }}],
         thresholds={"mode": "absolute", "steps": [{"color": "green", "value": None}]}),

    stat(27, "End of Day", "rainsoft_end_of_day", 22, 1, 2, 3,
         mappings=[{"type": "value", "options": {
             "0": {"text": "—",        "color": "text", "index": 0},
             "1": {"text": "ROLLOVER", "color": "blue", "index": 1},
         }}],
         thresholds={"mode": "absolute", "steps": [{"color": "text", "value": None}]}),

    # ── Row 2: Water Usage ─────────────────────────────────────────────────
    row_panel(7, "Water Usage", 4),

    stat(8,  "Today's Usage",       "rainsoft_daily_water_gallons",       0,  5, 6, 4, unit="gal", graph_mode="area"),
    stat(9,  "Since Last Regen",    "rainsoft_flow_since_regen_gallons",  6,  5, 6, 4, unit="gal", graph_mode="area"),
    stat(10, "28-Day Usage",        "rainsoft_water_28day_gallons",       12, 5, 6, 4, unit="gal"),
    stat(11, "Lifetime Flow",       "rainsoft_lifetime_flow_gallons",     18, 5, 6, 4, unit="gal"),

    # ── Row 3: Softener Health ─────────────────────────────────────────────
    row_panel(12, "Softener Health", 9),

    gauge(13, "Capacity Remaining", "rainsoft_capacity_remaining_percent", 0, 10, 8, 8,
          unit="percent", min_=0, max_=100,
          thresholds={"mode": "absolute", "steps": [
              {"color": "red",    "value": None},
              {"color": "orange", "value": 25},
              {"color": "yellow", "value": 50},
              {"color": "green",  "value": 75},
          ]}),

    stat(14, "Salt Remaining",         "rainsoft_salt_level_lbs",    8, 10, 4, 4, unit="lbs"),
    stat(15, "Average Weekly Salt",     "rainsoft_average_weekly_salt_lbs", 12, 10, 4, 4, unit="lbs"),
    stat(16, "Regens — Last 28 Days",   "rainsoft_regens_28day_count",16, 10, 4, 4),
    stat(17, "Capacity Before Last Regen","rainsoft_capacity_at_start_percent", 20, 10, 4, 4, unit="percent"),

    # Salt trend fills the right side of the health row (gauge occupies x=0-8, h=8)
    timeseries(19, "Salt Remaining Trend", [
        {**ds("rainsoft_salt_level_lbs", legend="Salt remaining (lbs)"), "refId": "A"},
    ], 8, 14, 16, 4, unit="lbs"),

    # ── Row 4: Filter Service Intervals ────────────────────────────────────
    row_panel(28, "Filter Service Intervals", 18),

    stat(29, "Drinking Water System — Service Due",
         'rainsoft_additional_system_remaining_months{number="1"}',
         0, 19, 8, 5,
         unit="suffix: months",
         graph_mode="area",
         thresholds={"mode": "absolute", "steps": [
             {"color": "red",    "value": None},
             {"color": "orange", "value": 1},
             {"color": "yellow", "value": 3},
             {"color": "green",  "value": 6},
         ]}),

    stat(30, "Filter System — Service Due",
         'rainsoft_additional_system_remaining_months{number="2"}',
         8, 19, 8, 5,
         unit="suffix: months",
         graph_mode="area",
         thresholds={"mode": "absolute", "steps": [
             {"color": "red",    "value": None},
             {"color": "orange", "value": 1},
             {"color": "yellow", "value": 3},
             {"color": "green",  "value": 6},
         ]}),

    stat(31, "Airmaster System — Service Due",
         'rainsoft_additional_system_remaining_months{number="3"}',
         16, 19, 8, 5,
         unit="suffix: months",
         graph_mode="area",
         thresholds={"mode": "absolute", "steps": [
             {"color": "red",    "value": None},
             {"color": "orange", "value": 1},
             {"color": "yellow", "value": 3},
             {"color": "green",  "value": 6},
         ]}),

    # ── Row 5: History ─────────────────────────────────────────────────────
    row_panel(20, "History", 24),

    timeseries(21, "Water Usage", [
        {**ds("rainsoft_daily_water_gallons",      legend="Today"),        "refId": "A"},
        {**ds("rainsoft_flow_since_regen_gallons", legend="Since Regen"),  "refId": "B"},
    ], 0, 25, 12, 8, unit="gal"),

    timeseries(22, "Capacity Remaining", [
        {**ds("rainsoft_capacity_remaining_percent", legend="Capacity %"), "refId": "A"},
    ], 12, 25, 12, 8, unit="percent"),

    timeseries(23, "WiFi Signal", [
        {**ds("rainsoft_wifi_rssi_dbm", legend="RSSI"), "refId": "A"},
    ], 0, 33, 12, 6, unit="dBm"),

    timeseries(24, "Lifetime Flow", [
        {**ds("rainsoft_lifetime_flow_gallons", legend="Gallons"), "refId": "A"},
    ], 12, 33, 12, 6, unit="gal", min_val=None),

    # ── Row 6: System Info ─────────────────────────────────────────────────
    row_panel(25, "System Info", 39),
    info_table(26, "System Information", "rainsoft_system_info",
               ["model","firmware","serial","install_date","hardness_gpg","iron_ppm",
                "unit_size_code","starting_capacity_setting","max_salt_setting",
                "resin_type_code","injector_code","psi_code","drain_flow_gpm"],
               0, 40, 24, 5),

    row_panel(38, "Configuration and Events", 45),
    stat(39, "Low-Salt Alarm", "rainsoft_salt_alarm_enabled", 0, 46, 4, 4,
         mappings=[{"type": "value", "options": {
             "0": {"text": "Off", "color": "yellow", "index": 0},
             "1": {"text": "On", "color": "green", "index": 1},
         }}]),
    stat(40, "Vacation Duration", "rainsoft_vacation_days", 4, 46, 4, 4, unit="d"),
    stat(41, "Last Salt Adjustment", "rainsoft_last_salt_adjustment_timestamp_seconds * 1000",
         8, 46, 8, 4, unit="dateTimeAsLocal",
         thresholds={"mode": "absolute", "steps": [{"color": "text", "value": None}]}),
    info_table(42, "Customer Settings", "rainsoft_customer_settings_info",
               ["regeneration_time","low_salt_alarm_time","salt_type","salt_form","salt_type_code","salt_form_code"],
               16, 46, 8, 4),
    info_table(43, "Additional System Definitions", "rainsoft_additional_system_info",
               ["number","category_code","type_code","install_date","interval_unit","service_interval"],
               0, 50, 16, 6),
    event_table(44, 16, 50, 8, 6),
]

dashboard = {
    "dashboard": {
        "id": None,
        "uid": "rainsoft-ec5",
        "title": "RainSoft EC5 Water Softener - Prometheus",
        "tags": ["rainsoft", "water", "homelab"],
        "timezone": "browser",
        "schemaVersion": 38,
        "version": 1,
        "refresh": "5m",
        "time": {"from": "now-7d", "to": "now"},
        "panels": panels,
    },
    "folderId": 0,
    "overwrite": True,
}

payload = json.dumps(dashboard).encode()
if output_path := os.getenv("DASHBOARD_OUTPUT"):
    with open(output_path, "wb") as output:
        output.write(payload)
    print(f"Dashboard JSON written to {output_path}")
    sys.exit(0)
req = urllib.request.Request(
    f"{GRAFANA_URL}/api/dashboards/db",
    data=payload,
    headers={"Content-Type": "application/json"},
)
creds = base64.b64encode(f"{USER}:{PASS}".encode()).decode()
req.add_header("Authorization", f"Basic {creds}")

try:
    with urllib.request.urlopen(req) as resp:
        result = json.load(resp)
        print(f"Dashboard created: {result.get('url', '(no url)')}")
        print(f"UID: {result.get('uid')}, status: {result.get('status')}")
except urllib.error.HTTPError as e:
    print(f"HTTP {e.code}: {e.read().decode()}", file=sys.stderr)
    sys.exit(1)

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs
from zoneinfo import ZoneInfo

_ET = ZoneInfo("America/New_York")

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, JSONResponse
from prometheus_client import Counter, Gauge, Info, generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response

app = FastAPI()

LOG_PATH = Path("/data/requests.jsonl")
STATE_PATH = Path("/data/last_state.json")
LOG_MAX_BYTES = int(os.getenv("RAINSOFT_LOG_MAX_BYTES", str(50 * 1024 * 1024)))
LOG_BACKUPS = max(1, int(os.getenv("RAINSOFT_LOG_BACKUPS", "5")))
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

# --- Prometheus metrics ---

requests_total = Counter(
    "rainsoft_requests_total",
    "Total requests received from RainSoft device",
    ["path"],
)
last_contact = Gauge(
    "rainsoft_last_contact_timestamp_seconds",
    "Unix timestamp of last contact from RainSoft device",
)

# stats_upload
system_status = Gauge("rainsoft_system_status", "System status (0=OK)")
daily_water = Gauge("rainsoft_daily_water_gallons", "Gallons used today")
flow_since_regen = Gauge("rainsoft_flow_since_regen_gallons", "Gallons since last regeneration")
lifetime_flow = Gauge("rainsoft_lifetime_flow_gallons", "Total lifetime gallons processed")
capacity_remaining = Gauge("rainsoft_capacity_remaining_percent", "Capacity remaining before next regeneration (%)")
capacity_at_start = Gauge("rainsoft_capacity_at_start_percent", "Capacity remaining immediately before the last regeneration (%)")
water_28day = Gauge("rainsoft_water_28day_gallons", "Water used in last 28 days (gallons)")
average_weekly_salt = Gauge("rainsoft_average_weekly_salt_lbs", "Average weekly salt used, calculated over 28 days (lbs)")
regens_28day = Gauge("rainsoft_regens_28day_count", "Regenerations in the rolling last 28 days")
# Compatibility series retained so existing Prometheus history and queries remain usable.
salt_28day_legacy = Gauge("rainsoft_salt_28day_lbs", "Deprecated: use rainsoft_average_weekly_salt_lbs")
regens_28day_legacy = Gauge("rainsoft_regens_28day_total", "Deprecated: use rainsoft_regens_28day_count")
last_regen_ts = Gauge("rainsoft_last_regen_timestamp_seconds", "Unix timestamp of last regeneration")
end_of_day = Gauge("rainsoft_end_of_day", "End-of-day rollover flag (1=midnight rollover in progress)")
rssi = Gauge("rainsoft_wifi_rssi_dbm", "WiFi RSSI (dBm)")

# customer_settings_upload
salt_level = Gauge("rainsoft_salt_level_lbs", "Estimated salt remaining in tank (lbs)")
vacation_mode = Gauge("rainsoft_vacation_mode", "Vacation mode enabled (1=yes)")
vacation_days = Gauge("rainsoft_vacation_days", "Configured vacation duration (days)")
regen_time = Gauge("rainsoft_regeneration_time_seconds", "Configured automatic regeneration time as seconds after midnight")
salt_alarm = Gauge("rainsoft_salt_alarm_enabled", "Low-salt audible alarm enabled (1=yes)")
salt_alarm_hour = Gauge("rainsoft_salt_alarm_hour", "Configured low-salt alarm hour (0-23)")
customer_info = Info("rainsoft_customer_settings", "RainSoft customer settings")

# additional_system_history_upload
additional_system_interval = Gauge(
    "rainsoft_additional_system_remaining_months",
    "Remaining service interval for each configured additional system (months)",
    ["number"],
)
additional_system_interval_legacy = Gauge(
    "rainsoft_additional_system_remain_interval",
    "Deprecated: use rainsoft_additional_system_remaining_months",
    ["number"],
)
additional_system_info = Info("rainsoft_additional_system", "Configured additional system definition", ["number"])

last_event = Gauge("rainsoft_last_event_timestamp_seconds", "Most recent occurrence of a device event", ["code"])
last_salt_adjustment = Gauge("rainsoft_last_salt_adjustment_timestamp_seconds", "Most recent manual salt-level adjustment")

# system info (installer_settings_upload) — set once, exposed as labels
system_info = Info("rainsoft_system", "RainSoft system information")

_system_info_state: dict[str, str] = {}
_customer_info_state: dict[str, str] = {}
_additional_system_definitions: dict[str, dict[str, str]] = {}
_archive_metadata_loaded = 0


# --- State persistence ---

def load_state():
    """Restore metric values from disk so restarts don't zero out gauges."""
    if not STATE_PATH.exists():
        return
    try:
        s = json.loads(STATE_PATH.read_text())
    except Exception:
        return

    _safe_set(system_status,      s.get("system_status"))
    _safe_set(daily_water,        s.get("daily_water"))
    _safe_set(flow_since_regen,   s.get("flow_since_regen"))
    _safe_set(lifetime_flow,      s.get("lifetime_flow"))
    _safe_set(capacity_remaining, s.get("capacity_remaining"))
    _safe_set(capacity_at_start,  s.get("capacity_at_start"))
    _safe_set(water_28day,        s.get("water_28day"))
    salt_average = s.get("average_weekly_salt", s.get("salt_28day"))
    _safe_set(average_weekly_salt, salt_average)
    _safe_set(salt_28day_legacy,  salt_average)
    _safe_set(regens_28day,       s.get("regens_28day"))
    _safe_set(regens_28day_legacy, s.get("regens_28day"))
    _safe_set(last_regen_ts,      s.get("last_regen_ts"))
    _safe_set(end_of_day,         s.get("end_of_day"))
    _safe_set(rssi,               s.get("rssi"))
    _safe_set(salt_level,         s.get("salt_level"))
    _safe_set(vacation_mode,      s.get("vacation_mode"))
    _safe_set(vacation_days,      s.get("vacation_days"))
    _safe_set(regen_time,         s.get("regen_time"))
    _safe_set(salt_alarm,         s.get("salt_alarm"))
    _safe_set(salt_alarm_hour,    s.get("salt_alarm_hour"))
    _safe_set(last_salt_adjustment, s.get("last_salt_adjustment"))
    _safe_set(last_contact,       s.get("last_contact"))

    for num, val in s.get("additional_systems", {}).items():
        if val is not None:
            additional_system_interval.labels(number=num).set(val)
            additional_system_interval_legacy.labels(number=num).set(val)

    global _system_info_state, _customer_info_state, _additional_system_definitions, _archive_metadata_loaded
    _system_info_state = s.get("system_info") or {}
    _customer_info_state = s.get("customer_info") or {}
    _additional_system_definitions = s.get("additional_system_definitions") or {}
    _archive_metadata_loaded = int(s.get("archive_metadata_loaded", 0))
    if _system_info_state:
        system_info.info(_system_info_state)
    if _customer_info_state:
        customer_info.info(_customer_info_state)
    for num, definition in _additional_system_definitions.items():
        additional_system_info.labels(number=num).info(definition)
    for code, occurred_at in s.get("events", {}).items():
        _safe_set(last_event.labels(code=code), occurred_at)

    print(f"State restored from {STATE_PATH}", flush=True)


def save_state():
    """Persist current metric values to disk."""
    try:
        state = json.dumps({
            "system_status":      _get(system_status),
            "daily_water":        _get(daily_water),
            "flow_since_regen":   _get(flow_since_regen),
            "lifetime_flow":      _get(lifetime_flow),
            "capacity_remaining": _get(capacity_remaining),
            "capacity_at_start":  _get(capacity_at_start),
            "water_28day":        _get(water_28day),
            "average_weekly_salt": _get(average_weekly_salt),
            "regens_28day":       _get(regens_28day),
            "last_regen_ts":      _get(last_regen_ts),
            "end_of_day":         _get(end_of_day),
            "rssi":               _get(rssi),
            "salt_level":         _get(salt_level),
            "vacation_mode":      _get(vacation_mode),
            "vacation_days":      _get(vacation_days),
            "regen_time":         _get(regen_time),
            "salt_alarm":         _get(salt_alarm),
            "salt_alarm_hour":    _get(salt_alarm_hour),
            "last_salt_adjustment": _get(last_salt_adjustment),
            "last_contact":       _get(last_contact),
            "additional_systems": {
                sample.labels.get("number", ""): sample.value
                for metric in additional_system_interval.collect()
                for sample in metric.samples
                if sample.name == "rainsoft_additional_system_remaining_months"
            },
            "system_info": _system_info_state,
            "customer_info": _customer_info_state,
            "additional_system_definitions": _additional_system_definitions,
            "events": {
                sample.labels.get("code", ""): sample.value
                for metric in last_event.collect()
                for sample in metric.samples
                if sample.name == "rainsoft_last_event_timestamp_seconds"
            },
            "archive_metadata_loaded": _archive_metadata_loaded,
        })
        temporary = STATE_PATH.with_suffix(".tmp")
        temporary.write_text(state)
        temporary.replace(STATE_PATH)
    except Exception as e:
        print(f"Failed to save state: {e}", flush=True)


def _safe_set(gauge: Gauge, val):
    if val is not None:
        gauge.set(float(val))


def _get(gauge: Gauge) -> float | None:
    try:
        return gauge._value.get()
    except Exception:
        return None


@app.on_event("startup")
async def startup():
    load_state()
    restore_archive_metadata()


def restore_archive_metadata():
    """One-time migration of rare definitions/events from the pre-metric JSONL archive."""
    global _archive_metadata_loaded, _additional_system_definitions
    if _archive_metadata_loaded >= 2 or not LOG_PATH.exists():
        return
    try:
        latest_installer = {}
        latest_customer = {}
        with LOG_PATH.open() as archive:
            for line in archive:
                entry = json.loads(line)
                path = entry.get("path", "")
                data = entry.get("data", {})
                parsed = data.get("body_parsed", data)
                payload = parsed.get("content", {}).get("payload", {})
                if path.endswith("/define_additional_systems"):
                    for system in payload.get("additional_systems", []):
                        num = str(system.get("number", ""))
                        if num:
                            _additional_system_definitions[num] = {
                                "category_code": str(system.get("category", "")),
                                "type_code": str(system.get("type", "")),
                                "install_date": str(system.get("inst_date", "")),
                                "interval_unit": str(system.get("interval_unit", "")),
                                "service_interval": str(system.get("service_interval", "")),
                            }
                elif path.endswith("/log_events"):
                    for event in payload.get("events", []):
                        code, occurred_at = str(event.get("code", "")), event.get("occurred_at")
                        if code and occurred_at not in (None, ""):
                            last_event.labels(code=code).set(float(occurred_at))
                elif path.endswith("/setting_changes_upload"):
                    for change in payload.get("setting_changes", []):
                        if change.get("set_at") not in (None, ""):
                            last_salt_adjustment.set(float(change["set_at"]))
                elif path.endswith("/installer_settings_upload") and payload:
                    latest_installer = payload
                elif path.endswith("/customer_settings_upload") and payload:
                    latest_customer = payload
        for num, definition in _additional_system_definitions.items():
            additional_system_info.labels(number=num).info(definition)
        if latest_installer:
            _update_system_info(latest_installer)
        if latest_customer:
            _update_customer_settings(latest_customer)
        _archive_metadata_loaded = 2
        save_state()
        print("Rare metadata restored from request archive", flush=True)
    except Exception as e:
        print(f"Failed to restore archive metadata: {e}", flush=True)


# --- Helpers ---

def parse_body(body: bytes) -> dict:
    text = body.decode("utf-8", errors="replace")
    parsed = {k: v[0] for k, v in parse_qs(text).items()}
    if "content" in parsed:
        try:
            parsed["content"] = json.loads(parsed["content"])
        except Exception:
            pass
    return parsed


def log_entry(path: str, data: dict):
    entry = {"timestamp": datetime.now(timezone.utc).isoformat(), "path": path, "data": data}
    print(json.dumps(entry, indent=2), flush=True)
    _rotate_log_if_needed()
    with LOG_PATH.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def _rotate_log_if_needed():
    """Bound log growth while retaining several complete JSONL archives."""
    if LOG_MAX_BYTES <= 0 or not LOG_PATH.exists() or LOG_PATH.stat().st_size < LOG_MAX_BYTES:
        return
    oldest = LOG_PATH.with_name(f"{LOG_PATH.name}.{LOG_BACKUPS}")
    if oldest.exists():
        oldest.unlink()
    for index in range(LOG_BACKUPS - 1, 0, -1):
        source = LOG_PATH.with_name(f"{LOG_PATH.name}.{index}")
        if source.exists():
            source.replace(LOG_PATH.with_name(f"{LOG_PATH.name}.{index + 1}"))
    LOG_PATH.replace(LOG_PATH.with_name(f"{LOG_PATH.name}.1"))


def _set_if_present(metric: Gauge, payload: dict, key: str):
    """Update a gauge only when a partial device payload contains the field."""
    if key in payload and payload[key] not in (None, ""):
        metric.set(float(payload[key]))


def _update_customer_settings(payload: dict):
    global _customer_info_state
    for metric, key in (
        (salt_level, "salt_lbs"), (vacation_mode, "vacation_mode"),
        (vacation_days, "vacation_days"), (salt_alarm, "salt_buzzer"),
        (salt_alarm_hour, "salt_buzzer_hour"),
    ):
        _set_if_present(metric, payload, key)
    if "regen_hour" in payload and "regen_minute" in payload:
        regen_time.set(float(payload["regen_hour"]) * 3600 + float(payload["regen_minute"]) * 60)
    _customer_info_state = {
        "salt_type_code": str(payload.get("salt_type", "")),
        "salt_form_code": str(payload.get("salt_form", "")),
        "salt_type": {"0": "Sodium chloride", "1": "Potassium chloride"}.get(str(payload.get("salt_type", "")), "Unknown"),
        "salt_form": {"0": "Bag salt", "1": "Block salt"}.get(str(payload.get("salt_form", "")), "Unknown"),
        "regeneration_time": (
            f"{int(payload['regen_hour']):02d}:{int(payload['regen_minute']):02d}"
            if "regen_hour" in payload and "regen_minute" in payload else ""
        ),
        "low_salt_alarm_time": (
            f"{int(payload['salt_buzzer_hour']):02d}:00" if "salt_buzzer_hour" in payload else ""
        ),
    }
    customer_info.info(_customer_info_state)


def _update_system_info(payload: dict):
    global _system_info_state
    _system_info_state = {
        "model": str(payload.get("model", "")), "firmware": str(payload.get("firmware_num", "")),
        "serial": str(payload.get("sys_serial_num", "")), "install_date": str(payload.get("install_date", "")),
        "hardness_gpg": str(payload.get("hardness", "")).strip(),
        "iron_ppm": str(payload.get("iron_level", "")).strip(),
        "unit_size_code": str(payload.get("unit_size", "")),
        "starting_capacity_setting": str(payload.get("starting_cap", "")),
        "max_salt_setting": str(payload.get("max_salt", "")),
        "language_code": str(payload.get("language", "")),
        "resin_type_code": str(payload.get("resin_type", "")),
        "injector_code": str(payload.get("injector", "")), "psi_code": str(payload.get("psi", "")),
        "drain_flow_gpm": str(payload.get("drain_flow", "")).strip(),
    }
    system_info.info(_system_info_state)


def track(path: str):
    requests_total.labels(path=path).inc()
    last_contact.set(time.time())


# --- Routes ---

@app.get("/metrics")
async def prometheus_metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/api/device/v1/water_softener/stats_upload")
async def handle_stats_upload(request: Request):
    data = parse_body(await request.body())
    payload = data.get("content", {}).get("payload", {})
    log_entry(request.url.path, data)
    track(request.url.path)

    if not payload:
        return PlainTextResponse("OK")

    for metric, key in (
        (system_status, "system_status"),
        (daily_water, "daily_water"),
        (flow_since_regen, "flow_since_regen"),
        (lifetime_flow, "lifetime_flow"),
        (capacity_remaining, "capacity_remaining"),
        (capacity_at_start, "capacity_at_start"),
        (water_28day, "water_28_day"),
        (average_weekly_salt, "salt_28_day"),
        (salt_28day_legacy, "salt_28_day"),
        (regens_28day, "regens_28_day"),
        (regens_28day_legacy, "regens_28_day"),
        (rssi, "rssi"),
        (end_of_day, "end_of_day"),
    ):
        _set_if_present(metric, payload, key)

    regen_date_str = payload.get("last_regen_date", "")
    if regen_date_str:
        try:
            dt = datetime.strptime(regen_date_str, "%m/%d/%Y").replace(tzinfo=_ET)
            last_regen_ts.set(dt.timestamp())
        except ValueError:
            pass

    save_state()
    return PlainTextResponse("OK")


@app.post("/api/device/v1/water_softener/customer_settings_upload")
async def handle_customer_settings(request: Request):
    data = parse_body(await request.body())
    payload = data.get("content", {}).get("payload", {})
    log_entry(request.url.path, data)
    track(request.url.path)

    if payload:
        _update_customer_settings(payload)
        save_state()

    return PlainTextResponse("OK")


@app.post("/api/device/v1/water_softener/installer_settings_upload")
async def handle_installer_settings(request: Request):
    data = parse_body(await request.body())
    payload = data.get("content", {}).get("payload", {})
    log_entry(request.url.path, data)
    track(request.url.path)

    if payload:
        _update_system_info(payload)
        save_state()

    return PlainTextResponse("OK")


@app.post("/api/device/v1/water_softener/additional_system_history_upload")
async def handle_additional_system_history(request: Request):
    data = parse_body(await request.body())
    payload = data.get("content", {}).get("payload", {})
    log_entry(request.url.path, data)
    track(request.url.path)

    for system in payload.get("additional_systems", []):
        num = system.get("number", "")
        interval = system.get("remain_interval")
        if num and interval is not None:
            additional_system_interval.labels(number=num).set(float(interval))
            additional_system_interval_legacy.labels(number=num).set(float(interval))

    save_state()
    return PlainTextResponse("OK")


@app.post("/api/device/v1/water_softener/define_additional_systems")
async def handle_define_additional_systems(request: Request):
    data = parse_body(await request.body())
    payload = data.get("content", {}).get("payload", {})
    log_entry(request.url.path, data)
    track(request.url.path)

    global _additional_system_definitions
    for system in payload.get("additional_systems", []):
        num = str(system.get("number", ""))
        if not num:
            continue
        definition = {
            "category_code": str(system.get("category", "")),
            "type_code": str(system.get("type", "")),
            "install_date": str(system.get("inst_date", "")),
            "interval_unit": str(system.get("interval_unit", "")),
            "service_interval": str(system.get("service_interval", "")),
        }
        _additional_system_definitions[num] = definition
        additional_system_info.labels(number=num).info(definition)
    save_state()
    return PlainTextResponse("OK")


@app.post("/api/device/v1/water_softener/log_events")
async def handle_log_events(request: Request):
    data = parse_body(await request.body())
    payload = data.get("content", {}).get("payload", {})
    log_entry(request.url.path, data)
    track(request.url.path)
    for event in payload.get("events", []):
        code = str(event.get("code", ""))
        occurred_at = event.get("occurred_at")
        if code and occurred_at not in (None, ""):
            last_event.labels(code=code).set(float(occurred_at))
    save_state()
    return PlainTextResponse("OK")


@app.post("/api/device/v1/water_softener/setting_changes_upload")
async def handle_setting_changes(request: Request):
    data = parse_body(await request.body())
    payload = data.get("content", {}).get("payload", {})
    log_entry(request.url.path, data)
    track(request.url.path)
    changed = False
    for change in payload.get("setting_changes", []):
        if "salt_lbs" in change:
            salt_level.set(float(change["salt_lbs"]))
            changed = True
            if change.get("set_at") not in (None, ""):
                last_salt_adjustment.set(float(change["set_at"]))
    if changed:
        save_state()
    return PlainTextResponse("OK")


@app.post("/api/device/v1/water_softener/get_time")
async def handle_get_time(request: Request):
    data = parse_body(await request.body())
    log_entry(request.url.path, data)
    track(request.url.path)
    ts = int(time.time())
    # Mirror real server format: echo id/t, wrap time in content.payload
    return JSONResponse({
        "content": {"ts": ts, "payload": {"time": ts}},
        "id": data.get("id", ""),
        "t": str(ts),
    })


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def catch_all(request: Request, path: str):
    body = await request.body()
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "method": request.method,
        "path": request.url.path,
        "query": str(request.query_params),
        "headers": dict(request.headers),
        "body_text": body.decode("utf-8", errors="replace"),
        "client_ip": request.client.host if request.client else None,
    }
    try:
        entry["body_parsed"] = parse_body(body)
    except Exception:
        pass
    log_entry(request.url.path, entry)
    track(request.url.path)
    return PlainTextResponse("OK")

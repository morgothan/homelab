import json
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
capacity_at_start = Gauge("rainsoft_capacity_at_start_percent", "Capacity at start of current cycle (%)")
water_28day = Gauge("rainsoft_water_28day_gallons", "Water used in last 28 days (gallons)")
salt_28day = Gauge("rainsoft_salt_28day_lbs", "Salt used in last 28 days (lbs)")
regens_28day = Gauge("rainsoft_regens_28day_total", "Regenerations in last 28 days")
last_regen_ts = Gauge("rainsoft_last_regen_timestamp_seconds", "Unix timestamp of last regeneration")
end_of_day = Gauge("rainsoft_end_of_day", "End-of-day rollover flag (1=midnight rollover in progress)")
rssi = Gauge("rainsoft_wifi_rssi_dbm", "WiFi RSSI (dBm)")

# customer_settings_upload
salt_level = Gauge("rainsoft_salt_level_lbs", "Estimated salt remaining in tank (lbs)")
vacation_mode = Gauge("rainsoft_vacation_mode", "Vacation mode enabled (1=yes)")

# additional_system_history_upload
additional_system_interval = Gauge(
    "rainsoft_additional_system_remain_interval",
    "Remaining service interval for each additional filter/component",
    ["number"],
)

# system info (installer_settings_upload) — set once, exposed as labels
system_info = Info("rainsoft_system", "RainSoft system information")


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
    _safe_set(salt_28day,         s.get("salt_28day"))
    _safe_set(regens_28day,       s.get("regens_28day"))
    _safe_set(last_regen_ts,      s.get("last_regen_ts"))
    _safe_set(end_of_day,         s.get("end_of_day"))
    _safe_set(rssi,               s.get("rssi"))
    _safe_set(salt_level,         s.get("salt_level"))
    _safe_set(vacation_mode,      s.get("vacation_mode"))
    _safe_set(last_contact,       s.get("last_contact"))

    for num, val in s.get("additional_systems", {}).items():
        if val is not None:
            additional_system_interval.labels(number=num).set(val)

    info = s.get("system_info")
    if info:
        system_info.info(info)

    print(f"State restored from {STATE_PATH}", flush=True)


def save_state():
    """Persist current metric values to disk."""
    try:
        STATE_PATH.write_text(json.dumps({
            "system_status":      _get(system_status),
            "daily_water":        _get(daily_water),
            "flow_since_regen":   _get(flow_since_regen),
            "lifetime_flow":      _get(lifetime_flow),
            "capacity_remaining": _get(capacity_remaining),
            "capacity_at_start":  _get(capacity_at_start),
            "water_28day":        _get(water_28day),
            "salt_28day":         _get(salt_28day),
            "regens_28day":       _get(regens_28day),
            "last_regen_ts":      _get(last_regen_ts),
            "end_of_day":         _get(end_of_day),
            "rssi":               _get(rssi),
            "salt_level":         _get(salt_level),
            "vacation_mode":      _get(vacation_mode),
            "last_contact":       _get(last_contact),
            "additional_systems": {
                num: _get(additional_system_interval.labels(number=num))
                for num in ("1", "2", "3")
            },
            "system_info": _info_labels(),
        }))
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


def _info_labels() -> dict | None:
    try:
        # prometheus_client stores Info labels in _labelnames/_labelvalues
        metrics = list(system_info._metrics.values())
        if metrics:
            return dict(zip(metrics[0]._labelnames, metrics[0]._labelvalues))
    except Exception:
        pass
    return None


@app.on_event("startup")
async def startup():
    load_state()


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
    with LOG_PATH.open("a") as f:
        f.write(json.dumps(entry) + "\n")


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

    system_status.set(float(payload.get("system_status", 0)))
    daily_water.set(float(payload.get("daily_water", 0)))
    flow_since_regen.set(float(payload.get("flow_since_regen", 0)))
    lifetime_flow.set(float(payload.get("lifetime_flow", 0)))
    capacity_remaining.set(float(payload.get("capacity_remaining", 0)))
    capacity_at_start.set(float(payload.get("capacity_at_start", 0)))
    water_28day.set(float(payload.get("water_28_day", 0)))
    salt_28day.set(float(payload.get("salt_28_day", 0)))
    regens_28day.set(float(payload.get("regens_28_day", 0)))
    rssi.set(float(payload.get("rssi", 0)))
    end_of_day.set(float(payload.get("end_of_day", 0)))

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
        salt_level.set(float(payload.get("salt_lbs", 0)))
        vacation_mode.set(float(payload.get("vacation_mode", 0)))
        save_state()

    return PlainTextResponse("OK")


@app.post("/api/device/v1/water_softener/installer_settings_upload")
async def handle_installer_settings(request: Request):
    data = parse_body(await request.body())
    payload = data.get("content", {}).get("payload", {})
    log_entry(request.url.path, data)
    track(request.url.path)

    if payload:
        system_info.info({
            "model":         payload.get("model", ""),
            "firmware":      payload.get("firmware_num", ""),
            "serial":        payload.get("sys_serial_num", ""),
            "install_date":  payload.get("install_date", ""),
            "hardness":      payload.get("hardness", ""),
            "iron_level":    payload.get("iron_level", "").strip(),
            "unit_size":     payload.get("unit_size", ""),
            "starting_cap":  payload.get("starting_cap", ""),
            "max_salt_lbs":  payload.get("max_salt", ""),
        })
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

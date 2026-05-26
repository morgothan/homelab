import json
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, JSONResponse
from prometheus_client import Counter, Gauge, Info, generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response

app = FastAPI()

LOG_PATH = Path("/data/requests.jsonl")
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
rssi = Gauge("rainsoft_wifi_rssi_dbm", "WiFi RSSI (dBm)")
end_of_day = Gauge("rainsoft_end_of_day", "End-of-day rollover flag (1=midnight rollover in progress)")

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
            dt = datetime.strptime(regen_date_str, "%m/%d/%Y").replace(tzinfo=timezone.utc)
            last_regen_ts.set(dt.timestamp())
        except ValueError:
            pass

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

    return PlainTextResponse("OK")


@app.post("/api/device/v1/water_softener/installer_settings_upload")
async def handle_installer_settings(request: Request):
    data = parse_body(await request.body())
    payload = data.get("content", {}).get("payload", {})
    log_entry(request.url.path, data)
    track(request.url.path)

    if payload:
        system_info.info({
            "model": payload.get("model", ""),
            "firmware": payload.get("firmware_num", ""),
            "serial": payload.get("sys_serial_num", ""),
            "install_date": payload.get("install_date", ""),
            "hardness": payload.get("hardness", ""),
            "iron_level": payload.get("iron_level", "").strip(),
            "unit_size": payload.get("unit_size", ""),
            "starting_cap": payload.get("starting_cap", ""),
            "max_salt_lbs": payload.get("max_salt", ""),
        })

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

    return PlainTextResponse("OK")


@app.post("/api/device/v1/water_softener/get_time")
async def handle_get_time(request: Request):
    data = parse_body(await request.body())
    log_entry(request.url.path, data)
    track(request.url.path)
    return JSONResponse({"ts": int(time.time())})


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

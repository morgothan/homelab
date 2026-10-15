"""Infrastructure monitoring collectors: Prometheus, Kopia, Beszel, Jellystat."""

import asyncio
import logging
import ssl
import time
from datetime import datetime, timedelta, timezone

import httpx

log = logging.getLogger(__name__)


# ── Prometheus / infrastructure checks ────────────────────────────────────────

async def _prom_query(client: httpx.AsyncClient, query: str) -> list[dict]:
    """Run a Prometheus instant query; return result list (empty on failure)."""
    from config import PROMETHEUS_URL

    try:
        resp = await client.get(
            f"{PROMETHEUS_URL}/api/v1/query",
            params={"query": query},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") == "success":
            return data["data"]["result"]
    except Exception as e:
        log.debug("Prometheus query failed (%s): %s", query[:50], e)
    return []


def _prom_val(result: list[dict], default: float = 0.0) -> float:
    """Extract scalar value from a single-result Prometheus query."""
    if result:
        try:
            return float(result[0]["value"][1])
        except (KeyError, IndexError, ValueError):
            pass
    return default


async def _check_ups(client: httpx.AsyncClient) -> tuple[list, list]:
    alerts, info = [], []
    charge_r, runtime_r, load_r, ob_r, lb_r = await asyncio.gather(
        _prom_query(client, "nut_battery_charge"),
        _prom_query(client, "nut_battery_runtime_seconds"),
        _prom_query(client, "nut_load"),
        _prom_query(client, 'nut_ups_status{status="OB"}'),
        _prom_query(client, 'nut_ups_status{status="LB"}'),
    )
    if not charge_r:
        return alerts, info
    charge    = _prom_val(charge_r)
    runtime_m = int(_prom_val(runtime_r) / 60)
    load      = _prom_val(load_r)
    on_batt   = _prom_val(ob_r) == 1.0
    low_bat   = _prom_val(lb_r) == 1.0
    ups_name  = charge_r[0]["metric"].get("ups", "ups")
    info.append(
        f"UPS ({ups_name}): {'ON BATTERY — ' if on_batt else ''}"
        f"battery {charge*100:.0f}%, runtime {runtime_m}m, load {load*100:.0f}%"
    )
    if on_batt:
        alerts.append(
            f"UPS ON BATTERY: {ups_name} running on battery power, "
            f"{charge*100:.0f}% charge, {runtime_m}m runtime remaining"
        )
    elif low_bat:
        alerts.append(f"UPS LOW BATTERY: {ups_name} at {charge*100:.0f}%, {runtime_m}m remaining")
    elif charge < 0.5:
        alerts.append(f"UPS WARNING: {ups_name} battery at {charge*100:.0f}%")
    return alerts, info


async def _check_disk(client: httpx.AsyncClient) -> tuple[list, list]:
    from config import NODE_EXPORTER_INSTANCE

    alerts, info = [], []
    host = NODE_EXPORTER_INSTANCE.split(":")[0]
    avail_r, size_r = await asyncio.gather(
        _prom_query(client,
            f"node_filesystem_avail_bytes{{instance='{NODE_EXPORTER_INSTANCE}',fstype='ext4'}}"),
        _prom_query(client,
            f"node_filesystem_size_bytes{{instance='{NODE_EXPORTER_INSTANCE}',fstype='ext4'}}"),
    )
    avail_by_mp = {r["metric"]["mountpoint"]: float(r["value"][1]) for r in avail_r}
    size_by_mp  = {r["metric"]["mountpoint"]: float(r["value"][1]) for r in size_r}
    for mp, avail in avail_by_mp.items():
        size     = size_by_mp.get(mp, 1)
        avail_gb = avail / 1e9
        used_pct = (1 - avail / size) * 100 if size else 0
        info.append(f"Disk {mp} ({host}): {avail_gb:.1f} GB free ({used_pct:.0f}% used)")
        if avail_gb < 5:
            alerts.append(
                f"DISK CRITICAL: {mp} on {host} has {avail_gb:.1f} GB free ({used_pct:.0f}% used)"
            )
        elif avail_gb < 15:
            alerts.append(
                f"DISK WARNING: {mp} on {host} at {used_pct:.0f}% used, {avail_gb:.1f} GB remaining"
            )
    return alerts, info


async def _check_tls_certs(client: httpx.AsyncClient) -> tuple[list, list]:
    alerts, info = [], []
    certs_r  = await _prom_query(client, "traefik_tls_certs_not_after")
    now_ts   = time.time()
    seen_cns: set[str] = set()
    for r in sorted(certs_r, key=lambda x: float(x["value"][1])):
        days_left = (float(r["value"][1]) - now_ts) / 86400
        if days_left >= 21:
            continue
        cn   = r["metric"].get("cn", "unknown")
        sans = r["metric"].get("sans", "")
        key  = f"{cn}|{sans}"
        if key in seen_cns:
            continue
        seen_cns.add(key)
        label = cn if not sans or cn == sans else f"{cn} ({sans})"
        if days_left < 7:
            alerts.append(f"CERT CRITICAL: {label} expires in {days_left:.0f} days")
        else:
            alerts.append(f"CERT WARNING: {label} expires in {days_left:.0f} days")
    return alerts, info


async def _check_adguard_metrics(client: httpx.AsyncClient) -> tuple[list, list]:
    alerts, info = [], []
    queries_r, blocked_r, prot_r = await asyncio.gather(
        _prom_query(client, "adguard_queries"),
        _prom_query(client, "adguard_queries_blocked"),
        _prom_query(client, "adguard_protection_enabled"),
    )
    for r in prot_r:
        if float(r["value"][1]) == 0:
            alerts.append(f"ADGUARD CRITICAL: protection disabled on {r['metric'].get('server','adguard')}")
    queries_by = {r["metric"]["server"]: float(r["value"][1]) for r in queries_r}
    blocked_by = {r["metric"]["server"]: float(r["value"][1]) for r in blocked_r}
    for server, total in sorted(queries_by.items(), key=lambda x: -x[1]):
        blocked   = blocked_by.get(server, 0)
        block_pct = (blocked / total * 100) if total > 0 else 0
        label     = server.replace("http://", "").replace("https://", "")
        info.append(f"AdGuard ({label}): {total/1e6:.1f}M lifetime queries, {block_pct:.1f}% blocked")
    return alerts, info


async def _check_media_pipeline(client: httpx.AsyncClient) -> tuple[list, list]:
    alerts, info = [], []
    sq_r, se_r, sm_r, rq_r, re_r, rm_r = await asyncio.gather(
        _prom_query(client, "sonarr_queue_count"),
        _prom_query(client, "sonarr_queue_error"),
        _prom_query(client, "sonarr_missing_episodes"),
        _prom_query(client, "radarr_queue_count"),
        _prom_query(client, "radarr_queue_error"),
        _prom_query(client, "radarr_missing_movies"),
    )
    if sq_r:
        sonarr_q, sonarr_err, sonarr_miss = int(_prom_val(sq_r)), int(_prom_val(se_r)), int(_prom_val(sm_r))
        info.append(f"Sonarr: {sonarr_q} downloads in queue, {sonarr_err} errors, {sonarr_miss} missing episodes")
        if sonarr_err > 0:
            alerts.append(f"Sonarr: {sonarr_err} queue error(s)")
    if rq_r:
        radarr_q, radarr_err, radarr_miss = int(_prom_val(rq_r)), int(_prom_val(re_r)), int(_prom_val(rm_r))
        info.append(f"Radarr: {radarr_q} downloads in queue, {radarr_err} errors, {radarr_miss} missing movies")
        if radarr_err > 0:
            alerts.append(f"Radarr: {radarr_err} queue error(s)")
    return alerts, info


async def check_prometheus() -> dict:
    """Query Prometheus for infrastructure health metrics.

    Returns {"alerts": [...], "info": [...]} — alerts are noteworthy conditions,
    info lines are always-on statistics for the LLM prompt context.
    """
    out: dict = {"alerts": [], "info": []}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            results = await asyncio.gather(
                _check_ups(client),
                _check_disk(client),
                _check_tls_certs(client),
                _check_adguard_metrics(client),
                _check_media_pipeline(client),
                return_exceptions=True,
            )
        for result in results:
            if isinstance(result, tuple):
                alerts, info = result
                out["alerts"].extend(alerts)
                out["info"].extend(info)
            else:
                log.warning("Prometheus sub-check raised: %s", result)
    except Exception as e:
        log.warning("check_prometheus failed: %s", e)
    return out


async def check_kopia() -> dict:
    """Query the Kopia WebUI API for backup source health.

    Returns {"alerts": [...], "info": [...]} where:
    - alerts: sources with missed backups (> 36h since last snapshot) or errors
    - info: brief summary of all active sources
    """
    from config import KOPIA_PASS, KOPIA_URL, KOPIA_USER

    out: dict = {"alerts": [], "info": []}

    if not KOPIA_PASS:
        return out

    try:
        # Kopia uses a self-signed cert; connection is Docker-internal only.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        async with httpx.AsyncClient(
            verify=ctx, timeout=20, auth=(KOPIA_USER, KOPIA_PASS)
        ) as client:
            r = await client.get(f"{KOPIA_URL}/api/v1/sources")
            r.raise_for_status()
            sources = r.json().get("sources", [])

        now = datetime.now(timezone.utc)
        # Active = last snapshot within 30 days (stale/decommissioned sources are silent)
        active_cutoff = now - timedelta(days=30)
        warn_cutoff   = now - timedelta(hours=36)
        crit_cutoff   = now - timedelta(days=7)

        ok_count   = 0
        warn_srcs  = []
        crit_srcs  = []

        for src_entry in sources:
            src  = src_entry.get("source", {})
            last = src_entry.get("lastSnapshot")
            label = f"{src.get('userName','?')}@{src.get('host','?')}:{src.get('path','?')}"

            if not last:
                continue

            err = last.get("error", "")
            ts_raw = last.get("startTime", "")
            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            except Exception:
                continue

            if ts < active_cutoff:
                continue  # decommissioned/inactive source — don't alert

            if err:
                crit_srcs.append(f"{label}: {err[:100]}")
            elif ts < crit_cutoff:
                age_d = int((now - ts).total_seconds() / 86400)
                crit_srcs.append(f"{label}: no backup in {age_d} days")
            elif ts < warn_cutoff:
                age_h = int((now - ts).total_seconds() / 3600)
                warn_srcs.append(f"{label}: no backup in {age_h}h")
            else:
                ok_count += 1

        total_active = ok_count + len(warn_srcs) + len(crit_srcs)
        if total_active == 0:
            return out

        for msg in crit_srcs:
            out["alerts"].append(f"BACKUP CRITICAL: {msg}")
        for msg in warn_srcs:
            out["alerts"].append(f"BACKUP WARNING: {msg}")

        if ok_count == total_active:
            out["info"].append(f"Kopia backups: all {ok_count} active sources current")
        else:
            out["info"].append(
                f"Kopia backups: {ok_count}/{total_active} sources current"
                + (f", {len(warn_srcs)} warned" if warn_srcs else "")
                + (f", {len(crit_srcs)} critical" if crit_srcs else "")
            )

    except Exception as e:
        log.warning("check_kopia failed: %s", e)

    return out


async def check_beszel() -> dict:
    """Query Beszel for per-host CPU, memory, disk, and uptime status.

    Returns {"alerts": [...], "info": [...]} — alerts for hosts that are down
    or have critically high resource usage; info gives a compact summary.
    """
    from config import BESZEL_EMAIL, BESZEL_PASS, BESZEL_URL

    out: dict = {"alerts": [], "info": []}

    if not BESZEL_EMAIL or not BESZEL_PASS:
        return out

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            auth_r = await client.post(
                f"{BESZEL_URL}/api/collections/users/auth-with-password",
                json={"identity": BESZEL_EMAIL, "password": BESZEL_PASS},
            )
            auth_r.raise_for_status()
            token = auth_r.json().get("token", "")

            sys_r = await client.get(
                f"{BESZEL_URL}/api/collections/systems/records",
                headers={"Authorization": token},
                params={"perPage": 100},
            )
            sys_r.raise_for_status()
            systems = sys_r.json().get("items", [])

        down, high_disk, high_mem, ok = [], [], [], []
        for s in systems:
            name   = s.get("name", "unknown")
            status = s.get("status", "unknown")
            info   = s.get("info") or {}
            cpu    = info.get("cpu", 0)
            mp     = info.get("mp", 0)   # memory %
            dp     = info.get("dp", 0)   # disk %

            if status != "up":
                down.append(f"{name} ({status})")
            elif dp > 90:
                high_disk.append(f"{name}: disk {dp:.0f}%")
            elif mp > 92:
                high_mem.append(f"{name}: mem {mp:.0f}%")
            else:
                ok.append(f"{name} cpu={cpu:.0f}% mem={mp:.0f}% disk={dp:.0f}%")

        for h in down:
            out["alerts"].append(f"HOST DOWN: {h}")
        for h in high_disk:
            out["alerts"].append(f"DISK WARNING: {h}")
        for h in high_mem:
            out["alerts"].append(f"MEMORY WARNING: {h}")

        total = len(systems)
        if down:
            out["info"].append(
                f"Beszel: {len(ok)}/{total} hosts up; DOWN: {', '.join(down)}"
            )
        elif high_disk or high_mem:
            flagged = [h.split(":")[0] for h in high_disk + high_mem]
            out["info"].append(
                f"Beszel: all {total} hosts up; resource alerts: {', '.join(flagged)}"
            )
        else:
            out["info"].append(f"Beszel: all {total} hosts up, resources nominal")

    except Exception as e:
        log.warning("check_beszel failed: %s", e)

    return out


async def check_jellystat() -> dict:
    """Query Jellyfin for active streams and Jellystat for 7-day play statistics.

    Returns {"alerts": [...], "info": [...]} — no alerts (informational only);
    info carries current stream count and 7-day play trend for the LLM.
    """
    from config import JELLYFIN_KEY, JELLYFIN_URL, JELLYSTAT_KEY, JELLYSTAT_URL
    from homelab_news.jellyfin import authorization_headers as jellyfin_auth_headers

    out: dict = {"alerts": [], "info": []}

    if not JELLYFIN_KEY and not JELLYSTAT_KEY:
        return out

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            coros = []
            if JELLYFIN_KEY:
                coros.append(client.get(f"{JELLYFIN_URL}/Sessions",
                                        headers=jellyfin_auth_headers(JELLYFIN_KEY)))
            if JELLYSTAT_KEY:
                coros.append(client.get(f"{JELLYSTAT_URL}/stats/getViewsByLibraryType",
                                        params={"days": 7},
                                        headers={"x-api-token": JELLYSTAT_KEY}))
            results = await asyncio.gather(*coros)

        idx = 0
        if JELLYFIN_KEY:
            sessions_r = results[idx]; idx += 1
            sessions_r.raise_for_status()
            active = [s for s in sessions_r.json() if s.get("NowPlayingItem")]
            transcodes   = sum(1 for s in active if s.get("TranscodingInfo"))
            direct_plays = len(active) - transcodes
            if active:
                parts = []
                if direct_plays: parts.append(f"{direct_plays} direct")
                if transcodes:   parts.append(f"{transcodes} transcode")
                detail = f" ({', '.join(parts)})" if parts else ""
                out["info"].append(
                    f"Jellyfin: {len(active)} active stream{'s' if len(active) != 1 else ''}{detail}"
                )
            else:
                out["info"].append("Jellyfin: no active streams")

        if JELLYSTAT_KEY:
            stats_r = results[idx]
            stats_r.raise_for_status()
            views = stats_r.json()
            total_7d = sum(v for v in views.values() if isinstance(v, (int, float)))
            type_parts = [f"{k}: {v}" for k, v in views.items()
                          if isinstance(v, (int, float)) and v > 0]
            if total_7d > 0:
                out["info"].append(
                    f"Jellyfin (7d): {total_7d} plays"
                    + (f" ({', '.join(type_parts)})" if type_parts else "")
                )

    except Exception as e:
        log.warning("check_jellystat failed: %s", e)

    return out

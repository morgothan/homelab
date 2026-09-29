"""Shared orchestration and compatibility facade.

Historically this was a 4,500-line god module. The cohesive domains have been
extracted into focused modules (``templates``, ``security``, ``containers``,
``media``, ``llm``, ``hindsight``) and are re-exported here so existing callers
keep working during the migration. What remains in this file is the edition
orchestration (``run_news_cycle``, ``generate_newspaper``, periodic summaries)
plus the Prometheus/infra checks that feed the edition.
"""

import asyncio
import json
import logging
import os
import re
import ssl
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

from config import (
    EVENT_LEDGER_FILE, INVESTIGATIONS_FILE, OLLAMA_TIMEOUT, TODAY_FILE,
    UPDATE_DETECTION_STATE_FILE, UPDATES_FILE, VLLM_MODEL, VLLM_URL,
)
from homelab_news.capabilities import configured_capabilities
from homelab_news.configuration import APP_SETTINGS
from operational_coverage import build_operational_alerts_article, select_news_issues
from storage import load_json, save_json

log = logging.getLogger(__name__)

_LLM_URL   = VLLM_URL
_LLM_MODEL = VLLM_MODEL

# ── Compatibility re-exports ─────────────────────────────────────────────────
# The portable domains now live in focused modules; these names are re-exported
# so that ``lib`` remains a stable facade for existing callers and tests.

from articles import SECTION_ORDER  # noqa: E402

from templates import (  # noqa: E402
    _CSS, _FAVICON_SVG,
    alerts_card, containers_card, log_card, masthead_archive, masthead_rolling,
    masthead_today, masthead_wire, nav_bar, page_wrap, render_articles_html,
    render_asn_blocklist_html, render_asn_suggestions_html, render_blotter_html,
    render_blotter_skeleton, render_library_scan_html, render_recent_media_html,
    render_issue_rows, render_bans_card, update_howto, updates_card,
    _render_ban_row,
)

from containers import (  # noqa: E402
    get_container_status, get_container_status_async, get_containers_local,
    get_containers_pct, get_containers_ssh, get_containers_tcp,
    latest_semver_tag, parse_image_ref, remote_digest, _semver_sort_key,
    _semver_tag_pattern,
)

from media import (  # noqa: E402
    build_library_additions_article, fetch_recent_media, library_addition_summaries,
    library_addition_titles, load_media_events, merge_library_additions,
    resolve_jellyfin_links,
)

from security import (  # noqa: E402
    check_docker_logs, check_fail2ban_bans, check_loki, check_asn_blocks,
    enrich_ips, fetch_crowdsec_decisions, LokiCollection, _collect_issues,
    _group_by_ip, _label_sip_phone_prefix, _suggest_asn_blocks,
    _security_prompt_block, _classify_ban, _fetch_loki_complete,
)

from hindsight import (  # noqa: E402
    hindsight_recall, hindsight_retain_newspaper, hindsight_targeted_recall,
    _TARGETED_RECALL_CACHE,
)

from llm import (  # noqa: E402
    generate_homelab_intel, llm_analysis, llm_changelog_analysis,
    _compress_messages, _load_context, _sanitize_for_llm,
    _truncate_to_token_limit,
)

from config import REMOTE_HOSTS  # noqa: E402


def _parse_remote_hosts() -> list[tuple[str, str]]:
    """Compatibility wrapper for :func:`config.parse_remote_hosts`."""
    from config import parse_remote_hosts

    return parse_remote_hosts()


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


# ── Edition generation ────────────────────────────────────────────────────────

def _fmt_section(data: Optional[dict], alerts_hdr: str, info_hdr: Optional[str] = None) -> str:
    if not data:
        return ""
    out: list[str] = []
    if data.get("alerts"):
        out.append(alerts_hdr)
        out.extend(f"  {a}" for a in data["alerts"])
    if data.get("info"):
        if info_hdr:
            out.append(info_hdr)
        out.extend(f"  {i}" for i in data["info"])
    return ("\n" + "\n".join(out)) if out else ""


def _validate_articles(raw: list, max_count: int = 16) -> list[dict]:
    """Validate and clamp LLM article output.

    Enforces field-length limits so oversized injected content cannot be stored
    or displayed. Unknown section values are normalised to City Hall.
    """
    from articles import validate_articles

    return validate_articles(raw, max_count)


def _parse_llm_json(content: str) -> list:
    """Parse LLM output as a JSON array using three progressively looser strategies."""
    from articles import parse_llm_json

    return parse_llm_json(content)


def _ban_summary(bans: list[dict]) -> list[str]:
    """Summarise a ban list into compact strings for LLM context.

    Returns a list of strings like:
      ["22 IPs banned", "top attackers: 185.177.72.17 (env file sweep ×1162),
       185.177.72.38 (env file sweep ×1162), ...", "categories: env file sweep×18,
       PHP exploit probe×2, git exposure scan×1, ..."]
    """
    if not bans:
        return []
    cat_counts: dict[str, int] = defaultdict(int)
    for b in bans:
        cat_counts[b.get("category", "unknown")] += 1

    top = sorted(bans, key=lambda x: x.get("hit_count", 0), reverse=True)[:10]
    top_str = ", ".join(
        f"{b['ip']} ({b.get('category', 'scan')} \xd7{b.get('hit_count', 0)})"
        for b in top
    )
    cat_str = ", ".join(
        f"{cat}\xd7{n}"
        for cat, n in sorted(cat_counts.items(), key=lambda x: -x[1])
    )
    parts = [f"{len(bans)} IPs banned"]
    if top_str:
        parts.append(f"top attackers: {top_str}")
    if len(bans) > 1:
        parts.append(f"categories: {cat_str}")
    return parts


async def generate_newspaper(
    docker_issues: list[dict],
    loki_issues: list[dict],
    update_hosts: dict,
    unhealthy_names: list[str],
    bans: Optional[list[dict]] = None,
    probes: Optional[list[dict]] = None,
    prometheus: Optional[dict] = None,
    kopia: Optional[dict] = None,
    beszel: Optional[dict] = None,
    jellystat: Optional[dict] = None,
    asn_suggestions: Optional[list[dict]] = None,
    media_events: Optional[list[dict]] = None,
    correlations: Optional[list[dict]] = None,
    targeted_history: str = "",
) -> Optional[list[dict]]:
    from security import _SECURITY_NOISE, _security_prompt_block

    # Strip fail2ban/WAF noise from raw log issues — these events are already
    # captured accurately in the structured security block below. Leaving them
    # in causes the LLM to re-interpret scanner 403 blocks as "authentication
    # failures" or "credential attacks".
    clean_docker = [i for i in docker_issues if not _SECURITY_NOISE.search(i.get("message", ""))]
    clean_loki   = [i for i in loki_issues   if not _SECURITY_NOISE.search(i.get("message", ""))]
    selected_docker = select_news_issues(clean_docker)
    selected_loki = select_news_issues(clean_loki)
    operational_alert = build_operational_alerts_article(clean_docker + clean_loki)

    lines: list[str] = []
    if unhealthy_names:
        lines.append("UNHEALTHY CONTAINERS: " + ", ".join(unhealthy_names))
    else:
        lines.append("CONTAINER HEALTH: all containers running normally")

    for label, host in update_hosts.items():
        if host.get("status", "done") != "done":
            continue
        for r in host.get("results", []):
            if r["status"] != "update_available":
                continue
            ver = f", update available: {r['new_version']}" if r.get("new_version") else ""
            line = f"UPDATE AVAILABLE (not yet applied) on {label}: {r['container']} ({r['image']}{ver})"
            cl = r.get("changelog_analysis")
            if cl:
                # Sanitize before re-embedding: this text is LLM-generated from
                # external GitHub release notes and is a second-order injection path.
                line += f" — CHANGELOG: {_sanitize_for_llm(cl, max_len=200)}"
            lines.append(line)

    if selected_docker:
        lines.append("\nSELECTED DOCKER LOG ISSUES:")
        for i in selected_docker:
            msg = _sanitize_for_llm(_label_sip_phone_prefix(i['message']), max_len=120)
            lines.append(f"  [{i['source']} {i['level'].upper()} x{i['count']}; {i['selection_reason']}] {msg}")

    if selected_loki:
        lines.append("\nSELECTED NETWORK/SYSLOG ISSUES:")
        for i in selected_loki:
            msg = _sanitize_for_llm(_label_sip_phone_prefix(i['message']), max_len=120)
            lines.append(f"  [{i['source']} {i['level'].upper()} x{i['count']}; {i['selection_reason']}] {msg}")

    lines.append("\n" + _security_prompt_block(bans or [], probes or [], asn_suggestions))

    for block in [
        _fmt_section(prometheus, "PROMETHEUS ALERTS:", "PROMETHEUS METRICS:"),
        _fmt_section(kopia,      "BACKUP ALERTS:"),
        _fmt_section(beszel,     "HOST ALERTS:"),
        _fmt_section(jellystat,  "JELLYFIN ALERTS:", "JELLYFIN ACTIVITY:"),
    ]:
        if block:
            lines.append(block)

    situation = "\n".join(lines)
    if correlations:
        from correlations import format_correlations

        situation += (
            "\n\nCROSS-SOURCE TIMING CORRELATIONS (authoritative timing only; do not claim causation):\n"
            + format_correlations(correlations)
        )
    context = _load_context()
    context_block = f"HOMELAB CONTEXT (use this to write accurate service names and understand what's normal):\n{context}\n\n" if context else ""
    recalled = targeted_history or await hindsight_recall(situation[:2000])
    recalled_block = (
        f"SERVICE-SPECIFIC PAST CONTEXT (from memory — reference if directly relevant, e.g. "
        f"a recurring issue or 'as previously reported'; don't force it):\n{recalled}\n\n"
        if recalled else ""
    )
    system = (
        "You are the editor of a homelab status newspaper covering a full day of events.\n\n"
        + context_block
        + recalled_block
        + "LAYOUT: The page has one full-width Lead Story at the top, then each section shows its\n"
        "articles side-by-side in columns. Write 1–3 articles per section that has noteworthy\n"
        "activity — aim for 8–16 articles total. The FIRST article in your array is the Lead Story\n"
        "(make it the most important event of the day). Omit sections with nothing to report.\n\n"
        "SECURITY INTERPRETATION GUIDE — read before writing any security article:\n"
        "- PATH SCANNERS = automated bots probing for vulnerable files (.env, .git, wp-admin, etc.).\n"
        "  These are NOT login failures. Write as 'scanning', 'probing', or 'vulnerability sweep'.\n"
        "  A scanner hitting 50 paths is not 'attempting to access protected resources'.\n"
        "- CREDENTIAL ATTACKS = actual brute-force on the Authelia login endpoint (/api/firstfactor).\n"
        "  Only use 'authentication attack', 'credential stuffing', or 'login brute-force' for this.\n"
        "- HTTP 403 in raw logs = a bot was blocked by the scanner-block router, NOT a failed login.\n"
        "- The SECURITY block is pre-classified and authoritative. Base all security articles on it.\n"
        "  Do not write security articles from raw FailToBan or WAF log lines — those are already\n"
        "  summarised in the SECURITY block and will cause misclassification if used directly.\n"
        "- ASN BLOCK CANDIDATES = autonomous systems with multiple banned IPs, identified for manual review.\n"
        "  If present, write one Public Safety article: name the ASN(s), IP count, and that manual\n"
        "  review is recommended. Do NOT suggest or imply automatic blocking.\n\n"
        "OPERATIONAL LOG INTERPRETATION GUIDE — read before writing any infra/syslog article:\n"
        "- A HIGH-VOLUME line from ONE daemon on ONE host (e.g. ntpd logging 'network unreachable'\n"
        "  every poll) = a stuck or misconfigured daemon on that host. It is NOT a network outage,\n"
        "  connectivity loss, or uplink/switch fault. Report the host, the daemon, the message, and\n"
        "  the rate; say it is not service-impacting unless a correlated alert says otherwise.\n"
        "- Do NOT infer cascading failures, and do NOT recommend broad investigations ('check the\n"
        "  uplink and switch port health') that the evidence does not support.\n"
        "- A steady rate with no start spike and no correlated impact = a persistent condition to\n"
        "  fix, not an incident. One short factual article ('Upstairs AP's ntpd has logged send\n"
        "  failures at ~110/hr for weeks; time sync still working; needs a config fix'), not a\n"
        "  lead story. Escalation labels from the deterministic layer name the condition, not its\n"
        "  blast radius — 'NTP time-sync failures on one host' is exactly that, nothing wider.\n\n"
        "Rules:\n"
        "- 'UPDATE AVAILABLE' lines are PENDING updates that have NOT been installed — nothing has\n"
        "  been upgraded, rebuilt, or refreshed yet. Write these as availability, not completed action:\n"
        "  say 'Update Available for X' or 'X Update Pending', never 'X Jumps to', 'X Upgraded to',\n"
        "  'saw an update', 'now running', or other past-tense/completed phrasing.\n"
        "- Group related items into one article. 'Five *arr apps have routine updates' = 1 article, not 5.\n"
        "- Within a section, order by importance: errors first, routine updates last.\n"
        "- Headline: punchy, specific, real-newspaper style. Name the attack type and scale.\n"
        "  Good: 'Scanner Sweeps 56 .env Paths, Earns 24h Cloudflare Block'\n"
        "  Bad: 'System Experiencing Authentication Failures'\n"
        "- Every article blurb: 2–3 sentences, AP wire style, specific counts and service names.\n"
        "- If something is completely fine, skip it — don't pad with 'all clear' articles.\n"
        "- Assign each article a section. Use exactly one of:\n"
        "    City Hall        — container health, image updates, service restarts\n"
        "    Public Safety    — security attacks, IP bans, scanner activity\n"
        "    Weather          — UPS/power events, system performance\n"
        "    City Archives    — backup and storage health\n"
        "    Arts & Entertainment — Sonarr, Radarr, Jellystat, Jellyfin, media pipeline\n"
        "    Public Works     — DNS, networking, Traefik configuration\n"
        "  Default to City Hall if unsure.\n"
        "- Output ONLY a valid JSON array. No markdown fences, no explanation, no preamble.\n"
        "  Format: [{\"headline\": \"...\", \"blurb\": \"...\", \"section\": \"City Hall\"}]"
    )
    messages = _compress_messages([
        {"role": "system", "content": system},
        {"role": "user",   "content": f"CURRENT HOMELAB STATUS:\n{situation}"},
    ])
    try:
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
            resp = await client.post(
                f"{_LLM_URL}/v1/chat/completions",
                json={
                    "model": _LLM_MODEL,
                    "messages": messages,
                    "stream": False,
                    "max_tokens": 2500,
                    "temperature": 0.3,
                    "chat_template_kwargs": {"enable_thinking": False},
                },
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"].strip()
            articles = _parse_llm_json(content)
            if articles:
                valid = _validate_articles(articles, max_count=15 if operational_alert else 16)
                if valid:
                    if operational_alert:
                        valid.append(operational_alert)
                    return valid
    except Exception as e:
        log.warning("Newspaper generation failed (%s): %s", type(e).__name__, e)
    return [operational_alert] if operational_alert else None


async def generate_periodic_summary(
    scope: str,           # "week" | "month" | "year"
    period_label: str,    # human-readable, e.g. "May 2026" or "2026-05-11 to 2026-05-17"
    entries: list[dict],  # [{"period": str, "articles": [{headline, blurb}, ...]}]
) -> Optional[list[dict]]:
    # Build a sanitized JSON structure — SmartCrusher can deduplicate repeated article shapes
    sanitized_entries = []
    for entry in entries:
        articles = [
            {
                "headline": _sanitize_for_llm(a.get("headline", ""), max_len=200),
                "blurb":    _sanitize_for_llm(a.get("blurb", ""), max_len=200),
            }
            for a in (entry.get("articles") or [])
        ]
        entry_bans = entry.get("ban_summary") or []
        if not entry_bans:
            raw_bans = entry.get("bans") or []
            if raw_bans:
                entry_bans = _ban_summary(raw_bans)
        sanitized_entries.append({
            "period":   entry["period"],
            "articles": articles,
            "security": "; ".join(entry_bans) if entry_bans else None,
        })

    scope_map = {
        "week":  ("weekly digest",  "daily editions"),
        "month": ("monthly review", "weekly digests"),
        "year":  ("annual report",  "monthly reviews"),
    }
    title, source = scope_map.get(scope, ("digest", "editions"))

    ctx = _load_context()
    ctx_block = f"HOMELAB CONTEXT (use for accurate service names):\n{ctx}\n\n" if ctx else ""
    system = (
        f"You are the editor writing the {title} for a homelab status newspaper.\n"
        + ctx_block
        + f"Below are summaries from the {source} covering: {period_label}.\n\n"
        "Identify TRENDS and PATTERNS across this period:\n"
        "- Issues that recurred multiple times (state how often)\n"
        "- Things that got better or were resolved\n"
        "- Things that got worse or are persisting\n"
        "- Periodic patterns (e.g. 'every weekend', 'Tuesdays consistently')\n"
        "- One-time significant events worth remembering\n"
        "- Security: repeat-offender IPs banned across multiple days, trends in scan volume,\n"
        "  common attack patterns (e.g. credential stuffing, .env scanning)\n\n"
        "Rules:\n"
        "- Write 3–6 articles. Skip anything minor that appeared only once.\n"
        "- Headlines: name the service and the trend, not vague phrases.\n"
        "- Blurbs: 2–3 sentences, quantify recurrence where possible.\n"
        "- Output ONLY a valid JSON array. No markdown, no preamble.\n"
        "  Format: [{\"headline\": \"...\", \"blurb\": \"...\", \"section\": \"City Hall\"}]"
    )
    messages = _compress_messages([
        {"role": "system", "content": system},
        {"role": "user",   "content": json.dumps(sanitized_entries, indent=2)},
    ])
    try:
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
            resp = await client.post(
                f"{_LLM_URL}/v1/chat/completions",
                json={
                    "model": _LLM_MODEL,
                    "messages": messages,
                    "stream": False,
                    "max_tokens": 3000,
                    "temperature": 0.3,
                    "chat_template_kwargs": {"enable_thinking": False},
                },
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"].strip()
            articles = _parse_llm_json(content)
            if articles:
                valid = _validate_articles(articles, max_count=10)
                if valid:
                    return valid
    except Exception as e:
        log.warning("Periodic summary failed (%s): %s", type(e).__name__, e)
    return None


# ── Shared news-cycle worker ─────────────────────────────────────────────────

async def run_news_cycle(since: datetime, target_file: str) -> None:
    """Gather data, two-phase save (preserve existing newspaper), then run LLM.

    Shared by today.py (since=midnight, target=TODAY_FILE) and rolling.py
    (since=now-ROLLING_HOURS, target=ROLLING_FILE). The only difference between
    those two workers is the time window and output path.
    """
    since_ts = int(since.timestamp())
    log.info("run_news_cycle: %s → %s", since.strftime("%Y-%m-%d %H:%M UTC"), target_file)

    features = APP_SETTINGS.features

    async def disabled(value):
        return value

    disabled_loki = LokiCollection([], {
        "collection_complete": True,
        "disabled": True,
        "raw_entries": 0,
        "window_start": since.isoformat(),
        "window_end": datetime.now(timezone.utc).isoformat(),
    })

    (docker_issues, loki_issues, (bans, probes),
     prometheus, kopia, beszel, jellystat) = await asyncio.gather(
        check_docker_logs(since_ts=since_ts) if features.docker else disabled([]),
        check_loki(start=since) if features.loki else disabled(disabled_loki),
        check_fail2ban_bans() if features.security else disabled(([], [])),
        check_prometheus() if features.prometheus else disabled({}),
        check_kopia() if features.backups else disabled({}),
        check_beszel() if features.host_monitoring else disabled({}),
        check_jellystat() if features.media else disabled({}),
    )
    loki_collection = getattr(loki_issues, "metadata", {
        "collection_complete": True,
        "raw_entries": sum(int(issue.get("count") or 1) for issue in loki_issues),
    })
    capabilities = configured_capabilities(features)
    capabilities["loki"]["healthy"] = bool(loki_collection.get("collection_complete"))
    capabilities["loki"]["detail"] = (
        "disabled" if not features.loki else
        f"{loki_collection.get('raw_entries', 0)} entries; complete={loki_collection.get('collection_complete')}"
    )

    asn_suggestions = _suggest_asn_blocks(bans)
    # Library additions are a seven-day feature, independent of the shorter
    # daily/rolling operational-log window used by the rest of the edition.
    media_events = (
        await fetch_recent_media(datetime.now(timezone.utc) - timedelta(days=7))
        if features.media else []
    )
    if asn_suggestions:
        log.info("ASN block candidates: %s", ", ".join(s["asn"] for s in asn_suggestions))

    # Phase 1: persist raw data immediately; keep the previous newspaper and its
    # successful build timestamp while the LLM re-renders.  built_at must only
    # move when a new edition is successfully generated, otherwise the UI would
    # present stale articles as fresh.
    existing = load_json(target_file) or {}
    attempt_at = datetime.now(timezone.utc).isoformat()

    from correlations import (
        append_events, build_cycle_events, correlate_events, events_since,
        record_update_detections, targeted_recall_queries,
    )

    cycle_events = build_cycle_events(
        docker_issues=docker_issues,
        loki_issues=loki_issues,
        bans=bans,
        observed_at=attempt_at,
    )
    cycle_events += record_update_detections(
        (load_json(UPDATES_FILE) or {}).get("hosts", {}),
        UPDATE_DETECTION_STATE_FILE,
        attempt_at,
    )
    ledger = append_events(EVENT_LEDGER_FILE, cycle_events)
    correlation_cutoff = since - timedelta(minutes=10)
    recent_events = events_since(ledger[:1000], correlation_cutoff)
    correlations = correlate_events(recent_events)
    save_json(target_file, {
        "built_at":        existing.get("built_at"),
        "last_attempt_at": attempt_at,
        "generation_status": "updating",
        "newspaper":       existing.get("newspaper"),
        "docker_issues":   docker_issues,
        "docker_analysis": existing.get("docker_analysis"),
        "loki_issues":     loki_issues,
        "loki_collection": loki_collection,
        "loki_analysis":   existing.get("loki_analysis"),
        "bans":            bans,
        "asn_suggestions": asn_suggestions,
        "media_events":    media_events,
        "correlations":    correlations,
        "investigations":  existing.get("investigations") or [],
        "capabilities":    capabilities,
        "configuration":   APP_SETTINGS.public_dict(),
    })

    unhealthy, _, _ = await get_container_status_async()
    unhealthy_names = [c.name for c in unhealthy]
    updates_raw  = load_json(UPDATES_FILE) or {}
    update_hosts = updates_raw.get("hosts", {})
    recall_queries = targeted_recall_queries(cycle_events, correlations)
    targeted_history = await hindsight_targeted_recall(recall_queries)

    # Phase 2: LLM calls — run sequentially to avoid concurrent KV-cache spikes on vLLM.
    # (vLLM batches concurrent requests together; 3 simultaneous prefills exhaust memory.)
    docker_analysis = await llm_analysis(docker_issues, "Docker container")
    loki_analysis   = await llm_analysis(loki_issues,   "network/syslog (from Loki)")
    newspaper = await generate_newspaper(
        docker_issues, loki_issues, update_hosts, unhealthy_names,
        bans, probes, prometheus, kopia, beszel, jellystat, asn_suggestions, media_events,
        correlations, targeted_history,
    )
    log.info("run_news_cycle complete: %d articles, %d bans",
             len(newspaper) if newspaper else 0, len(bans))

    if newspaper:
        built_at = datetime.now(timezone.utc).isoformat()
        articles = merge_library_additions(newspaper, media_events)
        generation_status = "ok"
        generation_error = None
    else:
        # An unavailable LLM must not erase the last good edition.  The web UI
        # uses generation_status to identify the retained articles as stale.
        built_at = existing.get("built_at")
        articles = merge_library_additions(existing.get("newspaper") or [], media_events)
        generation_status = "stale"
        generation_error = "LLM generation unavailable"
        log.warning("News generation unavailable; preserving previous edition in %s", target_file)

    investigations = existing.get("investigations") or []
    if getattr(features, "investigations", True) and newspaper:
        from investigations import investigate_edition

        investigations = await investigate_edition(
            articles=articles,
            docker_issues=docker_issues,
            loki_issues=loki_issues,
            events=ledger[:1000],
            correlations=correlations,
            cache_path=INVESTIGATIONS_FILE,
            llm_url=VLLM_URL,
            llm_model=VLLM_MODEL,
            llm_timeout=OLLAMA_TIMEOUT,
        )

    result = {
        "built_at":        built_at,
        "last_attempt_at": attempt_at,
        "generation_status": generation_status,
        "newspaper":       articles,
        "docker_issues":   docker_issues,
        "docker_analysis": docker_analysis,
        "loki_issues":     loki_issues,
        "loki_collection": loki_collection,
        "loki_analysis":   loki_analysis,
        "bans":            bans,
        "asn_suggestions": asn_suggestions,
        "media_events":    media_events,
        "correlations":    correlations,
        "investigations":  investigations,
        "capabilities":    capabilities,
        "configuration":   APP_SETTINGS.public_dict(),
    }
    if generation_error:
        result["generation_error"] = generation_error
    save_json(target_file, result)


# ── Worker loop helper ───────────────────────────────────────────────────────

async def run_loop(fn, interval: int, log=None) -> None:
    from runtime import run_loop as run_worker_loop

    await run_worker_loop(fn, interval, log)


# ── GitHub release notes ──────────────────────────────────────────────────────

async def fetch_github_release_notes(source_url: str) -> Optional[tuple[str, str]]:
    from config import GITHUB_TOKEN

    m = re.match(r'https?://github\.com/([^/]+/[^/#?]+?)(?:\.git)?/?(?:[#?].*)?$', source_url)
    if not m:
        return None
    repo = m.group(1)
    headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "homelab-monitor/1.0"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"https://api.github.com/repos/{repo}/releases/latest",
                                    headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("tag_name", ""), (data.get("body") or "").strip()
            log.debug("GitHub releases %s -> HTTP %d", repo, resp.status_code)
    except Exception as e:
        log.debug("GitHub release fetch failed for %s: %s", repo, e)
    return None

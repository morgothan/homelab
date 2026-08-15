"""Web server — reads /data/*.json and serves HTML. No LLM dependency."""

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Optional

from html import escape as _h

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

from lib import (
    REFRESH_INTERVAL, UPDATE_INTERVAL, LOG_HOURS, ROLLING_HOURS, SITE_NAME,
    TODAY_FILE, ROLLING_FILE, ARCHIVE_DIR, ARCHIVE_INDEX, UPDATES_FILE, PERIODIC_FILE, HOMELAB_INTEL_FILE,
    IP_INTEL_FILE, LIBRARY_SCAN_FILE, MEDIA_EVENTS_FILE,
    _FAVICON_SVG, _CSS,
    load_json, save_json, get_container_status, get_container_status_async, check_fail2ban_bans, enrich_ips,
    _suggest_asn_blocks, check_asn_blocks,
    page_wrap, nav_bar, masthead_today, masthead_rolling, masthead_archive, masthead_wire,
    render_articles_html, render_blotter_html, render_blotter_skeleton,
    render_asn_suggestions_html, render_asn_blocklist_html, render_library_scan_html,
    _render_ban_row,
    log_card, containers_card, updates_card, update_howto,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = FastAPI()

_MEDIA_EVENT_LIMIT = 500

# Blotter cache — check_fail2ban_bans reads up to 60 MB of access log on every call.
# Cache the result for BLOTTER_TTL seconds; bans change at most every few minutes.
_blotter_cache: Optional[tuple[list, list, float]] = None  # (bans, probes, ts)
BLOTTER_TTL = 60


def _init_page() -> str:
    body = (
        '<header class="mast"><hr class="rule-dbl">'
        f'<div class="mast-name">{SITE_NAME}</div>'
        '<div class="mast-sub">Homelab Intelligence Dispatch &mdash; Est. 2026</div>'
        '</header>'
        '<div style="text-align:center;margin-top:60px;font-family:\'Courier New\',monospace">'
        '<p style="color:var(--gold);font-size:1rem">Initializing&#x2026;</p>'
        '<p style="color:var(--muted);font-size:12px;margin-top:8px">'
        'First edition ready in a few minutes</p>'
        '</div>'
    )
    return page_wrap(body, refresh=30)


def _status_bar(
    n_running: int,
    unhealthy: list,
    update_hosts: dict,
    n_issues: int,
    issues_label: str,
) -> str:
    hosts = {k: v for k, v in update_hosts.items() if k != "_checked_at"}
    pending: list[str] = []
    for host, hdata in hosts.items():
        for r in hdata.get("results", []):
            if r["status"] != "update_available":
                continue
            ver = f" → {r['new_version']}" if r.get("new_version") else ""
            line = f"{host}/{r['container']}{ver}"
            cl = r.get("changelog_analysis")
            if cl:
                line += f"\n  {cl[:120]}"
            pending.append(line)
    n_updates = len(pending)
    n_unhealthy = len(unhealthy)

    def _dot(cls: str, text: str) -> str:
        return f'<span class="{cls}">{text}</span>'

    parts = [_dot("c-ok" if not n_unhealthy else "c-err",
                  f"{'✓' if not n_unhealthy else '✗'} {n_running} containers")]
    if n_unhealthy:
        parts.append(_dot("c-err", f"⚠ {n_unhealthy} unhealthy"))
    if n_updates:
        tip = _h("\n".join(pending))
        parts.append(f'<span class="c-warn has-tip" data-tip="{tip}">{n_updates} image updates available</span>')
    else:
        parts.append(_dot("c-ok", "all images current"))
    if n_issues:
        parts.append(f"<span>{n_issues} {issues_label}</span>")
    else:
        parts.append(_dot("c-ok", f"no {issues_label}"))
    return '<div class="np-status">' + "".join(parts) + '</div>'


def _built_at_text(record: dict) -> str:
    built_at = record.get("built_at", "")
    if built_at:
        return built_at[0:16].replace("T", " ") + " UTC"
    return "unknown time"


@app.post("/api/events/seerr")
async def receive_seerr_event(request: Request):
    """Receive Seerr's generic webhook and retain a bounded event history."""
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)
    if not isinstance(payload, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)

    event = str(payload.get("event") or payload.get("notification_type") or "").strip()
    subject = str(payload.get("subject") or "").strip()
    message = str(payload.get("message") or "").strip()
    if not any((event, subject, message)):
        return JSONResponse({"error": "event, subject, or message required"}, status_code=400)

    record = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "notification_type": str(payload.get("notification_type") or "")[:120],
        "event": event[:120],
        "subject": subject[:300],
        "message": message[:2000],
    }
    events = load_json(MEDIA_EVENTS_FILE) or []
    if not isinstance(events, list):
        events = []
    events.append(record)
    save_json(MEDIA_EVENTS_FILE, events[-_MEDIA_EVENT_LIMIT:])
    return JSONResponse({"accepted": True}, status_code=202)


@app.get("/")
async def index():
    today = load_json(TODAY_FILE)
    updates_raw = load_json(UPDATES_FILE) or {}
    unhealthy, _, n_running = await get_container_status_async()
    update_hosts = updates_raw.get("hosts", {})
    if updates_raw.get("checked_at"):
        update_hosts["_checked_at"] = updates_raw["checked_at"][11:16] + " UTC"

    if today is None:
        return Response(content=_init_page(), media_type="text/html; charset=utf-8")

    newspaper = today.get("newspaper")
    stale = today.get("generation_status") == "stale" and bool(newspaper)
    docker_issues = today.get("docker_issues") or []
    loki_issues   = today.get("loki_issues") or []

    if newspaper:
        articles_html = render_articles_html(newspaper)
        page_refresh  = REFRESH_INTERVAL
    elif newspaper == []:
        articles_html = (
            '<div class="np-pending">'
            f'Edition unavailable — next update in {UPDATE_INTERVAL // 60} min<br>'
            '<small style="font-size:0.75rem">'
            '<a href="/current" style="color:var(--gold2)">View rolling report</a>'
            '</small></div>'
        )
        page_refresh = UPDATE_INTERVAL
    else:
        articles_html = (
            '<div class="np-pending">'
            "The newsroom is preparing today's edition&#x2026;<br>"
            '<small style="font-size:0.75rem">Check back in a few minutes</small>'
            '</div>'
        )
        page_refresh = 30

    n_issues = len(docker_issues) + len(loki_issues)
    status = _status_bar(n_running, unhealthy, update_hosts, n_issues, "log issues today")
    body = (
        masthead_today(_built_at_text(today), stale=stale)
        + nav_bar("front")
        + articles_html
        + status
    )
    return Response(content=page_wrap(body, refresh=page_refresh),
                    media_type="text/html; charset=utf-8")


@app.get("/current")
async def current_events():
    rolling = load_json(ROLLING_FILE)
    updates_raw = load_json(UPDATES_FILE) or {}
    unhealthy, starting, n_running = await get_container_status_async()
    update_hosts = updates_raw.get("hosts", {})
    if updates_raw.get("checked_at"):
        update_hosts["_checked_at"] = updates_raw["checked_at"][11:16] + " UTC"

    if rolling is None:
        return Response(content=_init_page(), media_type="text/html; charset=utf-8")

    newspaper     = rolling.get("newspaper")
    docker_issues = rolling.get("docker_issues") or []
    loki_issues   = rolling.get("loki_issues") or []
    docker_analysis = rolling.get("docker_analysis")
    loki_analysis   = rolling.get("loki_analysis")
    now_str = _built_at_text(rolling)
    stale = rolling.get("generation_status") == "stale" and bool(newspaper)

    if newspaper:
        articles_html = render_articles_html(newspaper)
        page_refresh  = REFRESH_INTERVAL
    elif newspaper == []:
        articles_html = f'<div class="np-pending">Report unavailable — refreshing in {REFRESH_INTERVAL // 60} min</div>'
        page_refresh  = REFRESH_INTERVAL
    else:
        articles_html = (
            '<div class="np-pending">Preparing live report&#x2026;<br>'
            '<small style="font-size:0.75rem">Check back in a few minutes</small></div>'
        )
        page_refresh = 30

    body = (
        masthead_rolling(now_str, stale=stale)
        + nav_bar("current")
        + articles_html
        + '<details class="np-section" open>'
        + '<summary class="np-dispatch-head">Field Dispatches</summary>'
        + '<div class="grid" style="margin-top:16px">'
        + containers_card(unhealthy, starting, n_running)
        + updates_card(update_hosts)
        + log_card("Docker Container Logs", f"Last {ROLLING_HOURS}h", docker_issues, docker_analysis)
        + log_card("Network &amp; Syslog", f"Last {ROLLING_HOURS}h &nbsp;&middot;&nbsp; via Loki", loki_issues, loki_analysis)
        + '</div></details>'
    )
    return Response(content=page_wrap(body, refresh=page_refresh),
                    media_type="text/html; charset=utf-8")


@app.get("/wire")
async def wire_reports():
    intel = load_json(HOMELAB_INTEL_FILE)
    updates_raw = load_json(UPDATES_FILE) or {}
    update_hosts = updates_raw.get("hosts", {})

    if intel is None and not update_hosts:
        return Response(content=_init_page(), media_type="text/html; charset=utf-8")

    checked_at = ""
    if intel and intel.get("checked_at"):
        raw = intel["checked_at"]
        checked_at = raw[0:16].replace("T", " ") + " UTC"
    elif updates_raw.get("checked_at"):
        raw = updates_raw["checked_at"]
        checked_at = raw[0:16].replace("T", " ") + " UTC"

    articles = (intel or {}).get("articles") or []
    sources  = (intel or {}).get("sources", {})

    if articles:
        articles_html = render_articles_html(articles)
    elif intel is not None:
        articles_html = (
            '<div class="np-pending">'
            f'Wire desk is compiling the next bulletin&#x2026;<br>'
            '<small style="font-size:0.75rem">Check back in a few minutes</small>'
            '</div>'
        )
    else:
        articles_html = (
            '<div class="np-pending">Initializing wire reports&#x2026;<br>'
            '<small style="font-size:0.75rem">First check runs at startup</small></div>'
        )

    # Source status grid
    source_rows: list[str] = []
    for key, src in sources.items():
        raw_label = src.get("label", key)
        lbl    = _h(raw_label)
        status = src.get("status", "unknown")
        updates = src.get("updates", [])
        ts_str  = src.get("ts", "")
        ts_disp = _h(ts_str[11:16]) if ts_str else ""

        if status == "error":
            err = _h(src.get("error", "unknown")[:60])
            row_body = f'<span class="c-warn">&#x26a0; check failed: {err}</span>'
        elif updates:
            items = []
            for u in updates[:5]:
                pkg = _h(u.get("package") or u.get("app", "?"))
                new = _h(u.get("new_version", "?"))
                items.append(f'<span class="c-warn">{pkg} &#x2192; {new}</span>')
            row_body = " &nbsp; ".join(items)
        else:
            row_body = '<span class="c-ok">&#x2713; current</span>'

        lbl_cls = "c-gold has-tip" if updates else "c-gold"
        tip_attr = f' data-tip="{_h(update_howto(source_label=raw_label))}"' if updates else ""
        source_rows.append(
            '<div class="upd">'
            f'<span class="{lbl_cls}"{tip_attr}>{lbl}'
            + (f'<span class="c-dim" style="font-size:11px"> &mdash; {ts_disp}</span>' if ts_disp else '')
            + f'</span>{row_body}</div>'
        )

    # Docker image updates summary
    docker_rows: list[str] = []
    for label, host in update_hosts.items():
        available = [r for r in host.get("results", []) if r["status"] == "update_available"]
        if not available:
            continue
        for r in available[:5]:
            ver = f" &#x2192; {_h(r['new_version'])}" if r.get("new_version") else ""
            tip = _h(update_howto(container=r["container"], host=label))
            docker_rows.append(
                '<div class="upd">'
                f'<span class="c-blue has-tip" data-tip="{tip}">{_h(label)}/{_h(r["container"])}</span>'
                f'<span class="c-dim">{_h(r["image"])}{ver}</span>'
                '</div>'
            )

    dispatches = ""
    if source_rows or docker_rows:
        all_rows = source_rows + (
            ['<hr class="rule-sng" style="margin:8px 0">'] + docker_rows if docker_rows else []
        )
        dispatches = (
            '<details class="np-section" open>'
            '<summary class="np-dispatch-head">Sources &amp; Status</summary>'
            '<div style="margin-top:12px">'
            + "<br>".join(all_rows)
            + '</div></details>'
        )

    body = masthead_wire(checked_at or "pending") + nav_bar("wire") + articles_html + dispatches
    return Response(content=page_wrap(body, refresh=UPDATE_INTERVAL),
                    media_type="text/html; charset=utf-8")


@app.get("/blotter")
async def blotter():
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    body = masthead_rolling(now_str) + nav_bar("blotter") + render_blotter_skeleton()
    return Response(content=page_wrap(body), media_type="text/html; charset=utf-8")


_CS_PAGE = 50  # rows per page for CrowdSec infinite scroll


@app.get("/api/bans")
async def api_bans():
    global _blotter_cache
    now = time.monotonic()
    if _blotter_cache is None or now - _blotter_cache[2] > BLOTTER_TTL:
        bans, probes = await check_fail2ban_bans()
        _blotter_cache = (bans, probes, now)
    else:
        bans, probes, _ = _blotter_cache
    ip_cache = load_json(IP_INTEL_FILE) or {}
    intel = {b["ip"]: ip_cache.get(b["ip"], {}) for b in bans}
    cf_bans = [b for b in bans if b.get("source") != "crowdsec"]
    cs_bans = [b for b in bans if b.get("source") == "crowdsec"]
    # Only query AbuseIPDB for IPs that actually connected (cf-fail2ban + probes);
    # CrowdSec preemptive blocks never touched the server so skip them there.
    cf_ban_ips = {b["ip"] for b in cf_bans}
    asyncio.create_task(enrich_ips([b["ip"] for b in bans], abuse_only_ips=cf_ban_ips))
    asn_suggestions = _suggest_asn_blocks(bans)
    asn_blocks      = check_asn_blocks()
    # Return only the first page of CS rows; JS fetches more via /api/cs-bans
    first_cs = cs_bans[:_CS_PAGE]
    return JSONResponse({
        "cf":                   [_render_ban_row(b, intel) for b in cf_bans],
        "cs":                   [_render_ban_row(b, intel) for b in first_cs],
        "cs_total":             len(cs_bans),
        "asn_blocks_html":      render_asn_blocklist_html(asn_blocks),
        "asn_suggestions_html": render_asn_suggestions_html(asn_suggestions),
    })


@app.get("/api/cs-bans")
async def api_cs_bans(offset: int = 0):
    global _blotter_cache
    now = time.monotonic()
    if _blotter_cache is None or now - _blotter_cache[2] > BLOTTER_TTL:
        bans, probes = await check_fail2ban_bans()
        _blotter_cache = (bans, probes, now)
    else:
        bans, probes, _ = _blotter_cache
    cs_bans = [b for b in bans if b.get("source") == "crowdsec"]
    page = cs_bans[offset:offset + _CS_PAGE]
    ip_cache = load_json(IP_INTEL_FILE) or {}
    intel = {b["ip"]: ip_cache.get(b["ip"], {}) for b in page}
    return JSONResponse({
        "rows":     [_render_ban_row(b, intel) for b in page],
        "total":    len(cs_bans),
        "has_more": offset + _CS_PAGE < len(cs_bans),
    })


@app.get("/entertainment")
async def entertainment():
    data = load_json(LIBRARY_SCAN_FILE)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    body = masthead_rolling(now_str) + nav_bar("entertainment") + render_library_scan_html(data)
    return Response(content=page_wrap(body), media_type="text/html; charset=utf-8")


@app.get("/detailed")
async def detailed():
    return RedirectResponse(url="/current", status_code=301)


@app.get("/archive")
async def archive_index():
    from itertools import groupby
    index = load_json(ARCHIVE_INDEX) or []
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if not index:
        content = '<div class="arch-empty">No archives yet &mdash; the first edition will appear tomorrow morning.</div>'
    else:
        # Group by YYYY-MM, preserving newest-first order from the index
        def _ym(entry): return entry["date"][:7]
        def _year(ym): return ym[:4]

        sections = []
        prev_year = None
        for ym, group in groupby(index, key=_ym):
            year = _year(ym)
            entries = list(group)
            month_label = datetime.strptime(ym, "%Y-%m").strftime("%B %Y")
            is_first = not sections  # open the most recent month

            if year != prev_year:
                sections.append(f'<div class="arch-section-head">{_h(year)}</div>')
                prev_year = year

            top = entries[0]
            lead_headline = _h(top["headline"]) if top.get("headline") else ""
            day_count = len(entries)

            rows = []
            for entry in entries:
                d = entry["date"]
                headline = _h(entry["headline"]) if entry.get("headline") else '<span class="c-dim">No articles</span>'
                n_issues = entry.get("n_issues", 0)
                rows.append(
                    f'<a class="arch-day" href="/archive/{_h(d)}">'
                    f'<span class="arch-date">{_h(d)}</span>'
                    f'<span class="arch-headline">{headline}</span>'
                    f'<span class="arch-meta">{n_issues} issues</span></a>'
                )

            open_attr = " open" if is_first else ""
            sections.append(
                f'<details class="arch-period"{open_attr}>'
                f'<summary>'
                f'<div class="arch-period-hd">'
                f'<span class="arch-date">{_h(month_label)}</span>'
                f'<span class="arch-meta">{day_count} edition{"s" if day_count != 1 else ""}</span>'
                f'</div>'
                f'<div class="arch-period-lead">{lead_headline}</div>'
                f'</summary>'
                f'<div class="arch-period-body arch-index">{"".join(rows)}</div>'
                f'</details>'
            )

        content = '<div class="arch-index">' + "".join(sections) + '</div>'

    body = masthead_rolling(now_str) + nav_bar("archive") + content
    return Response(content=page_wrap(body, refresh=3600),
                    media_type="text/html; charset=utf-8")


@app.get("/archive/{date_str}")
async def archive_day(date_str: str):
    import os as _os
    from datetime import datetime as _dt
    try:
        _dt.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return Response(content="Invalid date. Use YYYY-MM-DD.", status_code=400,
                        media_type="text/plain")
    rec = load_json(_os.path.join(ARCHIVE_DIR, f"{date_str}.json"))
    if rec is None:
        return Response(content=f"No archive found for {date_str}.", status_code=404,
                        media_type="text/plain")

    bans = rec.get("bans") or []
    articles_html = render_articles_html(rec.get("newspaper") or [])
    body = (
        masthead_archive(date_str)
        + nav_bar("archive-day")
        + articles_html
        + render_blotter_html(bans, collapsed=True)
        + '<div class="grid" style="margin-top:24px">'
        + log_card("Docker Container Logs", f"Full day &mdash; {_h(date_str)}",
                   rec.get("docker_issues") or [], rec.get("docker_analysis"))
        + log_card("Network &amp; Syslog", f"Full day &mdash; {_h(date_str)} &nbsp;&middot;&nbsp; via Loki",
                   rec.get("loki_issues") or [], rec.get("loki_analysis"))
        + '</div>'
    )
    return Response(content=page_wrap(body, refresh=None),
                    media_type="text/html; charset=utf-8")


def _section(title: str, items: list[dict], label_key: str, empty_msg: str) -> str:
    html = f'<div class="arch-section-head">{_h(title)}</div>'
    if not items:
        return html + f'<div class="np-pending">{_h(empty_msg)}</div>'
    parts = []
    for idx, item in enumerate(items):
        label    = item.get(label_key, "")
        articles = item.get("articles") or []
        lead     = articles[0]["headline"] if articles else ""
        count    = len(articles)
        open_attr = " open" if idx == 0 else ""
        parts.append(
            f'<details class="arch-period"{open_attr}>'
            f'<summary>'
            f'<div class="arch-period-hd">'
            f'<span class="arch-date">{_h(label)}</span>'
            f'<span class="arch-meta">{count} article{"s" if count != 1 else ""}</span>'
            f'</div>'
            + (f'<div class="arch-period-lead">{_h(lead)}</div>' if lead else '')
            + f'</summary>'
            f'<div class="arch-period-body">{render_articles_html(articles)}</div>'
            f'</details>'
        )
    return html + "".join(parts)


@app.get("/trends")
async def trends():
    periodic = load_json(PERIODIC_FILE) or {}
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    sections: list[str] = []

    sections.append(_section(
        "Annual Reports", periodic.get("yearly", []), "year",
        "No annual reports yet — first one on January 1st.",
    ))
    sections.append(_section(
        "Monthly Reviews", periodic.get("monthly", []), "period",
        "No monthly reviews yet — first one on the 1st of next month.",
    ))
    sections.append(_section(
        "Weekly Digests", periodic.get("weekly", []), "period",
        "No weekly digests yet — first one this Sunday at midnight UTC.",
    ))

    body = masthead_rolling(now_str) + nav_bar("trends") + "".join(sections)
    return Response(content=page_wrap(body, refresh=3600),
                    media_type="text/html; charset=utf-8")


@app.get("/favicon.svg")
async def favicon_svg():
    return Response(content=_FAVICON_SVG, media_type="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=86400"})


@app.get("/favicon.ico")
async def favicon_ico():
    return Response(content=_FAVICON_SVG, media_type="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=86400"})


@app.get("/health")
async def health():
    return JSONResponse({"status": "ok", "ts": datetime.now(timezone.utc).isoformat()})

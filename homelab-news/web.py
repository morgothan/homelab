"""Web server — reads /data/*.json and serves HTML. No LLM dependency."""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Response
from fastapi.responses import RedirectResponse

from lib import (
    REFRESH_INTERVAL, UPDATE_INTERVAL, LOG_HOURS, ROLLING_HOURS,
    TODAY_FILE, ROLLING_FILE, ARCHIVE_FILE, UPDATES_FILE, PERIODIC_FILE,
    _FAVICON_SVG, _CSS,
    load_json, get_container_status, check_fail2ban_bans, enrich_ips,
    page_wrap, nav_bar, masthead_today, masthead_rolling, masthead_archive,
    render_articles_html, render_blotter_html, log_card, containers_card, updates_card,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = FastAPI()


def _init_page() -> str:
    body = (
        '<header class="mast"><hr class="rule-dbl">'
        '<div class="mast-name">Sketchyasfuckistan News</div>'
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
        from html import escape as _h
        tip = _h("\n".join(pending))
        parts.append(f'<span class="c-warn has-tip" data-tip="{tip}">{n_updates} image updates available</span>')
    else:
        parts.append(_dot("c-ok", "all images current"))
    if n_issues:
        parts.append(f"<span>{n_issues} {issues_label}</span>")
    else:
        parts.append(_dot("c-ok", f"no {issues_label}"))
    return '<div class="np-status">' + "".join(parts) + '</div>'


@app.get("/")
async def index():
    today = load_json(TODAY_FILE)
    updates_raw = load_json(UPDATES_FILE) or {}
    unhealthy, _, n_running = get_container_status()
    update_hosts = updates_raw.get("hosts", {})
    if updates_raw.get("checked_at"):
        update_hosts["_checked_at"] = updates_raw["checked_at"][11:16] + " UTC"

    if today is None:
        return Response(content=_init_page(), media_type="text/html; charset=utf-8")

    newspaper = today.get("newspaper")
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
        masthead_today()
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
    unhealthy, starting, n_running = get_container_status()
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
    built_at = rolling.get("built_at", "")
    now_str  = built_at[0:16].replace("T", " ") + " UTC" if built_at else datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

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
        masthead_rolling(now_str)
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


@app.get("/blotter")
async def blotter():
    bans, _ = await check_fail2ban_bans()
    intel = await enrich_ips([b["ip"] for b in bans])
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    body = (
        masthead_rolling(now_str)
        + nav_bar("blotter")
        + render_blotter_html(bans, intel=intel)
    )
    return Response(content=page_wrap(body, refresh=60),
                    media_type="text/html; charset=utf-8")


@app.get("/detailed")
async def detailed():
    return RedirectResponse(url="/current", status_code=301)


@app.get("/archive")
async def archive_index():
    archive = load_json(ARCHIVE_FILE) or []
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if not archive:
        content = '<div class="arch-empty">No archives yet &mdash; the first edition will appear tomorrow morning.</div>'
    else:
        from html import escape as _h
        rows = []
        for rec in archive:
            d = rec["date"]
            articles = rec.get("newspaper") or []
            headline = _h(articles[0]["headline"]) if articles else '<span class="c-dim">No articles</span>'
            n_issues = len(rec.get("docker_issues", [])) + len(rec.get("loki_issues", []))
            rows.append(
                f'<a class="arch-day" href="/archive/{_h(d)}">'
                f'<span class="arch-date">{_h(d)}</span>'
                f'<span class="arch-headline">{headline}</span>'
                f'<span class="arch-meta">{n_issues} issues</span></a>'
            )
        content = '<div class="arch-index">' + "".join(rows) + '</div>'

    body = masthead_rolling(now_str) + nav_bar("archive") + content
    return Response(content=page_wrap(body, refresh=3600),
                    media_type="text/html; charset=utf-8")


@app.get("/archive/{date_str}")
async def archive_day(date_str: str):
    from datetime import datetime as _dt
    try:
        _dt.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return Response(content="Invalid date. Use YYYY-MM-DD.", status_code=400,
                        media_type="text/plain")
    from html import escape as _h
    archive = load_json(ARCHIVE_FILE) or []
    rec = next((r for r in archive if r["date"] == date_str), None)
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


@app.get("/trends")
async def trends():
    from html import escape as _h
    periodic = load_json(PERIODIC_FILE) or {}
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    sections: list[str] = []

    def _section(title: str, items: list[dict], label_key: str, empty_msg: str) -> str:
        html = f'<div class="arch-section-head">{_h(title)}</div>'
        if not items:
            return html + f'<div class="np-pending">{_h(empty_msg)}</div>'
        parts = []
        for item in items:
            label = item.get(label_key, "")
            articles = item.get("articles") or []
            headline = _h(articles[0]["headline"]) if articles else '<span class="c-dim">No articles</span>'
            parts.append(
                f'<div class="arch-period">'
                f'<span class="arch-date">{_h(label)}</span>'
                f'<span class="arch-headline">{headline}</span>'
                f'<span class="arch-meta">{len(articles)} articles</span></div>'
                + render_articles_html(articles)
            )
        return html + "".join(parts)

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

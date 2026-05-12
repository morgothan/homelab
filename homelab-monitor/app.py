"""Homelab monitor — container health, image updates, log analysis."""

import asyncio
import json
import logging
import os
import re
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import date as _date, datetime, timedelta, timezone
from html import escape as _h
from typing import Optional

import docker
import httpx
from fastapi import FastAPI, Response
from fastapi.responses import RedirectResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────

LOKI_URL         = os.getenv("LOKI_URL", "http://loki:3100")
REFRESH_INTERVAL = int(os.getenv("REFRESH_INTERVAL", "900"))
UPDATE_INTERVAL  = int(os.getenv("UPDATE_INTERVAL", "3600"))
LOG_HOURS        = int(os.getenv("LOG_HOURS", "6"))
DOCKER_AUTH      = os.getenv("DOCKER_AUTH_FILE", "/root/.docker/config.json")
SKOPEO_TIMEOUT   = int(os.getenv("SKOPEO_TIMEOUT", "20"))
OLLAMA_URL       = os.getenv("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL     = os.getenv("OLLAMA_MODEL", "gemma4:e4b")
GITHUB_TOKEN     = os.getenv("GITHUB_TOKEN", "")  # optional, raises API rate limit from 60 to 5000/hr
SSH_KEY          = os.getenv("SSH_KEY", "/root/.ssh/id_ed25519")
ARCHIVE_FILE     = os.getenv("ARCHIVE_FILE", "/data/archive.json")
MAX_ARCHIVE_DAYS = int(os.getenv("MAX_ARCHIVE_DAYS", "90"))

# Remote Docker hosts: comma-separated URLs (set via REMOTE_DOCKER_HOSTS env var), e.g.
#   tcp://host1:2375,ssh://user@host2
def _parse_remote_hosts() -> list[tuple[str, str]]:
    raw = os.getenv("REMOTE_DOCKER_HOSTS", "")
    hosts = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        url = entry if "://" in entry else f"tcp://{entry}"
        host_part = url.split("://", 1)[1].split("@")[-1]  # strip scheme + user@
        label = host_part.split(":")[0].split(".")[0]       # first hostname segment
        hosts.append((label, url))
    return hosts

REMOTE_HOSTS: list[tuple[str, str]] = _parse_remote_hosts()

_digest_cache: dict[str, Optional[str]] = {}  # image_ref → remote digest, shared across all hosts
_source_cache: dict[str, Optional[str]] = {}  # image_ref → OCI source URL (populated during digest check)

# ── Filters ───────────────────────────────────────────────────────────────────

NOISE = re.compile(
    r'GET /(?:health|ping|metrics|favicon|robots|api/health)'
    r'|HEAD /'
    r'|"GET / HTTP'
    r'|level=info\b'
    r'|"level":"info"'
    r'|Accepted connection'
    r'|healthcheck\s+passed'
    r'|liveness probe succeeded'
    r'|readiness probe succeeded'
    r'|Starting up'
    r'|Listening on'
    r'|dhclient.*bound to'
    r'|DHCP.*renew'
    r'|ntpd.*synchronized'
    r'|systemd.*(?:Started|Stopped|Reached target)'
    r'|CRON\[.*CMD'
    r'|session (?:opened|closed) for user'
    r'|pam_unix.*session'
    r'|New session.*of user'
    r'|Removed session'
    r'|Log statistics'
    r'|eps_last',
    re.I,
)

CONCERNING = re.compile(
    r'\b(?:error|critical|fatal|fail(?:ed|ure)?|refused|denied'
    r'|timeout|unreachable|exception|traceback|panic|segfault'
    r'|oom.kill|killed|abort|crash|corrupt|WARN(?:ING)?)\b',
    re.I,
)

# ── Log helpers ───────────────────────────────────────────────────────────────

_ANSI = re.compile(r'\x1b\[[0-9;]*m')


def _strip_ansi(s: str) -> str:
    return _ANSI.sub('', s)


def _dedup_key(source: str, msg: str) -> str:
    msg = _strip_ansi(msg)
    msg = re.sub(r'\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b', '[IP]', msg)
    msg = re.sub(r'\b[0-9a-f]{40,}\b', '[HASH]', msg, flags=re.I)
    msg = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s,\]]*', '[TS]', msg)
    msg = re.sub(r'\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?', '[TS]', msg)
    msg = re.sub(r'audit\(\d+[\d.]*:\d+\)', 'audit([AUDIT])', msg)
    msg = re.sub(r'\b\d+(?:\.\d+)?\s*(?:ms|µs|us|ns)\b', '[DUR]', msg)
    msg = re.sub(r'\b\d+(?:\.\d+)?s\b', '[DUR]', msg)
    msg = re.sub(r'duration(?:_seconds)?=\S+', 'duration=[DUR]', msg)
    msg = re.sub(r'\b\d{5,}\b', '[N]', msg)
    return f"{source}|{msg.strip()[:180]}"


def _extract_text(line: str) -> str:
    if not line.startswith("{"):
        return line
    try:
        obj = json.loads(line)
        level = obj.get("level", "")
        msg = obj.get("msg", obj.get("message", ""))
        err = obj.get("err", obj.get("error", ""))
        return " ".join(p for p in (level, msg, err) if p) or line
    except Exception:
        return line


def _collect_issues(source: str, lines: list[str]) -> tuple[list[dict], dict[str, int]]:
    issues: list[dict] = []
    seen: dict[str, int] = defaultdict(int)
    for raw in lines:
        line = _strip_ansi(_extract_text(raw.strip()))
        if not line or len(line) < 8:
            continue
        if not CONCERNING.search(line):
            continue
        if NOISE.search(line):
            continue
        key = _dedup_key(source, line)
        seen[key] += 1
        if seen[key] == 1:
            level = "error" if re.search(r"\b(?:error|critical|fatal)\b", line, re.I) else "warn"
            issues.append({"source": source, "level": level,
                           "message": line[:300], "_key": key})
    return issues, seen


# ── HTML rendering ────────────────────────────────────────────────────────────

_CSS = """
:root {
  --bg:     #0a0a0a;
  --surf:   #111111;
  --card:   #141414;
  --bdr:    #222222;
  --dim:    #1a1a1a;
  --text:   #cccccc;
  --muted:  #555555;
  --gold:   #c9a84c;
  --gold2:  #7a6430;
  --ok:     #559966;
  --warn:   #c88840;
  --err:    #cc4444;
  --blue:   #4499cc;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: Georgia, "Times New Roman", serif;
  max-width: 1120px;
  margin: 0 auto;
  padding: 32px 20px 80px;
  font-size: 14px;
  line-height: 1.5;
}
/* ── Masthead ── */
.mast { text-align: center; margin-bottom: 32px; }
.rule-dbl { border: none; border-top: 3px double var(--gold); margin-bottom: 14px; }
.rule-sng { border: none; border-top: 1px solid var(--bdr); }
.mast-name {
  font-size: 2.8rem;
  font-weight: bold;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--gold);
  line-height: 1.1;
}
.mast-sub {
  font-size: 0.72rem;
  letter-spacing: 0.24em;
  text-transform: uppercase;
  color: var(--muted);
  margin-top: 5px;
}
.mast-meta {
  font-size: 0.75rem;
  color: var(--muted);
  font-family: "Courier New", monospace;
  margin: 10px 0;
}
/* ── Layout ── */
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.full { grid-column: 1 / -1; }
/* ── Card ── */
.card { background: var(--card); border: 1px solid var(--bdr); }
.card-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 9px 16px;
  border-bottom: 1px solid var(--bdr);
  background: var(--surf);
}
.card-title {
  font-size: 0.68rem;
  letter-spacing: 0.22em;
  text-transform: uppercase;
  color: var(--gold);
  font-weight: bold;
}
.card-meta {
  font-size: 0.7rem;
  color: var(--muted);
  font-family: "Courier New", monospace;
}
.card-body {
  padding: 14px 16px;
  font-family: "Courier New", Courier, monospace;
  font-size: 12px;
  line-height: 1.7;
}
/* ── Colours ── */
.c-ok   { color: var(--ok); }
.c-warn { color: var(--warn); }
.c-err  { color: var(--err); }
.c-dim  { color: var(--muted); }
.c-blue { color: var(--blue); }
.c-gold { color: var(--gold2); }
/* ── Issue rows ── */
.issues { width: 100%; }
.issue {
  display: grid;
  grid-template-columns: 3rem 5rem minmax(70px, 140px) 1fr;
  gap: 10px;
  padding: 6px 0;
  border-bottom: 1px solid var(--dim);
  align-items: baseline;
}
.issue:last-child { border-bottom: none; }
/* ── Update rows ── */
.upd {
  display: grid;
  grid-template-columns: 14em 1fr;
  gap: 10px;
  padding: 5px 0;
  border-bottom: 1px solid var(--dim);
}
.upd:last-child { border-bottom: none; }
/* ── Container rows ── */
.ctr {
  display: grid;
  grid-template-columns: 1.4em 1fr auto;
  gap: 8px;
  padding: 4px 0;
}
/* ── LLM block ── */
.analysis {
  margin-top: 14px;
  padding: 10px 14px;
  border-left: 2px solid var(--gold2);
  background: rgba(201, 168, 76, 0.04);
  white-space: pre-wrap;
  font-size: 11.5px;
  color: #aaaaaa;
}
.analysis-hd {
  font-size: 0.62rem;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: var(--gold2);
  margin-bottom: 8px;
}
/* ── Archive ── */
.arch-index { margin-top: 8px; }
.arch-day {
  display: grid;
  grid-template-columns: 10em 1fr 7em;
  gap: 12px;
  padding: 10px 0;
  border-bottom: 1px solid var(--bdr);
  align-items: baseline;
  text-decoration: none;
  color: inherit;
}
.arch-day:last-child { border-bottom: none; }
.arch-day:hover .arch-date { color: var(--gold); }
.arch-date {
  color: var(--gold2);
  font-family: "Courier New", monospace;
  font-size: 0.8rem;
  white-space: nowrap;
}
.arch-headline { font-size: 0.88rem; color: var(--text); }
.arch-meta { font-size: 0.72rem; color: var(--muted); font-family: "Courier New", monospace; text-align: right; }
.arch-empty { text-align:center; padding:48px 20px; color:var(--muted); font-style:italic; }
/* ── Changelog analysis ── */
.changelog {
  margin: 2px 0 8px 14px;
  padding: 5px 10px;
  border-left: 2px solid var(--warn);
  background: rgba(200, 136, 64, 0.05);
  font-size: 11px;
  color: #aaaaaa;
  white-space: pre-wrap;
  line-height: 1.6;
}
.changelog-tag {
  font-size: 10px;
  color: var(--muted);
  margin-left: 8px;
}
/* ── Newspaper front page ── */
.np-nav {
  text-align: center;
  font-size: 0.68rem;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: var(--muted);
  font-family: "Courier New", monospace;
  margin-bottom: 20px;
}
.np-nav a { color: var(--gold2); text-decoration: none; }
.np-nav a:hover { color: var(--gold); }
.np-nav strong { color: var(--gold); }
.np-lead {
  padding: 22px 0 18px;
  border-bottom: 1px solid var(--bdr);
}
.np-lead-kicker {
  font-size: 0.62rem;
  letter-spacing: 0.22em;
  text-transform: uppercase;
  color: var(--gold2);
  font-family: "Courier New", monospace;
  margin-bottom: 8px;
}
.np-lead-hl {
  font-size: 2rem;
  font-weight: bold;
  line-height: 1.15;
  color: var(--text);
  margin-bottom: 12px;
}
.np-lead-blurb {
  font-size: 0.9rem;
  line-height: 1.75;
  color: #aaaaaa;
  max-width: 720px;
}
.np-cols {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  border-bottom: 1px solid var(--bdr);
}
.np-article {
  padding: 16px 20px;
  border-top: 1px solid var(--bdr);
  border-right: 1px solid var(--bdr);
}
.np-article:last-child { border-right: none; }
.np-article-kicker {
  font-size: 0.58rem;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  color: var(--muted);
  font-family: "Courier New", monospace;
  margin-bottom: 5px;
}
.np-hl {
  font-size: 1.05rem;
  font-weight: bold;
  line-height: 1.2;
  color: var(--text);
  margin-bottom: 8px;
  padding-bottom: 7px;
  border-bottom: 1px solid var(--bdr);
}
.np-blurb {
  font-size: 0.82rem;
  line-height: 1.7;
  color: #999999;
}
.np-briefs {
  border-top: 1px solid var(--bdr);
  padding: 14px 0 0;
  margin-top: 0;
}
.np-briefs-head {
  font-size: 0.62rem;
  letter-spacing: 0.22em;
  text-transform: uppercase;
  color: var(--gold2);
  font-family: "Courier New", monospace;
  margin-bottom: 10px;
}
.np-brief {
  padding: 7px 0;
  border-bottom: 1px solid var(--dim);
}
.np-brief:last-child { border-bottom: none; }
.np-brief-hl {
  font-size: 0.85rem;
  font-weight: bold;
  color: var(--text);
}
.np-brief-blurb {
  font-size: 0.78rem;
  color: #888888;
  line-height: 1.5;
}
.np-pending {
  text-align: center;
  padding: 56px 20px;
  color: var(--muted);
  font-style: italic;
  font-size: 0.88rem;
  border-bottom: 1px solid var(--bdr);
}
.np-status {
  display: flex;
  flex-wrap: wrap;
  gap: 6px 24px;
  padding: 12px 0 0;
  font-family: "Courier New", monospace;
  font-size: 0.68rem;
  color: var(--muted);
}
"""


_FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    '<rect width="32" height="32" rx="3" fill="#0f0f0f"/>'
    # Masthead double rule
    '<rect x="3" y="4" width="26" height="1.5" fill="#c9a84c"/>'
    '<rect x="3" y="6.5" width="26" height="0.6" fill="#c9a84c"/>'
    # Headline block
    '<rect x="3" y="10" width="26" height="5" rx="0.5" fill="#c9a84c"/>'
    # Column divider
    '<rect x="15.2" y="17.5" width="0.6" height="11" fill="#2a2a2a"/>'
    # Left column body text
    '<rect x="3" y="18" width="10" height="1.5" rx="0.3" fill="#3d3d3d"/>'
    '<rect x="3" y="21" width="10" height="1.5" rx="0.3" fill="#383838"/>'
    '<rect x="3" y="24" width="7" height="1.5" rx="0.3" fill="#333"/>'
    # Right column body text
    '<rect x="17" y="18" width="12" height="1.5" rx="0.3" fill="#3d3d3d"/>'
    '<rect x="17" y="21" width="9" height="1.5" rx="0.3" fill="#383838"/>'
    '<rect x="17" y="24" width="11" height="1.5" rx="0.3" fill="#333"/>'
    '</svg>'
)


def _page_wrap(body: str, refresh: Optional[int] = REFRESH_INTERVAL) -> str:
    refresh_tag = f'<meta http-equiv="refresh" content="{refresh}">' if refresh else ""
    return (
        '<!DOCTYPE html><html lang="en"><head>'
        '<meta charset="utf-8">'
        '<title>Sketchyasfuckistan News</title>'
        '<link rel="icon" href="/favicon.svg" type="image/svg+xml">'
        + refresh_tag
        + '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<style>' + _CSS + '</style>'
        '</head><body>' + body + '</body></html>'
    )


def _nav_bar(active: str) -> str:
    def _item(href: str, label: str, key: str) -> str:
        return f'<strong>{label}</strong>' if active == key else f'<a href="{href}">{label}</a>'
    return (
        '<div class="np-nav">'
        + _item("/", "Front Page", "front")
        + " &nbsp;&middot;&nbsp; "
        + _item("/current", "Current Events", "current")
        + " &nbsp;&middot;&nbsp; "
        + _item("/archive", "Archive", "archive")
        + '</div>'
    )


def _masthead(now_str: str) -> str:
    return (
        '<header class="mast">'
        '<hr class="rule-dbl">'
        '<div class="mast-name">Sketchyasfuckistan News</div>'
        '<div class="mast-sub">Homelab Intelligence Dispatch &mdash; Est. 2026</div>'
        '<hr class="rule-sng" style="margin:10px 0">'
        f'<div class="mast-meta">Generated {_h(now_str)}'
        f' &nbsp;&middot;&nbsp; Refresh {REFRESH_INTERVAL // 60}m'
        f' &nbsp;&middot;&nbsp; Log window {LOG_HOURS}h</div>'
        '<hr class="rule-sng" style="margin-top:10px">'
        '</header>'
    )


def _masthead_today() -> str:
    today_str = datetime.now(timezone.utc).strftime("%A, %B %-d, %Y")
    return (
        '<header class="mast">'
        '<hr class="rule-dbl">'
        '<div class="mast-name">Sketchyasfuckistan News</div>'
        '<div class="mast-sub">Homelab Intelligence Dispatch &mdash; Est. 2026</div>'
        '<hr class="rule-sng" style="margin:10px 0">'
        f'<div class="mast-meta">Today\'s Edition &mdash; {_h(today_str)}'
        f' &nbsp;&middot;&nbsp; Updated hourly</div>'
        '<hr class="rule-sng" style="margin-top:10px">'
        '</header>'
    )


def _lvl_badge(level: str) -> str:
    if level == "error":
        return '<span class="c-err">ERR</span>'
    return '<span class="c-warn">WRN</span>'


def _render_issue_rows(issues: list[dict]) -> str:
    if not issues:
        return '<span class="c-ok">&#x2713;&nbsp; No issues found.</span>'
    rows = []
    for i in issues:
        rows.append(
            '<div class="issue">'
            + _lvl_badge(i["level"])
            + f'<span class="c-dim">&#xd7;{i["count"]}</span>'
            + f'<span class="c-gold">{_h(i["source"])}</span>'
            + f'<span>{_h(i["message"][:220])}</span>'
            + '</div>'
        )
    return ''.join(rows)


def _log_card(title: str, meta: str, issues: list[dict], analysis: Optional[str]) -> str:
    body = _render_issue_rows(issues)
    if analysis:
        body += (
            '<div class="analysis">'
            '<div class="analysis-hd">AI Analysis</div>'
            + _h(analysis)
            + '</div>'
        )
    return (
        '<div class="card full">'
        '<div class="card-head">'
        f'<span class="card-title">{title}</span>'
        f'<span class="card-meta">{meta}</span>'
        '</div>'
        f'<div class="card-body">{body}</div>'
        '</div>'
    )


def _containers_card(unhealthy: list, starting: list, n_running: int) -> str:
    if not unhealthy:
        body = '<span class="c-ok">&#x2713;&nbsp; All containers running and healthy.</span>'
    else:
        rows = []
        for c in unhealthy:
            health = c.attrs.get("State", {}).get("Health", {}).get("Status", "")
            detail = c.status + (f" / {health}" if health else "")
            rows.append(
                '<div class="ctr">'
                '<span class="c-err">&#x2717;</span>'
                f'<span>{_h(c.name)}</span>'
                f'<span class="c-warn">{_h(detail)}</span>'
                '</div>'
            )
        body = ''.join(rows)
    if starting:
        names = _h(", ".join(c.name for c in starting))
        body += f'<div class="c-dim" style="margin-top:8px">Starting: {names}</div>'
    return (
        '<div class="card">'
        '<div class="card-head">'
        '<span class="card-title">Container Status</span>'
        f'<span class="card-meta">{n_running} running</span>'
        '</div>'
        f'<div class="card-body">{body}</div>'
        '</div>'
    )


def _updates_card(update_hosts: dict) -> str:
    all_done = all(h["status"] == "done" for h in update_hosts.values())
    any_checking = any(h["status"] in ("checking", "pending") for h in update_hosts.values())
    meta = "in progress…" if any_checking else (
        "checked " + max(
            (h["ts"] for h in update_hosts.values() if h["ts"]),
            default=None,
        ).strftime("%H:%M UTC")
        if all_done and any(h["ts"] for h in update_hosts.values()) else "—"
    )

    sections = []
    for label, host in update_hosts.items():
        if host["status"] in ("pending", "checking"):
            body = '<span class="c-dim">checking&#x2026;</span>'
        else:
            results = host["results"]
            available = [r for r in results if r["status"] == "update_available"]
            failed    = [r for r in results if r["status"] == "check_failed"]
            if not results:
                body = '<span class="c-dim">no containers found</span>'
            elif not available:
                body = '<span class="c-ok">&#x2713; current</span>'
            else:
                rows = []
                for r in available:
                    new_ver = r.get("new_version", "")
                    tag_html = (f'<span class="changelog-tag">&#x2192; {_h(new_ver)}</span>'
                                if new_ver else "")
                    rows.append(
                        '<div class="upd">'
                        f'<span class="c-blue">{_h(r["container"])}</span>'
                        f'<span class="c-dim">{_h(r["image"])}{tag_html}</span>'
                        '</div>'
                    )
                    cl = r.get("changelog_analysis")
                    if cl is None and "changelog_analysis" not in r:
                        # Analysis still running
                        rows.append('<div class="changelog c-dim">changelog&#x2026;</div>')
                    elif cl:
                        rows.append(f'<div class="changelog">{_h(cl)}</div>')
                body = ''.join(rows)
            if failed:
                names = _h(", ".join(r["container"] for r in failed))
                body += f'<div class="c-dim" style="margin-top:4px;font-size:11px">check failed: {names}</div>'

        ts_str = host["ts"].strftime("%H:%M") if host["ts"] else ""
        sections.append(
            f'<div style="margin-bottom:10px">'
            f'<div style="margin-bottom:4px">'
            f'<span class="c-gold">{_h(label)}</span>'
            + (f'<span class="c-dim" style="font-size:11px"> — {ts_str}</span>' if ts_str else '')
            + f'</div>'
            f'{body}'
            f'</div>'
        )

    body_html = '<hr class="sep">'.join(sections) if sections else '<span class="c-dim">No hosts configured.</span>'
    return (
        '<div class="card">'
        '<div class="card-head">'
        '<span class="card-title">Image Updates</span>'
        f'<span class="card-meta">{_h(meta)}</span>'
        '</div>'
        f'<div class="card-body">{body_html}</div>'
        '</div>'
    )


def _masthead_archive(date_str: str) -> str:
    return (
        '<header class="mast">'
        '<hr class="rule-dbl">'
        '<div class="mast-name">Sketchyasfuckistan News</div>'
        '<div class="mast-sub">Homelab Intelligence Dispatch &mdash; Est. 2026</div>'
        '<hr class="rule-sng" style="margin:10px 0">'
        f'<div class="mast-meta">Edition for {_h(date_str)}</div>'
        '<hr class="rule-sng" style="margin-top:10px">'
        '</header>'
    )


def _render_archive_index(archive: list[dict]) -> str:
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if not archive:
        content = '<div class="arch-empty">No archives yet &mdash; the first edition will appear tomorrow morning.</div>'
    else:
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
                f'<span class="arch-meta">{n_issues} issues</span>'
                '</a>'
            )
        content = '<div class="arch-index">' + "".join(rows) + '</div>'
    body = _masthead(now_str) + _nav_bar("archive") + content
    return _page_wrap(body, refresh=3600)


def _render_articles_html(articles: list[dict]) -> str:
    """Shared newspaper article layout used by both front page and archive day view."""
    if not articles:
        return '<div class="np-pending">No articles available for this edition.</div>'
    lead, *rest = articles
    columns = rest[:3]   # articles 2-4 → column grid
    briefs  = rest[3:]   # articles 5+ → "In Brief" strip
    html = (
        '<div class="np-lead">'
        '<div class="np-lead-kicker">Lead Story</div>'
        f'<div class="np-lead-hl">{_h(lead["headline"])}</div>'
        f'<div class="np-lead-blurb">{_h(lead["blurb"])}</div>'
        '</div>'
    )
    if columns:
        kickers = ["Also", "Elsewhere", "Update"]
        cols = "".join(
            '<div class="np-article">'
            f'<div class="np-article-kicker">{kickers[idx % len(kickers)]}</div>'
            f'<div class="np-hl">{_h(a["headline"])}</div>'
            f'<div class="np-blurb">{_h(a["blurb"])}</div>'
            '</div>'
            for idx, a in enumerate(columns)
        )
        html += f'<div class="np-cols">{cols}</div>'
    if briefs:
        items = "".join(
            f'<div class="np-brief">'
            f'<span class="np-brief-hl">{_h(a["headline"])}</span>'
            f' &mdash; <span class="np-brief-blurb">{_h(a["blurb"])}</span>'
            f'</div>'
            for a in briefs
        )
        html += f'<div class="np-briefs"><div class="np-briefs-head">In Brief</div>{items}</div>'
    return html


def _render_archive_day(rec: dict) -> str:
    d = rec["date"]
    docker_issues  = rec.get("docker_issues") or []
    loki_issues    = rec.get("loki_issues") or []
    docker_analysis = rec.get("docker_analysis")
    loki_analysis   = rec.get("loki_analysis")
    articles_html = _render_articles_html(rec.get("newspaper") or [])
    nav = (
        '<div class="np-nav" style="margin-bottom:8px">'
        f'<a href="/archive">&larr; Archive</a>'
        ' &nbsp;&middot;&nbsp; '
        + _nav_bar("archive").replace('<div class="np-nav">', "").replace("</div>", "")
        + '</div>'
    )
    body = (
        _masthead_archive(d)
        + _nav_bar("archive")
        + articles_html
        + '<div class="grid" style="margin-top:24px">'
        + _log_card("Docker Container Logs", f"Full day &mdash; {_h(d)}", docker_issues, docker_analysis)
        + _log_card("Network &amp; Syslog", f"Full day &mdash; {_h(d)} &nbsp;&middot;&nbsp; via Loki", loki_issues, loki_analysis)
        + '</div>'
    )
    return _page_wrap(body, refresh=None)  # static page, no auto-refresh


def _render_today_front_page(
    n_running: int,
    unhealthy: list,
    update_hosts: dict,
    today_data: dict,
) -> str:
    newspaper    = today_data.get("newspaper")
    docker_issues = today_data.get("docker_issues") or []
    loki_issues   = today_data.get("loki_issues") or []
    still_checking = any(h["status"] in ("pending", "checking") for h in update_hosts.values())
    # None  = not yet generated → poll fast
    # []    = generation failed → stop fast-polling
    # [...] = articles ready
    page_refresh = 30 if (still_checking or newspaper is None) else REFRESH_INTERVAL

    if newspaper:
        articles_html = _render_articles_html(newspaper)
    elif newspaper is None:
        articles_html = (
            '<div class="np-pending">'
            "The newsroom is preparing today's edition&#x2026;<br>"
            '<small style="font-size:0.75rem">Check back in a few minutes</small>'
            '</div>'
        )
    else:
        articles_html = (
            '<div class="np-pending">'
            f'Edition unavailable — next update in {UPDATE_INTERVAL // 60} min<br>'
            '<small style="font-size:0.75rem">'
            '<a href="/current" style="color:var(--gold2)">View rolling report</a>'
            '</small>'
            '</div>'
        )

    n_updates = sum(
        len([r for r in h["results"] if r["status"] == "update_available"])
        for h in update_hosts.values()
    )
    n_issues   = len(docker_issues) + len(loki_issues)
    n_unhealthy = len(unhealthy)

    def _dot(cls: str, text: str) -> str:
        return f'<span class="{cls}">{text}</span>'

    status_parts = [_dot("c-ok" if not n_unhealthy else "c-err",
                         f"{'✓' if not n_unhealthy else '✗'} {n_running} containers")]
    if n_unhealthy:
        status_parts.append(_dot("c-err", f"⚠ {n_unhealthy} unhealthy"))
    if still_checking:
        status_parts.append("<span>update checks in progress…</span>")
    elif n_updates:
        status_parts.append(_dot("c-warn", f"{n_updates} image updates available"))
    else:
        status_parts.append(_dot("c-ok", "all images current"))
    if n_issues:
        status_parts.append(f"<span>{n_issues} log issues today</span>")
    else:
        status_parts.append(_dot("c-ok", "no log issues today"))

    status_bar = '<div class="np-status">' + "".join(status_parts) + '</div>'
    body = _masthead_today() + _nav_bar("front") + articles_html + status_bar
    return _page_wrap(body, refresh=page_refresh)


def _render_current_events(
    now_str: str,
    n_running: int,
    unhealthy: list,
    starting: list,
    update_hosts: dict,
    docker_issues: list[dict],
    docker_analysis: Optional[str],
    loki_issues: list[dict],
    loki_analysis: Optional[str],
    newspaper: Optional[list[dict]],
) -> str:
    still_checking = any(h["status"] in ("pending", "checking") for h in update_hosts.values())
    page_refresh = 30 if (still_checking or newspaper is None) else REFRESH_INTERVAL

    if newspaper:
        articles_html = _render_articles_html(newspaper)
    elif newspaper is None:
        articles_html = (
            '<div class="np-pending">'
            "Preparing live report&#x2026;<br>"
            '<small style="font-size:0.75rem">Check back in a few minutes</small>'
            '</div>'
        )
    else:
        articles_html = (
            '<div class="np-pending">'
            f'Report unavailable — refreshing in {REFRESH_INTERVAL // 60} min'
            '</div>'
        )

    body = (
        _masthead(now_str)
        + _nav_bar("current")
        + articles_html
        + '<div class="grid" style="margin-top:24px">'
        + _containers_card(unhealthy, starting, n_running)
        + _updates_card(update_hosts)
        + _log_card("Docker Container Logs", f"Last {LOG_HOURS}h",
                    docker_issues, docker_analysis)
        + _log_card("Network &amp; Syslog",
                    f"Last {LOG_HOURS}h &nbsp;&middot;&nbsp; via Loki",
                    loki_issues, loki_analysis)
        + '</div>'
    )
    return _page_wrap(body, refresh=page_refresh)


def _init_page() -> str:
    body = (
        '<header class="mast">'
        '<hr class="rule-dbl">'
        '<div class="mast-name">Sketchyasfuckistan News</div>'
        '<div class="mast-sub">Homelab Intelligence Dispatch &mdash; Est. 2026</div>'
        '</header>'
        '<div style="text-align:center;margin-top:60px;font-family:\'Courier New\',monospace">'
        '<p style="color:var(--gold);font-size:1rem">Initializing&#x2026;</p>'
        '<p style="color:var(--muted);font-size:12px;margin-top:8px">'
        'First report ready in ~1 minute</p>'
        '</div>'
    )
    return _page_wrap(body, refresh=15)


# ── State ─────────────────────────────────────────────────────────────────────

_lock = asyncio.Lock()

def _blank_host_state(status: str = "pending") -> dict:
    return {"status": status, "ts": None, "results": []}

_state: dict = {
    "log_data": {           # rolling window (last LOG_HOURS) — drives Current Events page
        "built_at": None,
        "docker_issues": [],
        "docker_analysis": None,
        "loki_issues": [],
        "loki_analysis": None,
        "newspaper": None,
    },
    "today_data": {         # midnight-to-now — drives Front Page
        "built_at": None,
        "docker_issues": [],
        "docker_analysis": None,
        "loki_issues": [],
        "loki_analysis": None,
        "newspaper": None,
    },
    "update_hosts": {
        "local": _blank_host_state(),
        **{label: _blank_host_state() for label, _ in REMOTE_HOSTS},
    },
    "archive": [],  # list of daily records, newest first; persisted to ARCHIVE_FILE
}


def _load_archive() -> list[dict]:
    try:
        with open(ARCHIVE_FILE) as f:
            records = json.load(f)
            log.info("Loaded %d archive records from %s", len(records), ARCHIVE_FILE)
            return records
    except FileNotFoundError:
        return []
    except Exception as e:
        log.warning("Failed to load archive: %s", e)
        return []


def _save_archive_sync(records: list[dict]) -> None:
    try:
        os.makedirs(os.path.dirname(ARCHIVE_FILE), exist_ok=True)
        tmp = ARCHIVE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(records, f)
        os.replace(tmp, ARCHIVE_FILE)
    except Exception as e:
        log.warning("Failed to save archive: %s", e)

# ── Image updates (independent background loop) ───────────────────────────────

def _parse_image_ref(raw: str) -> str:
    if "@sha256:" in raw:
        raw = raw.split("@")[0]
    if ":" not in raw.split("/")[-1]:
        raw += ":latest"
    return raw


async def _remote_digest(image_ref: str) -> Optional[str]:
    has_auth = os.path.exists(DOCKER_AUTH)
    attempts = [["--authfile", DOCKER_AUTH]] if has_auth else []
    attempts.append(["--no-creds"])

    for auth_args in attempts:
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "skopeo", "inspect",
                "--override-arch", "amd64", "--override-os", "linux",
                *auth_args,
                f"docker://{image_ref}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=SKOPEO_TIMEOUT)
            if proc.returncode == 0:
                data = json.loads(out)
                # Cache OCI source URL while we have the inspect payload — avoids a second call later
                labels = data.get("Labels") or {}
                _source_cache[image_ref] = labels.get("org.opencontainers.image.source")
                return data.get("Digest")
        except Exception:
            if proc is not None:
                try:
                    proc.kill()
                    await proc.communicate()
                except Exception:
                    pass
    return None


def _get_containers_local() -> list[dict]:
    dc = docker.from_env()
    out = []
    for c in dc.containers.list():
        ref = _parse_image_ref(c.attrs["Config"]["Image"])
        try:
            img = dc.images.get(c.attrs["Image"])
            digests = img.attrs.get("RepoDigests", [])
            local_digest = digests[0].split("@")[1] if digests else None
        except Exception:
            local_digest = None
        out.append({"name": c.name, "image": ref, "local_digest": local_digest})
    return out


def _get_containers_tcp(url: str) -> list[dict]:
    dc = docker.DockerClient(base_url=url, timeout=10)
    out = []
    try:
        for c in dc.containers.list():
            ref = _parse_image_ref(c.attrs["Config"]["Image"])
            try:
                img = dc.images.get(c.attrs["Image"])
                digests = img.attrs.get("RepoDigests", [])
                local_digest = digests[0].split("@")[1] if digests else None
            except Exception:
                local_digest = None
            out.append({"name": c.name, "image": ref, "local_digest": local_digest})
    finally:
        dc.close()
    return out


async def _get_containers_ssh(url: str) -> list[dict]:
    # url: ssh://user@hostname
    target = url[len("ssh://"):]
    # Locate docker binary; try PATH first, then common paths.
    # Inspect the image (not container) to get RepoDigests — some hosts don't
    # populate RepoDigests in the container inspect object.
    detect_cmd = (
        "docker_bin=$(which docker 2>/dev/null || "
        "for p in /usr/local/bin/docker /usr/bin/docker; do [ -x $p ] && echo $p && break; done); "
        r'$docker_bin ps --format "{{.Names}}\t{{.Image}}" 2>/dev/null | '
        r"while IFS=$(printf '\t') read name image; do "
        r'  digests=$($docker_bin image inspect "$image" --format "{{json .RepoDigests}}" 2>/dev/null || echo "[]"); '
        r'  printf "%s\t%s\t%s\n" "$name" "$image" "$digests"; '
        r"done"
    )
    proc = await asyncio.create_subprocess_exec(
        "ssh",
        "-F", "/dev/null",              # ignore mounted host config (ownership mismatch)
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        "-i", SSH_KEY,
        target,
        detect_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=40)
    except asyncio.TimeoutError:
        if proc.returncode is None:
            try:
                proc.kill()
                await proc.communicate()
            except Exception:
                pass
        return []

    if proc.returncode != 0:
        log.warning("SSH to %s failed: %s", target, err.decode(errors="replace")[:200])
        return []

    containers = []
    for line in out.decode(errors="replace").splitlines():
        parts = line.strip().split("\t", 2)
        if len(parts) < 3:
            continue
        name, image, digests_json = parts
        name = name.lstrip("/")
        try:
            digests = json.loads(digests_json)
            local_digest = digests[0].split("@")[1] if digests else None
        except Exception:
            local_digest = None
        containers.append({"name": name, "image": _parse_image_ref(image), "local_digest": local_digest})
    return containers


async def _cached_remote_digest(image_ref: str, sem: asyncio.Semaphore) -> Optional[str]:
    """Return remote digest, using a run-wide cache to avoid duplicate skopeo calls."""
    if image_ref in _digest_cache:
        return _digest_cache[image_ref]
    async with sem:
        # Re-check after acquiring semaphore — another coroutine may have filled it
        if image_ref in _digest_cache:
            return _digest_cache[image_ref]
        result = await _remote_digest(image_ref)
    _digest_cache[image_ref] = result
    return result


async def _check_host(label: str, url: str, sem: asyncio.Semaphore) -> None:
    """Fetch container list, compare digests, store results in state."""
    async with _lock:
        _state["update_hosts"][label]["status"] = "checking"

    try:
        loop = asyncio.get_running_loop()
        if url == "local":
            containers = await loop.run_in_executor(None, _get_containers_local)
        elif url.startswith("ssh://"):
            containers = await _get_containers_ssh(url)
        else:
            containers = await loop.run_in_executor(None, _get_containers_tcp, url)
    except Exception as e:
        log.error("Failed to list containers for %s: %s", label, e)
        async with _lock:
            _state["update_hosts"][label] = {
                "status": "done", "ts": datetime.now(timezone.utc),
                "results": [{"container": "—", "image": str(e), "status": "check_failed"}],
            }
        return

    async def _check_one(c: dict) -> dict:
        remote = await _cached_remote_digest(c["image"], sem)
        if remote is None:
            return {"container": c["name"], "image": c["image"], "status": "check_failed"}
        if c["local_digest"] is None:
            return {"container": c["name"], "image": c["image"], "status": "unknown"}
        status = "update_available" if c["local_digest"] != remote else "current"
        return {"container": c["name"], "image": c["image"], "status": status}

    results = await asyncio.gather(*(_check_one(c) for c in containers), return_exceptions=True)
    results = sorted(
        [r for r in results if isinstance(r, dict)],
        key=lambda r: (r["status"] != "update_available", r["container"]),
    )
    async with _lock:
        _state["update_hosts"][label] = {
            "status": "done",
            "ts": datetime.now(timezone.utc),
            "results": results,
        }
    log.info("Update check done for %s: %d containers", label, len(results))


async def _run_update_check():
    log.info("Starting image update check across all hosts")
    _digest_cache.clear()
    _source_cache.clear()
    sem = asyncio.Semaphore(5)
    host_tasks = [asyncio.create_task(_check_host("local", "local", sem))]
    for label, url in REMOTE_HOSTS:
        host_tasks.append(asyncio.create_task(_check_host(label, url, sem)))
    await asyncio.gather(*host_tasks, return_exceptions=True)
    log.info("All host update checks complete")


async def _fetch_github_release_notes(source_url: str) -> Optional[tuple[str, str]]:
    """Return (tag, release_body) for the latest GitHub release, or None."""
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
                tag  = data.get("tag_name", "")
                body = (data.get("body") or "").strip()
                return tag, body
            log.debug("GitHub releases %s → HTTP %d", repo, resp.status_code)
    except Exception as e:
        log.debug("GitHub release fetch failed for %s: %s", repo, e)
    return None


async def _llm_changelog_analysis(container: str, image: str, tag: str, notes: str) -> Optional[str]:
    """Return a brief LLM summary of breaking changes in release notes, or None."""
    if not notes:
        return None
    prompt = (
        f"Release notes for Docker image '{image}' (new version: {tag}) running in a homelab.\n"
        "Stack: Traefik, Authelia, Jellyfin, Prometheus, Grafana, Redis, Home Assistant.\n\n"
        "List ONLY items a homelab operator must act on:\n"
        "- Breaking changes or required config/migration steps\n"
        "- Security vulnerabilities fixed\n"
        "- Deprecated settings that need updating\n"
        "If there is nothing requiring action, respond with exactly: No action required.\n"
        "Be terse — 1-3 bullet points max. No preamble, no markdown headers.\n\n"
        f"RELEASE NOTES ({tag}):\n{notes[:2500]}"
    )
    try:
        async with httpx.AsyncClient(timeout=180.0) as client:
            resp = await client.post(
                f"{OLLAMA_URL}/api/chat",
                json={
                    "model": OLLAMA_MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "options": {"num_ctx": 4096, "temperature": 0.1, "num_predict": 300},
                },
            )
            resp.raise_for_status()
            return resp.json()["message"]["content"].strip()
    except Exception as e:
        log.warning("Changelog LLM failed for %s: %s", container, e)
        return None


async def _analyze_changelogs() -> None:
    """For every container with update_available, fetch release notes and LLM-analyze them."""
    async with _lock:
        targets = [
            (label, idx, r["image"], r["container"])
            for label, host in _state["update_hosts"].items()
            if host["status"] == "done"
            for idx, r in enumerate(host["results"])
            if r["status"] == "update_available" and "changelog_analysis" not in r
        ]

    if not targets:
        return
    log.info("Analyzing changelogs for %d updated containers", len(targets))

    for label, idx, image, container in targets:
        source_url = _source_cache.get(image)
        tag, analysis = "", None

        if source_url:
            release = await _fetch_github_release_notes(source_url)
            if release:
                tag, notes = release
                raw = await _llm_changelog_analysis(container, image, tag, notes)
                # Normalize "no action" responses to None so the UI can omit them cleanly
                if raw and raw.strip().lower().rstrip(".") != "no action required":
                    analysis = raw

        async with _lock:
            results = _state["update_hosts"].get(label, {}).get("results", [])
            if idx < len(results) and results[idx].get("container") == container:
                results[idx]["changelog_analysis"] = analysis
                if tag:
                    results[idx]["new_version"] = tag
        log.info("Changelog %s/%s: %s", label, container,
                 "action needed" if analysis else ("no action" if source_url else "no source"))


async def _update_loop():
    while True:
        try:
            await _run_update_check()
            await _analyze_changelogs()
        except Exception as e:
            log.error("Update loop error: %s", e)
        await asyncio.sleep(UPDATE_INTERVAL)


# ── Docker logs ───────────────────────────────────────────────────────────────

def _fetch_logs_sync(container, since_ts: int, until_ts: Optional[int] = None) -> list[str]:
    try:
        kwargs: dict = {"since": since_ts, "stdout": True, "stderr": True, "stream": False}
        if until_ts is not None:
            kwargs["until"] = until_ts
        raw = container.logs(**kwargs)
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace").splitlines()
    except Exception:
        pass
    return []


async def check_docker_logs(
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
) -> list[dict]:
    if since_ts is None:
        since_ts = int((datetime.now(timezone.utc) - timedelta(hours=LOG_HOURS)).timestamp())
    try:
        dc = docker.from_env()
        containers = dc.containers.list()
    except Exception as e:
        return [{"source": "docker", "level": "error", "message": str(e), "count": 1}]

    loop = asyncio.get_running_loop()
    all_issues: list[dict] = []
    all_seen: dict[str, int] = defaultdict(int)

    async def _process_container(c):
        try:
            raw_lines = await asyncio.wait_for(
                loop.run_in_executor(None, _fetch_logs_sync, c, since_ts, until_ts),
                timeout=30.0,
            )
        except asyncio.TimeoutError:
            log.warning("Timeout fetching logs for %s", c.name)
            raw_lines = []
        return _collect_issues(c.name, raw_lines)

    results = await asyncio.gather(*(_process_container(c) for c in containers), return_exceptions=True)
    for result in results:
        if not isinstance(result, tuple):
            continue
        issues, seen = result
        all_issues.extend(issues)
        for k, v in seen.items():
            all_seen[k] += v

    for i in all_issues:
        i["count"] = all_seen[i.pop("_key")]
    return all_issues[:60]


# ── Loki logs ─────────────────────────────────────────────────────────────────

async def check_loki(
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> list[dict]:
    if end is None:
        end = datetime.now(timezone.utc)
    if start is None:
        start = end - timedelta(hours=LOG_HOURS)
    query = (
        '{job=~".+"} '
        '|~ `(?i)(error|critical|fatal|fail|refused|denied|timeout|warn)`'
    )
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{LOKI_URL}/loki/api/v1/query_range",
                params={
                    "query": query,
                    "start": str(int(start.timestamp() * 1_000_000_000)),
                    "end": str(int(end.timestamp() * 1_000_000_000)),
                    "limit": "500",
                    "direction": "backward",
                },
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return [{"source": "loki", "level": "warn",
                 "message": f"Could not reach Loki at {LOKI_URL}: {e}", "count": 1}]

    all_issues: list[dict] = []
    all_seen: dict[str, int] = defaultdict(int)

    for stream in data.get("data", {}).get("result", []):
        labels = stream.get("stream", {})
        source = (
            labels.get("host") or labels.get("hostname") or
            labels.get("container_name") or labels.get("app") or
            labels.get("job") or "unknown"
        )
        lines = [line for _ts, line in stream.get("values", [])]
        issues, seen = _collect_issues(source, lines)
        all_issues.extend(issues)
        for k, v in seen.items():
            all_seen[k] += v

    for i in all_issues:
        i["count"] = all_seen[i.pop("_key")]
    return all_issues[:60]


# ── LLM analysis (Ollama) ─────────────────────────────────────────────────────

async def _llm_analysis(issues: list[dict], context: str) -> Optional[str]:
    if not issues:
        return None
    # Send only the top issues sorted by severity then count — keeps the prompt small
    # enough for a CPU-only 3B model to handle in reasonable time
    ranked = sorted(issues, key=lambda i: (i["level"] != "error", -i["count"]))[:10]
    entries = "\n".join(
        f"[{i['source']} {i['level'].upper()} \xd7{i['count']}] {i['message'][:140]}"
        for i in ranked
    )
    prompt = (
        "Homelab log analysis. Stack: Traefik, Authelia, Redis, Prometheus, Jellyfin, UniFi.\n"
        "For each entry: one line saying what it means, one line starting with '→' saying what to do.\n"
        "If it is harmless noise, write 'Noise: <reason>'. No preamble.\n\n"
        f"ENTRIES ({context}):\n{entries}"
    )
    try:
        async with httpx.AsyncClient(timeout=300.0) as client:
            resp = await client.post(
                f"{OLLAMA_URL}/api/chat",
                json={
                    "model": OLLAMA_MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "options": {"num_ctx": 4096, "temperature": 0.1, "num_predict": 500},
                },
            )
            resp.raise_for_status()
            return resp.json()["message"]["content"].strip()
    except Exception as e:
        log.warning("Ollama analysis failed (%s): %s", type(e).__name__, e)
        return None


async def _generate_newspaper(
    docker_issues: list[dict],
    loki_issues: list[dict],
    update_hosts: dict,
    unhealthy: list,
) -> Optional[list[dict]]:
    """Ask Ollama to write 3-5 newspaper articles summarising the current homelab state."""
    lines: list[str] = []

    if unhealthy:
        lines.append("UNHEALTHY CONTAINERS: " + ", ".join(c.name for c in unhealthy))
    else:
        lines.append("CONTAINER HEALTH: all containers running normally")

    for label, host in update_hosts.items():
        if host.get("status", "done") != "done":
            continue
        for r in host["results"]:
            if r["status"] != "update_available":
                continue
            ver = f" -> {r['new_version']}" if r.get("new_version") else ""
            line = f"UPDATE on {label}: {r['container']} ({r['image']}{ver})"
            cl = r.get("changelog_analysis")
            if cl:
                line += f" — BREAKING/NOTABLE: {cl[:200]}"
            lines.append(line)

    if docker_issues:
        lines.append("\nTOP DOCKER LOG ISSUES:")
        for i in sorted(docker_issues, key=lambda x: (x["level"] != "error", -x["count"]))[:5]:
            lines.append(f"  [{i['source']} {i['level'].upper()} ×{i['count']}] {i['message'][:120]}")

    if loki_issues:
        lines.append("\nTOP NETWORK/SYSLOG ISSUES:")
        for i in sorted(loki_issues, key=lambda x: (x["level"] != "error", -x["count"]))[:5]:
            lines.append(f"  [{i['source']} {i['level'].upper()} ×{i['count']}] {i['message'][:120]}")

    situation = "\n".join(lines)
    prompt = (
        "You are the editor of a homelab status newspaper covering a full day of events.\n"
        "Write 4 to 10 articles — enough to cover everything noteworthy, no more.\n\n"
        "Rules:\n"
        "- Group related items into one article. 'Five *arr apps have routine updates' = 1 article, not 5.\n"
        "- Order by importance: breaking changes and errors first, routine updates last.\n"
        "- Headline: punchy, specific, real-newspaper style. Name the service and the issue.\n"
        "  Good: 'Traefik Logs 847 Failed Redis Auth Attempts'\n"
        "  Bad: 'System Experiencing Connectivity Issues'\n"
        "- Articles 1–4: blurb is 2-3 sentences, AP wire style, specific counts and service names.\n"
        "- Articles 5+: blurb is 1 sentence only — these run as brief notes below the fold.\n"
        "- If something is completely fine, skip it — don't pad with 'all clear' articles.\n"
        "- Output ONLY a valid JSON array. No markdown fences, no explanation, no preamble.\n"
        "  Format: [{\"headline\": \"...\", \"blurb\": \"...\"}]\n\n"
        f"CURRENT HOMELAB STATUS:\n{situation}"
    )
    try:
        async with httpx.AsyncClient(timeout=300.0) as client:
            resp = await client.post(
                f"{OLLAMA_URL}/api/chat",
                json={
                    "model": OLLAMA_MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "options": {"num_ctx": 4096, "temperature": 0.3, "num_predict": 1500},
                },
            )
            resp.raise_for_status()
            content = resp.json()["message"]["content"].strip()
            # Strip markdown fences the model sometimes adds despite instructions
            content = re.sub(r"^```(?:json)?\n?", "", content)
            content = re.sub(r"\n?```$", "", content.strip())

            articles = None

            # Attempt 1: direct parse
            try:
                articles = json.loads(content)
            except json.JSONDecodeError:
                pass

            # Attempt 2: extract the outermost [...] array and retry
            if not isinstance(articles, list):
                m = re.search(r'\[[\s\S]*\]', content)
                if m:
                    try:
                        articles = json.loads(m.group(0))
                    except json.JSONDecodeError:
                        pass

            # Attempt 3: extract individual {...} objects with regex
            if not isinstance(articles, list):
                articles = []
                for m in re.finditer(r'\{[^{}]+\}', content, re.DOTALL):
                    try:
                        obj = json.loads(m.group(0))
                        if "headline" in obj and "blurb" in obj:
                            articles.append(obj)
                    except json.JSONDecodeError:
                        pass

            if isinstance(articles, list):
                valid = [
                    a for a in articles[:10]
                    if isinstance(a, dict) and "headline" in a and "blurb" in a
                ]
                if valid:
                    return valid
    except Exception as e:
        log.warning("Newspaper generation failed (%s): %s", type(e).__name__, e)
    return None


# ── Log refresh (cached, slow) ────────────────────────────────────────────────

async def _run_analysis(docker_issues: list[dict], loki_issues: list[dict]) -> None:
    """Run Ollama analyses sequentially and update state when each completes."""
    docker_analysis = await _llm_analysis(docker_issues, "Docker container")
    async with _lock:
        _state["log_data"]["docker_analysis"] = docker_analysis
    loki_analysis = await _llm_analysis(loki_issues, "network/syslog (from Loki)")
    async with _lock:
        _state["log_data"]["loki_analysis"] = loki_analysis
    log.info("LLM analysis complete — generating newspaper")
    loop = asyncio.get_running_loop()
    unhealthy, _, _ = await loop.run_in_executor(None, _get_container_status)
    async with _lock:
        update_hosts = dict(_state["update_hosts"])
    newspaper = await _generate_newspaper(docker_issues, loki_issues, update_hosts, unhealthy)
    async with _lock:
        # Store [] on failure — distinguishes "not yet run" (None) from "ran but failed" ([])
        # so the page stops polling at 30s even when the model returns bad JSON
        _state["log_data"]["newspaper"] = newspaper if newspaper is not None else []
    log.info("Newspaper generation complete (%d articles)", len(newspaper) if newspaper else 0)


async def _refresh_log_data() -> None:
    log.info("Refreshing log data")
    docker_issues, loki_issues = await asyncio.gather(
        check_docker_logs(),
        check_loki(),
    )
    # Store issues immediately so the page reflects current logs right away
    async with _lock:
        _state["log_data"]["built_at"] = datetime.now(timezone.utc)
        _state["log_data"]["docker_issues"] = docker_issues
        _state["log_data"]["loki_issues"] = loki_issues
    log.info("Log data updated, queuing analysis")
    # Analysis runs independently — doesn't delay the next refresh cycle
    asyncio.create_task(_run_analysis(docker_issues, loki_issues))


async def _run_today_analysis(docker_issues: list[dict], loki_issues: list[dict]) -> None:
    """Run LLM analysis for today's data and generate the front-page newspaper."""
    docker_analysis = await _llm_analysis(docker_issues, "Docker container (today)")
    async with _lock:
        _state["today_data"]["docker_analysis"] = docker_analysis
    loki_analysis = await _llm_analysis(loki_issues, "network/syslog (from Loki, today)")
    async with _lock:
        _state["today_data"]["loki_analysis"] = loki_analysis
    log.info("Today LLM analysis complete — generating front page newspaper")
    loop = asyncio.get_running_loop()
    unhealthy, _, _ = await loop.run_in_executor(None, _get_container_status)
    async with _lock:
        update_hosts = dict(_state["update_hosts"])
    newspaper = await _generate_newspaper(docker_issues, loki_issues, update_hosts, unhealthy)
    async with _lock:
        _state["today_data"]["newspaper"] = newspaper if newspaper is not None else []
    log.info("Front page complete (%d articles)", len(newspaper) if newspaper else 0)


async def _refresh_today_data() -> None:
    midnight = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    since_ts = int(midnight.timestamp())
    log.info("Refreshing today's front page (since %s UTC)", midnight.strftime("%Y-%m-%d"))
    docker_issues, loki_issues = await asyncio.gather(
        check_docker_logs(since_ts=since_ts),
        check_loki(start=midnight),
    )
    async with _lock:
        _state["today_data"]["built_at"] = datetime.now(timezone.utc)
        _state["today_data"]["docker_issues"] = docker_issues
        _state["today_data"]["loki_issues"] = loki_issues
    asyncio.create_task(_run_today_analysis(docker_issues, loki_issues))


# ── Container status (fast, per-request) ──────────────────────────────────────

def _get_container_status() -> tuple[list, list, int]:
    try:
        dc = docker.from_env()
        all_c = dc.containers.list(all=True)
        running = dc.containers.list()
        unhealthy = [
            c for c in all_c
            if c.status != "running"
            or c.attrs.get("State", {}).get("Health", {}).get("Status") == "unhealthy"
        ]
        starting = [
            c for c in all_c
            if c.status == "running"
            and c.attrs.get("State", {}).get("Health", {}).get("Status") == "starting"
        ]
        return unhealthy, starting, len(running)
    except Exception:
        return [], [], 0


# ── Daily archive ─────────────────────────────────────────────────────────────

async def _run_daily_archive(date_str: Optional[str] = None) -> None:
    """Collect a full day of logs, run analysis, and append to the archive."""
    if date_str is None:
        yesterday = datetime.now(timezone.utc) - timedelta(days=1)
        date_str = yesterday.strftime("%Y-%m-%d")

    async with _lock:
        if any(r["date"] == date_str for r in _state["archive"]):
            log.info("Archive already exists for %s, skipping", date_str)
            return

    log.info("Building daily archive for %s", date_str)
    day_start = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    day_end   = day_start + timedelta(days=1)
    since_ts  = int(day_start.timestamp())
    until_ts  = int(day_end.timestamp())

    docker_issues, loki_issues = await asyncio.gather(
        check_docker_logs(since_ts=since_ts, until_ts=until_ts),
        check_loki(start=day_start, end=day_end),
    )
    docker_analysis = await _llm_analysis(docker_issues, "Docker container")
    loki_analysis   = await _llm_analysis(loki_issues, "network/syslog (from Loki)")

    async with _lock:
        update_snapshot = {
            label: {"results": [r for r in host.get("results", []) if r["status"] == "update_available"]}
            for label, host in _state["update_hosts"].items()
        }
    loop = asyncio.get_running_loop()
    unhealthy, _, _ = await loop.run_in_executor(None, _get_container_status)
    newspaper = await _generate_newspaper(docker_issues, loki_issues, update_snapshot, unhealthy)

    record: dict = {
        "date": date_str,
        "built_at": datetime.now(timezone.utc).isoformat(),
        "docker_issues": docker_issues[:50],
        "docker_analysis": docker_analysis,
        "loki_issues": loki_issues[:50],
        "loki_analysis": loki_analysis,
        "newspaper": newspaper or [],
    }

    async with _lock:
        _state["archive"].insert(0, record)
        _state["archive"] = _state["archive"][:MAX_ARCHIVE_DAYS]

    await loop.run_in_executor(None, _save_archive_sync, list(_state["archive"]))
    log.info("Daily archive saved for %s (%d docker, %d loki issues)",
             date_str, len(docker_issues), len(loki_issues))


async def _daily_archive_loop() -> None:
    # Catch up if yesterday is missing (e.g. container restarted after midnight)
    yesterday_str = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    async with _lock:
        have_yesterday = any(r["date"] == yesterday_str for r in _state["archive"])
    if not have_yesterday:
        try:
            await _run_daily_archive(yesterday_str)
        except Exception as e:
            log.error("Catch-up archive for %s failed: %s", yesterday_str, e)

    while True:
        now = datetime.now(timezone.utc)
        # Fire at 00:01 UTC each day (gives Loki a minute to flush the last logs)
        next_run = (now + timedelta(days=1)).replace(hour=0, minute=1, second=0, microsecond=0)
        wait_secs = (next_run - now).total_seconds()
        log.info("Next daily archive in %.0fs (at %s UTC)", wait_secs, next_run.strftime("%Y-%m-%d %H:%M"))
        await asyncio.sleep(wait_secs)
        try:
            await _run_daily_archive()
        except Exception as e:
            log.error("Daily archive failed: %s", e)


# ── Background tasks ──────────────────────────────────────────────────────────

async def _refresh_loop():
    while True:
        try:
            await _refresh_log_data()
        except Exception as e:
            log.error("Failed to refresh log data: %s", e)
        await asyncio.sleep(REFRESH_INTERVAL)


async def _today_data_loop():
    while True:
        try:
            await _refresh_today_data()
        except Exception as e:
            log.error("Today data loop error: %s", e)
        await asyncio.sleep(UPDATE_INTERVAL)


@asynccontextmanager
async def lifespan(_: FastAPI):
    _state["archive"] = _load_archive()
    asyncio.create_task(_refresh_loop())
    asyncio.create_task(_update_loop())
    asyncio.create_task(_today_data_loop())
    asyncio.create_task(_daily_archive_loop())
    yield


app = FastAPI(lifespan=lifespan)


@app.get("/")
async def index():
    loop = asyncio.get_running_loop()
    unhealthy, _, n_running = await loop.run_in_executor(None, _get_container_status)

    async with _lock:
        today_data   = dict(_state["today_data"])
        update_hosts = dict(_state["update_hosts"])

    if today_data["built_at"] is None:
        html = _init_page()
    else:
        html = _render_today_front_page(
            n_running=n_running,
            unhealthy=unhealthy,
            update_hosts=update_hosts,
            today_data=today_data,
        )
    return Response(content=html, media_type="text/html; charset=utf-8")


@app.get("/current")
async def current_events():
    loop = asyncio.get_running_loop()
    unhealthy, starting, n_running = await loop.run_in_executor(None, _get_container_status)

    async with _lock:
        log_data     = dict(_state["log_data"])
        update_hosts = dict(_state["update_hosts"])

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    if log_data["built_at"] is None:
        html = _init_page()
    else:
        html = _render_current_events(
            now_str=now_str,
            n_running=n_running,
            unhealthy=unhealthy,
            starting=starting,
            update_hosts=update_hosts,
            docker_issues=log_data["docker_issues"],
            docker_analysis=log_data["docker_analysis"],
            loki_issues=log_data["loki_issues"],
            loki_analysis=log_data["loki_analysis"],
            newspaper=log_data["newspaper"],
        )
    return Response(content=html, media_type="text/html; charset=utf-8")


@app.get("/detailed")
async def detailed():
    return RedirectResponse(url="/current", status_code=301)


@app.get("/archive")
async def archive_index():
    async with _lock:
        archive = list(_state["archive"])
    return Response(content=_render_archive_index(archive), media_type="text/html; charset=utf-8")


@app.get("/archive/{date_str}")
async def archive_day(date_str: str):
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return Response(content="Invalid date. Use YYYY-MM-DD.", status_code=400,
                        media_type="text/plain")
    async with _lock:
        rec = next((r for r in _state["archive"] if r["date"] == date_str), None)
    if rec is None:
        return Response(content=f"No archive found for {date_str}.", status_code=404,
                        media_type="text/plain")
    return Response(content=_render_archive_day(rec), media_type="text/html; charset=utf-8")


@app.get("/favicon.svg")
async def favicon_svg():
    return Response(content=_FAVICON_SVG, media_type="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=86400"})


@app.get("/favicon.ico")
async def favicon_ico():
    return Response(content=_FAVICON_SVG, media_type="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=86400"})

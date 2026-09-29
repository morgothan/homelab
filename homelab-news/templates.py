"""HTML rendering for the web application.

Pure view layer: builds HTML fragments and full pages from already-computed
data. No network, LLM, or filesystem access — ``web`` reads the JSON snapshots
and passes them in. Assets (CSS, favicon) live here too.
"""

from collections import defaultdict
from datetime import datetime
from html import escape as _h
from typing import Optional
from zoneinfo import ZoneInfo

from articles import SECTION_ORDER
from config import (
    LOCAL, LOG_HOURS, REFRESH_INTERVAL, SITE_NAME, UPDATE_INTERVAL,
)
from media import library_addition_titles

_ET = ZoneInfo("America/New_York")


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
.mast { text-align: center; margin-bottom: 32px; }
.rule-dbl { border: none; border-top: 3px double var(--gold); margin-bottom: 14px; }
.rule-sng { border: none; border-top: 1px solid var(--bdr); }
.mast-name {
  font-size: 2.8rem; font-weight: bold; letter-spacing: 0.08em;
  text-transform: uppercase; color: var(--gold); line-height: 1.1;
}
.mast-sub {
  font-size: 0.72rem; letter-spacing: 0.24em; text-transform: uppercase;
  color: var(--muted); margin-top: 5px;
}
.mast-meta { font-size: 0.75rem; color: var(--muted); font-family: "Courier New", monospace; margin: 10px 0; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.full { grid-column: 1 / -1; }
.card { background: var(--card); border: 1px solid var(--bdr); }
.card-head {
  display: flex; justify-content: space-between; align-items: center;
  padding: 9px 16px; border-bottom: 1px solid var(--bdr); background: var(--surf);
}
.card-title { font-size: 0.68rem; letter-spacing: 0.22em; text-transform: uppercase; color: var(--gold); font-weight: bold; }
.card-meta { font-size: 0.7rem; color: var(--muted); font-family: "Courier New", monospace; }
.card-body { padding: 14px 16px; font-family: "Courier New", Courier, monospace; font-size: 12px; line-height: 1.7; }
.c-ok   { color: var(--ok); }
.c-warn { color: var(--warn); }
.c-err  { color: var(--err); }
.c-dim  { color: var(--muted); }
.c-blue { color: var(--blue); }
.c-gold { color: var(--gold2); }
.issue {
  display: grid; grid-template-columns: 3rem 5rem minmax(70px, 140px) 1fr;
  gap: 10px; padding: 6px 0; border-bottom: 1px solid var(--dim); align-items: baseline;
}
.issue:last-child { border-bottom: none; }
.upd { display: grid; grid-template-columns: 14em 1fr; gap: 10px; padding: 5px 0; border-bottom: 1px solid var(--dim); }
.upd:last-child { border-bottom: none; }
.ctr { display: grid; grid-template-columns: 1.4em 1fr auto; gap: 8px; padding: 4px 0; }
.analysis {
  margin-top: 14px; padding: 10px 14px; border-left: 2px solid var(--gold2);
  background: rgba(201, 168, 76, 0.04); white-space: pre-wrap; font-size: 11.5px; color: #aaaaaa;
}
.analysis-hd { font-size: 0.62rem; letter-spacing: 0.18em; text-transform: uppercase; color: var(--gold2); margin-bottom: 8px; }
.arch-index { margin-top: 8px; }
.arch-day {
  display: grid; grid-template-columns: 10em 1fr 7em; gap: 12px; padding: 10px 0;
  border-bottom: 1px solid var(--bdr); align-items: baseline; text-decoration: none; color: inherit;
}
.arch-day:last-child { border-bottom: none; }
.arch-day:hover .arch-date { color: var(--gold); }
.arch-date { color: var(--gold2); font-family: "Courier New", monospace; font-size: 0.8rem; white-space: nowrap; }
.arch-headline { font-size: 0.88rem; color: var(--text); }
.arch-meta { font-size: 0.72rem; color: var(--muted); font-family: "Courier New", monospace; text-align: right; }
.arch-empty { text-align:center; padding:48px 20px; color:var(--muted); font-style:italic; }
.arch-section-head {
  font-size: 0.62rem; letter-spacing: 0.22em; text-transform: uppercase;
  color: var(--gold2); font-family: "Courier New", monospace;
  margin: 32px 0 12px; padding-bottom: 6px; border-bottom: 1px solid var(--bdr);
}
.arch-period { border-bottom: 1px solid var(--dim); }
.arch-period:last-child { border-bottom: none; }
.arch-period > summary {
  display: block; cursor: pointer; padding: 10px 4px 8px; list-style: none;
  user-select: none;
}
.arch-period > summary::-webkit-details-marker { display: none; }
.arch-period > summary::marker { display: none; }
.arch-period-hd {
  display: flex; justify-content: space-between; align-items: baseline; gap: 12px;
}
.arch-period-hd .arch-date { display: flex; align-items: center; gap: 7px; }
.arch-period-hd .arch-date::before {
  content: "▶"; font-size: 0.55rem; color: var(--gold2);
  display: inline-block; transition: transform 0.15s; flex-shrink: 0;
}
.arch-period[open] > summary .arch-date::before { transform: rotate(90deg); }
.arch-period > summary:hover .arch-date { color: var(--gold); }
.arch-period-lead { font-size: 0.85rem; color: var(--muted); margin-top: 3px; padding-left: 19px;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.arch-period-body { padding: 4px 0 14px 19px; }
.changelog {
  margin: 2px 0 8px 14px; padding: 5px 10px; border-left: 2px solid var(--warn);
  background: rgba(200, 136, 64, 0.05); font-size: 11px; color: #aaaaaa; white-space: pre-wrap; line-height: 1.6;
}
.changelog-tag { font-size: 10px; color: var(--muted); margin-left: 8px; }
.np-nav {
  text-align: center; font-size: 0.68rem; letter-spacing: 0.18em; text-transform: uppercase;
  color: var(--muted); font-family: "Courier New", monospace; margin-bottom: 20px;
}
.np-nav a { color: var(--gold2); text-decoration: none; }
.np-nav a:hover { color: var(--gold); }
.np-nav strong { color: var(--gold); }
.np-lead { padding: 22px 0 18px; border-bottom: 3px double var(--bdr); }
.np-lead-kicker {
  font-size: 0.62rem; letter-spacing: 0.22em; text-transform: uppercase;
  color: var(--gold2); font-family: "Courier New", monospace; margin-bottom: 8px;
}
.np-lead-hl { font-size: 2rem; font-weight: bold; line-height: 1.15; color: var(--text); margin-bottom: 12px; }
.np-lead-blurb { font-size: 0.9rem; line-height: 1.75; color: #aaaaaa; max-width: 720px; margin-bottom: 10px; }
.np-lead-section {
  display: inline-block; font-size: 0.58rem; letter-spacing: 0.2em; text-transform: uppercase;
  font-family: "Courier New", monospace; color: var(--bg); background: var(--gold2);
  padding: 2px 7px; border-radius: 2px;
}
.np-cols { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); border-bottom: 1px solid var(--bdr); }
.np-article { padding: 16px 20px; border-top: 1px solid var(--bdr); border-right: 1px solid var(--bdr); }
.np-article:last-child { border-right: none; }
.np-article-kicker {
  font-size: 0.58rem; letter-spacing: 0.2em; text-transform: uppercase;
  color: var(--muted); font-family: "Courier New", monospace; margin-bottom: 5px;
}
.np-hl { font-size: 1.05rem; font-weight: bold; line-height: 1.2; color: var(--text); margin-bottom: 8px; padding-bottom: 7px; border-bottom: 1px solid var(--bdr); }
.np-blurb { font-size: 0.82rem; line-height: 1.7; color: #999999; }
.np-media-additions { margin: 6px 0 0; padding-left: 18px; }
.np-media-additions li { margin: 3px 0; padding-left: 2px; }
.np-media-additions li::marker { color: var(--gold2); }
.np-briefs { border-top: 1px solid var(--bdr); padding: 14px 0 0; margin-top: 0; }
.np-briefs-head {
  font-size: 0.62rem; letter-spacing: 0.22em; text-transform: uppercase;
  color: var(--gold2); font-family: "Courier New", monospace; margin-bottom: 10px;
}
.np-brief { padding: 7px 0; border-bottom: 1px solid var(--dim); }
.np-brief:last-child { border-bottom: none; }
.np-brief-hl { font-size: 0.85rem; font-weight: bold; color: var(--text); }
.np-brief-blurb { font-size: 0.78rem; color: #888888; line-height: 1.5; }
.np-blotter { border-top: 1px solid var(--bdr); padding: 14px 0 0; margin-top: 0; }
.np-blotter-head {
  font-size: 0.62rem; letter-spacing: 0.22em; text-transform: uppercase;
  color: var(--gold2); font-family: "Courier New", monospace; margin-bottom: 10px;
}
.np-blotter-item { padding: 6px 0; border-bottom: 1px solid var(--dim); display: flex; gap: 14px; align-items: baseline; flex-wrap: wrap; }
.np-blotter-item:last-child { border-bottom: none; }
.np-blotter-ip { font-size: 0.85rem; font-weight: bold; font-family: "Courier New", monospace; }
.np-blotter-cat { font-size: 0.85rem; font-weight: bold; }
.np-blotter-meta { font-size: 0.78rem; color: #888888; }
.np-blotter-cat a { color: inherit; text-decoration-color: var(--gold); text-underline-offset: 2px; }
.np-blotter-offense { font-size: 0.78rem; }
.np-blotter-offense.abuse-med { color: var(--gold2); font-weight: bold; }
.np-blotter-offense.abuse-hi  { color: #e05c5c; font-weight: bold; }
.np-blotter-paths { width: 100%; font-size: 0.72rem; color: var(--muted); font-family: "Courier New", monospace; padding: 2px 0 4px; }
.np-blotter-intel { width: 100%; font-size: 0.72rem; color: var(--muted); padding: 1px 0 3px; }
.np-blotter-intel .flag { margin-right: 4px; }
.np-blotter-intel .abuse-hi { color: #e05c5c; font-weight: bold; }
.np-blotter-intel .abuse-med { color: var(--gold2); }
.np-blotter-intel .badge-threat { background: #7a1a1a; color: #ffcccc; border-radius: 3px; padding: 1px 5px; font-size: 0.68rem; font-weight: bold; letter-spacing: 0.04em; }
.badge-cs { background: #1a3a5c; color: #aad4ff; border-radius: 3px; padding: 1px 5px; font-size: 0.68rem; }
.np-blotter-count { font-size: 0.7em; color: var(--muted); }
.np-blotter-empty { padding: 10px 0; }
.np-blotter-page { border-top: 3px double var(--bdr); padding: 14px 0 0; margin-top: 24px; }
.np-blotter-section-head {
  font-size: 0.58rem; letter-spacing: 0.2em; text-transform: uppercase;
  color: var(--muted); font-family: "Courier New", monospace;
  border-bottom: 1px solid var(--dim); padding-bottom: 6px; margin: 16px 0 8px;
}
.np-blotter-scroll {
  max-height: 380px; overflow-y: auto;
  border: 1px solid var(--bdr); border-radius: 3px;
  padding: 0 10px; margin-bottom: 10px;
  scrollbar-width: thin; scrollbar-color: var(--gold2) var(--bg);
}
.np-blotter-scroll::-webkit-scrollbar { width: 4px; }
.np-blotter-scroll::-webkit-scrollbar-track { background: var(--bg); }
.np-blotter-scroll::-webkit-scrollbar-thumb { background: var(--gold2); border-radius: 2px; }
.np-blotter-scroll::-webkit-scrollbar-thumb:hover { background: var(--gold); }
.np-blotter-scroll .np-blotter-item:last-child { border-bottom: none; }
.np-blotter-sentinel { height: 1px; }
.np-blotter-loading { padding: 10px 0; color: var(--muted); font-size: 0.78rem; font-family: "Courier New", monospace; }
.np-blotter-page-head {
  font-size: 0.62rem; letter-spacing: 0.26em; text-transform: uppercase;
  color: var(--gold2); font-family: "Courier New", monospace;
  border-bottom: 1px solid var(--bdr); padding-bottom: 8px; margin-bottom: 14px;
}
/* Collapsible newspaper sections */
details.np-section > summary { list-style: none; cursor: pointer; user-select: none; display: block; }
details.np-section > summary::-webkit-details-marker { display: none; }
details.np-section > summary::after { content: " ▾"; color: var(--gold2); font-size: 0.65rem; }
details.np-section[open] > summary::after { content: " ▴"; }
.np-cols-head {
  font-size: 0.62rem; letter-spacing: 0.22em; text-transform: uppercase;
  color: var(--gold2); font-family: "Courier New", monospace; padding: 12px 0 0;
}
.np-dispatch-head {
  font-size: 0.62rem; letter-spacing: 0.22em; text-transform: uppercase;
  color: var(--gold2); font-family: "Courier New", monospace;
  border-top: 1px solid var(--bdr); border-bottom: 1px solid var(--bdr);
  padding: 10px 0; margin-top: 24px;
}
.np-pending {
  text-align: center; padding: 56px 20px; color: var(--muted);
  font-style: italic; font-size: 0.88rem; border-bottom: 1px solid var(--bdr);
}
.np-status {
  display: flex; flex-wrap: wrap; gap: 6px 24px; padding: 12px 0 0;
  font-family: "Courier New", monospace; font-size: 0.68rem; color: var(--muted);
}
.has-tip { position: relative; cursor: default; }
.has-tip::after {
  content: attr(data-tip);
  position: absolute;
  bottom: calc(100% + 6px);
  left: 50%;
  transform: translateX(-50%);
  background: var(--card);
  border: 1px solid var(--bdr);
  color: var(--text);
  font-size: 0.72rem;
  line-height: 1.7;
  padding: 7px 12px;
  border-radius: 4px;
  white-space: pre-wrap;
  max-width: 340px;
  width: max-content;
  pointer-events: none;
  opacity: 0;
  transition: opacity 0.15s;
  z-index: 100;
}
.has-tip:hover::after { opacity: 1; }
.ban-row {
  display: grid; grid-template-columns: 9em 8em 9em 4em 1fr;
  gap: 10px; padding: 6px 0; border-bottom: 1px solid var(--dim); align-items: baseline;
}
.ban-row:last-child { border-bottom: none; }
.ban-details > summary { list-style: none; display: flex; justify-content: space-between; align-items: center; cursor: pointer; user-select: none; }
.ban-details > summary::-webkit-details-marker { display: none; }
.ban-details > summary .card-meta::after { content: " ▾"; }
.ban-details[open] > summary .card-meta::after { content: " ▴"; }
/* Section dividers */
.np-section-divider {
  font-size: 0.64rem; letter-spacing: 0.26em; text-transform: uppercase;
  color: var(--gold2); font-family: "Courier New", monospace;
  border-top: 3px double var(--bdr); border-bottom: 1px solid var(--bdr);
  padding: 8px 0; margin: 24px 0 0; cursor: pointer; user-select: none; display: block;
}
.np-section-divider::after { content: " ▾"; }
details.np-section[open] > .np-section-divider::after { content: " ▴"; }
"""


_FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    '<rect width="32" height="32" rx="3" fill="#0f0f0f"/>'
    '<rect x="3" y="4" width="26" height="1.5" fill="#c9a84c"/>'
    '<rect x="3" y="6.5" width="26" height="0.6" fill="#c9a84c"/>'
    '<rect x="3" y="10" width="26" height="5" rx="0.5" fill="#c9a84c"/>'
    '<rect x="15.2" y="17.5" width="0.6" height="11" fill="#2a2a2a"/>'
    '<rect x="3" y="18" width="10" height="1.5" rx="0.3" fill="#3d3d3d"/>'
    '<rect x="3" y="21" width="10" height="1.5" rx="0.3" fill="#383838"/>'
    '<rect x="3" y="24" width="7" height="1.5" rx="0.3" fill="#333"/>'
    '<rect x="17" y="18" width="12" height="1.5" rx="0.3" fill="#3d3d3d"/>'
    '<rect x="17" y="21" width="9" height="1.5" rx="0.3" fill="#383838"/>'
    '<rect x="17" y="24" width="11" height="1.5" rx="0.3" fill="#333"/>'
    '</svg>'
)


def page_wrap(body: str, refresh: Optional[int] = None) -> str:
    refresh_script = ""
    if refresh:
        refresh_script = (
            f'<script>'
            f'(function(){{var iv={refresh}*1000;'
            # Track open <details> elements so they survive a refresh
            f'function openKeys(){{return Array.from(document.querySelectorAll("details[open]"))'
            f'.map(function(d){{return d.querySelector("summary")?d.querySelector("summary").textContent.trim():""}});}}'
            f'setInterval(function(){{'
            f'fetch(location.href,{{cache:"no-store"}})'
            f'.then(function(r){{return r.text();}})'
            f'.then(function(html){{'
            f'var p=new DOMParser();'
            f'var nd=p.parseFromString(html,"text/html").body.innerHTML;'
            f'if(nd!==document.body.innerHTML){{'
            # Re-open any <details> that were open before the swap
            f'var ok=openKeys();'
            f'document.body.innerHTML=nd;'
            f'if(ok.length){{document.querySelectorAll("details").forEach(function(d){{'
            f'var s=d.querySelector("summary");'
            f'if(s&&ok.indexOf(s.textContent.trim())>=0)d.setAttribute("open","");}});}}'
            f'}}}}).catch(function(){{}});'
            f'}},iv);'
            f'}})();'
            f'</script>'
        )
    return (
        '<!DOCTYPE html><html lang="en"><head>'
        f'<meta charset="utf-8"><title>{SITE_NAME}</title>'
        '<link rel="icon" href="/favicon.svg" type="image/svg+xml">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<style>' + _CSS + '</style>'
        '</head><body>' + body + refresh_script + '</body></html>'
    )


def nav_bar(active: str) -> str:
    def _item(href: str, label: str, key: str) -> str:
        return f'<strong>{label}</strong>' if active == key else f'<a href="{href}">{label}</a>'
    return (
        '<div class="np-nav">'
        + _item("/", "Front Page", "front")
        + " &nbsp;&middot;&nbsp; "
        + _item("/current", "Current Events", "current")
        + " &nbsp;&middot;&nbsp; "
        + _item("/wire", "Wire Reports", "wire")
        + " &nbsp;&middot;&nbsp; "
        + _item("/blotter", "Police Blotter", "blotter")
        + " &nbsp;&middot;&nbsp; "
        + _item("/entertainment", "Arts &amp; Entertainment", "entertainment")
        + " &nbsp;&middot;&nbsp; "
        + _item("/archive", "Archive", "archive")
        + " &nbsp;&middot;&nbsp; "
        + _item("/trends", "Trends", "trends")
        + " &nbsp;&middot;&nbsp; "
        + _item("/search", "Search", "search")
        + '</div>'
    )


def _masthead(subtitle: str, meta: str) -> str:
    return (
        f'<header class="mast"><hr class="rule-dbl">'
        f'<div class="mast-name">{SITE_NAME}</div>'
        f'<div class="mast-sub">{subtitle}</div>'
        '<hr class="rule-sng" style="margin:10px 0">'
        f'<div class="mast-meta">{meta}</div>'
        '<hr class="rule-sng" style="margin-top:10px"></header>'
    )


def _generation_notice(stale: bool) -> str:
    if not stale:
        return ""
    return ' &nbsp;&middot;&nbsp; <span class="c-warn">&#9888; Update failed; showing last successful edition</span>'


def masthead_rolling(now_str: str, stale: bool = False) -> str:
    return _masthead(
        "Homelab Intelligence Dispatch &mdash; Est. 2026",
        f'Generated {_h(now_str)}{_generation_notice(stale)} &nbsp;&middot;&nbsp; Refresh {REFRESH_INTERVAL // 60}m &nbsp;&middot;&nbsp; Log window {LOG_HOURS}h',
    )


def masthead_today(now_str: str = "", stale: bool = False) -> str:
    today_str = datetime.now(_ET).strftime("%A, %B %-d, %Y")
    generated = f" &nbsp;&middot;&nbsp; Generated {_h(now_str)}" if now_str else ""
    return _masthead(
        "Homelab Intelligence Dispatch &mdash; Est. 2026",
        f"Today's Edition &mdash; {_h(today_str)}{generated}{_generation_notice(stale)} &nbsp;&middot;&nbsp; Updated hourly",
    )


def masthead_archive(date_str: str) -> str:
    return _masthead(
        "Homelab Intelligence Dispatch &mdash; Est. 2026",
        f"Edition for {_h(date_str)}",
    )


def masthead_wire(checked_at: str) -> str:
    return _masthead(
        "Wire Reports &mdash; Software Intelligence Desk",
        f'Last checked {_h(checked_at)} &nbsp;&middot;&nbsp; Updates every {UPDATE_INTERVAL // 60}m',
    )


def lvl_badge(level: str) -> str:
    if level == "error":
        return '<span class="c-err">ERR</span>'
    return '<span class="c-warn">WRN</span>'


def render_issue_rows(issues: list[dict]) -> str:
    if not issues:
        return '<span class="c-ok">&#x2713;&nbsp; No issues found.</span>'
    return "".join(
        '<div class="issue">'
        + lvl_badge(i["level"])
        + f'<span class="c-dim">&#xd7;{i["count"]}</span>'
        + f'<span class="c-gold">{_h(i["source"])}</span>'
        + f'<span>{_h(i["message"][:220])}</span>'
        + '</div>'
        for i in issues
    )


def log_card(title: str, meta: str, issues: list[dict], analysis: Optional[str]) -> str:
    body = render_issue_rows(issues)
    if analysis:
        body += (
            '<div class="analysis"><div class="analysis-hd">AI Analysis</div>'
            + _h(analysis) + '</div>'
        )
    return (
        '<div class="card full"><div class="card-head">'
        f'<span class="card-title">{title}</span>'
        f'<span class="card-meta">{meta}</span>'
        f'</div><div class="card-body">{body}</div></div>'
    )


def render_bans_card(bans: list[dict]) -> str:
    n = len(bans)
    meta = f'{n} active ban{"s" if n != 1 else ""} &nbsp;&middot;&nbsp; cf-fail2ban 24h &middot; CrowdSec 4h'
    if not bans:
        return (
            '<div class="card full"><div class="card-head">'
            '<span class="card-title">Blocked IPs</span>'
            f'<span class="card-meta">{meta}</span>'
            '</div><div class="card-body">'
            '<span class="c-ok">&#x2713;&nbsp; No active IP bans.</span>'
            '</div></div>'
        )
    def _ban_row(b):
        expires = "&#x221e; permanent" if b["expires_in"] == "permanent" else _h(b["expires_in"])
        offense = b.get("offense_count", 1)
        offense_str = ""
        if offense >= 2:
            suffixes = ["st", "nd", "rd"]
            suffix = suffixes[offense - 1] if offense <= 3 else "th"
            offense_str = f'<span class="c-err"> &#x26a0;{offense}{suffix}</span>'
        return (
            '<div class="ban-row">'
            f'<span class="c-err">{_h(b["ip"])}</span>'
            f'<span class="c-dim">+{_h(b["blocked_for"])}</span>'
            f'<span class="c-warn">expires in {expires}</span>'
            f'<span class="c-dim">&#xd7;{b["hit_count"]}</span>'
            f'<span class="c-gold">{_h(b.get("category", "vulnerability scan"))}</span>'
            + offense_str +
            '</div>'
        )
    rows = "".join(_ban_row(b) for b in bans)
    return (
        '<div class="card full">'
        '<details class="ban-details">'
        '<summary class="card-head ban-summary">'
        '<span class="card-title">Blocked IPs</span>'
        f'<span class="card-meta">{meta}</span>'
        '</summary>'
        f'<div class="card-body">{rows}</div>'
        '</details></div>'
    )


def alerts_card(alerts: list) -> str:
    """Deterministic, code-rendered outage list — not routed through the LLM article
    writer, so a down service can't get silently dropped from a summarization prompt."""
    if not alerts:
        return ""
    rows = [
        '<div class="ctr"><span class="c-err">&#x2717;</span>'
        f'<span>{_h(a["label"])}</span><span class="c-warn">{_h(a["detail"])}</span></div>'
        for a in alerts
    ]
    return (
        '<div class="card"><div class="card-head">'
        '<span class="card-title">Service Alerts</span>'
        f'<span class="card-meta c-err">{len(alerts)} down</span>'
        f'</div><div class="card-body">{"".join(rows)}</div></div>'
    )


def containers_card(unhealthy: list, starting: list, n_running: int) -> str:
    if not unhealthy:
        body = '<span class="c-ok">&#x2713;&nbsp; All containers running and healthy.</span>'
    else:
        rows = []
        for c in unhealthy:
            health = c.attrs.get("State", {}).get("Health", {}).get("Status", "")
            detail = c.status + (f" / {health}" if health else "")
            rows.append(
                '<div class="ctr"><span class="c-err">&#x2717;</span>'
                f'<span>{_h(c.name)}</span><span class="c-warn">{_h(detail)}</span></div>'
            )
        body = ''.join(rows)
    if starting:
        body += f'<div class="c-dim" style="margin-top:8px">Starting: {_h(", ".join(c.name for c in starting))}</div>'
    return (
        '<div class="card"><div class="card-head">'
        '<span class="card-title">Container Status</span>'
        f'<span class="card-meta">{n_running} running</span>'
        f'</div><div class="card-body">{body}</div></div>'
    )


# Per-host mapping for Docker-based updates: label (as reported by _check_host) -> FQDN
# running this repo's dc.sh wrapper. Hosts not listed here aren't managed by this repo.
_DC_SH_HOSTS = {
    "local": f"traefik.{LOCAL}",
    "spark": f"spark.{LOCAL}",
}

# Non-Docker update sources (see updates.py check_* functions) -> how to actually apply them.
_SOURCE_HOWTO = {
    "Proxmox VE":      "SSH to the Proxmox host: apt update && apt upgrade -y "
                        "(hypervisor — do this in a maintenance window)",
    "Primary DNS":     "AdGuard Home UI → Settings → General → Check for updates (self-updates in place)",
    "Secondary DNS":   "Proxmox LXC 110: pct exec 110 -- /opt/AdGuardHome/AdGuardHome -s update",
    "Kids DNS":        "AdGuard Home UI → Settings → General → Check for updates (self-updates in place)",
    "Jellyfin":        "Jellyfin Dashboard → General → Check for updates (not managed by this repo)",
    "TrueNAS Apps":    'TrueNAS UI → Apps → Update, or over SSH: midclt call app.upgrade \'["<app>"]\'',
    "TrueNAS Scale":   "TrueNAS UI → System → Update (reboots the NAS), or: midclt call update.update",
    "Home Assistant":  "HA UI → Settings → System → Updates → Update",
    "Beszel":          "SSH to the Beszel host: docker compose pull beszel && docker compose up -d beszel",
    "vLLM":            f"Distributed vLLM runs via sparkrun on the 2-node spark cluster "
                        f"(systemd: sparkrun-deepseek on spark1, recipe @spark-arena/c236b076..., "
                        f"model deepseek-v4-flash-0731). Update the sparkrun CLI: SSH to spark.{LOCAL} "
                        f"(and the docker host): sparkrun setup update. Swap the vLLM build / model: "
                        f"pick a newer recipe (sparkrun search / sparkrun show @spark-arena/<id>), then "
                        f"sparkrun export systemd <recipe> --cluster <spark-cluster> --port 8000 "
                        f"--served-model-name <name> --service-name sparkrun-deepseek --install, and "
                        f"sudo systemctl restart sparkrun-deepseek. Rollback to single-node Qwen3.6: "
                        f"sudo systemctl disable --now sparkrun-deepseek && systemctl --user enable --now vllm.",
    "DGX Spark":       f"SSH to spark.{LOCAL}: sudo apt update && sudo apt upgrade "
                        "(NVIDIA driver/CUDA packages — review before rebooting)",
    "Traefik Plugins": "Bump the version: field for the plugin in traefik/traefik.yml, "
                        "then: ./dc.sh restart traefik",
}


def update_howto(*, container: str = "", host: str = "", source_label: str = "") -> str:
    """Tooltip text explaining how to actually apply a given update."""
    if source_label:
        return _SOURCE_HOWTO.get(
            source_label,
            f"Update via {source_label}'s own admin UI/CLI — not orchestrated by this repo.",
        )
    fqdn = _DC_SH_HOSTS.get(host)
    if fqdn:
        return f"On {fqdn}: ./dc.sh pull {container} && ./dc.sh up -d {container}"
    return f"SSH to {host} and update via its own docker workflow — not part of this repo's compose stack."


def updates_card(update_hosts: dict) -> str:
    if not update_hosts:
        body = '<span class="c-dim">No update data yet — check running.</span>'
        return (
            '<div class="card"><div class="card-head">'
            '<span class="card-title">Image Updates</span>'
            '<span class="card-meta">pending</span>'
            f'</div><div class="card-body">{body}</div></div>'
        )

    checked_at = update_hosts.get("_checked_at")
    meta = f'checked {checked_at}' if checked_at else "—"
    hosts = {k: v for k, v in update_hosts.items() if k != "_checked_at"}

    sections = []
    for label, host in hosts.items():
        results = host.get("results", [])
        available = [r for r in results if r["status"] == "update_available"]
        failed    = [r for r in results if r["status"] == "check_failed"]
        ts_str = host.get("ts", "")
        ts_disp = ts_str[11:16] if ts_str else ""

        if not results:
            body = '<span class="c-dim">no containers found</span>'
        elif not available:
            body = '<span class="c-ok">&#x2713; current</span>'
        else:
            rows = []
            for r in available:
                new_ver = r.get("new_version", "")
                tag_html = f'<span class="changelog-tag">&#x2192; {_h(new_ver)}</span>' if new_ver else ""
                tip = _h(update_howto(container=r["container"], host=label))
                rows.append(
                    '<div class="upd">'
                    f'<span class="c-blue has-tip" data-tip="{tip}">{_h(r["container"])}</span>'
                    f'<span class="c-dim">{_h(r["image"])}{tag_html}</span></div>'
                )
                cl = r.get("changelog_analysis")
                if cl:
                    rows.append(f'<div class="changelog">{_h(cl)}</div>')
            body = ''.join(rows)
        if failed:
            body += f'<div class="c-dim" style="margin-top:4px;font-size:11px">check failed: {_h(", ".join(r["container"] for r in failed))}</div>'

        sections.append(
            f'<div style="margin-bottom:10px">'
            f'<div style="margin-bottom:4px"><span class="c-gold">{_h(label)}</span>'
            + (f'<span class="c-dim" style="font-size:11px"> — {ts_disp}</span>' if ts_disp else '')
            + f'</div>{body}</div>'
        )

    body_html = '<hr class="sep">'.join(sections)
    return (
        '<div class="card"><div class="card-head">'
        '<span class="card-title">Image Updates</span>'
        f'<span class="card-meta">{_h(meta)}</span>'
        f'</div><div class="card-body">{body_html}</div></div>'
    )


def _intel_line(info: dict) -> str:
    """Format a single geo/ASN/abuse/CrowdSec intel line for a ban entry."""
    if not info:
        return ""
    parts: list[str] = []
    badges: list[str] = []

    cc = info.get("country_code", "")
    country = info.get("country", "")
    city = info.get("city", "")
    if cc:
        flag = "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc.upper() if c.isalpha())
        loc = ", ".join(filter(None, [city, country]))
        parts.append(f'<span class="flag">{flag}</span>{_h(loc)}')

    org = info.get("org") or info.get("isp", "")
    asn = info.get("asn", "")
    if org:
        parts.append(_h(f"{org} ({asn})" if asn else org))

    abuse_score = info.get("abuse_score")
    if abuse_score is not None:
        if abuse_score >= 50:
            cls = "abuse-hi"
        elif abuse_score >= 20:
            cls = "abuse-med"
        else:
            cls = ""
        label = f"Abuse: {abuse_score}%"
        if info.get("usage_type"):
            label += f" · {info['usage_type']}"
        parts.append(f'<span class="{cls}">{_h(label)}</span>' if cls else _h(label))

    # CrowdSec CTI
    cs_score = info.get("crowdsec_score")
    if cs_score is not None and cs_score > 0:
        if cs_score >= 3:
            score_cls = "abuse-hi"
        else:
            score_cls = "abuse-med"
        parts.append(f'<span class="{score_cls}">CrowdSec: {cs_score}/5</span>')

    cs_noise = info.get("crowdsec_noise", 0)
    if cs_noise and cs_noise >= 7:
        parts.append(f'<span class="abuse-med">noise:{cs_noise}/10</span>')

    behaviors = info.get("crowdsec_behaviors", [])
    if behaviors:
        top = behaviors[:3]
        parts.append(_h(" · ".join(top)))

    if info.get("crowdsec_is_tor"):
        badges.append('<span class="badge-threat">TOR</span>')
    if info.get("crowdsec_is_proxy"):
        badges.append('<span class="badge-threat">VPN/Proxy</span>')

    classifications = info.get("crowdsec_classifications", [])
    for label in classifications[:2]:
        badges.append(f'<span class="badge-cs">{_h(label)}</span>')

    if not parts and not badges:
        return ""
    body = " &nbsp;·&nbsp; ".join(parts)
    if badges:
        body = ("&nbsp;".join(badges) + ("&nbsp;&nbsp;" if parts else "")) + body
    return '<div class="np-blotter-intel">' + body + "</div>"


def _render_ban_row(b: dict, intel: dict) -> str:
    paths_html = ""
    if b.get("paths"):
        paths_html = (
            '<div class="np-blotter-paths">'
            + ' &middot; '.join(_h(p) for p in b["paths"][:5])
            + '</div>'
        )
    intel_html = _intel_line(intel.get(b["ip"], {}))
    offense = b.get("offense_count", 1)
    offense_html = ""
    if offense >= 2:
        tier_cls = "abuse-hi" if offense >= 5 else ("abuse-med" if offense >= 3 else "")
        suffixes = ["st", "nd", "rd"]
        suffix = suffixes[offense - 1] if offense <= 3 else "th"
        label = f"&#x26a0; {offense}{suffix} offense"
        offense_html = f' &middot; <span class="np-blotter-offense{" " + tier_cls if tier_cls else ""}">{label}</span>'
    expires_display = "&#x221e; permanent" if b["expires_in"] == "permanent" else _h(b["expires_in"])
    is_cs = b.get("source") == "crowdsec"
    hits_html = "" if is_cs else f'&times;{b["hit_count"]} hits &middot; '
    return (
        '<div class="np-blotter-item">'
        + f'<span class="np-blotter-ip c-err">{_h(b["ip"])}</span>'
        + f'<span class="np-blotter-cat c-gold">{_h(b.get("category", "vulnerability scan"))}</span>'
        + f'<span class="np-blotter-meta">{hits_html}'
        + f'blocked {_h(b["blocked_for"])}'
        + f' &middot; expires in {expires_display}'
        + offense_html + '</span>'
        + intel_html
        + paths_html
        + '</div>'
    )


def _render_ban_rows(bans: list[dict], intel: dict) -> str:
    return "".join(_render_ban_row(b, intel) for b in bans)


def render_blotter_skeleton() -> str:
    """Blotter page shell — data loaded client-side via /api/bans + /api/cs-bans."""
    js = r"""
(function(){
  var CHUNK=30;
  var cl=document.getElementById('cs-list');
  var cf=document.getElementById('cf-list');
  var cfH=document.getElementById('cf-head');
  var csH=document.getElementById('cs-head');
  var cnt=document.getElementById('blotter-count');
  var asn=document.getElementById('asn-content');

  var csBuf=[];      // rows buffered from server, not yet in DOM
  var csRendered=0;  // rows inserted into DOM
  var csFetched=0;   // rows received from server total
  var csTotal=0;     // total CS bans on server
  var cfCount=0;
  var fetching=false;
  var ob=null,sent=null;

  function flushBuf(){
    if(!csBuf.length||!sent)return;
    var batch=csBuf.splice(0,CHUNK);
    var tmp=document.createElement('div');
    tmp.innerHTML=batch.join('');
    while(tmp.firstChild)cl.insertBefore(tmp.firstChild,sent);
    csRendered+=batch.length;
    if(csFetched>=csTotal&&!csBuf.length){
      sent.remove();sent=null;
      if(ob){ob.disconnect();ob=null;}
    } else if(ob&&sent){
      ob.observe(sent);
    }
  }

  function fetchMore(){
    if(fetching||csFetched>=csTotal)return;
    fetching=true;
    fetch('/api/cs-bans?offset='+csFetched)
      .then(function(r){return r.json();})
      .then(function(d){
        csTotal=d.total;
        csBuf=csBuf.concat(d.rows);
        csFetched+=d.rows.length;
        fetching=false;
        updateHead();
        flushBuf();
      })
      .catch(function(){fetching=false;});
  }

  function updateHead(){
    csH.innerHTML='CrowdSec — '+csTotal+' ban'+(csTotal!==1?'s':'')+' · 4h bantime';
    cnt.textContent=(cfCount+csTotal)+' active ban'+((cfCount+csTotal)!==1?'s':'');
  }

  function setup(data){
    cfCount=data.cf.length;
    csTotal=data.cs_total;
    csFetched=data.cs.length;
    csBuf=data.cs.slice();
    csRendered=0;

    cfH.innerHTML='cf-fail2ban — '+cfCount+' ban'+(cfCount!==1?'s':'')+' · 24h bantime';
    cf.innerHTML=cfCount?data.cf.join(''):'<div class="np-blotter-empty"><span class="c-ok">✓  None.</span></div>';
    updateHead();
    cl.innerHTML='';

    if(!csTotal){
      cl.innerHTML='<div class="np-blotter-empty"><span class="c-ok">✓  None.</span></div>';
      cnt.textContent=cfCount+' active ban'+(cfCount!==1?'s':'');
      return;
    }

    sent=document.createElement('div');sent.className='np-blotter-sentinel';cl.appendChild(sent);
    ob=new IntersectionObserver(function(e){
      if(!e[0].isIntersecting)return;
      ob.unobserve(sent);
      if(csBuf.length)flushBuf();
      else fetchMore();
    },{root:cl,threshold:0.0});
    ob.observe(sent);
    flushBuf();

    if(asn)asn.innerHTML=(data.asn_blocks_html||'')+(data.asn_suggestions_html||'');
  }

  fetch('/api/bans')
    .then(function(r){return r.json();})
    .then(setup)
    .catch(function(){
      cf.innerHTML='<div class="np-blotter-empty"><span class="c-err">Error loading ban data.</span></div>';
      cl.innerHTML='';
    });
})();
"""
    return (
        '<div class="np-blotter-page">'
        '<div class="np-blotter-page-head">Police Blotter'
        '<span class="np-blotter-meta" id="blotter-count" style="margin-left:14px">loading&hellip;</span>'
        '</div>'
        '<div class="np-blotter-section-head" id="cf-head">cf-fail2ban &middot; 24h bantime</div>'
        '<div id="cf-list"><div class="np-blotter-loading">loading&hellip;</div></div>'
        '<div class="np-blotter-section-head" id="cs-head">CrowdSec &middot; 4h bantime</div>'
        '<div class="np-blotter-scroll" id="cs-list"><div class="np-blotter-loading">loading&hellip;</div></div>'
        '</div>'
        '<div id="asn-content"></div>'
        f'<script>{js}</script>'
    )


def render_blotter_html(bans: list[dict], *, collapsed: bool = False, intel: Optional[dict] = None) -> str:
    """Server-side blotter render — used for archive snapshots (collapsed=True)."""
    intel = intel or {}
    cf_bans = [b for b in bans if b.get("source") != "crowdsec"]
    cs_bans = [b for b in bans if b.get("source") == "crowdsec"]
    n = len(cf_bans) + len(cs_bans)
    count_str = f'{n} active ban{"s" if n != 1 else ""}'

    if not bans:
        entries_html = '<div class="np-blotter-empty"><span class="c-ok">&#x2713;&nbsp; No active IP bans.</span></div>'
    else:
        cf_html = _render_ban_rows(cf_bans, intel) if cf_bans else '<div class="np-blotter-empty"><span class="c-ok">&#x2713;&nbsp; None.</span></div>'
        cs_html = _render_ban_rows(cs_bans, intel) if cs_bans else '<div class="np-blotter-empty"><span class="c-ok">&#x2713;&nbsp; None.</span></div>'
        entries_html = (
            f'<div class="np-blotter-section-head">cf-fail2ban &mdash; {len(cf_bans)} ban{"s" if len(cf_bans) != 1 else ""} &middot; 24h bantime</div>'
            + cf_html
            + f'<div class="np-blotter-section-head">CrowdSec &mdash; {len(cs_bans)} ban{"s" if len(cs_bans) != 1 else ""} &middot; 4h bantime</div>'
            + '<div class="np-blotter-scroll">' + cs_html + '</div>'
        )

    if collapsed:
        return (
            '<details class="np-blotter np-section">'
            f'<summary class="np-blotter-head">Police Blotter'
            f' <span class="np-blotter-count">({count_str})</span></summary>'
            + entries_html
            + '</details>'
        )
    return (
        '<div class="np-blotter-page">'
        f'<div class="np-blotter-page-head">Police Blotter'
        f'<span class="np-blotter-meta" style="margin-left:14px">{count_str}</span>'
        f'</div>'
        + entries_html
        + '</div>'
    )


def render_library_scan_html(data: Optional[dict]) -> str:
    """Render the weekly library-dupe-scan findings (duplicate content + wrong audio language)."""
    if not data:
        return (
            '<div class="np-blotter-page">'
            '<div class="np-blotter-page-head">Media Library Report</div>'
            '<div class="np-blotter-empty"><span class="np-pending">No scan has run yet.</span></div>'
            '</div>'
        )

    generated_at = data.get("generated_at", "unknown")
    dupes = data.get("confirmed_dupes", [])
    langs = data.get("lang_flags", [])

    def _dupe_row(d: dict) -> str:
        eps = ", ".join(
            f'S{e["season"]:02d}E{e["episode"]:02d} &ldquo;{_h(e.get("title") or "")}&rdquo;'
            for e in d["episodes"]
        )
        paths = "".join(f'<div class="np-blotter-paths">{_h(p)}</div>' for p in dict.fromkeys(e["path"] for e in d["episodes"]))
        return (
            '<div class="np-blotter-item">'
            f'<span class="np-blotter-cat c-err">{_h(d["series"])}</span>'
            f'<span class="np-blotter-meta">{eps}</span>'
            + paths +
            '</div>'
        )

    def _lang_row(f: dict) -> str:
        return (
            '<div class="np-blotter-item">'
            f'<span class="np-blotter-cat c-warn">{_h(f["series"])} S{f["season"]:02d}E{f["episode"]:02d}</span>'
            f'<span class="np-blotter-meta">&ldquo;{_h(f.get("title") or "")}&rdquo;'
            f' &mdash; expected {_h(f["expected_lang"])}, found {_h(f["actual_lang"])}</span>'
            f'<div class="np-blotter-paths">{_h(f["path"])}</div>'
            '</div>'
        )

    dupes_html = (
        "".join(_dupe_row(d) for d in dupes)
        if dupes else '<div class="np-blotter-empty"><span class="c-ok">&#x2713;&nbsp; None found.</span></div>'
    )
    langs_html = (
        "".join(_lang_row(f) for f in langs)
        if langs else '<div class="np-blotter-empty"><span class="c-ok">&#x2713;&nbsp; None found.</span></div>'
    )

    return (
        '<div class="np-blotter-page">'
        f'<div class="np-blotter-page-head">Media Library Report'
        f'<span class="np-blotter-meta" style="margin-left:14px">last scanned {_h(generated_at)}</span>'
        '</div>'
        f'<div class="np-blotter-section-head">Duplicate-Content Episodes &mdash; {len(dupes)} group{"s" if len(dupes) != 1 else ""}</div>'
        + dupes_html +
        f'<div class="np-blotter-section-head">Wrong Audio-Language Episodes &mdash; {len(langs)} file{"s" if len(langs) != 1 else ""}</div>'
        + langs_html +
        '</div>'
    )


def render_recent_media_html(media_events: list[dict], links: Optional[dict[str, str]] = None) -> str:
    """Render Seerr availability events as the Entertainment page's top list."""
    titles = library_addition_titles(media_events)
    count = len(titles)
    count_text = f'{count} addition{"s" if count != 1 else ""}'
    if titles:
        links = links or {}
        items = "".join(
            '<div class="np-blotter-item">'
            '<span class="np-blotter-cat c-gold">'
            + (f'<a href="{_h(links[title])}">{_h(title)}</a>' if title in links else _h(title))
            + '</span>'
            '</div>'
            for title in titles
        )
    else:
        items = (
            '<div class="np-blotter-empty">'
            '<span class="np-pending">No new media added in the past 7 days.</span>'
            '</div>'
        )
    return (
        '<div class="np-blotter-page">'
        '<div class="np-blotter-page-head">New Media &mdash; Past 7 Days'
        f'<span class="np-blotter-meta" style="margin-left:14px">{count_text}</span>'
        '</div>'
        + items
        + '</div>'
    )


def render_asn_suggestions_html(suggestions: list[dict]) -> str:
    """Render ASN block candidate panel for the blotter page."""
    if not suggestions:
        return ""
    rows = []
    for s in suggestions:
        org_str  = _h(s["org"]) if s["org"] else "unknown org"
        ut_str   = f' &middot; <span class="np-blotter-cat">{_h(s["usage_type"])}</span>' if s["usage_type"] else ""
        cs_str   = f' &middot; {s["crowdsec_count"]} on CrowdSec blocklist' if s["crowdsec_count"] else ""
        large_str = (
            ' &middot; <span class="c-err" title="Major cloud/CDN provider — blocking this ASN risks collateral damage to legitimate traffic">'
            '&#x26a0; Large shared ASN — block with caution</span>'
        ) if s.get("large_asn") else ""
        rows.append(
            '<div class="np-blotter-item">'
            f'<span class="np-blotter-ip c-warn">{_h(s["asn"])}</span>'
            f'<span class="np-blotter-cat c-gold">{org_str}</span>'
            f'<span class="np-blotter-meta">'
            f'{s["ip_count"]} banned IPs'
            f' &middot; avg abuse {s["avg_abuse"]:.0f}%'
            f'{cs_str}'
            f'{ut_str}'
            f'{large_str}'
            '</span>'
            '</div>'
        )
    return (
        '<div class="np-blotter-page" style="margin-top:18px">'
        '<div class="np-blotter-page-head" style="color:#f5a623">&#x26a0;&nbsp; ASN Block Candidates'
        '<span class="np-blotter-meta" style="margin-left:14px">manual review — run cf-fail2ban --block-asn &lt;ASN&gt;</span>'
        '</div>'
        + "".join(rows)
        + '</div>'
    )


def render_asn_blocklist_html(asn_blocks: list[dict]) -> str:
    """Render the permanently-blocked ASN list panel for the blotter page."""
    if not asn_blocks:
        return ""
    rows = []
    for b in asn_blocks:
        org_str   = _h(b["org"]) if b["org"] else "unknown org"
        notes_str = ""
        if b.get("notes"):
            notes_str = f'<div class="np-blotter-paths">{_h(b["notes"])}</div>'
        rows.append(
            '<div class="np-blotter-item">'
            f'<span class="np-blotter-ip c-err">{_h(b["asn"])}</span>'
            f'<span class="np-blotter-cat c-gold">{org_str}</span>'
            f'<span class="np-blotter-meta">'
            f'blocked {_h(b["blocked_at"])}'
            f' &middot; rule {_h(b["cf_rule_id"])}'
            '</span>'
            + notes_str
            + '</div>'
        )
    return (
        '<div class="np-blotter-page" style="margin-top:18px">'
        '<div class="np-blotter-page-head">ASN Blocklist'
        '<span class="np-blotter-meta" style="margin-left:14px">'
        f'{len(asn_blocks)} ASN{"s" if len(asn_blocks) != 1 else ""} permanently blocked'
        ' &nbsp;&middot;&nbsp; manage with cf-fail2ban --block-asn / --unblock-asn'
        '</span></div>'
        + "".join(rows)
        + '</div>'
    )


def render_articles_html(articles: list[dict]) -> str:
    if not articles:
        return '<div class="np-pending">No articles available for this edition.</div>'

    lead_idx = next((i for i, a in enumerate(articles)
                     if a.get("source") != "seerr-library-additions"), None)
    if lead_idx is None:
        html = ""
        rest = articles
    else:
        lead = articles[lead_idx]
        rest = articles[:lead_idx] + articles[lead_idx + 1:]
        lead_section = lead.get("section", "").strip()
        if lead_section not in SECTION_ORDER:
            lead_section = "City Hall"
        html = (
            '<div class="np-lead">'
            '<div class="np-lead-kicker">Lead Story</div>'
            f'<div class="np-lead-hl">{_h(lead["headline"])}</div>'
            f'<div class="np-lead-blurb">{_h(lead["blurb"])}</div>'
            f'<div class="np-lead-section">{_h(lead_section)}</div>'
            '</div>'
        )

    # Group remaining articles by section, preserving within-section order.
    # The lead article's section may appear again if the LLM wrote more articles for it.
    by_section: dict[str, list[dict]] = defaultdict(list)
    for a in rest:
        section = a.get("section", "").strip()
        if section not in SECTION_ORDER:
            section = "City Hall"
        by_section[section].append(a)

    section_kickers = {
        "City Hall": ["Report", "Update", "Bulletin", "Dispatch"],
        "Public Safety": ["Alert", "Incident", "Report", "Advisory"],
        "Weather": ["Reading", "Update", "Status", "Monitor"],
        "City Archives": ["Report", "Status", "Update", "Audit"],
        "Arts & Entertainment": ["Review", "Update", "Report", "Feature"],
        "Public Works": ["Update", "Status", "Report", "Notice"],
    }
    default_kickers = ["Report", "Update", "Bulletin", "Notice"]

    def _card_blurb(article: dict) -> str:
        additions = article.get("media_additions")
        if article.get("source") == "seerr-library-additions" and not isinstance(additions, list):
            legacy_blurb = str(article.get("blurb") or "")
            prefix = "Now available: "
            if legacy_blurb.startswith(prefix):
                additions = legacy_blurb.removeprefix(prefix).removesuffix(".").split("; ")
        if article.get("source") == "seerr-library-additions" and isinstance(additions, list):
            items = "".join(f"<li>{_h(item)}</li>" for item in additions if item)
            return (
                '<div class="np-blurb">Now available:'
                f'<ul class="np-media-additions">{items}</ul></div>'
            )
        return f'<div class="np-blurb">{_h(article["blurb"])}</div>'

    for section in SECTION_ORDER:
        arts = by_section.get(section)
        if not arts:
            continue
        cols = arts[:3]
        briefs = arts[3:]
        kickers = section_kickers.get(section, default_kickers)

        col_html = "".join(
            '<div class="np-article">'
            f'<div class="np-article-kicker">{kickers[idx % len(kickers)]}</div>'
            f'<div class="np-hl">{_h(a["headline"])}</div>'
            f'{_card_blurb(a)}</div>'
            for idx, a in enumerate(cols)
        )
        brief_html = ""
        if briefs:
            brief_items = "".join(
                f'<div class="np-brief"><span class="np-brief-hl">{_h(a["headline"])}</span>'
                f' &mdash; <span class="np-brief-blurb">{_h(a["blurb"])}</span></div>'
                for a in briefs
            )
            brief_html = f'<div class="np-briefs">{brief_items}</div>'

        html += (
            '<details class="np-section" open>'
            f'<summary class="np-section-divider">{_h(section)}</summary>'
            f'<div class="np-cols">{col_html}</div>'
            f'{brief_html}'
            '</details>'
        )

    return html

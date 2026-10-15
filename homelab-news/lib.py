"""Shared orchestration for the homelab newspaper.

Historically this was a 4,500-line god module. The cohesive domains have been
extracted into focused modules (``templates``, ``security``, ``containers``,
``media``, ``llm``, ``hindsight``), and the infrastructure/Prometheus collectors
now live in ``homelab_news.collectors.monitoring``. What remains in this file is
the edition orchestration: ``run_news_cycle``, ``generate_newspaper``, and
periodic summaries.
"""

import asyncio
import json
import logging
import os
import re
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
from homelab_news.newsroom.coverage import build_operational_alerts_article, select_news_issues
from storage import load_json, save_json

from containers import get_container_status_async
from hindsight import hindsight_recall, hindsight_targeted_recall
from homelab_news.collectors.monitoring import (
    check_beszel, check_jellystat, check_kopia, check_prometheus,
)
from llm import (
    generate_articles, llm_analysis, _compress_messages, _load_context,
    _sanitize_for_llm,
)
from media import fetch_recent_media, merge_library_additions
from security import (
    check_docker_logs, check_fail2ban_bans, check_loki, LokiCollection,
    _label_sip_phone_prefix, _suggest_asn_blocks, _security_prompt_block,
)

log = logging.getLogger(__name__)


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


_SCOPE_KEY_FIELD = {"week": "week_start", "month": "month", "year": "year"}


def build_period_digest(
    *,
    scope: str,                    # "week" | "month" | "year"
    key: str,                      # value for the scope's key field (week_start / month / year)
    period: str = "",              # human label; weekly/monthly only (yearly carries none)
    articles: list[dict],          # generated digest articles
    ban_records: list[dict] = (),  # raw per-IP ban records; aggregated uniquely per-IP for weekly
    container: list[dict] = (),    # existing records for this scope, newest-first (pre-cap)
    max_entries: int | None = None,  # cap; None -> no cap (yearly)
    built_at: str | None = None,   # ISO timestamp; defaults to now-UTC
) -> list[dict]:
    """Build and cap one period-digest record.

    Shared by the weekly/monthly/yearly workers in ``periodic.py`` and
    ``backfill.py``: owns the unique-ban-per-IP aggregation, the per-period
    ``ban_summary`` (via ``_ban_summary``, weekly only), and the record/cap
    behaviour both workers historically applied. Returns the updated
    newest-first, capped list of records for the scope; the caller persists it
    under the scope's key with its exact ``save_json`` sequencing.

    The produced record keeps the exact key order the workers emitted
    historically (relevant because ``storage.save_json`` does not sort keys):

      week:   {week_start, period, built_at, articles, ban_summary}
      month:  {month, period, built_at, articles}
      year:   {year, built_at, articles}
    """
    if built_at is None:
        built_at = datetime.now(timezone.utc).isoformat()

    key_field = _SCOPE_KEY_FIELD[scope]
    record: dict = {key_field: key}
    if scope != "year":
        record["period"] = period
    record["built_at"] = built_at
    record["articles"] = articles
    if scope == "week":
        all_bans: list[dict] = []
        seen_ips: set[str] = set()
        for b in ban_records:
            if b["ip"] not in seen_ips:
                all_bans.append(b)
                seen_ips.add(b["ip"])
        record["ban_summary"] = _ban_summary(all_bans)

    combined = [record] + list(container)
    # Restore the backfill workers' historical newest-first sort. For the
    # periodic path the freshly built record is already the newest, so the
    # sort is a stable no-op; for backfill's partial-resume scenario (oldest
    # record first over a container already holding newer entries) it puts the
    # list back in newest-first order before capping.
    if len(combined) > 1:
        combined.sort(key=lambda r: r[key_field], reverse=True)
    if max_entries is not None:
        combined = combined[:max_entries]
    return combined


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
    operational_alert: Optional[dict] = None,
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
    valid = await generate_articles(
        messages,
        max_tokens=2500,
        temperature=0.3,
        max_count=15 if operational_alert else 16,
    )
    if not valid:
        # A total LLM failure must be reported as a failure, not masked as a successful
        # edition — run_news_cycle relies on falsy here to preserve the previous edition
        # and merges a fresh operational_alert into it separately.
        return None
    if operational_alert:
        valid.append(operational_alert)
    return valid


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
    return await generate_articles(messages, max_tokens=3000, temperature=0.3, max_count=10)


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

    from security import _SECURITY_NOISE

    clean_docker = [i for i in docker_issues if not _SECURITY_NOISE.search(i.get("message", ""))]
    clean_loki   = [i for i in loki_issues   if not _SECURITY_NOISE.search(i.get("message", ""))]
    operational_alert = build_operational_alerts_article(clean_docker + clean_loki)

    # Phase 2: LLM calls — run sequentially to avoid concurrent KV-cache spikes on vLLM.
    # (vLLM batches concurrent requests together; 3 simultaneous prefills exhaust memory.)
    docker_analysis = await llm_analysis(docker_issues, "Docker container")
    loki_analysis   = await llm_analysis(loki_issues,   "network/syslog (from Loki)")
    newspaper = await generate_newspaper(
        docker_issues, loki_issues, update_hosts, unhealthy_names,
        bans, probes, prometheus, kopia, beszel, jellystat, asn_suggestions, media_events,
        correlations, targeted_history, operational_alert,
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
        # Still refresh the deterministic operational-alerts entry (if any) on top
        # of the preserved edition — it needs no LLM and would otherwise go stale.
        built_at = existing.get("built_at")
        preserved = [a for a in (existing.get("newspaper") or [])
                     if a.get("source") != "deterministic-operational-alerts"]
        if operational_alert:
            preserved = [operational_alert] + preserved
        articles = merge_library_additions(preserved, media_events)
        generation_status = "stale"
        generation_error = "LLM generation unavailable"
        log.warning("News generation unavailable; preserving previous edition in %s", target_file)

    investigations = existing.get("investigations") or []
    if getattr(features, "investigations", True) and newspaper:
        from investigations import investigate_edition, persist_investigations
        from hindsight import hindsight_retain_investigations

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
        new_reports = persist_investigations(investigations)
        if new_reports:
            await hindsight_retain_investigations(new_reports)

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

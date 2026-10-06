"""Operational log collection and security intelligence.

Grouped by their shared machinery: the issue-extraction pipeline (raw docker /
Loki lines → deduped, IP-grouped issue dicts), plus the security functions that
feed the Police Blotter and the LLM security prompt — IP enrichment, fail2ban
ban tracking, CrowdSec LAPI merge, and ASN clustering.
"""

import asyncio
import ipaddress
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

import docker

from config import (
    ABUSEIPDB_KEY, CF_FAIL2BAN_STATE, CROWDSEC_KEY,
    CROWDSEC_LAPI_KEY, CROWDSEC_LAPI_URL, IP_INTEL_FILE, IP_INTEL_TTL,
    LOG_HOURS, LOKI_URL, TRAEFIK_ACCESS_LOG,
)
from homelab_news.collectors.loki import LokiCollector
from storage import load_json, save_json
from privacy import redact_text

log = logging.getLogger(__name__)

# Generic labels that identify no real host — a sender that lost track of its own
# hostname (e.g. rsyslog caching it at daemon start before it was set) still reports
# one of these literally. Don't let that read as a resolved device identity downstream.
_AMBIGUOUS_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "unknown", ""}

# ── Log filtering ─────────────────────────────────────────────────────────────

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
    # Grafana returns this while refreshing an active user's short-lived session
    # cookie. Dashboard panels can emit several of these before the browser
    # completes the rotation; it is not a rejected login or credential failure.
    r'|\[session\.token\.rotate\]\s+token needs to be rotated'
    # cloudflared emits two ERR lines when an incoming client abandons a request.
    # This is client lifecycle noise, not a tunnel or origin connectivity failure.
    r'|Incoming request ended abruptly: context canceled'
    r'|eps_last'
    # UniFi/UDM internal chatter that self-describes as non-failure or is a routine
    # retry/telemetry cycle, but matches CONCERNING on a keyword like "error"/"fail"/
    # "timeout" used as a field name or in a phrase that negates it.
    r"|stime is unknown \(not an error\)"
    r'|garp\.get_ipv4_by_mac\(\).*Resource busy'
    r'|Register transaction got error: No Error'
    r'|failed to contact mcad'
    r'|service_json event fail, retry'
    r'|probe_runner_dispatch\(\):\s*\[\w+\]\s*start'
    r'|smartctl failed device=\S+ err="exit status 2"'
    r'|"event_type":"soft fail"'
    # Jellyfin logs the full ffmpeg command at INFO level.  The literal
    # "-loglevel error" is an ffmpeg argument, not the severity of this line.
    r'|\[INF\].*\b(?:ffmpeg|ffprobe)\b.*-loglevel error\b',
    re.I,
)

CONCERNING = re.compile(
    r'\b(?:error|critical|fatal|fail(?:ed|ure)?|refused|denied'
    r'|timeout|unreachable|exception|traceback|panic|segfault'
    r'|oom.kill|killed|abort|crash|corrupt|WARN(?:ING)?)\b',
    re.I,
)

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


_RFC1918 = re.compile(
    r'^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.)'
)


def _fix_waf_client_ip(line: str) -> str:
    """Replace ModSecurity client_ip with real IP from request headers.

    ModSecurity reads client_ip from the raw TCP socket, so it always sees
    Traefik's internal Docker IP.  The real client IP is present in the
    request headers forwarded by the traefik-modsecurity-plugin.
    """
    if '"transaction"' not in line or '"client_ip"' not in line:
        return line
    try:
        obj = json.loads(line)
        t = obj.get("transaction", {})
        ip = t.get("client_ip", "")
        if not ip or not _RFC1918.match(ip):
            return line
        hdrs = (t.get("request", {}) or {}).get("headers", {}) or {}
        real_ip = (
            hdrs.get("Cf-Connecting-Ip")
            or hdrs.get("X-Real-Ip")
            or (hdrs.get("X-Forwarded-For", "").split(",")[0].strip())
        )
        if real_ip and real_ip != ip:
            t["client_ip"] = real_ip
            obj["transaction"] = t
            return json.dumps(obj)
    except Exception:
        pass
    return line


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


_IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
# SIP desk/DECT phones (Grandstream, Yealink) prefix every syslog line with
# [MAC][firmware-version] and sometimes [pid]. The version (e.g. 1.0.3.25) is a dotted quad that
# _IP_RE would otherwise mistake for a source IP and aggregate on, producing
# bogus "N patterns from 1.0.3.25" groups and "a device at 1.0.3.25" blurbs.
_SIP_PHONE_PREFIX_RE = re.compile(
    r'\[(?P<mac>[0-9A-Fa-f:]{12,17})\]'
    r'\[(?P<firmware>\d+(?:\.\d+){3})\]'
    r'(?:\[(?P<pid>\d+)\])?'
)


def _label_sip_phone_prefix(message: str) -> str:
    """Make compact phone syslog fields unambiguous to downstream LLMs."""
    def replace(match: re.Match) -> str:
        labeled = f"[device {match.group('mac')}][firmware {match.group('firmware')}]"
        if match.group('pid'):
            labeled += f"[pid {match.group('pid')}]"
        return labeled

    return _SIP_PHONE_PREFIX_RE.sub(replace, message)


def _valid_ipv4(addr: str) -> bool:
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in addr.split('.'))


def _group_by_ip(issues: list[dict]) -> list[dict]:
    """Collapse multiple issues sharing the same source IP into one aggregated entry."""
    groups: dict[tuple, list[int]] = defaultdict(list)
    for idx, issue in enumerate(issues):
        m = _IP_RE.search(_SIP_PHONE_PREFIX_RE.sub('', issue["message"]))
        if m and _valid_ipv4(m.group(1)):
            groups[(issue["source"], issue["level"], m.group(1))].append(idx)

    to_remove: set[int] = set()
    for (_, _, ip), indices in groups.items():
        if len(indices) < 3:
            continue
        total = sum(issues[i]["count"] for i in indices)
        n = len(indices)
        rep = issues[indices[0]]["message"][:180]
        issues[indices[0]]["count"] = total
        issues[indices[0]]["message"] = f"[{n} patterns from {ip}, \xd7{total} total] {rep}"[:300]
        first_seen = [issues[i].get("first_seen") for i in indices if issues[i].get("first_seen")]
        last_seen = [issues[i].get("last_seen") for i in indices if issues[i].get("last_seen")]
        if first_seen:
            issues[indices[0]]["first_seen"] = min(first_seen)
        if last_seen:
            issues[indices[0]]["last_seen"] = max(last_seen)
        to_remove.update(indices[1:])

    return [issue for idx, issue in enumerate(issues) if idx not in to_remove]


def _collect_issues(source: str, lines: list) -> tuple[list[dict], dict[str, int]]:
    issues: list[dict] = []
    seen: dict[str, int] = defaultdict(int)
    issue_by_key: dict[str, dict] = {}
    for raw in lines:
        observed_at = ""
        if isinstance(raw, tuple):
            observed_at, raw_line = raw
        else:
            raw_line = raw
            match = re.match(r"^(\d{4}-\d{2}-\d{2}T\S+)\s+(.*)$", raw_line)
            if match:
                observed_at, raw_line = match.groups()
        line = redact_text(_strip_ansi(_extract_text(_fix_waf_client_ip(raw_line.strip()))))
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
            issue = {"source": source, "level": level,
                     "message": line[:300], "_key": key}
            if observed_at:
                issue["first_seen"] = observed_at
                issue["last_seen"] = observed_at
            issues.append(issue)
            issue_by_key[key] = issue
        elif observed_at:
            issue = issue_by_key[key]
            issue.setdefault("first_seen", observed_at)
            issue["last_seen"] = observed_at
    return issues, seen


# ── Docker log fetching ───────────────────────────────────────────────────────

def _fetch_logs_sync(container, since_ts: int, until_ts: Optional[int] = None) -> list[str]:
    try:
        kwargs: dict = {
            "since": since_ts, "stdout": True, "stderr": True,
            "stream": False, "timestamps": True,
        }
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

    async def _process(c):
        try:
            raw_lines = await asyncio.wait_for(
                loop.run_in_executor(None, _fetch_logs_sync, c, since_ts, until_ts),
                timeout=30.0,
            )
        except asyncio.TimeoutError:
            log.warning("Timeout fetching logs for %s", c.name)
            raw_lines = []
        return _collect_issues(c.name, raw_lines)

    results = await asyncio.gather(*(_process(c) for c in containers), return_exceptions=True)
    for result in results:
        if not isinstance(result, tuple):
            continue
        issues, seen = result
        all_issues.extend(issues)
        for k, v in seen.items():
            all_seen[k] += v

    for i in all_issues:
        i["count"] = all_seen[i.pop("_key")]
    all_issues = _group_by_ip(all_issues)
    return sorted(all_issues, key=lambda x: (x["level"] != "error", -x["count"]))[:500]


# ── Loki log fetching ─────────────────────────────────────────────────────────

class LokiCollection(list):
    """List of grouped issues with auditable raw-collection metadata."""

    def __init__(self, issues: list[dict], metadata: dict):
        super().__init__(issues)
        self.metadata = metadata


async def _fetch_loki_complete(
    client: httpx.AsyncClient,
    query: str,
    start_ns: int,
    end_ns: int,
    *,
    page_size: int = 5000,
    max_depth: int = 64,
    max_requests: int = 4096,
) -> tuple[list[tuple[dict, str, str]], dict]:
    """Compatibility wrapper around the packaged Loki collector."""
    collector = LokiCollector(
        LOKI_URL, query, page_size=page_size, max_depth=max_depth, max_requests=max_requests
    )
    result = await collector.collect_ns(client, start_ns, end_ns)
    return result.events, result.metadata


async def check_loki(
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> list[dict]:
    if end is None:
        end = datetime.now(timezone.utc)
    if start is None:
        start = end - timedelta(hours=LOG_HOURS)

    query = '{job=~".+"} |~ `(?i)(error|critical|fatal|fail|refused|denied|timeout|warn)`'
    start_ns = int(start.timestamp() * 1_000_000_000)
    end_ns   = int(end.timestamp()   * 1_000_000_000)
    raw_lines: dict[str, list[tuple[str, str]]] = defaultdict(list)
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            entries, metadata = await _fetch_loki_complete(client, query, start_ns, end_ns)
    except Exception as e:
        metadata = {
            "collection_complete": False,
            "window_start": start.isoformat(),
            "window_end": end.isoformat(),
            "raw_entries": 0,
            "requests": 0,
            "split_windows": 0,
            "truncated_slices": [],
            "error": str(e)[:300],
        }
        issue = {"source": "loki", "level": "error",
                 "message": f"Could not reach Loki at {LOKI_URL}: {e}", "count": 1}
        return LokiCollection([issue], metadata)

    metadata["window_start"] = start.isoformat()
    metadata["window_end"] = end.isoformat()
    timestamps = [int(timestamp) for _, timestamp, _ in entries]
    metadata["last_collected_at"] = (
        datetime.fromtimestamp(max(timestamps) / 1_000_000_000, tz=timezone.utc).isoformat()
        if timestamps else None
    )
    for labels, ts_str, line in entries:
        source = (
            labels.get("host") or labels.get("hostname") or
            labels.get("container_name") or labels.get("app") or
            labels.get("job") or "unknown"
        )
        if source.lower() in _AMBIGUOUS_HOSTS:
            # A sender mislabeled itself (e.g. rsyslog cached "localhost" from before its
            # hostname was finalized). Flag it instead of presenting a generic label as if
            # it were a resolved identity.
            source = f"unidentified host (reported as '{source}')"
        observed_at = datetime.fromtimestamp(int(ts_str) / 1_000_000_000, tz=timezone.utc).isoformat()
        raw_lines[source].append((observed_at, line))

    all_issues: list[dict] = []
    all_seen: dict[str, int] = defaultdict(int)

    for source, lines in raw_lines.items():
        issues, seen = _collect_issues(source, lines)
        all_issues.extend(issues)
        for k, v in seen.items():
            all_seen[k] += v

    for i in all_issues:
        i["count"] = all_seen[i.pop("_key")]
    all_issues = _group_by_ip(all_issues)
    if not metadata["collection_complete"]:
        all_issues.append({
            "source": "loki",
            "level": "error",
            "message": "Loki collection incomplete; one or more saturated time slices could not be exhausted",
            "count": len(metadata["truncated_slices"]),
        })
        log.error("Loki collection incomplete: %d saturated slices", len(metadata["truncated_slices"]))
    metadata["grouped_issues"] = len(all_issues)
    log.info(
        "Loki collection complete=%s entries=%d groups=%d requests=%d splits=%d",
        metadata["collection_complete"], metadata["raw_entries"], len(all_issues),
        metadata["requests"], metadata["split_windows"],
    )
    return LokiCollection(
        sorted(all_issues, key=lambda x: (x["level"] != "error", -x["count"])),
        metadata,
    )


# ── Attack classification ─────────────────────────────────────────────────────

# Fail2ban / WAF log lines that appear in docker/loki issues but are already
# captured (accurately) in the structured security block. Filtering these before
# the LLM sees them prevents it from misreading scanner 403 blocks as
# "authentication failures" or "credential attacks".
_SECURITY_NOISE = re.compile(
    r'FailToBan'
    r'|IP\s+blocked'
    r'|status\s+code\s+ban'
    r'|anomaly\s+score'
    r'|ModSecurity'
    r'|OWASP\s+CRS'
    r'|Coraza'
    r'|scanner.block'
    r'|block.scanner',
    re.I,
)

_ATTACK_SIGNATURES: list[tuple[re.Pattern, str]] = [
    # Checked top-to-bottom; each path gets the first matching label.
    (re.compile(r'/api/(?:firstfactor|secondfactor)', re.I),
     "credential stuffing"),
    (re.compile(r'\.aws/|\.s3cfg|gcloud/credentials|\.digitalocean/|\.azure/', re.I),
     "cloud credential sweep"),
    (re.compile(r'\.env(?:[./\-]|$)|/\.env$', re.I),
     "env file sweep"),
    (re.compile(r'\.git/', re.I),
     "git exposure scan"),
    (re.compile(r'wp-(?:admin|login|content|includes)|xmlrpc\.php', re.I),
     "WordPress probe"),
    (re.compile(r'phpinfo|eval\.php|shell\.php|cmd\.php|webshell', re.I),
     "PHP exploit probe"),
    (re.compile(r'/backup(?:s)?/|\.sql(?:\.gz)?$|\.bak$|\.tar\.gz$|\.dump$', re.I),
     "backup file scan"),
    (re.compile(r'/(?:cpanel|whm|plesk|panel|admin|administrator|manager|console)(?:/|$)', re.I),
     "admin panel probe"),
    (re.compile(r'(?:config|settings|configuration|credentials|secrets?)\.'
                r'(?:yml|yaml|json|php|ini|cfg|properties|xml)', re.I),
     "config file sweep"),
]


def _classify_ban(paths: list[str]) -> str:
    """Return a human-readable attack category based on the paths an IP requested."""
    if not paths:
        return "unknown"
    scores: dict[str, int] = defaultdict(int)
    for path in paths:
        for pattern, label in _ATTACK_SIGNATURES:
            if pattern.search(path):
                scores[label] += 1
                break
    if scores:
        return max(scores, key=scores.__getitem__)
    if all(p.strip().rstrip("/") in ("", "/") for p in paths):
        return "root scan"
    return "vulnerability scan"


def _fmt_duration(seconds: float) -> str:
    """Return human-readable duration: months, weeks, days, hours, minutes."""
    seconds = max(0, int(seconds))
    months, rem  = divmod(seconds, 30 * 86400)
    weeks,  rem  = divmod(rem,      7 * 86400)
    days,   rem  = divmod(rem,          86400)
    hours,  rem  = divmod(rem,           3600)
    minutes      = rem // 60
    parts = []
    if months:  parts.append(f"{months}mo")
    if weeks:   parts.append(f"{weeks}w")
    if days:    parts.append(f"{days}d")
    if hours:   parts.append(f"{hours}h")
    if minutes: parts.append(f"{minutes}m")
    return " ".join(parts) if parts else "<1m"


# ── IP enrichment (geo/ASN/abuse/CTI) ────────────────────────────────────────

async def enrich_ips(
    ips: list[str],
    abuse_only_ips: "set[str] | None" = None,
) -> dict[str, dict]:
    """Return geo/ASN/abuse/CTI intel for a list of IPs, using a persistent 7-day cache.

    Always queries ip-api.com (free, no key) for geo + ASN + ISP/org.
    Optionally queries AbuseIPDB for abuse score if ABUSEIPDB_KEY is set.
    Optionally queries CrowdSec CTI for threat score + behaviors if CROWDSEC_KEY is set.
    Results cached in /data/ip_intel.json so the blotter page stays fast.

    abuse_only_ips: if provided, AbuseIPDB lookups are restricted to this set.
      Use to avoid querying preemptively-blocked IPs (e.g. CrowdSec-only bans)
      that never actually connected to this host.
    """
    if not ips:
        return {}

    cache: dict[str, dict] = load_json(IP_INTEL_FILE) or {}
    now   = time.time()
    stale = [ip for ip in ips if ip not in cache or now - cache[ip].get("_ts", 0) > IP_INTEL_TTL]
    _stale_set = set(stale)  # O(1) lookups — stale can be 30k+ items, list membership is O(n²)
    # IPs cached without supplemental data that now have a key available
    needs_abuse = [
        ip for ip in ips
        if ip not in _stale_set
        and ABUSEIPDB_KEY
        and "abuse_score" not in cache.get(ip, {})
        and (abuse_only_ips is None or ip in abuse_only_ips)
    ]
    needs_cs = [
        ip for ip in ips
        if ip not in _stale_set and CROWDSEC_KEY and "crowdsec_score" not in cache.get(ip, {})
    ]

    dirty = False

    if stale:
        # ── ip-api.com batch (free, no key, max 100 IPs per request) ─────────
        _IPAPI_CHUNK = 100
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                for chunk_start in range(0, len(stale), _IPAPI_CHUNK):
                    chunk = stale[chunk_start:chunk_start + _IPAPI_CHUNK]
                    resp = await client.post(
                        "http://ip-api.com/batch",
                        params={"fields": "status,country,countryCode,city,isp,org,as,query"},
                        json=[{"query": ip} for ip in chunk],
                    )
                    resp.raise_for_status()
                    for item in resp.json():
                        ip = item.get("query", "")
                        if ip and item.get("status") == "success":
                            asn_raw = item.get("as", "")      # e.g. "AS12345 Some Org"
                            asn_num = asn_raw.split()[0] if asn_raw else ""
                            org     = item.get("org") or item.get("isp", "")
                            cache[ip] = {
                                "_ts":          now,
                                "country":      item.get("country", ""),
                                "country_code": item.get("countryCode", ""),
                                "city":         item.get("city", ""),
                                "isp":          item.get("isp", ""),
                                "org":          org,
                                "asn":          asn_num,
                            }
            dirty = True
        except Exception as e:
            log.warning("ip-api.com enrichment failed: %s", e)

    # ── AbuseIPDB per-IP (optional — only if key configured) ─────────────
    # Restrict to IPs that actually connected if abuse_only_ips is provided,
    # so preemptively-blocked IPs (e.g. CrowdSec-only bans) don't burn quota.
    _abuse_stale = [ip for ip in stale if ip in cache]
    if abuse_only_ips is not None:
        _abuse_stale = [ip for ip in _abuse_stale if ip in abuse_only_ips]
    abuse_targets = _abuse_stale + needs_abuse
    if ABUSEIPDB_KEY and abuse_targets:
        async with httpx.AsyncClient(timeout=10) as client:
            for ip in abuse_targets:
                try:
                    resp = await client.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        params={"ipAddress": ip, "maxAgeInDays": "90"},
                        headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                    )
                    resp.raise_for_status()
                    data = resp.json().get("data", {})
                    cache[ip]["abuse_score"]   = data.get("abuseConfidenceScore", 0)
                    cache[ip]["abuse_reports"] = data.get("totalReports", 0)
                    cache[ip]["usage_type"]    = data.get("usageType", "")
                    dirty = True
                except Exception as e:
                    log.warning("AbuseIPDB lookup for %s failed: %s", ip, e)

    # ── CrowdSec CTI per-IP (optional — only if key configured) ──────────
    # Free tier: 500 req/day ≈ ~20/hour. Throttle to 1 req/s to avoid 429.
    cs_targets = [ip for ip in stale if ip in cache] + needs_cs
    if CROWDSEC_KEY and cs_targets:
        async with httpx.AsyncClient(timeout=10) as client:
            for ip in cs_targets:
                try:
                    resp = await client.get(
                        f"https://cti.api.crowdsec.net/v2/smoke/{ip}",
                        headers={"x-api-key": CROWDSEC_KEY, "Accept": "application/json"},
                    )
                    if resp.status_code == 429:
                        log.warning("CrowdSec rate-limited; stopping CTI lookups for this run")
                        break
                    if resp.status_code == 404:
                        # IP unknown to CrowdSec — store empty record so we don't re-query
                        cache[ip]["crowdsec_score"]           = 0
                        cache[ip]["crowdsec_noise"]           = 0
                        cache[ip]["crowdsec_behaviors"]       = []
                        cache[ip]["crowdsec_classifications"] = []
                        cache[ip]["crowdsec_is_tor"]          = False
                        cache[ip]["crowdsec_is_proxy"]        = False
                        dirty = True
                        await asyncio.sleep(1.1)
                        continue
                    resp.raise_for_status()
                    data = resp.json()
                    scores  = data.get("scores", {}).get("overall", {})
                    cls     = data.get("classifications", {})
                    cache[ip]["crowdsec_score"]           = scores.get("total", 0)
                    cache[ip]["crowdsec_noise"]           = data.get("background_noise_score", 0)
                    cache[ip]["crowdsec_behaviors"]       = [
                        b["name"] for b in data.get("behaviors", [])
                    ]
                    cache[ip]["crowdsec_classifications"] = [
                        c["label"] for c in cls.get("classifications", [])
                    ]
                    cache[ip]["crowdsec_is_tor"]          = cls.get("is_tor", False)
                    cache[ip]["crowdsec_is_proxy"]        = cls.get("is_proxy", False) or cls.get("is_vpn", False)
                    dirty = True
                    await asyncio.sleep(1.1)
                except Exception as e:
                    log.warning("CrowdSec lookup for %s failed: %s", ip, e)

    if dirty:
        save_json(IP_INTEL_FILE, cache)

    return {ip: cache.get(ip, {}) for ip in ips}


# ── CrowdSec LAPI ────────────────────────────────────────────────────────────

_CS_SCENARIO_MAP = {
    "http-wordpress-scan":          "WordPress scan",
    "http-admin-interface-probing": "admin probe",
    "http-probing":                 "http probing",
    "http-bad-user-agent":          "bad user agent",
    "http-backdoors-attempts":      "backdoor attempt",
    "http-technology-probing":      "technology probe",
    "http-crawl-non_statics":       "crawler",
    "http-sensitive-files":         "config file sweep",
    "http-path-traversal-probing":  "path traversal",
    "ssh-bf":                       "SSH brute force",
    "ssh-slow-bf":                  "SSH brute force",
}


def _cs_scenario_to_category(scenario: str) -> str:
    name = scenario.split("/", 1)[-1]
    return _CS_SCENARIO_MAP.get(name, name.replace("-", " "))


def _parse_cs_duration(s: str) -> Optional[float]:
    """Parse CrowdSec duration string like '3h59m59.7s' into seconds. Negative = expired."""
    m = re.match(r'^(-?)(?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?$', s.strip())
    if not m:
        return None
    sign = -1 if m.group(1) == '-' else 1
    h  = int(m.group(2) or 0)
    mi = int(m.group(3) or 0)
    sc = float(m.group(4) or 0)
    return sign * (h * 3600 + mi * 60 + sc)


async def fetch_crowdsec_decisions() -> list[dict]:
    """Fetch active CrowdSec ban decisions from the local LAPI."""
    if not CROWDSEC_LAPI_KEY:
        return []
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{CROWDSEC_LAPI_URL}/v1/decisions",
                params={"type": "ban"},
                headers={"X-Api-Key": CROWDSEC_LAPI_KEY},
            )
            if resp.status_code == 204:
                return []
            if resp.status_code == 200:
                return resp.json() or []
            log.warning("CrowdSec LAPI returned %d", resp.status_code)
    except Exception as e:
        log.warning("CrowdSec LAPI fetch failed: %s", e)
    return []


# ── fail2ban ban tracking ─────────────────────────────────────────────────────

FAIL2BAN_ALLOWLIST = [
    # IPv4 private / loopback
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    # IPv6 loopback / link-local / ULA
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]

BANTIME_HOURS       = 24    # must match traefik/configs/middlewares-fail2ban.yml bantime
FINDTIME_MINUTES    = 10    # must match fail2ban findtime
FAIL2BAN_MAXRETRY   = 10    # must match fail2ban maxretry
ACCESS_LOG_TAIL_MB  = 60    # bytes to read from end of access log (~26h of traffic)

_AUTH_ENDPOINT = re.compile(r'/api/(?:firstfactor|secondfactor)', re.I)


def _is_allowlisted(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in FAIL2BAN_ALLOWLIST)
    except ValueError:
        return False


def _extract_real_ip(client_host: str) -> str:
    """Return the real external IP from a potentially comma-separated ClientHost field.

    Traefik sometimes logs ClientHost as 'internal_ip,external_ip' when multiple
    proxies are in the chain (e.g. '127.0.0.1,185.177.72.17'). Take the last
    non-private IP, falling back to the first segment.
    """
    if "," not in client_host:
        return client_host
    for part in reversed(client_host.split(",")):
        part = part.strip()
        if part and not _is_allowlisted(part):
            try:
                ipaddress.ip_address(part)
                return part
            except ValueError:
                continue
    return client_host.split(",")[0].strip()


def _read_access_log_tail(path: str, max_bytes: int) -> str:
    size = os.path.getsize(path)
    offset = max(0, size - max_bytes)
    with open(path, "r", errors="replace") as f:
        if offset > 0:
            f.seek(offset)
            f.readline()  # skip partial first line
        return f.read()


def _parse_access_log_hits(raw: str, cutoff: datetime) -> dict[str, list[tuple[datetime, str]]]:
    """Parse access log lines, returning {ip: [(timestamp, path), ...]} for suspicious responses.

    Collects 403/429 (scanner blocks) and 401s on auth endpoints (brute-force login attempts,
    since Authelia returns 401 for bad credentials rather than 403).
    """
    ip_hits: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
    for line in raw.splitlines():
        if ('"DownstreamStatus":403' not in line
                and '"DownstreamStatus":429' not in line
                and '"DownstreamStatus":401' not in line):
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        status = obj.get("DownstreamStatus")
        if status not in (401, 403, 429):
            continue
        path = obj.get("RequestPath", "")
        if status == 401 and not _AUTH_ENDPOINT.search(path):
            continue
        raw_host = obj.get("ClientHost", "")
        if not raw_host:
            continue
        ip = _extract_real_ip(raw_host)
        if _is_allowlisted(ip):
            continue
        ts_str = obj.get("StartUTC") or obj.get("time", "")
        if not ts_str:
            continue
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            continue
        if ts < cutoff:
            continue
        ip_hits[ip].append((ts, path))
    return ip_hits


def _build_probes(
    access_hits: dict[str, list[tuple[datetime, str]]],
    banned_ips: set[str],
    now: datetime,
) -> list[dict]:
    """Return IPs generating scanner 403s in the last 2h that haven't been banned yet."""
    window = timedelta(hours=2)
    probes = []
    for ip, hits in access_hits.items():
        if ip in banned_ips:
            continue
        # Auth-path 401s are brute-force attempts, not path probes — exclude them here
        recent = [
            (ts, p) for ts, p in hits
            if ts > now - window and p and not _AUTH_ENDPOINT.search(p)
        ]
        if len(recent) < 3:
            continue
        paths: list[str] = []
        for _, p in recent:
            if p not in paths:
                paths.append(p)
            if len(paths) >= 5:
                break
        probes.append({
            "ip":        ip,
            "hit_count": len(recent),
            "paths":     paths,
            "category":  _classify_ban(paths),
        })
    return sorted(probes, key=lambda x: x["hit_count"], reverse=True)[:10]


_CS_LOCAL_ORIGINS = frozenset({"crowdsec", "cscli"})


def _security_prompt_block(
    bans: list[dict],
    probes: list[dict],
    asn_suggestions: Optional[list[dict]] = None,
) -> str:
    """Build a pre-classified security section for the LLM prompt.

    Separates credential attacks from path scanners so the LLM cannot conflate
    scanner 403 blocks with login failures. Appends ASN block recommendations
    when multiple bans cluster to the same autonomous system.
    """
    if not bans and not probes:
        return "SECURITY: No active IP bans, no active probing detected."

    parts: list[str] = []

    if bans:
        # Split locally-detected attacks from preemptive community/blocklist blocks.
        # Only local bans represent IPs that actually hit this host.
        local_bans = [
            b for b in bans
            if b.get("source") != "crowdsec" or b.get("cs_origin", "") in _CS_LOCAL_ORIGINS
        ]
        preemptive_bans = [
            b for b in bans
            if b.get("source") == "crowdsec" and b.get("cs_origin", "") not in _CS_LOCAL_ORIGINS
        ]

        auth_bans    = [b for b in local_bans if b.get("category") == "credential stuffing"]
        scanner_bans = [b for b in local_bans if b.get("category") != "credential stuffing"]

        parts.append(f"SECURITY — {len(local_bans)} IPs actively blocked (attacked this host directly):")

        if auth_bans:
            parts.append(
                f"  CREDENTIAL ATTACKS ({len(auth_bans)} IP{'s' if len(auth_bans)>1 else ''}):"
                f" brute-force on Authelia login endpoint (/api/firstfactor)"
            )
            for b in auth_bans[:5]:
                parts.append(
                    f"    {b['ip']}: {b['hit_count']} login attempts,"
                    f" banned {b['blocked_for']} ago, expires in {b['expires_in']}"
                )

        if scanner_bans:
            cat_counts: dict[str, int] = defaultdict(int)
            for b in scanner_bans:
                cat_counts[b.get("category", "unknown")] += 1
            cat_str = ", ".join(
                f"{cat} \xd7{n}" for cat, n in sorted(cat_counts.items(), key=lambda x: -x[1])
            )
            parts.append(
                f"  PATH SCANNERS ({len(scanner_bans)} IP{'s' if len(scanner_bans)>1 else ''}):"
                f" automated bots probing for vulnerable files (.env, .git, wp-admin, etc.)"
                f" — NOT login attempts. Categories: {cat_str}"
            )
            top = sorted(scanner_bans, key=lambda x: x.get("hit_count", 0), reverse=True)[:5]
            for b in top:
                parts.append(
                    f"    {b['ip']}: {b['hit_count']} probe hits"
                    f" ({b.get('category', 'scan')}), banned {b['blocked_for']} ago"
                )

        if preemptive_bans:
            parts.append(
                f"  NOTE: {len(preemptive_bans)} additional IPs preemptively blocked via"
                f" CrowdSec community feeds/blocklists — these IPs did NOT scan this host;"
                f" they are flagged in other people's threat intel. Do not report them as attackers."
            )

    if probes:
        parts.append(
            f"  ACTIVE PROBING — {len(probes)} IP{'s' if len(probes)>1 else ''}"
            f" generating scanner hits (not yet at ban threshold):"
        )
        for p in probes[:5]:
            # Raw paths are omitted here — they are external attacker-controlled
            # strings and are a prompt injection surface. The classified category
            # is sufficient context for the LLM.
            parts.append(
                f"    {p['ip']}: {p['hit_count']} hits"
                f" ({p.get('category', 'scan')})"
            )

    if asn_suggestions:
        parts.append(
            f"\nASN BLOCK CANDIDATES — {len(asn_suggestions)} autonomous system"
            f"{'s' if len(asn_suggestions)>1 else ''} with multiple banned IPs"
            f" (manual block required — do NOT block automatically):"
        )
        for s in asn_suggestions:
            cs_note    = f", {s['crowdsec_count']} on CrowdSec blocklist" if s["crowdsec_count"] else ""
            ut_note    = f" ({s['usage_type']})" if s["usage_type"] else ""
            large_note = " [LARGE SHARED ASN — block with caution]" if s.get("large_asn") else ""
            parts.append(
                f"  {s['asn']} ({s['org']}){ut_note}: {s['ip_count']} IPs banned,"
                f" avg abuse score {s['avg_abuse']:.0f}%{cs_note}"
                f" — consider: cf-fail2ban --block-asn {s['asn']}{large_note}"
            )

    return "\n".join(parts)


def _merge_crowdsec(bans: list[dict], cs_decisions: list[dict]) -> list[dict]:
    """Append CrowdSec ban decisions that aren't already tracked by cf-fail2ban.

    All decisions (local IDS + CAPI + blocklists) are included so the police blotter
    shows the full picture. The 'cs_origin' field is stored on each entry so callers
    can distinguish locally-detected attacks ('crowdsec', 'cscli') from preemptive
    community/blocklist blocks ('CAPI', 'lists:*').
    """
    if not cs_decisions:
        return bans
    existing_ips = {b["ip"] for b in bans}
    now = datetime.now(timezone.utc)
    for d in cs_decisions:
        ip = d.get("value", "")
        origin = d.get("origin", "")
        if not ip or d.get("scope", "").lower() != "ip" or ip in existing_ips:
            continue
        remaining = _parse_cs_duration(d.get("duration", ""))
        if remaining is None or remaining <= 0:
            continue
        expires_dt  = now + timedelta(seconds=remaining)
        # CrowdSec ban duration is 4h by default; best estimate of start = now - (4h - remaining)
        duration_total = 4 * 3600
        banned_dt   = now - timedelta(seconds=max(0, duration_total - remaining))
        bans.append({
            "ip":           ip,
            "banned_since": banned_dt.strftime("%Y-%m-%d %H:%M UTC"),
            "expires_at":   expires_dt.strftime("%Y-%m-%d %H:%M UTC"),
            "blocked_for":  _fmt_duration((now - banned_dt).total_seconds()),
            "expires_in":   _fmt_duration(remaining),
            "hit_count":    0,
            "paths":        [],
            "category":     _cs_scenario_to_category(d.get("scenario", "")),
            "offense_count": 1,
            "source":       "crowdsec",
            "cs_origin":    origin,
        })
        existing_ips.add(ip)
    return bans


async def check_fail2ban_bans() -> tuple[list[dict], list[dict]]:
    """Return (active_bans, active_probes).

    active_bans: IPs blocked by cf-fail2ban (Cloudflare IP Access Rules) and/or
      CrowdSec (Cloudflare IP List via bouncer), enriched with hit counts and paths
      from the Traefik access log where available.
    active_probes: IPs generating scanner 403s in the last 2h but not yet banned.

    Primary source: cf-fail2ban state file (authoritative, matches Cloudflare blocks).
    Fallback: reconstruct from Traefik access log (403+429 sliding window).
    CrowdSec decisions are merged from the local LAPI in both paths.
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=BANTIME_HOURS + 2)
    cs_decisions = await fetch_crowdsec_decisions()

    # Load access log tail for path/hit-count enrichment (used by both paths)
    access_hits: dict[str, list[tuple[datetime, str]]] = {}
    if os.path.exists(TRAEFIK_ACCESS_LOG):
        try:
            loop = asyncio.get_running_loop()
            raw = await asyncio.wait_for(
                loop.run_in_executor(
                    None, _read_access_log_tail, TRAEFIK_ACCESS_LOG, ACCESS_LOG_TAIL_MB * 1024 * 1024
                ),
                timeout=30.0,
            )
            access_hits = _parse_access_log_hits(raw, cutoff)
        except Exception as e:
            log.warning("Failed to read Traefik access log: %s", e)

    # ── Primary: cf-fail2ban state file ───────────────────────────────────────
    if os.path.exists(CF_FAIL2BAN_STATE):
        try:
            with open(CF_FAIL2BAN_STATE) as f:
                state = json.load(f)
            result = []
            for ip, info in state.get("banned", {}).items():
                expires_ts = info.get("expires_at")  # None = permanent ban
                banned_ts  = info.get("banned_at", 0)
                permanent  = expires_ts is None
                if not permanent and expires_ts <= now.timestamp():
                    continue  # expired (cf-fail2ban cleanup may be pending)
                ban_start = datetime.fromtimestamp(banned_ts, tz=timezone.utc)

                # Live access log data (present if ban is recent, absent if log has rolled)
                # Normalize IP notation before lookup (state file and access log may differ)
                try:
                    norm_ip = str(ipaddress.ip_address(ip))
                except ValueError:
                    norm_ip = ip
                live_hits = access_hits.get(norm_ip) or access_hits.get(ip, [])
                live_paths: list[str] = []
                for _, p in live_hits:
                    if p and p not in live_paths and len(live_paths) < 5:
                        live_paths.append(p)

                # Prefer metadata stored at ban time; fall back to live log.
                # This ensures category/paths are correct even after the log rolls.
                stored_paths    = info.get("paths") or []
                stored_category = info.get("category", "")
                stored_hits     = info.get("hit_count", 0)

                paths     = live_paths    or stored_paths
                hit_count = len(live_hits) or stored_hits
                # Don't trust stored "unknown" — re-classify if we have paths now
                effective_stored = stored_category if stored_category and stored_category != "unknown" else ""
                category  = effective_stored or _classify_ban(paths)

                if permanent:
                    expires_at_str = "permanent"
                    expires_in_str = "permanent"
                else:
                    expires    = datetime.fromtimestamp(expires_ts, tz=timezone.utc)
                    expires_at_str = expires.strftime("%Y-%m-%d %H:%M UTC")
                    expires_in_str = _fmt_duration((expires - now).total_seconds())

                result.append({
                    "ip":            ip,
                    "banned_since":  ban_start.strftime("%Y-%m-%d %H:%M UTC"),
                    "expires_at":    expires_at_str,
                    "blocked_for":   _fmt_duration((now - ban_start).total_seconds()),
                    "expires_in":    expires_in_str,
                    "hit_count":     hit_count,
                    "paths":         paths,
                    "category":      category,
                    "offense_count": info.get("offense_count", 1),
                })
            # Permanent bans sort to top, then by expiration descending
            bans = sorted(
                result,
                key=lambda x: ("0" if x["expires_at"] == "permanent" else "1" + x["expires_at"]),
            )
            bans = _merge_crowdsec(bans, cs_decisions)
            banned_ips = {b["ip"] for b in bans}
            probes = _build_probes(access_hits, banned_ips, now)
            return bans, probes
        except Exception as e:
            log.warning("Failed to read cf-fail2ban state file, falling back to access log: %s", e)

    # ── Fallback: reconstruct from access log (403+429 sliding window) ────────
    if not access_hits:
        log.warning("No access log data and no state file — cannot determine active bans")
        return [], []

    result = []
    for ip, hits in access_hits.items():
        hits.sort(key=lambda x: x[0])
        ban_start: Optional[datetime] = None
        for i in range(len(hits)):
            window_end = hits[i][0] + timedelta(minutes=FINDTIME_MINUTES)
            window = [h for h in hits[i:] if h[0] <= window_end]
            if len(window) >= FAIL2BAN_MAXRETRY:
                ban_start = window[FAIL2BAN_MAXRETRY - 1][0]
                break
        if ban_start is None:
            continue
        expires = ban_start + timedelta(hours=BANTIME_HOURS)
        if expires <= now:
            continue
        paths: list[str] = []
        for _, p in hits:
            if p and p not in paths and len(paths) < 5:
                paths.append(p)
        result.append({
            "ip":           ip,
            "banned_since": ban_start.strftime("%Y-%m-%d %H:%M UTC"),
            "expires_at":   expires.strftime("%Y-%m-%d %H:%M UTC"),
            "blocked_for":  _fmt_duration((now - ban_start).total_seconds()),
            "expires_in":   _fmt_duration((expires - now).total_seconds()),
            "hit_count":    len(hits),
            "paths":        paths,
            "category":     _classify_ban(paths),
        })
    def _ip_key(ip: str) -> tuple:
        a = ipaddress.ip_address(ip)
        return (a.version, int(a))
    bans = sorted(result, key=lambda x: (-x["hit_count"],) + _ip_key(x["ip"]))
    bans = _merge_crowdsec(bans, cs_decisions)
    banned_ips = {b["ip"] for b in bans}
    probes = _build_probes(access_hits, banned_ips, now)
    return bans, probes


def check_asn_blocks() -> list[dict]:
    """Return the list of manually-blocked ASNs from the cf-fail2ban state file.

    Each entry: {"asn": "AS22295", "org": "...", "blocked_at": "...", "cf_rule_id": "..."}
    Returns an empty list if the state file doesn't exist or has no banned_asns.
    """
    try:
        with open(CF_FAIL2BAN_STATE) as f:
            state = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

    banned_asns = state.get("banned_asns", {})
    result = []
    for asn, info in banned_asns.items():
        blocked_ts = info.get("blocked_at", 0)
        try:
            blocked_str = datetime.fromtimestamp(blocked_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            blocked_str = "unknown"
        result.append({
            "asn":         asn,
            "org":         info.get("org", ""),
            "blocked_at":  blocked_str,
            "cf_rule_id":  info.get("cf_rule_id", ""),
            "notes":       info.get("notes", ""),
        })
    return sorted(result, key=lambda x: x["asn"])


# ── ASN clustering ────────────────────────────────────────────────────────────

# Minimum thresholds for surfacing an ASN block recommendation.
_ASN_MIN_IPS        = 2      # distinct banned IPs from the same ASN
_ASN_MIN_ABUSE      = 75     # average AbuseIPDB score across those IPs
_ASN_DC_USAGE_FRAG  = "Data" # matches "Data Center/Web Hosting/Transit" etc.

# Major cloud providers / CDNs where ASN-level blocking causes unacceptable
# collateral damage. Attackers do spin up VMs on these, but millions of
# legitimate services share the same ASNs — never suggest blocking them.
_ASN_NEVER_SUGGEST: frozenset[str] = frozenset({
    "AS8075",   # Microsoft / Azure
    "AS8069",   # Microsoft
    "AS8068",   # Microsoft
    "AS16509",  # Amazon / AWS
    "AS14618",  # Amazon / AWS
    "AS15169",  # Google / GCP
    "AS396982", # Google Cloud
    "AS13335",  # Cloudflare
    "AS20940",  # Akamai
    "AS54113",  # Fastly
    "AS14061",  # DigitalOcean
    "AS63949",  # Linode / Akamai
    "AS16276",  # OVH
    "AS24940",  # Hetzner
    "AS20473",  # Vultr
    "AS46606",  # Unified Layer / Bluehost
    "AS36351",  # SoftLayer / IBM Cloud
})


def _suggest_asn_blocks(bans: list[dict]) -> list[dict]:
    """Cluster active bans by ASN and return candidates worth a manual block.

    Reads the ip_intel cache (no network I/O). Returns a list ordered by
    IP count descending, each entry:
      {"asn": "AS12345", "org": "Acme Hosting", "ip_count": 4,
       "avg_abuse": 100.0, "usage_type": "Data Center/...",
       "crowdsec_count": 3, "ips": ["1.2.3.4", ...]}

    Only ASNs meeting BOTH of:
      - >= _ASN_MIN_IPS distinct banned IPs
      - avg abuse_score >= _ASN_MIN_ABUSE  OR  >=1 IP has data-center usage_type
    are returned. Unknown/empty ASN fields are skipped.
    """
    try:
        cache: dict[str, dict] = load_json(IP_INTEL_FILE) or {}
    except Exception:
        return []

    # Don't suggest ASNs that are already blocked
    try:
        state = load_json(CF_FAIL2BAN_STATE) or {}
        already_blocked: frozenset[str] = frozenset(state.get("banned_asns", {}).keys())
    except Exception:
        already_blocked = frozenset()

    # Group banned IPs by ASN — only locally-detected attacks, not preemptive blocklist blocks
    by_asn: dict[str, dict] = {}
    for b in bans:
        if b.get("source") == "crowdsec" and b.get("cs_origin", "") not in _CS_LOCAL_ORIGINS:
            continue
        ip  = b["ip"]
        intel = cache.get(ip, {})
        asn = intel.get("asn", "").strip()
        if not asn or asn == "AS0":
            continue
        if asn not in by_asn:
            by_asn[asn] = {
                "asn":         asn,
                "org":         intel.get("org") or intel.get("isp") or "",
                "usage_types": [],
                "abuse_scores": [],
                "crowdsec_count": 0,
                "ips": [],
            }
        entry = by_asn[asn]
        entry["ips"].append(ip)
        ut = intel.get("usage_type", "")
        if ut:
            entry["usage_types"].append(ut)
        score = intel.get("abuse_score")
        if score is not None:
            entry["abuse_scores"].append(score)
        if intel.get("crowdsec_classifications"):
            entry["crowdsec_count"] += 1

    suggestions = []
    for asn, entry in by_asn.items():
        if asn in already_blocked:
            continue  # already have an ASN-level rule in Cloudflare
        ip_count = len(entry["ips"])
        if ip_count < _ASN_MIN_IPS:
            continue
        scores = entry["abuse_scores"]
        avg_abuse = sum(scores) / len(scores) if scores else 0.0
        dc_hit = any(_ASN_DC_USAGE_FRAG in ut for ut in entry["usage_types"])
        if avg_abuse < _ASN_MIN_ABUSE and not dc_hit:
            continue
        suggestions.append({
            "asn":           asn,
            "org":           entry["org"],
            "ip_count":      ip_count,
            "avg_abuse":     round(avg_abuse, 1),
            "usage_type":    entry["usage_types"][0] if entry["usage_types"] else "",
            "crowdsec_count": entry["crowdsec_count"],
            "ips":           entry["ips"],
            "large_asn":     asn in _ASN_NEVER_SUGGEST,
        })

    return sorted(suggestions, key=lambda x: (-x["ip_count"], -x["avg_abuse"]))

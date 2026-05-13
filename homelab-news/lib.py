"""Shared library: config, log fetching, LLM calls, HTML rendering, file I/O."""

import asyncio
import json
import logging
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from html import escape as _h
from typing import Optional

import docker
import httpx

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
GITHUB_TOKEN     = os.getenv("GITHUB_TOKEN", "")
SSH_KEY          = os.getenv("SSH_KEY", "/root/.ssh/id_ed25519")
MAX_ARCHIVE_DAYS = int(os.getenv("MAX_ARCHIVE_DAYS", "90"))

# Ollama request timeout — generous to survive a full queue at midnight
# (3 scripts × 3 LLM calls × ~5 min each = up to 45 min worst case)
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "3600"))

DATA_DIR     = os.getenv("DATA_DIR", "/data")
TODAY_FILE   = os.path.join(DATA_DIR, "today.json")
ROLLING_FILE = os.path.join(DATA_DIR, "rolling.json")
ARCHIVE_FILE = os.path.join(DATA_DIR, "archive.json")
UPDATES_FILE  = os.path.join(DATA_DIR, "updates.json")
PERIODIC_FILE = os.path.join(DATA_DIR, "periodic.json")

MAX_WEEKLY  = int(os.getenv("MAX_WEEKLY",  "16"))  # ~4 months of weeklies
MAX_MONTHLY = int(os.getenv("MAX_MONTHLY", "24"))  # 2 years of monthlies
BANTIME_HOURS = 24  # must match traefik/configs/middlewares-fail2ban.yml bantime

_ATTACK_SIGNATURES: list[tuple[re.Pattern, str]] = [
    # Checked top-to-bottom; each path gets the first matching label.
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
    """Return human-readable duration like '2h 15m' or '45m'."""
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m = rem // 60
    if h:
        return f"{h}h {m}m" if m else f"{h}h"
    return f"{m}m" if m else "<1m"


def _parse_remote_hosts() -> list[tuple[str, str]]:
    raw = os.getenv("REMOTE_DOCKER_HOSTS", "")
    hosts = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        url = entry if "://" in entry else f"tcp://{entry}"
        host_part = url.split("://", 1)[1].split("@")[-1]
        label = host_part.split(":")[0].split(".")[0]
        hosts.append((label, url))
    return hosts

REMOTE_HOSTS: list[tuple[str, str]] = _parse_remote_hosts()

# ── File I/O ──────────────────────────────────────────────────────────────────

def load_json(path: str):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except Exception as e:
        log.warning("Failed to load %s: %s", path, e)
        return None


def save_json(path: str, data) -> None:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, path)
    except Exception as e:
        log.warning("Failed to save %s: %s", path, e)

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
    r'|eps_last',
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


def _group_by_ip(issues: list[dict]) -> list[dict]:
    """Collapse multiple issues sharing the same source IP into one aggregated entry."""
    groups: dict[tuple, list[int]] = defaultdict(list)
    for idx, issue in enumerate(issues):
        m = _IP_RE.search(issue["message"])
        if m:
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
        to_remove.update(indices[1:])

    return [issue for idx, issue in enumerate(issues) if idx not in to_remove]


def _collect_issues(source: str, lines: list[str]) -> tuple[list[dict], dict[str, int]]:
    issues: list[dict] = []
    seen: dict[str, int] = defaultdict(int)
    for raw in lines:
        line = _strip_ansi(_extract_text(_fix_waf_client_ip(raw.strip())))
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

# ── Docker log fetching ───────────────────────────────────────────────────────

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
    return sorted(all_issues, key=lambda x: (x["level"] != "error", -x["count"]))[:60]

# ── Loki log fetching ─────────────────────────────────────────────────────────

async def check_loki(
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> list[dict]:
    if end is None:
        end = datetime.now(timezone.utc)
    if start is None:
        start = end - timedelta(hours=LOG_HOURS)

    query = '{job=~".+"} |~ `(?i)(error|critical|fatal|fail|refused|denied|timeout|warn)`'
    PAGE_SIZE = 5000   # Loki server default max_entries_limit_per_query
    MAX_PAGES = 20     # safety cap: 20 × 5 000 = 100 000 entries max
    start_ns = int(start.timestamp() * 1_000_000_000)
    end_ns   = int(end.timestamp()   * 1_000_000_000)

    raw_lines: dict[str, list[str]] = defaultdict(list)

    for page in range(MAX_PAGES):
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{LOKI_URL}/loki/api/v1/query_range",
                    params={
                        "query":     query,
                        "start":     str(start_ns),
                        "end":       str(end_ns),
                        "limit":     str(PAGE_SIZE),
                        "direction": "forward",
                    },
                )
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:
            if page == 0:
                return [{"source": "loki", "level": "warn",
                         "message": f"Could not reach Loki at {LOKI_URL}: {e}", "count": 1}]
            log.warning("Loki page %d fetch failed: %s", page, e)
            break

        result = data.get("data", {}).get("result", [])
        page_count = 0
        max_ts_ns  = 0

        for stream in result:
            labels = stream.get("stream", {})
            source = (
                labels.get("host") or labels.get("hostname") or
                labels.get("container_name") or labels.get("app") or
                labels.get("job") or "unknown"
            )
            for ts_str, line in stream.get("values", []):
                ts_ns = int(ts_str)
                page_count += 1
                if ts_ns > max_ts_ns:
                    max_ts_ns = ts_ns
                raw_lines[source].append(line)

        if page_count < PAGE_SIZE or max_ts_ns == 0:
            break  # last page — window exhausted

        if page == MAX_PAGES - 1:
            log.warning("Loki pagination hit MAX_PAGES=%d; some entries may be missing", MAX_PAGES)
            break

        start_ns = max_ts_ns + 1
        if start_ns >= end_ns:
            break
        log.info("Loki page %d returned %d entries; fetching next page from ts %d",
                 page, page_count, start_ns)

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
    return sorted(all_issues, key=lambda x: (x["level"] != "error", -x["count"]))[:60]

# ── fail2ban ban tracking ─────────────────────────────────────────────────────

async def check_fail2ban_bans() -> list[dict]:
    """Return currently active fail2ban bans parsed from Traefik container logs.

    Each entry: {ip, banned_since, expires_at, blocked_for, expires_in, hit_count, paths}
    """
    now = datetime.now(timezone.utc)
    since_ts = int((now - timedelta(hours=BANTIME_HOURS + 2)).timestamp())

    try:
        dc = docker.from_env()
        traefik = dc.containers.get("traefik")
        loop = asyncio.get_running_loop()
        raw = await asyncio.wait_for(
            loop.run_in_executor(None, _fetch_logs_sync, traefik, since_ts),
            timeout=30.0,
        )
    except Exception as e:
        log.warning("Failed to fetch Traefik logs for fail2ban: %s", e)
        return []

    bans: dict[str, dict] = {}
    for line in raw:
        line = line.strip()
        if '"reason":"banned"' not in line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if obj.get("reason") != "banned":
            continue
        ip = obj.get("ip", "")
        if not ip:
            continue
        ts_str = obj.get("time", "")
        path = obj.get("path", "")
        if ip not in bans:
            bans[ip] = {"first_seen": ts_str, "paths": [], "count": 0}
        bans[ip]["count"] += 1
        if ts_str and ts_str < bans[ip]["first_seen"]:
            bans[ip]["first_seen"] = ts_str
        if path and path not in bans[ip]["paths"] and len(bans[ip]["paths"]) < 5:
            bans[ip]["paths"].append(path)

    result = []
    for ip, d in bans.items():
        try:
            first = datetime.fromisoformat(d["first_seen"].replace("Z", "+00:00"))
        except Exception:
            continue
        expires = first + timedelta(hours=BANTIME_HOURS)
        if expires <= now:
            continue
        result.append({
            "ip":          ip,
            "banned_since": first.strftime("%Y-%m-%d %H:%M UTC"),
            "expires_at":  expires.strftime("%Y-%m-%d %H:%M UTC"),
            "blocked_for": _fmt_duration((now - first).total_seconds()),
            "expires_in":  _fmt_duration((expires - now).total_seconds()),
            "hit_count":   d["count"],
            "paths":       d["paths"],
            "category":    _classify_ban(d["paths"]),
        })

    return sorted(result, key=lambda x: x["hit_count"], reverse=True)


# ── LLM calls (Ollama) ────────────────────────────────────────────────────────

async def llm_analysis(issues: list[dict], context: str) -> Optional[str]:
    if not issues:
        return None
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
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
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


async def generate_newspaper(
    docker_issues: list[dict],
    loki_issues: list[dict],
    update_hosts: dict,
    unhealthy_names: list[str],
    bans: Optional[list[dict]] = None,
) -> Optional[list[dict]]:
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
            ver = f" -> {r['new_version']}" if r.get("new_version") else ""
            line = f"UPDATE on {label}: {r['container']} ({r['image']}{ver})"
            cl = r.get("changelog_analysis")
            if cl:
                line += f" — BREAKING/NOTABLE: {cl[:200]}"
            lines.append(line)

    if docker_issues:
        lines.append("\nTOP DOCKER LOG ISSUES:")
        for i in sorted(docker_issues, key=lambda x: (x["level"] != "error", -x["count"]))[:5]:
            lines.append(f"  [{i['source']} {i['level'].upper()} x{i['count']}] {i['message'][:120]}")

    if loki_issues:
        lines.append("\nTOP NETWORK/SYSLOG ISSUES:")
        for i in sorted(loki_issues, key=lambda x: (x["level"] != "error", -x["count"]))[:5]:
            lines.append(f"  [{i['source']} {i['level'].upper()} x{i['count']}] {i['message'][:120]}")

    if bans:
        lines.append(f"\nACTIVE FAIL2BAN BANS ({len(bans)} IPs blocked):")
        for b in bans[:5]:
            lines.append(
                f"  {b['ip']} — blocked {b['blocked_for']}, "
                f"{b['hit_count']} blocked hits, type: {b.get('category', 'vulnerability scan')}"
            )

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
        "- Articles 1-4: blurb is 2-3 sentences, AP wire style, specific counts and service names.\n"
        "- Articles 5+: blurb is 1 sentence only — these run as brief notes below the fold.\n"
        "- If something is completely fine, skip it — don't pad with 'all clear' articles.\n"
        "- Output ONLY a valid JSON array. No markdown fences, no explanation, no preamble.\n"
        "  Format: [{\"headline\": \"...\", \"blurb\": \"...\"}]\n\n"
        f"CURRENT HOMELAB STATUS:\n{situation}"
    )
    try:
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
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
            content = re.sub(r"^```(?:json)?\n?", "", content)
            content = re.sub(r"\n?```$", "", content.strip())

            articles = None
            try:
                articles = json.loads(content)
            except json.JSONDecodeError:
                pass
            if not isinstance(articles, list):
                m = re.search(r'\[[\s\S]*\]', content)
                if m:
                    try:
                        articles = json.loads(m.group(0))
                    except json.JSONDecodeError:
                        pass
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
                valid = [a for a in articles[:10]
                         if isinstance(a, dict) and "headline" in a and "blurb" in a]
                if valid:
                    return valid
    except Exception as e:
        log.warning("Newspaper generation failed (%s): %s", type(e).__name__, e)
    return None


async def generate_periodic_summary(
    scope: str,           # "week" | "month" | "year"
    period_label: str,    # human-readable, e.g. "May 2026" or "2026-05-11 to 2026-05-17"
    entries: list[dict],  # [{"period": str, "articles": [{headline, blurb}, ...]}]
) -> Optional[list[dict]]:
    lines: list[str] = []
    for entry in entries:
        lines.append(f"=== {entry['period']} ===")
        for a in entry.get("articles") or []:
            lines.append(f"• {a.get('headline', '')}: {a.get('blurb', '')[:200]}")
        entry_bans = entry.get("bans") or []
        if entry_bans:
            ban_parts = ", ".join(
                f"{b['ip']} ({b.get('category', 'scan')}, {b['hit_count']} hits)"
                for b in entry_bans[:5]
            )
            lines.append(f"  Banned IPs ({len(entry_bans)} total): {ban_parts}")
    body = "\n".join(lines)

    scope_map = {
        "week":  ("weekly digest",  "daily editions"),
        "month": ("monthly review", "weekly digests"),
        "year":  ("annual report",  "monthly reviews"),
    }
    title, source = scope_map.get(scope, ("digest", "editions"))

    prompt = (
        f"You are the editor writing the {title} for a homelab status newspaper.\n"
        f"Below are summaries from the {source} covering: {period_label}.\n\n"
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
        "  Format: [{\"headline\": \"...\", \"blurb\": \"...\"}]\n\n"
        f"SOURCE DATA ({period_label}):\n{body}"
    )
    try:
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
            resp = await client.post(
                f"{OLLAMA_URL}/api/chat",
                json={
                    "model": OLLAMA_MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "options": {"num_ctx": 8192, "temperature": 0.3, "num_predict": 1500},
                },
            )
            resp.raise_for_status()
            content = resp.json()["message"]["content"].strip()
            content = re.sub(r"^```(?:json)?\n?", "", content)
            content = re.sub(r"\n?```$", "", content.strip())
            articles = None
            try:
                articles = json.loads(content)
            except json.JSONDecodeError:
                pass
            if not isinstance(articles, list):
                m = re.search(r'\[[\s\S]*\]', content)
                if m:
                    try:
                        articles = json.loads(m.group(0))
                    except json.JSONDecodeError:
                        pass
            if isinstance(articles, list):
                valid = [a for a in articles[:10]
                         if isinstance(a, dict) and "headline" in a and "blurb" in a]
                if valid:
                    return valid
    except Exception as e:
        log.warning("Periodic summary failed (%s): %s", type(e).__name__, e)
    return None


async def llm_changelog_analysis(container: str, image: str, tag: str, notes: str) -> Optional[str]:
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
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
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

# ── GitHub release notes ──────────────────────────────────────────────────────

async def fetch_github_release_notes(source_url: str) -> Optional[tuple[str, str]]:
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

# ── Container status ──────────────────────────────────────────────────────────

def get_container_status() -> tuple[list, list, int]:
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


async def get_container_status_async() -> tuple[list, list, int]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, get_container_status)

# ── Image update checking ─────────────────────────────────────────────────────

def parse_image_ref(raw: str) -> str:
    if "@sha256:" in raw:
        raw = raw.split("@")[0]
    if ":" not in raw.split("/")[-1]:
        raw += ":latest"
    return raw


async def remote_digest(image_ref: str) -> tuple[Optional[str], Optional[str]]:
    """Return (digest, oci_source_url) for an image, trying auth then no-creds."""
    has_auth = os.path.exists(DOCKER_AUTH)
    attempts = [["--authfile", DOCKER_AUTH]] if has_auth else []
    attempts.append(["--no-creds"])
    for auth_args in attempts:
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "skopeo", "inspect",
                "--override-arch", "amd64", "--override-os", "linux",
                *auth_args, f"docker://{image_ref}",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=SKOPEO_TIMEOUT)
            if proc.returncode == 0:
                data = json.loads(out)
                labels = data.get("Labels") or {}
                source = labels.get("org.opencontainers.image.source")
                return data.get("Digest"), source
        except Exception:
            if proc is not None:
                try:
                    proc.kill()
                    await proc.communicate()
                except Exception:
                    pass
    return None, None


def get_containers_local() -> list[dict]:
    dc = docker.from_env()
    out = []
    for c in dc.containers.list():
        ref = parse_image_ref(c.attrs["Config"]["Image"])
        try:
            img = dc.images.get(c.attrs["Image"])
            digests = img.attrs.get("RepoDigests", [])
            local_digest = digests[0].split("@")[1] if digests else None
        except Exception:
            local_digest = None
        out.append({"name": c.name, "image": ref, "local_digest": local_digest})
    return out


def get_containers_tcp(url: str) -> list[dict]:
    dc = docker.DockerClient(base_url=url, timeout=10)
    out = []
    try:
        for c in dc.containers.list():
            ref = parse_image_ref(c.attrs["Config"]["Image"])
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


async def get_containers_ssh(url: str) -> list[dict]:
    target = url[len("ssh://"):]
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
        "ssh", "-F", "/dev/null", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
        "-i", SSH_KEY, target, detect_cmd,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
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
        containers.append({"name": name, "image": parse_image_ref(image), "local_digest": local_digest})
    return containers

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
.arch-period {
  display: grid; grid-template-columns: 10em 1fr 7em; gap: 12px; padding: 10px 0 6px;
  border-bottom: 1px solid var(--dim); align-items: baseline;
}
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
.np-lead { padding: 22px 0 18px; border-bottom: 1px solid var(--bdr); }
.np-lead-kicker {
  font-size: 0.62rem; letter-spacing: 0.22em; text-transform: uppercase;
  color: var(--gold2); font-family: "Courier New", monospace; margin-bottom: 8px;
}
.np-lead-hl { font-size: 2rem; font-weight: bold; line-height: 1.15; color: var(--text); margin-bottom: 12px; }
.np-lead-blurb { font-size: 0.9rem; line-height: 1.75; color: #aaaaaa; max-width: 720px; }
.np-cols { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); border-bottom: 1px solid var(--bdr); }
.np-article { padding: 16px 20px; border-top: 1px solid var(--bdr); border-right: 1px solid var(--bdr); }
.np-article:last-child { border-right: none; }
.np-article-kicker {
  font-size: 0.58rem; letter-spacing: 0.2em; text-transform: uppercase;
  color: var(--muted); font-family: "Courier New", monospace; margin-bottom: 5px;
}
.np-hl { font-size: 1.05rem; font-weight: bold; line-height: 1.2; color: var(--text); margin-bottom: 8px; padding-bottom: 7px; border-bottom: 1px solid var(--bdr); }
.np-blurb { font-size: 0.82rem; line-height: 1.7; color: #999999; }
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
.np-pending {
  text-align: center; padding: 56px 20px; color: var(--muted);
  font-style: italic; font-size: 0.88rem; border-bottom: 1px solid var(--bdr);
}
.np-status {
  display: flex; flex-wrap: wrap; gap: 6px 24px; padding: 12px 0 0;
  font-family: "Courier New", monospace; font-size: 0.68rem; color: var(--muted);
}
.ban-row {
  display: grid; grid-template-columns: 9em 8em 9em 4em 1fr;
  gap: 10px; padding: 6px 0; border-bottom: 1px solid var(--dim); align-items: baseline;
}
.ban-row:last-child { border-bottom: none; }
.ban-details > summary { list-style: none; display: flex; justify-content: space-between; align-items: center; cursor: pointer; user-select: none; }
.ban-details > summary::-webkit-details-marker { display: none; }
.ban-details > summary .card-meta::after { content: " ▾"; }
.ban-details[open] > summary .card-meta::after { content: " ▴"; }
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
    refresh_tag = f'<meta http-equiv="refresh" content="{refresh}">' if refresh else ""
    return (
        '<!DOCTYPE html><html lang="en"><head>'
        '<meta charset="utf-8"><title>Sketchyasfuckistan News</title>'
        '<link rel="icon" href="/favicon.svg" type="image/svg+xml">'
        + refresh_tag
        + '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<style>' + _CSS + '</style>'
        '</head><body>' + body + '</body></html>'
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
        + _item("/archive", "Archive", "archive")
        + " &nbsp;&middot;&nbsp; "
        + _item("/trends", "Trends", "trends")
        + '</div>'
    )


def masthead_rolling(now_str: str) -> str:
    return (
        '<header class="mast"><hr class="rule-dbl">'
        '<div class="mast-name">Sketchyasfuckistan News</div>'
        '<div class="mast-sub">Homelab Intelligence Dispatch &mdash; Est. 2026</div>'
        '<hr class="rule-sng" style="margin:10px 0">'
        f'<div class="mast-meta">Generated {_h(now_str)}'
        f' &nbsp;&middot;&nbsp; Refresh {REFRESH_INTERVAL // 60}m'
        f' &nbsp;&middot;&nbsp; Log window {LOG_HOURS}h</div>'
        '<hr class="rule-sng" style="margin-top:10px"></header>'
    )


def masthead_today() -> str:
    today_str = datetime.now(timezone.utc).strftime("%A, %B %-d, %Y")
    return (
        '<header class="mast"><hr class="rule-dbl">'
        '<div class="mast-name">Sketchyasfuckistan News</div>'
        '<div class="mast-sub">Homelab Intelligence Dispatch &mdash; Est. 2026</div>'
        '<hr class="rule-sng" style="margin:10px 0">'
        f'<div class="mast-meta">Today\'s Edition &mdash; {_h(today_str)}'
        f' &nbsp;&middot;&nbsp; Updated hourly</div>'
        '<hr class="rule-sng" style="margin-top:10px"></header>'
    )


def masthead_archive(date_str: str) -> str:
    return (
        '<header class="mast"><hr class="rule-dbl">'
        '<div class="mast-name">Sketchyasfuckistan News</div>'
        '<div class="mast-sub">Homelab Intelligence Dispatch &mdash; Est. 2026</div>'
        '<hr class="rule-sng" style="margin:10px 0">'
        f'<div class="mast-meta">Edition for {_h(date_str)}</div>'
        '<hr class="rule-sng" style="margin-top:10px"></header>'
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
    meta = f'{n} active ban{"s" if n != 1 else ""} &nbsp;&middot;&nbsp; 24h bantime'
    if not bans:
        return (
            '<div class="card full"><div class="card-head">'
            '<span class="card-title">Blocked IPs</span>'
            f'<span class="card-meta">{meta}</span>'
            '</div><div class="card-body">'
            '<span class="c-ok">&#x2713;&nbsp; No active IP bans.</span>'
            '</div></div>'
        )
    rows = "".join(
        '<div class="ban-row">'
        f'<span class="c-err">{_h(b["ip"])}</span>'
        f'<span class="c-dim">+{_h(b["blocked_for"])}</span>'
        f'<span class="c-warn">expires in {_h(b["expires_in"])}</span>'
        f'<span class="c-dim">&#xd7;{b["hit_count"]}</span>'
        f'<span class="c-gold">{_h(b.get("category", "vulnerability scan"))}</span>'
        '</div>'
        for b in bans
    )
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
                rows.append(
                    '<div class="upd">'
                    f'<span class="c-blue">{_h(r["container"])}</span>'
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


def render_articles_html(articles: list[dict], bans: Optional[list[dict]] = None) -> str:
    if not articles:
        return '<div class="np-pending">No articles available for this edition.</div>'
    lead, *rest = articles
    columns = rest[:3]
    briefs  = rest[3:]
    html = (
        '<div class="np-lead"><div class="np-lead-kicker">Lead Story</div>'
        f'<div class="np-lead-hl">{_h(lead["headline"])}</div>'
        f'<div class="np-lead-blurb">{_h(lead["blurb"])}</div></div>'
    )
    if columns:
        kickers = ["Also", "Elsewhere", "Update"]
        cols = "".join(
            '<div class="np-article">'
            f'<div class="np-article-kicker">{kickers[idx % len(kickers)]}</div>'
            f'<div class="np-hl">{_h(a["headline"])}</div>'
            f'<div class="np-blurb">{_h(a["blurb"])}</div></div>'
            for idx, a in enumerate(columns)
        )
        html += f'<div class="np-cols">{cols}</div>'
    if briefs:
        items = "".join(
            f'<div class="np-brief"><span class="np-brief-hl">{_h(a["headline"])}</span>'
            f' &mdash; <span class="np-brief-blurb">{_h(a["blurb"])}</span></div>'
            for a in briefs
        )
        html += f'<div class="np-briefs"><div class="np-briefs-head">In Brief</div>{items}</div>'
    if bans:
        entries = "".join(
            f'<div class="np-blotter-item">'
            f'<span class="np-blotter-ip c-err">{_h(b["ip"])}</span>'
            f'<span class="np-blotter-cat c-gold">{_h(b.get("category", "vulnerability scan"))}</span>'
            f'<span class="np-blotter-meta">&times;{b["hit_count"]} hits'
            f' &middot; blocked {_h(b["blocked_for"])}'
            f' &middot; expires in {_h(b["expires_in"])}</span>'
            f'</div>'
            for b in bans
        )
        html += f'<div class="np-blotter"><div class="np-blotter-head">Police Blotter</div>{entries}</div>'
    return html

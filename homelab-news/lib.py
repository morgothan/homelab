"""Shared library: config, log fetching, LLM calls, HTML rendering, file I/O."""

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
from html import escape as _h
from typing import Optional

import docker
import httpx

log = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────

LOKI_URL         = os.getenv("LOKI_URL", "http://loki:3100")
REFRESH_INTERVAL = int(os.getenv("REFRESH_INTERVAL", "900"))
UPDATE_INTERVAL  = int(os.getenv("UPDATE_INTERVAL", "3600"))
LOG_HOURS        = int(os.getenv("LOG_HOURS", "1"))
DOCKER_AUTH      = os.getenv("DOCKER_AUTH_FILE", "/root/.docker/config.json")
SKOPEO_TIMEOUT   = int(os.getenv("SKOPEO_TIMEOUT", "20"))
SITE_NAME        = os.getenv("SITE_NAME", "Homelab News")
OLLAMA_URL       = os.getenv("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL     = os.getenv("OLLAMA_MODEL", "gemma4:e4b")
OLLAMA_NUM_GPU   = int(os.getenv("OLLAMA_NUM_GPU", "-1"))  # -1 = server decides
GITHUB_TOKEN     = os.getenv("GITHUB_TOKEN", "")
SSH_KEY          = os.getenv("SSH_KEY", "/root/.ssh/id_ed25519")
PROMETHEUS_URL   = os.getenv("PROMETHEUS_URL", "http://prometheus:9090")
NODE_EXPORTER_INSTANCE = os.getenv("NODE_EXPORTER_INSTANCE", "")
KOPIA_URL        = os.getenv("KOPIA_URL", "https://kopia-webui:5151")
KOPIA_USER       = os.getenv("KOPIA_USER", "admin")
KOPIA_PASS       = os.getenv("KOPIA_PASS", "")
BESZEL_URL       = os.getenv("BESZEL_URL", "")
BESZEL_EMAIL     = os.getenv("BESZEL_EMAIL", "")
BESZEL_PASS      = os.getenv("BESZEL_PASS", "")
TAUTULLI_URL     = os.getenv("TAUTULLI_URL", "http://tautulli:8181")
TAUTULLI_KEY     = os.getenv("TAUTULLI_KEY", "")

# Ollama request timeout — generous to survive a full queue at midnight
# (3 scripts × 3 LLM calls × ~5 min each = up to 45 min worst case)
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "3600"))

DATA_DIR     = os.getenv("DATA_DIR", "/data")
TODAY_FILE   = os.path.join(DATA_DIR, "today.json")
ROLLING_FILE = os.path.join(DATA_DIR, "rolling.json")
ARCHIVE_FILE = os.path.join(DATA_DIR, "archive.json")
UPDATES_FILE  = os.path.join(DATA_DIR, "updates.json")
PERIODIC_FILE      = os.path.join(DATA_DIR, "periodic.json")
HOMELAB_INTEL_FILE = os.path.join(DATA_DIR, "homelab_intel.json")

PVE_SSH_HOST     = os.getenv("PVE_SSH_HOST",     "")
TRUENAS_SSH_HOST = os.getenv("TRUENAS_SSH_HOST", "")
ADGUARD_URLS: list[tuple[str, str]] = [
    (os.getenv("ADGUARD_PRIMARY_URL", ""), "Primary DNS"),
    (os.getenv("ADGUARD_KIDS_URL",    ""), "Kids DNS"),
]
PLEX_LXC_ID         = os.getenv("PLEX_LXC_ID",         "")
HOMEASSISTANT_URL   = os.getenv("HOMEASSISTANT_URL",   "")
HOMEASSISTANT_TOKEN = os.getenv("HOMEASSISTANT_TOKEN", "")
BESZEL_SSH_HOST     = os.getenv("BESZEL_SSH_HOST",     "")

MAX_WEEKLY    = int(os.getenv("MAX_WEEKLY",    "16"))  # ~4 months of weeklies
MAX_MONTHLY   = int(os.getenv("MAX_MONTHLY",   "24"))  # 2 years of monthlies

CONTEXT_FILE   = os.path.join(DATA_DIR, "context.md")
IP_INTEL_FILE  = os.path.join(DATA_DIR, "ip_intel.json")
IP_INTEL_TTL   = 7 * 86400  # re-query after 7 days
ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_KEY", "")
CROWDSEC_KEY   = os.getenv("CROWDSEC_KEY", "")
GOTIFY_URL     = os.getenv("GOTIFY_URL", "")
GOTIFY_TOKEN   = os.getenv("GOTIFY_TOKEN", "")

ARCHIVE_DIR   = os.path.join(DATA_DIR, "archive")
ARCHIVE_INDEX = os.path.join(ARCHIVE_DIR, "index.json")
NOTIFIED_UPDATES_FILE = os.path.join(DATA_DIR, "notified_updates.json")


def _load_context() -> str:
    """Load optional homelab context file from /data/context.md.
    Returns empty string if the file doesn't exist."""
    try:
        with open(CONTEXT_FILE) as f:
            ctx = f.read().strip()
        return _sanitize_for_llm(ctx, max_len=3000)
    except FileNotFoundError:
        return ""
    except Exception as e:
        log.warning("Could not read context.md: %s", e)
        return ""


async def enrich_ips(ips: list[str]) -> dict[str, dict]:
    """Return geo/ASN/abuse/CTI intel for a list of IPs, using a persistent 7-day cache.

    Always queries ip-api.com (free, no key) for geo + ASN + ISP/org.
    Optionally queries AbuseIPDB for abuse score if ABUSEIPDB_KEY is set.
    Optionally queries CrowdSec CTI for threat score + behaviors if CROWDSEC_KEY is set.
    Results cached in /data/ip_intel.json so the blotter page stays fast.
    """
    if not ips:
        return {}

    cache: dict[str, dict] = load_json(IP_INTEL_FILE) or {}
    now   = time.time()
    stale = [ip for ip in ips if ip not in cache or now - cache[ip].get("_ts", 0) > IP_INTEL_TTL]
    # IPs cached without supplemental data that now have a key available
    needs_abuse = [
        ip for ip in ips
        if ip not in stale and ABUSEIPDB_KEY and "abuse_score" not in cache.get(ip, {})
    ]
    needs_cs = [
        ip for ip in ips
        if ip not in stale and CROWDSEC_KEY and "crowdsec_score" not in cache.get(ip, {})
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
    abuse_targets = [ip for ip in stale if ip in cache] + needs_abuse
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


SECTION_ORDER = [
    "City Hall",
    "Public Safety",
    "Weather",
    "City Archives",
    "Arts & Entertainment",
    "Public Works",
]

BANTIME_HOURS       = 24    # must match traefik/configs/middlewares-fail2ban.yml bantime
FINDTIME_MINUTES    = 10    # must match fail2ban findtime
FAIL2BAN_MAXRETRY   = 10    # must match fail2ban maxretry
TRAEFIK_ACCESS_LOG  = os.getenv("TRAEFIK_ACCESS_LOG",  "/traefik/access.log")
CF_FAIL2BAN_STATE   = os.getenv("CF_FAIL2BAN_STATE",   "/traefik/monitor/fail2ban-state.json")
ACCESS_LOG_TAIL_MB  = 60    # bytes to read from end of access log (~26h of traffic)

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

ROLLING_HOURS = int(os.getenv("ROLLING_HOURS", "1"))   # log window for current-events view

_AUTH_ENDPOINT = re.compile(r'/api/(?:firstfactor|secondfactor)', re.I)

# Patterns that indicate a prompt injection attempt in untrusted text.
# Applied before embedding external data (log messages, probe paths, changelog
# summaries) into LLM prompts. Matches are replaced with [FILTERED] to preserve
# context length without amplifying the payload.
_INJECTION_PATTERNS = re.compile(
    r'ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions?'
    r'|disregard\s+(?:the\s+)?(?:above|previous|prior|all)'
    r'|forget\s+(?:your\s+)?instructions?'
    r'|new\s+(?:task|instructions?|objective)'
    r'|override\s+(?:all\s+)?(?:instructions?|rules?|directives?)'
    r'|you\s+are\s+now\s+(?:a\s+)?(?:an?\s+)?(?:\w+\s+)*(?:assistant|bot|model|AI)'
    r'|\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>|</?s>'
    r'|\]\s*output\s*\[|output\s+json\s*:|output\s+only\s+json'
    r'|\[\{"headline"|\[\s*\{\s*"headline"'
    # Gemma and generic role-turn delimiters (prompt injection via turn-switching)
    r'|<start_of_turn>|<end_of_turn>'
    r'|<\|user\|>|<\|assistant\|>|<\|system\|>'
    '\n\nHuman:|\n\nAssistant:',   # non-raw so \n matches actual newlines
    re.I,
)


def _sanitize_for_llm(text: str, max_len: int = 200) -> str:
    """Sanitize untrusted text before embedding it in an LLM prompt.

    Replaces injection trigger phrases with [FILTERED] and truncates.
    Used for log messages, HTTP paths, and LLM-generated text that feeds
    into a second LLM call (e.g. changelog summaries → newspaper prompt).
    """
    sanitized = _INJECTION_PATTERNS.sub("[FILTERED]", text)
    return sanitized[:max_len]


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

async def notify_gotify(title: str, message: str, priority: int = 5) -> None:
    if not GOTIFY_URL or not GOTIFY_TOKEN:
        return
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(
                f"{GOTIFY_URL}/message",
                headers={"X-Gotify-Key": GOTIFY_TOKEN},
                json={"title": title, "message": message, "priority": priority},
            )
    except Exception as e:
        log.warning("Gotify notification failed: %s", e)


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
    return sorted(all_issues, key=lambda x: (x["level"] != "error", -x["count"]))[:500]

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
    return sorted(all_issues, key=lambda x: (x["level"] != "error", -x["count"]))[:500]

# ── fail2ban ban tracking ─────────────────────────────────────────────────────

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
        auth_bans    = [b for b in bans if b.get("category") == "credential stuffing"]
        scanner_bans = [b for b in bans if b.get("category") != "credential stuffing"]

        parts.append(f"SECURITY — {len(bans)} IPs Cloudflare-blocked (24h ban):")

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


async def check_fail2ban_bans() -> tuple[list[dict], list[dict]]:
    """Return (active_bans, active_probes).

    active_bans: IPs in cf-fail2ban state file (Cloudflare-blocked), enriched
      with hit counts and paths from the Traefik access log.
    active_probes: IPs generating scanner 403s in the last 2h but not yet banned.

    Primary source: cf-fail2ban state file (authoritative, matches Cloudflare blocks).
    Fallback: reconstruct from Traefik access log (403+429 sliding window).
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=BANTIME_HOURS + 2)

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

    # Group banned IPs by ASN
    by_asn: dict[str, dict] = {}
    for b in bans:
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


# ── Prometheus metrics ────────────────────────────────────────────────────────

async def _prom_query(client: httpx.AsyncClient, query: str) -> list[dict]:
    """Run a Prometheus instant query; return result list (empty on failure)."""
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


# ── Kopia backup health ───────────────────────────────────────────────────────

def _kopia_ssl_ctx() -> ssl.SSLContext:
    # Kopia uses a self-signed cert on its WebUI (kopia-webui:5151).
    # Verification is intentionally disabled: this connection is Docker-internal
    # on the proxy network only, so MITM risk is negligible.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def check_kopia() -> dict:
    """Query the Kopia WebUI API for backup source health.

    Returns {"alerts": [...], "info": [...]} where:
    - alerts: sources with missed backups (> 36h since last snapshot) or errors
    - info: brief summary of all active sources
    """
    out: dict = {"alerts": [], "info": []}

    if not KOPIA_PASS:
        return out

    try:
        ctx = _kopia_ssl_ctx()
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


# ── Beszel host metrics ───────────────────────────────────────────────────────

async def check_beszel() -> dict:
    """Query Beszel for per-host CPU, memory, disk, and uptime status.

    Returns {"alerts": [...], "info": [...]} — alerts for hosts that are down
    or have critically high resource usage; info gives a compact summary.
    """
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


# ── Tautulli Plex activity ────────────────────────────────────────────────────

async def check_tautulli() -> dict:
    """Query Tautulli for current Plex stream activity and recent play statistics.

    Returns {"alerts": [...], "info": [...]} — no alerts (Tautulli is informational);
    info carries current stream count and 7-day play trend for the LLM.
    """
    out: dict = {"alerts": [], "info": []}

    if not TAUTULLI_KEY:
        return out

    base_params = {"apikey": TAUTULLI_KEY}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            activity_r, plays_r = await asyncio.gather(
                client.get(f"{TAUTULLI_URL}/api/v2",
                           params={**base_params, "cmd": "get_activity"}),
                client.get(f"{TAUTULLI_URL}/api/v2",
                           params={**base_params, "cmd": "get_plays_by_date", "time_range": 7}),
            )
            activity_r.raise_for_status()
            plays_r.raise_for_status()

        act = activity_r.json().get("response", {}).get("data", {})
        streams      = int(act.get("stream_count", 0))
        transcodes   = int(act.get("stream_count_transcode", 0))
        direct_plays = int(act.get("stream_count_direct_play", 0))

        plays_data = plays_r.json().get("response", {}).get("data", {})
        series     = plays_data.get("series", [])
        total_7d   = 0
        by_type: dict[str, list] = {}
        for s in series:
            by_type[s["name"]] = s.get("data", [])
            if s["name"] == "Total":
                total_7d = sum(s.get("data", []))

        if streams > 0:
            stream_detail = []
            if direct_plays:
                stream_detail.append(f"{direct_plays} direct")
            if transcodes:
                stream_detail.append(f"{transcodes} transcode")
            detail = f" ({', '.join(stream_detail)})" if stream_detail else ""
            out["info"].append(f"Plex: {streams} active stream{'s' if streams != 1 else ''}{detail}")
        else:
            out["info"].append("Plex: no active streams")

        type_strs = [
            f"{n}: {sum(v)}" for n, v in by_type.items()
            if n != "Total" and sum(v) > 0
        ]
        if total_7d > 0:
            out["info"].append(
                f"Plex (7d): {total_7d} plays"
                + (f" ({', '.join(type_strs)})" if type_strs else "")
            )

    except Exception as e:
        log.warning("check_tautulli failed: %s", e)

    return out


# ── LLM calls (Ollama) ────────────────────────────────────────────────────────

def _ollama_opts(**kwargs) -> dict:
    """Merge caller-supplied options with the global OLLAMA_NUM_GPU override."""
    if OLLAMA_NUM_GPU >= 0:
        kwargs["num_gpu"] = OLLAMA_NUM_GPU
    return kwargs

async def llm_analysis(issues: list[dict], context: str) -> Optional[str]:
    if not issues:
        return None
    ranked = sorted(issues, key=lambda i: (i["level"] != "error", -i["count"]))[:10]
    entries = "\n".join(
        f"[{i['source']} {i['level'].upper()} \xd7{i['count']}] {_sanitize_for_llm(i['message'], max_len=140)}"
        for i in ranked
    )
    ctx = _load_context()
    ctx_block = f"HOMELAB CONTEXT:\n{ctx}\n\n" if ctx else ""
    prompt = (
        "Homelab log analysis.\n"
        + ctx_block
        + "For each entry: one line saying what it means, one line starting with '→' saying what to do.\n"
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
                    "options": _ollama_opts(num_ctx=4096, temperature=0.1, num_predict=500),
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
    probes: Optional[list[dict]] = None,
    prometheus: Optional[dict] = None,
    kopia: Optional[dict] = None,
    beszel: Optional[dict] = None,
    tautulli: Optional[dict] = None,
    asn_suggestions: Optional[list[dict]] = None,
) -> Optional[list[dict]]:
    # Strip fail2ban/WAF noise from raw log issues — these events are already
    # captured accurately in the structured security block below. Leaving them
    # in causes the LLM to re-interpret scanner 403 blocks as "authentication
    # failures" or "credential attacks".
    clean_docker = [i for i in docker_issues if not _SECURITY_NOISE.search(i.get("message", ""))]
    clean_loki   = [i for i in loki_issues   if not _SECURITY_NOISE.search(i.get("message", ""))]

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
                # Sanitize before re-embedding: this text is LLM-generated from
                # external GitHub release notes and is a second-order injection path.
                line += f" — CHANGELOG: {_sanitize_for_llm(cl, max_len=200)}"
            lines.append(line)

    if clean_docker:
        lines.append("\nTOP DOCKER LOG ISSUES:")
        for i in sorted(clean_docker, key=lambda x: (x["level"] != "error", -x["count"]))[:5]:
            msg = _sanitize_for_llm(i['message'], max_len=120)
            lines.append(f"  [{i['source']} {i['level'].upper()} x{i['count']}] {msg}")

    if clean_loki:
        lines.append("\nTOP NETWORK/SYSLOG ISSUES:")
        for i in sorted(clean_loki, key=lambda x: (x["level"] != "error", -x["count"]))[:5]:
            msg = _sanitize_for_llm(i['message'], max_len=120)
            lines.append(f"  [{i['source']} {i['level'].upper()} x{i['count']}] {msg}")

    lines.append("\n" + _security_prompt_block(bans or [], probes or [], asn_suggestions))

    if prometheus:
        prom_lines: list[str] = []
        if prometheus.get("alerts"):
            prom_lines.append("PROMETHEUS ALERTS:")
            prom_lines.extend(f"  {a}" for a in prometheus["alerts"])
        if prometheus.get("info"):
            prom_lines.append("PROMETHEUS METRICS:")
            prom_lines.extend(f"  {i}" for i in prometheus["info"])
        if prom_lines:
            lines.append("\n" + "\n".join(prom_lines))

    if kopia:
        kopia_lines: list[str] = []
        if kopia.get("alerts"):
            kopia_lines.append("BACKUP ALERTS:")
            kopia_lines.extend(f"  {a}" for a in kopia["alerts"])
        if kopia.get("info"):
            kopia_lines.extend(f"  {i}" for i in kopia["info"])
        if kopia_lines:
            lines.append("\n" + "\n".join(kopia_lines))

    if beszel:
        beszel_lines: list[str] = []
        if beszel.get("alerts"):
            beszel_lines.append("HOST ALERTS:")
            beszel_lines.extend(f"  {a}" for a in beszel["alerts"])
        if beszel.get("info"):
            beszel_lines.extend(f"  {i}" for i in beszel["info"])
        if beszel_lines:
            lines.append("\n" + "\n".join(beszel_lines))

    if tautulli:
        tautulli_lines: list[str] = []
        if tautulli.get("alerts"):
            tautulli_lines.append("PLEX ALERTS:")
            tautulli_lines.extend(f"  {a}" for a in tautulli["alerts"])
        if tautulli.get("info"):
            tautulli_lines.append("PLEX ACTIVITY:")
            tautulli_lines.extend(f"  {i}" for i in tautulli["info"])
        if tautulli_lines:
            lines.append("\n" + "\n".join(tautulli_lines))

    situation = "\n".join(lines)
    context = _load_context()
    context_block = f"HOMELAB CONTEXT (use this to write accurate service names and understand what's normal):\n{context}\n\n" if context else ""
    prompt = (
        "You are the editor of a homelab status newspaper covering a full day of events.\n\n"
        + context_block
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
        "Rules:\n"
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
        "    Arts & Entertainment — Sonarr, Radarr, Tautulli, Jellyfin, media pipeline\n"
        "    Public Works     — DNS, networking, Traefik configuration\n"
        "  Default to City Hall if unsure.\n"
        "- Output ONLY a valid JSON array. No markdown fences, no explanation, no preamble.\n"
        "  Format: [{\"headline\": \"...\", \"blurb\": \"...\", \"section\": \"City Hall\"}]\n\n"
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
                    "options": _ollama_opts(num_ctx=8192, temperature=0.3, num_predict=2500),
                },
            )
            resp.raise_for_status()
            content = resp.json()["message"]["content"].strip()
            articles = _parse_llm_json(content)
            if articles:
                valid = _validate_articles(articles)
                if valid:
                    return valid
    except Exception as e:
        log.warning("Newspaper generation failed (%s): %s", type(e).__name__, e)
    return None


def _validate_articles(raw: list, max_count: int = 16) -> list[dict]:
    """Validate and clamp LLM article output.

    Enforces field-length limits so oversized injected content cannot be stored
    or displayed. Unknown section values are normalised to City Hall.
    """
    valid = []
    for a in raw:
        if not isinstance(a, dict):
            continue
        if "headline" not in a or "blurb" not in a:
            continue
        headline = str(a["headline"])[:200]
        blurb    = str(a["blurb"])[:600]
        section  = str(a.get("section", "City Hall"))[:50]
        if section not in SECTION_ORDER:
            section = "City Hall"
        valid.append({"headline": headline, "blurb": blurb, "section": section})
        if len(valid) == max_count:
            break
    return valid


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


async def generate_periodic_summary(
    scope: str,           # "week" | "month" | "year"
    period_label: str,    # human-readable, e.g. "May 2026" or "2026-05-11 to 2026-05-17"
    entries: list[dict],  # [{"period": str, "articles": [{headline, blurb}, ...]}]
) -> Optional[list[dict]]:
    lines: list[str] = []
    for entry in entries:
        lines.append(f"=== {entry['period']} ===")
        for a in entry.get("articles") or []:
            headline = _sanitize_for_llm(a.get("headline", ""), max_len=200)
            blurb    = _sanitize_for_llm(a.get("blurb", ""), max_len=200)
            lines.append(f"• {headline}: {blurb}")
        entry_bans = entry.get("ban_summary") or []
        if not entry_bans:
            # Fallback: build from raw bans list (daily archive entries)
            raw_bans = entry.get("bans") or []
            if raw_bans:
                entry_bans = _ban_summary(raw_bans)
        if entry_bans:
            lines.append(f"  Security: {'; '.join(entry_bans)}")
    body = "\n".join(lines)

    scope_map = {
        "week":  ("weekly digest",  "daily editions"),
        "month": ("monthly review", "weekly digests"),
        "year":  ("annual report",  "monthly reviews"),
    }
    title, source = scope_map.get(scope, ("digest", "editions"))

    ctx = _load_context()
    ctx_block = f"HOMELAB CONTEXT (use for accurate service names):\n{ctx}\n\n" if ctx else ""
    prompt = (
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
        "  Format: [{\"headline\": \"...\", \"blurb\": \"...\", \"section\": \"City Hall\"}]\n\n"
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
                    "options": _ollama_opts(num_ctx=8192, temperature=0.3, num_predict=3000),
                },
            )
            resp.raise_for_status()
            content = resp.json()["message"]["content"].strip()
            articles = _parse_llm_json(content)
            if articles:
                valid = _validate_articles(articles, max_count=10)
                if valid:
                    return valid
    except Exception as e:
        log.warning("Periodic summary failed (%s): %s", type(e).__name__, e)
    return None


def _parse_llm_json(content: str) -> list:
    """Parse LLM output as a JSON array using three progressively looser strategies."""
    content = re.sub(r"^```(?:json)?\n?", "", content)
    content = re.sub(r"\n?```$", "", content.strip())
    try:
        result = json.loads(content)
        if isinstance(result, list):
            return result
    except json.JSONDecodeError:
        pass
    m = re.search(r'\[[\s\S]*\]', content)
    if m:
        try:
            result = json.loads(m.group(0))
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            pass
    articles = []
    for m in re.finditer(r'\{[^{}]+\}', content, re.DOTALL):
        try:
            obj = json.loads(m.group(0))
            if "headline" in obj and "blurb" in obj:
                articles.append(obj)
        except json.JSONDecodeError:
            pass
    return articles


async def llm_changelog_analysis(container: str, image: str, tag: str, notes: str) -> Optional[str]:
    if not notes:
        return None
    safe_image = _sanitize_for_llm(image, max_len=100)
    safe_tag   = _sanitize_for_llm(tag, max_len=50)
    safe_notes = _sanitize_for_llm(notes, max_len=2500)
    ctx = _load_context()
    ctx_block = (
        f"HOMELAB CONTEXT (use to flag breaking changes that affect this specific setup):\n{ctx}\n\n"
        if ctx else ""
    )
    prompt = (
        f"You are summarising a Docker image update for a homelab operator.\n"
        + ctx_block
        + f"Image: {safe_image}  New tag: {safe_tag}\n\n"
        f"RELEASE NOTES:\n{safe_notes}\n\n"
        "Write exactly 1-2 sentences describing what changed. Rules:\n"
        "- You MUST output something — never leave the response blank.\n"
        "- If the notes describe real changes (features, bug fixes, security patches), summarise them.\n"
        "- If the notes are sparse or this is just a base-image/container rebuild, say so: "
        "e.g. 'Container rebuild (ls456→ls457); qbittorrent application version unchanged at 5.2.0.'\n"
        "- Lead with any breaking changes or required migration steps if present.\n"
        "- If the homelab context is provided and the changelog contains breaking changes or config\n"
        "  migrations that affect services described in that context, flag them explicitly.\n"
        "Output only the 1-2 sentence summary. No headers, no bullet points, no preamble."
    )
    try:
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
            resp = await client.post(
                f"{OLLAMA_URL}/api/chat",
                json={
                    "model": OLLAMA_MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "options": _ollama_opts(num_ctx=4096, temperature=0.1, num_predict=1500),
                },
            )
            resp.raise_for_status()
            return resp.json()["message"]["content"].strip()
    except Exception as e:
        log.warning("Changelog LLM failed for %s: %s", container, e)
        return None

async def generate_homelab_intel(docker_hosts: dict, sources: dict) -> Optional[list[dict]]:
    """Generate newspaper articles summarising all available homelab software updates."""
    lines: list[str] = []

    docker_updates: list[str] = []
    for label, host in docker_hosts.items():
        for r in host.get("results", []):
            if r["status"] != "update_available":
                continue
            ver = f" → {r.get('new_version', '')}" if r.get("new_version") else ""
            cl  = _sanitize_for_llm(r.get("changelog_analysis", ""), max_len=120)
            docker_updates.append(
                f"  {label}/{r['container']}: {r['image']}{ver}" + (f" — {cl}" if cl else "")
            )
    if docker_updates:
        lines.append(f"DOCKER IMAGE UPDATES ({len(docker_updates)} available):")
        lines.extend(docker_updates[:20])
    else:
        lines.append("DOCKER: all images current")

    for key, src in sources.items():
        lbl    = src.get("label", key)
        status = src.get("status", "unknown")
        if status == "error":
            err = _sanitize_for_llm(src.get("error", "unknown"), max_len=80)
            lines.append(f"{lbl.upper()}: check failed — {err}")
            continue
        updates = src.get("updates", [])
        if not updates:
            cur = src.get("current_version", "")
            lines.append(f"{lbl.upper()}: current" + (f" (v{cur})" if cur else ""))
            continue
        for u in updates:
            pkg = _sanitize_for_llm(u.get("package") or u.get("app", "?"), max_len=60)
            cur = _sanitize_for_llm(u.get("current_version", "?"), max_len=30)
            new = _sanitize_for_llm(u.get("new_version", "?"), max_len=30)
            cl  = _sanitize_for_llm(u.get("changelog_analysis", ""), max_len=150)
            lines.append(
                f"{lbl.upper()} UPDATE: {pkg} {cur} → {new}" + (f" — {cl}" if cl else "")
            )

    situation = "\n".join(lines)
    ctx = _load_context()
    ctx_block = (
        f"HOMELAB CONTEXT:\n{ctx}\n\n" if ctx else ""
    )
    plex_flag = (
        "KNOWN ISSUE — Plex + Intel Arc HW transcoding is currently broken: Plex's bundled "
        "iHD_drv_video.so (musl-compiled) references C23 glibc symbols not present in libgcompat.so.0. "
        "GPU: 8086:7D55 (Meteor Lake Arc). If any Plex update is listed, scan its changelog for "
        "Intel Arc, VA-API, musl, iHD, or C23 — and flag prominently if a fix is present.\n\n"
        "KNOWN ISSUE — Ollama/llama.cpp ggml-vulkan backend produces garbled output for gemma4 models "
        "on Intel Arc Xe-LPG (Meteor Lake) iGPU (upstream bugs: ollama#15248, ollama#15328). "
        "Workaround active: OLLAMA_NUM_GPU=0 forces gemma4 to CPU. "
        "If any Ollama update is listed, scan its changelog for: gemma4, Vulkan, Intel Arc, ggml-vulkan, "
        "sliding window attention, or garbled output — and flag prominently if a fix is present so the "
        "workaround can be removed.\n\n"
    )
    prompt = (
        "You are the software intelligence desk editor for a homelab newspaper.\n\n"
        + ctx_block
        + plex_flag
        + "Write 2–6 newspaper articles summarising the available software updates below.\n\n"
        "Rules:\n"
        "- Lead with security patches and kernel updates (most urgent).\n"
        "- Group related items: multiple *arr app updates = 1 article; Docker rebuilds = 1 article.\n"
        "- If everything is current, write a single brief 'All Systems Current' article.\n"
        "- Name specific packages and version numbers in blurbs.\n"
        "- Blurbs: 2 sentences, AP wire style, specific and factual.\n"
        "- Assign sections: 'City Hall' (app/container updates), 'Public Safety' (security/CVE),\n"
        "  'Weather' (system/kernel), 'Arts & Entertainment' (Plex/media), 'Public Works' (DNS/network).\n"
        "- Output ONLY a valid JSON array. No markdown, no explanation.\n"
        "  Format: [{\"headline\": \"...\", \"blurb\": \"...\", \"section\": \"City Hall\"}]\n\n"
        f"SOFTWARE UPDATE STATUS:\n{situation}"
    )
    try:
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
            resp = await client.post(
                f"{OLLAMA_URL}/api/chat",
                json={
                    "model": OLLAMA_MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "options": _ollama_opts(num_ctx=8192, temperature=0.3, num_predict=2000),
                },
            )
            resp.raise_for_status()
            content = resp.json()["message"]["content"].strip()
            articles = _parse_llm_json(content)
            if articles:
                valid = _validate_articles(articles, max_count=10)
                if valid:
                    return valid
    except Exception as e:
        log.warning("generate_homelab_intel failed (%s): %s", type(e).__name__, e)
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

    (docker_issues, loki_issues, (bans, probes),
     prometheus, kopia, beszel, tautulli) = await asyncio.gather(
        check_docker_logs(since_ts=since_ts),
        check_loki(start=since),
        check_fail2ban_bans(),
        check_prometheus(),
        check_kopia(),
        check_beszel(),
        check_tautulli(),
    )

    asn_suggestions = _suggest_asn_blocks(bans)
    if asn_suggestions:
        log.info("ASN block candidates: %s", ", ".join(s["asn"] for s in asn_suggestions))

    # Phase 1: persist raw data immediately; keep the previous newspaper so the
    # page stays readable while the LLM re-renders.
    existing = load_json(target_file) or {}
    save_json(target_file, {
        "built_at":        datetime.now(timezone.utc).isoformat(),
        "newspaper":       existing.get("newspaper"),
        "docker_issues":   docker_issues,
        "docker_analysis": existing.get("docker_analysis"),
        "loki_issues":     loki_issues,
        "loki_analysis":   existing.get("loki_analysis"),
        "bans":            bans,
        "asn_suggestions": asn_suggestions,
    })

    unhealthy, _, _ = await get_container_status_async()
    unhealthy_names = [c.name for c in unhealthy]
    updates_raw  = load_json(UPDATES_FILE) or {}
    update_hosts = updates_raw.get("hosts", {})

    # Phase 2: LLM calls — run analysis and newspaper in parallel.
    (docker_analysis, loki_analysis), newspaper = await asyncio.gather(
        asyncio.gather(
            llm_analysis(docker_issues, "Docker container"),
            llm_analysis(loki_issues,   "network/syslog (from Loki)"),
        ),
        generate_newspaper(
            docker_issues, loki_issues, update_hosts, unhealthy_names,
            bans, probes, prometheus, kopia, beszel, tautulli, asn_suggestions,
        ),
    )
    log.info("run_news_cycle complete: %d articles, %d bans",
             len(newspaper) if newspaper else 0, len(bans))

    save_json(target_file, {
        "built_at":        datetime.now(timezone.utc).isoformat(),
        "newspaper":       newspaper or [],
        "docker_issues":   docker_issues,
        "docker_analysis": docker_analysis,
        "loki_issues":     loki_issues,
        "loki_analysis":   loki_analysis,
        "bans":            bans,
        "asn_suggestions": asn_suggestions,
    })


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
.np-blotter-offense { font-size: 0.78rem; }
.np-blotter-offense.abuse-med { color: var(--gold2); font-weight: bold; }
.np-blotter-offense.abuse-hi  { color: #e05c5c; font-weight: bold; }
.np-blotter-paths { width: 100%; font-size: 0.72rem; color: var(--muted); font-family: "Courier New", monospace; padding: 2px 0 4px; }
.np-blotter-intel { width: 100%; font-size: 0.72rem; color: var(--muted); padding: 1px 0 3px; }
.np-blotter-intel .flag { margin-right: 4px; }
.np-blotter-intel .abuse-hi { color: #e05c5c; font-weight: bold; }
.np-blotter-intel .abuse-med { color: var(--gold2); }
.np-blotter-intel .badge-threat { background: #7a1a1a; color: #ffcccc; border-radius: 3px; padding: 1px 5px; font-size: 0.68rem; font-weight: bold; letter-spacing: 0.04em; }
.np-blotter-intel .badge-cs { background: #1a3a5c; color: #aad4ff; border-radius: 3px; padding: 1px 5px; font-size: 0.68rem; }
.np-blotter-count { font-size: 0.7em; color: var(--muted); }
.np-blotter-empty { padding: 10px 0; }
.np-blotter-page { border-top: 3px double var(--bdr); padding: 14px 0 0; margin-top: 24px; }
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
  white-space: pre;
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
        + _item("/archive", "Archive", "archive")
        + " &nbsp;&middot;&nbsp; "
        + _item("/trends", "Trends", "trends")
        + '</div>'
    )


def masthead_rolling(now_str: str) -> str:
    return (
        f'<header class="mast"><hr class="rule-dbl">'
        f'<div class="mast-name">{SITE_NAME}</div>'
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
        f'<header class="mast"><hr class="rule-dbl">'
        f'<div class="mast-name">{SITE_NAME}</div>'
        '<div class="mast-sub">Homelab Intelligence Dispatch &mdash; Est. 2026</div>'
        '<hr class="rule-sng" style="margin:10px 0">'
        f'<div class="mast-meta">Today\'s Edition &mdash; {_h(today_str)}'
        f' &nbsp;&middot;&nbsp; Updated hourly</div>'
        '<hr class="rule-sng" style="margin-top:10px"></header>'
    )


def masthead_archive(date_str: str) -> str:
    return (
        f'<header class="mast"><hr class="rule-dbl">'
        f'<div class="mast-name">{SITE_NAME}</div>'
        '<div class="mast-sub">Homelab Intelligence Dispatch &mdash; Est. 2026</div>'
        '<hr class="rule-sng" style="margin:10px 0">'
        f'<div class="mast-meta">Edition for {_h(date_str)}</div>'
        '<hr class="rule-sng" style="margin-top:10px"></header>'
    )


def masthead_wire(checked_at: str) -> str:
    return (
        f'<header class="mast"><hr class="rule-dbl">'
        f'<div class="mast-name">{SITE_NAME}</div>'
        '<div class="mast-sub">Wire Reports &mdash; Software Intelligence Desk</div>'
        '<hr class="rule-sng" style="margin:10px 0">'
        f'<div class="mast-meta">Last checked {_h(checked_at)}'
        f' &nbsp;&middot;&nbsp; Updates every {UPDATE_INTERVAL // 60}m</div>'
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


def render_blotter_html(bans: list[dict], *, collapsed: bool = False, intel: Optional[dict] = None) -> str:
    """Police blotter. collapsed=True renders as a closed <details> for archive snapshots.
    intel is a dict keyed by IP with geo/ASN/abuse data from enrich_ips()."""
    n = len(bans)
    count_str = f'{n} active ban{"s" if n != 1 else ""}'
    intel = intel or {}

    if not bans:
        entries_html = '<div class="np-blotter-empty"><span class="c-ok">&#x2713;&nbsp; No active IP bans.</span></div>'
    else:
        rows = []
        for b in bans:
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
            rows.append(
                '<div class="np-blotter-item">'
                f'<span class="np-blotter-ip c-err">{_h(b["ip"])}</span>'
                f'<span class="np-blotter-cat c-gold">{_h(b.get("category", "vulnerability scan"))}</span>'
                f'<span class="np-blotter-meta">&times;{b["hit_count"]} hits'
                f' &middot; blocked {_h(b["blocked_for"])}'
                f' &middot; expires in {expires_display}'
                + offense_html + '</span>'
                + intel_html
                + paths_html
                + '</div>'
            )
        entries_html = "".join(rows)

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
        f'<span class="np-blotter-meta" style="margin-left:14px">{count_str} &nbsp;&middot;&nbsp; 24h bantime</span>'
        f'</div>'
        + entries_html
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

    lead, *rest = articles
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
            f'<div class="np-blurb">{_h(a["blurb"])}</div></div>'
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

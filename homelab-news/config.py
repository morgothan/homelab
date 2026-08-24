"""Application configuration derived from environment variables.

This module is intentionally free of network and filesystem side effects.  Values
are evaluated once at process startup, matching the application's historical
configuration behavior.
"""

import os
from dataclasses import dataclass


def _integer(name: str, default: int) -> int:
    """Return integer environment variable NAME, using DEFAULT when it is unset."""
    return int(os.getenv(name, str(default)))


@dataclass(frozen=True)
class RuntimeSettings:
    """Scheduling and inference settings shared by newsroom workers."""

    refresh_interval: int
    update_interval: int
    log_hours: int
    rolling_hours: int
    site_name: str
    vllm_url: str
    vllm_model: str
    llm_timeout: int


LOCAL = os.getenv("LOCAL", "")
LOKI_URL = os.getenv("LOKI_URL", "http://loki:3100")
REFRESH_INTERVAL = _integer("REFRESH_INTERVAL", 900)
UPDATE_INTERVAL = _integer("UPDATE_INTERVAL", 3600)
LOG_HOURS = _integer("LOG_HOURS", 1)
ROLLING_HOURS = _integer("ROLLING_HOURS", 1)
SITE_NAME = os.getenv("SITE_NAME", "Homelab News")
VLLM_URL = os.getenv("VLLM_URL", "")
VLLM_MODEL = os.getenv("VLLM_MODEL", "")
OLLAMA_TIMEOUT = _integer("OLLAMA_TIMEOUT", 3600)

DOCKER_AUTH = os.getenv("DOCKER_AUTH_FILE", "/root/.docker/config.json")
SKOPEO_TIMEOUT = _integer("SKOPEO_TIMEOUT", 20)
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
SSH_KEY = os.getenv("SSH_KEY", "/root/.ssh/id_ed25519")
PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://prometheus:9090")
NODE_EXPORTER_INSTANCE = os.getenv("NODE_EXPORTER_INSTANCE", "")
KOPIA_URL = os.getenv("KOPIA_URL", "https://kopia-webui:5151")
KOPIA_USER = os.getenv("KOPIA_USER", "admin")
KOPIA_PASS = os.getenv("KOPIA_PASS", "")
BESZEL_URL = os.getenv("BESZEL_URL", "")
BESZEL_EMAIL = os.getenv("BESZEL_EMAIL", "")
BESZEL_PASS = os.getenv("BESZEL_PASS", "")
JELLYSTAT_URL = os.getenv("JELLYSTAT_URL", "http://jellystat:3000")
JELLYSTAT_KEY = os.getenv("JELLYSTAT_KEY", "")
JELLYFIN_URL = os.getenv("JELLYFIN_URL", "")
JELLYFIN_KEY = os.getenv("JELLYFIN_KEY", "")
JELLYFIN_WEB_URL = os.getenv("JELLYFIN_WEB_URL", "").rstrip("/")
RADARR_URL = os.getenv("RADARR_URL", "").rstrip("/")
RADARR_API_KEY = os.getenv("RADARR_API_KEY", "")
SONARR_URL = os.getenv("SONARR_URL", "").rstrip("/")
SONARR_API_KEY = os.getenv("SONARR_API_KEY", "")
SEERR_SETTINGS_FILE = os.getenv("SEERR_SETTINGS_FILE", "")

HINDSIGHT_URL = os.getenv("HINDSIGHT_URL", "")
HINDSIGHT_BANK = os.getenv("HINDSIGHT_BANK", "homelab_news")
HINDSIGHT_TIMEOUT = _integer("HINDSIGHT_TIMEOUT", 90)
TREND_REFLECTION_TIMEOUT = _integer("TREND_REFLECTION_TIMEOUT", 300)
TREND_REFRESH_INTERVAL = _integer("TREND_REFRESH_INTERVAL", 21600)

DATA_DIR = os.getenv("DATA_DIR", "/data")
TODAY_FILE = os.path.join(DATA_DIR, "today.json")
ROLLING_FILE = os.path.join(DATA_DIR, "rolling.json")
ARCHIVE_FILE = os.path.join(DATA_DIR, "archive.json")
UPDATES_FILE = os.path.join(DATA_DIR, "updates.json")
PERIODIC_FILE = os.path.join(DATA_DIR, "periodic.json")
TREND_INTELLIGENCE_FILE = os.path.join(DATA_DIR, "trend_intelligence.json")
HOMELAB_INTEL_FILE = os.path.join(DATA_DIR, "homelab_intel.json")
LIBRARY_SCAN_FILE = os.getenv("LIBRARY_SCAN_FILE", "/traefik/monitor/library-dupe-scan.json")
MEDIA_EVENTS_FILE = os.path.join(DATA_DIR, "media_events.json")
MEDIA_LINKS_FILE = os.path.join(DATA_DIR, "media_links.json")
RECENT_MEDIA_FILE = os.path.join(DATA_DIR, "recent_media.json")
CONTEXT_FILE = os.path.join(DATA_DIR, "context.md")
IP_INTEL_FILE = os.path.join(DATA_DIR, "ip_intel.json")
ARCHIVE_DIR = os.path.join(DATA_DIR, "archive")
ARCHIVE_INDEX = os.path.join(ARCHIVE_DIR, "index.json")

PVE_SSH_HOST = os.getenv("PVE_SSH_HOST", "")
TRUENAS_SSH_HOST = os.getenv("TRUENAS_SSH_HOST", "")
ADGUARD_URLS: list[tuple[str, str]] = [
    (os.getenv("ADGUARD_PRIMARY_URL", ""), "Primary DNS"),
    (os.getenv("ADGUARD_KIDS_URL", ""), "Kids DNS"),
]
HOMEASSISTANT_URL = os.getenv("HOMEASSISTANT_URL", "")
HOMEASSISTANT_TOKEN = os.getenv("HOMEASSISTANT_TOKEN", "")
BESZEL_SSH_HOST = os.getenv("BESZEL_SSH_HOST", "")
SPARK_SSH_HOST = os.getenv("SPARK_SSH_HOST", "")
HERMES_SSH_HOST = os.getenv("HERMES_SSH_HOST", "")

MAX_WEEKLY = _integer("MAX_WEEKLY", 16)
MAX_MONTHLY = _integer("MAX_MONTHLY", 24)
IP_INTEL_TTL = 7 * 86400
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
CROWDSEC_KEY = os.getenv("CROWDSEC_KEY", "")
CROWDSEC_LAPI_URL = os.getenv("CROWDSEC_LAPI_URL", "http://crowdsec:8080")
CROWDSEC_LAPI_KEY = os.getenv("CROWDSEC_LAPI_KEY", "")
TRAEFIK_ACCESS_LOG = os.getenv("TRAEFIK_ACCESS_LOG", "/traefik/access.log")
CF_FAIL2BAN_STATE = os.getenv("CF_FAIL2BAN_STATE", "/traefik/monitor/fail2ban-state.json")

RUNTIME_SETTINGS = RuntimeSettings(
    refresh_interval=REFRESH_INTERVAL,
    update_interval=UPDATE_INTERVAL,
    log_hours=LOG_HOURS,
    rolling_hours=ROLLING_HOURS,
    site_name=SITE_NAME,
    vllm_url=VLLM_URL,
    vllm_model=VLLM_MODEL,
    llm_timeout=OLLAMA_TIMEOUT,
)


def parse_remote_hosts(raw: str | None = None) -> list[tuple[str, str]]:
    """Parse configured Docker endpoints into stable display labels and URLs."""
    value = os.getenv("REMOTE_DOCKER_HOSTS", "") if raw is None else raw
    hosts: list[tuple[str, str]] = []
    for unparsed_entry in value.split(","):
        entry = unparsed_entry.strip()
        if not entry:
            continue
        if "=" in entry:
            explicit_label, entry = entry.split("=", 1)
            explicit_label = explicit_label.strip()
            entry = entry.strip()
        else:
            explicit_label = ""
        url = entry if "://" in entry else f"tcp://{entry}"
        host_part = url.split("://", 1)[1].split("@")[-1]
        inferred_label = host_part.split(":")[0].split(".")[0]
        hosts.append((explicit_label or inferred_label, url))
    return hosts


REMOTE_HOSTS = parse_remote_hosts()

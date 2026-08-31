"""Hourly worker: checks image digests + homelab software updates; generates wire report."""

import asyncio
import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Optional

import httpx

from config import (
    ADGUARD_PASSWORD, ADGUARD_URLS, ADGUARD_USERNAME, BESZEL_SSH_HOST, HERMES_SSH_HOST,
    CONTAINER_STATE_FILE, EVENT_LEDGER_FILE, HOMEASSISTANT_TOKEN, HOMEASSISTANT_URL,
    HOMELAB_INTEL_FILE,
    JELLYFIN_KEY, JELLYFIN_URL, PVE_SSH_HOST, REMOTE_HOSTS, SPARK_SSH_HOST,
    SPARK2_SSH_HOST,
    SSH_KEY, TRUENAS_SSH_HOST, UPDATE_INTERVAL, UPDATES_FILE,
)
from config import APP_SETTINGS
from runtime import run_loop
from storage import load_json, save_json

from lib import (
    remote_digest, parse_image_ref, latest_semver_tag,
    get_containers_local, get_containers_tcp, get_containers_ssh, get_containers_pct,
    fetch_github_release_notes, llm_changelog_analysis, generate_homelab_intel,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("updates")

_digest_cache: dict = {}
_source_cache: dict = {}
_version_cache: dict = {}

# Detects semver-pinned image tags so we can check :latest for update availability.
# Matches: v3.7.1, 3.7.1, 4.39.20, 2026.5.2, 8.8.0-alpine, etc.
# Does NOT match: latest, master, develop, alpine, main — those use the tag as-is.
_SEMVER_TAG_RE = re.compile(r"^v?\d+\.\d+")


def _latest_ref(image_ref: str) -> Optional[str]:
    """For a semver-pinned image, return the :latest ref to check for updates.
    Returns None for rolling tags (:latest, :master, etc.) so the caller uses image_ref as-is."""
    if ":" not in image_ref.split("/")[-1]:
        return None
    name, tag = image_ref.rsplit(":", 1)
    return f"{name}:latest" if _SEMVER_TAG_RE.match(tag) else None


# Known GitHub repos for common apps (used to fetch changelogs for non-Docker updates)
_GITHUB_URLS: dict[str, Optional[str]] = {
    "adguard-home":   "https://github.com/AdguardTeam/AdGuardHome",
    "jellyfin":       "https://github.com/jellyfin/jellyfin",
    "sonarr":         "https://github.com/Sonarr/Sonarr",
    "radarr":         "https://github.com/Radarr/Radarr",
    "lidarr":         "https://github.com/Lidarr/Lidarr",
    "prowlarr":       "https://github.com/Prowlarr/Prowlarr",
    "bazarr":         "https://github.com/morpheus65535/bazarr",
    "nextcloud":      "https://github.com/nextcloud/server",
    "vaultwarden":    "https://github.com/dani-garcia/vaultwarden",
    "home-assistant": "https://github.com/home-assistant/core",
    "homeassistant":  "https://github.com/home-assistant/core",
    "beszel":         "https://github.com/henrygd/beszel",
    "ollama":         "https://github.com/ollama/ollama",
    "vllm":           "https://github.com/vllm-project/vllm",
    "truenas":        None,
    # Traefik plugins (keyed by moduleName path)
    "madebymode/traefik-modsecurity-plugin":       "https://github.com/madebymode/traefik-modsecurity-plugin",
    "paxxs/traefik-get-real-ip":                   "https://github.com/Paxxs/traefik-get-real-ip",
    "solution-libre/traefik-plugin-robots-txt":    "https://github.com/solution-libre/traefik-plugin-robots-txt",
    "pascalminder/geoblock":                       "https://github.com/PascalMinder/geoblock",
    "tommoulard/fail2ban":                         "https://github.com/tomMoulard/fail2ban",
}


def _known_github_url(name: str) -> Optional[str]:
    return _GITHUB_URLS.get(name.lower())


async def _cached_digest(image_ref: str, sem: asyncio.Semaphore):
    if image_ref in _digest_cache:
        return _digest_cache[image_ref], _source_cache.get(image_ref), _version_cache.get(image_ref)
    async with sem:
        if image_ref in _digest_cache:
            return _digest_cache[image_ref], _source_cache.get(image_ref), _version_cache.get(image_ref)
        digest, source, version = await remote_digest(image_ref)
    _digest_cache[image_ref] = digest
    _source_cache[image_ref] = source
    _version_cache[image_ref] = version
    return digest, source, version


async def _check_host(label: str, url: str, sem: asyncio.Semaphore) -> dict:
    loop = asyncio.get_running_loop()
    try:
        if url == "local":
            containers = await loop.run_in_executor(None, get_containers_local)
        elif url.startswith("ssh://"):
            containers = await get_containers_ssh(url)
        elif url.startswith("pct://"):
            pve_host, ctid = url[len("pct://"):].split("/", 1)
            containers = await get_containers_pct(pve_host, ctid)
        else:
            containers = await loop.run_in_executor(None, get_containers_tcp, url)
    except Exception as e:
        log.error("Failed to list containers for %s: %s", label, e)
        return {"status": "done", "ts": datetime.now(timezone.utc).isoformat(), "results": [
            {"container": "—", "image": str(e), "status": "check_failed"}
        ]}

    async def _check_one(c: dict) -> dict:
        def observed(result: dict) -> dict:
            result["_local_digests"] = sorted(str(item) for item in c.get("local_digests", []) if item)
            return result

        image_ref = c["image"]
        if _latest_ref(image_ref):
            # Semver-pinned tag (e.g. traefik:v3.7.1) — check whether a newer tag has
            # actually been published, instead of comparing against :latest's digest
            # (see latest_semver_tag docstring for why that's unreliable).
            name, current_tag = image_ref.rsplit(":", 1)
            new_tag = await latest_semver_tag(name, current_tag)
            digest, source, _ = await _cached_digest(image_ref, sem)
            if digest is None:
                status = "check_failed"
            else:
                status = "update_available" if new_tag else "current"
            r = {"container": c["name"], "image": image_ref, "status": status}
            if status == "update_available":
                r["new_version"] = new_tag
                if source:
                    r["_source"] = source
            return observed(r)

        digest, source, _ = await _cached_digest(image_ref, sem)
        if digest is None:
            return observed({"container": c["name"], "image": image_ref, "status": "check_failed"})
        if not c["local_digests"]:
            return observed({"container": c["name"], "image": image_ref, "status": "unknown"})
        status = "update_available" if digest not in c["local_digests"] else "current"
        r = {"container": c["name"], "image": image_ref, "status": status}
        if status == "update_available" and source:
            r["_source"] = source
        return observed(r)

    results = await asyncio.gather(*(_check_one(c) for c in containers), return_exceptions=True)
    results = sorted(
        [r for r in results if isinstance(r, dict)],
        key=lambda r: (r["status"] != "update_available", r["container"]),
    )
    log.info("Update check done for %s: %d containers", label, len(results))
    return {"status": "done", "ts": datetime.now(timezone.utc).isoformat(), "results": results}


async def _ssh_run(host: str, cmd: str, timeout: int = 45) -> tuple[bool, str]:
    """Run cmd over SSH, return (success, stdout)."""
    proc = await asyncio.create_subprocess_exec(
        "ssh", "-F", "/dev/null", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
        "-i", SSH_KEY, host, cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        if proc.returncode == 0:
            return True, out.decode(errors="replace")
        log.warning("SSH %s failed (rc=%d): %s", host, proc.returncode,
                    err.decode(errors="replace")[:200])
        return False, err.decode(errors="replace")[:200]
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.communicate()
        except Exception:
            pass
        return False, "SSH timeout"


async def check_proxmox_apt() -> dict:
    """Check Proxmox VE for available apt upgrades."""
    label = "Proxmox VE"
    ts = datetime.now(timezone.utc).isoformat()
    # grep -v returns exit code 1 when nothing passes the filter (all packages current).
    # Use || true so the pipeline always exits 0.
    ok, out = await _ssh_run(
        PVE_SSH_HOST,
        "sudo -n apt-get update -qq 2>/dev/null; apt list --upgradable 2>/dev/null | grep -v 'Listing...' || true",
        timeout=90,
    )
    if not ok:
        return {"label": label, "status": "error", "ts": ts, "error": out, "updates": []}

    # apt list line: pve-manager/bullseye 7.4-3 amd64 [upgradable from: 7.4-1]
    pattern = re.compile(r'^(.+?)/.+?\s+(\S+)\s+\S+\s+\[upgradable from:\s+(\S+)\]')
    updates = []
    for line in out.splitlines():
        m = pattern.match(line.strip())
        if not m:
            continue
        updates.append({
            "package":         m.group(1),
            "new_version":     m.group(2),
            "current_version": m.group(3),
        })
    log.info("Proxmox: %d package updates available", len(updates))
    return {"label": label, "status": "done", "ts": ts, "updates": updates}


async def check_pve_lxc_status() -> dict:
    """Flag any Proxmox LXC configured to auto-start (onboot=1) that isn't running.

    Catches the class of failure where a host reboot (e.g. a kernel update) leaves a
    container's onboot start silently failed — Proxmox doesn't retry or alert on this.
    """
    label = "Proxmox LXCs"
    ts = datetime.now(timezone.utc).isoformat()
    if not PVE_SSH_HOST:
        return {"label": label, "status": "skipped", "ts": ts, "down": []}
    ok, out = await _ssh_run(
        PVE_SSH_HOST,
        "for id in $(sudo -n pct list | tail -n +2 | awk '{print $1}'); do "
        "cfg=$(sudo -n pct config $id); "
        "onboot=$(grep -oP 'onboot: \\K\\d+' <<<\"$cfg\"); "
        "name=$(grep -oP 'hostname: \\K\\S+' <<<\"$cfg\"); "
        "status=$(sudo -n pct status $id | awk '{print $2}'); "
        "echo \"$id|$name|${onboot:-0}|$status\"; "
        "done",
        timeout=60,
    )
    if not ok:
        return {"label": label, "status": "error", "ts": ts, "error": out, "down": []}

    down = []
    for line in out.strip().splitlines():
        parts = line.strip().split("|")
        if len(parts) != 4:
            continue
        ctid, name, onboot, status = parts
        if onboot == "1" and status != "running":
            down.append({"ctid": ctid, "name": name, "status": status})
    log.info("Proxmox LXCs: %d onboot container(s) not running", len(down))
    return {"label": label, "status": "done", "ts": ts, "down": down}


async def check_adguard_update(url: str, label: str) -> dict:
    """Check an AdGuard Home instance for available updates.

    Gets current version from the local API, then compares against the latest
    GitHub release. Avoids the /control/update/check endpoint which fails because
    AdGuard itself is the resolver (can't reach static.adtidy.org).
    """
    ts = datetime.now(timezone.utc).isoformat()
    try:
        auth = None
        if ADGUARD_USERNAME and ADGUARD_PASSWORD:
            auth = httpx.BasicAuth(ADGUARD_USERNAME, ADGUARD_PASSWORD)
        async with httpx.AsyncClient(timeout=10) as client:
            status_r = await client.get(f"{url}/control/status", auth=auth)
            status_r.raise_for_status()
            current_version = status_r.json().get("version", "?")
    except Exception as e:
        log.warning("AdGuard status check failed for %s: %s", label, e)
        return {"label": label, "status": "error", "ts": ts, "error": str(e)[:100], "updates": []}

    # Fetch latest release from GitHub (bypasses the DNS chicken-and-egg problem)
    release = await fetch_github_release_notes("https://github.com/AdguardTeam/AdGuardHome")
    latest_tag = release[0] if release else None
    new_version = latest_tag or current_version

    updates = []
    if new_version and new_version.lstrip("v") != current_version.lstrip("v"):
        updates.append({
            "app":             "adguard-home",
            "current_version": current_version,
            "new_version":     new_version,
        })
    return {
        "label":           label,
        "status":          "done",
        "ts":              ts,
        "current_version": current_version,
        "updates":         updates,
    }


async def check_jellyfin_update() -> dict:
    """Check current Jellyfin version via its API against latest GitHub release."""
    label = "Jellyfin"
    ts = datetime.now(timezone.utc).isoformat()

    if not JELLYFIN_URL or not JELLYFIN_KEY:
        return {"label": label, "status": "error", "ts": ts,
                "error": "JELLYFIN_URL or JELLYFIN_KEY not configured", "updates": []}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"{JELLYFIN_URL}/System/Info",
                headers={"X-Emby-Token": JELLYFIN_KEY},
            )
            r.raise_for_status()
            current_version = r.json().get("Version", "")
    except Exception as e:
        log.warning("Jellyfin version check failed: %s", e)
        return {"label": label, "status": "error", "ts": ts, "error": str(e)[:100], "updates": []}

    release = await fetch_github_release_notes("https://github.com/jellyfin/jellyfin")
    latest_tag = release[0] if release else None
    new_version = (latest_tag or "").lstrip("v")

    updates = []
    if new_version and new_version != current_version.lstrip("v"):
        updates.append({
            "app":             "jellyfin",
            "current_version": current_version,
            "new_version":     new_version,
        })
    log.info("Jellyfin: current=%s latest=%s updates=%d", current_version, new_version, len(updates))
    return {"label": label, "status": "done", "ts": ts,
            "current_version": current_version, "updates": updates}


async def check_truenas_apps() -> dict:
    """Check TrueNAS catalog apps for available upgrades via midclt."""
    label = "TrueNAS Apps"
    ts = datetime.now(timezone.utc).isoformat()

    cmd = """midclt call app.query '[["upgrade_available","=",true]]' 2>/dev/null"""
    ok, out = await _ssh_run(TRUENAS_SSH_HOST, cmd, timeout=60)
    if not ok:
        ok, out = await _ssh_run(TRUENAS_SSH_HOST, "sudo " + cmd, timeout=60)
    if not ok:
        return {"label": label, "status": "error", "ts": ts, "error": out[:100], "updates": []}

    try:
        apps = json.loads(out)
    except Exception as e:
        log.warning("TrueNAS: failed to parse midclt output: %s", e)
        return {"label": label, "status": "error", "ts": ts,
                "error": f"parse error: {e}", "updates": []}

    updates = [
        {
            "app":             a.get("name", "?"),
            "current_version": a.get("human_version", "?"),
            "new_version":     a.get("human_latest_version", "?"),
        }
        for a in apps
    ]
    log.info("TrueNAS: %d app updates available", len(updates))
    return {"label": label, "status": "done", "ts": ts, "updates": updates}


async def check_homeassistant_update() -> dict:
    """Check Home Assistant version via its REST API against latest GitHub release."""
    label = "Home Assistant"
    ts = datetime.now(timezone.utc).isoformat()
    if not HOMEASSISTANT_TOKEN:
        return {"label": label, "status": "error", "ts": ts,
                "error": "HOMEASSISTANT_TOKEN not set", "updates": []}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"{HOMEASSISTANT_URL}/api/config",
                headers={"Authorization": f"Bearer {HOMEASSISTANT_TOKEN}",
                         "Content-Type": "application/json"},
            )
            r.raise_for_status()
            current_version = r.json().get("version", "")
    except Exception as e:
        log.warning("Home Assistant version check failed: %s", e)
        return {"label": label, "status": "error", "ts": ts, "error": str(e)[:100], "updates": []}

    release = await fetch_github_release_notes("https://github.com/home-assistant/core")
    latest_tag = release[0] if release else None
    new_version = (latest_tag or "").lstrip("v")

    updates = []
    if new_version and new_version != current_version.lstrip("v"):
        updates.append({
            "app":             "home-assistant",
            "current_version": current_version,
            "new_version":     new_version,
        })
    log.info("Home Assistant: current=%s latest=%s updates=%d",
             current_version, new_version, len(updates))
    return {"label": label, "status": "done", "ts": ts,
            "current_version": current_version, "updates": updates}


async def check_truenas_update() -> dict:
    """Check TrueNAS Scale OS itself for a pending system update via midclt."""
    label = "TrueNAS Scale"
    ts = datetime.now(timezone.utc).isoformat()

    ok, ver_out = await _ssh_run(TRUENAS_SSH_HOST, "midclt call system.version 2>/dev/null", timeout=30)
    current_version = ver_out.strip() if ok else "?"

    ok, out = await _ssh_run(TRUENAS_SSH_HOST, "midclt call update.available_versions 2>/dev/null", timeout=60)
    if not ok or not out.strip():
        return {"label": label, "status": "error", "ts": ts,
                "error": out[:100] if not ok else "empty response", "updates": []}
    try:
        versions = json.loads(out)
    except Exception as e:
        return {"label": label, "status": "error", "ts": ts,
                "error": f"parse error: {e}", "updates": []}

    updates = []
    for entry in versions:
        new_version = entry.get("version", {}).get("version", "")
        if new_version:
            updates.append({
                "app":             "truenas",
                "current_version": current_version,
                "new_version":     new_version,
            })
    log.info("TrueNAS system: current=%s available_updates=%d", current_version, len(updates))
    return {"label": label, "status": "done", "ts": ts, "updates": updates}


async def check_beszel_update() -> dict:
    """Check Beszel hub version via container image label against latest GitHub release."""
    label = "Beszel"
    ts = datetime.now(timezone.utc).isoformat()
    ok, out = await _ssh_run(
        BESZEL_SSH_HOST,
        "docker inspect beszel --format '{{index .Config.Labels \"org.opencontainers.image.version\"}}' 2>/dev/null",
        timeout=15,
    )
    if not ok or not out.strip():
        return {"label": label, "status": "error", "ts": ts,
                "error": "could not read Beszel version label", "updates": []}
    current_version = out.strip()

    release = await fetch_github_release_notes("https://github.com/henrygd/beszel")
    latest_tag = release[0] if release else None
    new_version = (latest_tag or "").lstrip("v")

    updates = []
    if new_version and new_version != current_version.lstrip("v"):
        updates.append({
            "app":             "beszel",
            "current_version": current_version,
            "new_version":     new_version,
        })
    log.info("Beszel: current=%s latest=%s updates=%d", current_version, new_version, len(updates))
    return {"label": label, "status": "done", "ts": ts,
            "current_version": current_version, "updates": updates}


async def check_vllm_update() -> dict:
    """Check the spark inference stack. Since 2026-08-27 vLLM runs as a distributed,
    sparkrun-orchestrated container cluster (systemd `sparkrun-deepseek` on spark1),
    not a native venv — so the meaningful "is it current" signal is the `sparkrun`
    CLI version (real PyPI package) rather than the vLLM build (a pinned community
    fork image, `ghcr.io/bjk110/vllm-spark`, with no upstream "latest" to diff)."""
    label = "vLLM"
    ts = datetime.now(timezone.utc).isoformat()
    if not SPARK_SSH_HOST:
        return {"label": label, "status": "skipped", "ts": ts, "updates": []}
    ok, out = await _ssh_run(
        SPARK_SSH_HOST,
        "~/.local/bin/sparkrun --version 2>/dev/null | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1; "
        "echo '---'; "
        "docker exec \"$(docker ps -q -f name=node_0 2>/dev/null | head -1)\" "
        "/opt/env/bin/python -c 'import vllm; print(vllm.__version__)' 2>/dev/null",
        timeout=25,
    )
    sparkrun_version, _, vllm_build = (out.strip().partition("---"))
    sparkrun_version = sparkrun_version.strip()
    vllm_build = vllm_build.strip()
    if not ok or not sparkrun_version:
        return {"label": label, "status": "error", "ts": ts,
                "error": "could not read sparkrun version on spark", "updates": []}

    current_version = sparkrun_version
    if vllm_build:
        current_version += f" (vLLM {vllm_build} in container)"

    new_version = ""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get("https://pypi.org/pypi/sparkrun/json")
            r.raise_for_status()
            new_version = (r.json().get("info", {}).get("version") or "").strip()
    except Exception as e:  # noqa: BLE001
        log.warning("vLLM check: PyPI sparkrun lookup failed: %s", e)

    updates = []
    if new_version and new_version != sparkrun_version:
        updates.append({
            "app":             "sparkrun",
            "current_version": sparkrun_version,
            "new_version":     new_version,
        })
    log.info("vLLM/sparkrun: current=%s latest=%s vllm_build=%s updates=%d",
             sparkrun_version, new_version, vllm_build or "?", len(updates))
    return {"label": label, "status": "done", "ts": ts,
            "current_version": current_version, "updates": updates}


async def check_spark_apt(host: str, label: str) -> dict:
    """Check DGX Spark for available apt upgrades (NVIDIA drivers, CUDA, system packages)."""
    ts = datetime.now(timezone.utc).isoformat()
    if not host:
        return {"label": label, "status": "skipped", "ts": ts, "updates": []}
    ok, out = await _ssh_run(
        host,
        "apt-get update -qq 2>/dev/null; apt list --upgradable 2>/dev/null | grep -v 'Listing...' || true",
        timeout=120,
    )
    if not ok:
        return {"label": label, "status": "error", "ts": ts, "error": out, "updates": []}
    updates = []
    for line in out.splitlines():
        m = re.match(r'^([\w.+\-]+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from: (\S+)\]', line)
        if m:
            updates.append({
                "package": m.group(1),
                "current_version": m.group(3),
                "new_version": m.group(2),
            })
    log.info("%s apt: %d upgradable packages", label, len(updates))
    return {"label": label, "status": "done", "ts": ts, "updates": updates}


_TRAEFIK_YML_PATH = "/traefik/traefik.yml"


async def check_traefik_plugins() -> dict:
    """Check Traefik plugin versions against latest GitHub releases.

    Reads active plugin definitions from the mounted traefik.yml so the check
    stays in sync automatically when plugin versions are bumped there.
    """
    label = "Traefik Plugins"
    ts = datetime.now(timezone.utc).isoformat()

    raw_plugins: dict = {}
    try:
        with open(_TRAEFIK_YML_PATH) as f:
            text = f.read()
        in_plugins = False
        cur_name: Optional[str] = None
        cur: dict = {}
        for line in text.splitlines():
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if re.match(r"^\s*plugins\s*:", line):
                in_plugins = True
                continue
            if not in_plugins:
                continue
            if re.match(r"^\S", line):
                break
            m = re.match(r"^    ([\w][\w-]*):\s*$", line)
            if m:
                if cur_name and cur:
                    raw_plugins[cur_name] = cur
                cur_name = m.group(1)
                cur = {}
                continue
            m2 = re.match(r"^\s+moduleName:\s*[\"']?(.+?)[\"']?\s*$", line)
            if m2 and cur_name is not None:
                cur["moduleName"] = m2.group(1).strip()
                continue
            m3 = re.match(r"^\s+version:\s*[\"']?(.+?)[\"']?\s*$", line)
            if m3 and cur_name is not None:
                cur["version"] = m3.group(1).strip()
        if cur_name and cur:
            raw_plugins[cur_name] = cur
    except Exception as e:
        return {"label": label, "status": "error", "ts": ts,
                "error": f"could not read {_TRAEFIK_YML_PATH}: {e}", "updates": []}

    updates = []
    for plugin_name, meta in raw_plugins.items():
        module = meta.get("moduleName", "")
        current = meta.get("version", "")
        if not module or not current:
            continue
        # Build lookup key: lowercase the org/repo portion of the module path
        # e.g. "github.com/PascalMinder/geoblock" → "pascalminder/geoblock"
        key = "/".join(module.split("/")[-2:]).lower()
        github_url = _GITHUB_URLS.get(key)
        if not github_url:
            log.debug("No GitHub URL for traefik plugin %s (%s)", plugin_name, module)
            continue
        release = await fetch_github_release_notes(github_url)
        latest_tag = release[0] if release else None
        latest = (latest_tag or "").lstrip("v")
        if not latest:
            continue
        if latest != current.lstrip("v"):
            u = {
                "app":             plugin_name,
                "module":          module,
                "current_version": current,
                "new_version":     latest_tag or latest,
            }
            # Stash for changelog LLM lookup
            u["_github_url"] = github_url
            updates.append(u)

    log.info("Traefik plugins: %d updates available out of %d checked",
             len(updates), len(raw_plugins))
    return {"label": label, "status": "done", "ts": ts, "updates": updates}


async def run_homelab_checks() -> dict:
    """Run all non-Docker homelab update checks concurrently."""
    adguard_coros = [check_adguard_update(url, label) for url, label in ADGUARD_URLS]
    all_results = await asyncio.gather(
        check_proxmox_apt(),
        check_pve_lxc_status(),
        *adguard_coros,
        check_jellyfin_update(),
        check_truenas_apps(),
        check_homeassistant_update(),
        check_truenas_update(),
        check_beszel_update(),
        check_vllm_update(),
        check_spark_apt(SPARK_SSH_HOST, "DGX Spark"),
        check_spark_apt(SPARK2_SSH_HOST, "DGX Spark 2"),
        check_traefik_plugins(),
        return_exceptions=True,
    )
    def _key(label: str) -> str:
        return re.sub(r'\W+', '_', label.lower()).strip('_')

    keys = (
        ["proxmox", "proxmox_lxc"]
        + [_key(label) for _, label in ADGUARD_URLS]
        + ["jellyfin", "truenas", "home_assistant", "truenas_system", "beszel",
           "vllm", "dgx_spark", "dgx_spark_2", "traefik_plugins"]
    )
    sources: dict = {}
    for key, result in zip(keys, all_results):
        if isinstance(result, dict):
            sources[key] = result
        else:
            log.error("homelab check %s raised: %s", key, result)
    return sources


async def run() -> None:
    global _digest_cache, _source_cache, _version_cache
    _digest_cache = {}
    _source_cache = {}
    _version_cache = {}

    now_ts = datetime.now(timezone.utc).isoformat()
    log.info("Starting update check (Docker + homelab)")
    sem = asyncio.Semaphore(5)
    host_specs = [("local", "local")] + list(REMOTE_HOSTS)
    if SPARK_SSH_HOST:
        host_specs.append(("spark", f"ssh://{SPARK_SSH_HOST}"))
    if SPARK2_SSH_HOST:
        host_specs.append(("spark2", f"ssh://{SPARK2_SSH_HOST}"))
    if HERMES_SSH_HOST:
        host_specs.append(("hermes", f"ssh://{HERMES_SSH_HOST}"))
    # nntmux LXC (CT 106) was decommissioned 2026-08-21. Keep the container,
    # but do not poll it for Docker image updates while it is offline.
    # if PVE_SSH_HOST:
    #     host_specs.append(("nntmux", f"pct://{PVE_SSH_HOST}/106"))

    # Docker image checks and homelab checks run concurrently
    docker_coros = [_check_host(label, url, sem) for label, url in host_specs]
    all_gathered = await asyncio.gather(*docker_coros, run_homelab_checks(),
                                        return_exceptions=True)

    docker_results = all_gathered[:-1]
    homelab_result = all_gathered[-1]

    hosts: dict = {}
    for (label, _), result in zip(host_specs, docker_results):
        if isinstance(result, dict):
            hosts[label] = result
        else:
            log.error("Host check %s raised: %s", label, result)

    sources: dict = homelab_result if isinstance(homelab_result, dict) else {}

    # A remote registry change only means an update is available. Compare the
    # locally running image identity with the prior scan to record actual image
    # transitions separately, then remove the internal digest observations.
    from correlations import append_events, record_container_transitions

    transition_events = record_container_transitions(hosts, CONTAINER_STATE_FILE, now_ts)
    append_events(EVENT_LEDGER_FILE, transition_events)
    if transition_events:
        log.info("Recorded %d container image transition(s)", len(transition_events))

    # Changelog LLM for Docker image updates (sequential to avoid Ollama pile-up)
    for label, host in hosts.items():
        for r in host.get("results", []):
            if r["status"] != "update_available":
                continue
            source = r.pop("_source", None)
            if not source:
                continue
            release = await fetch_github_release_notes(source)
            if not release:
                continue
            tag, notes = release
            if tag:
                r["new_version"] = tag
            raw = await llm_changelog_analysis(r["container"], r["image"], tag, notes)
            r["changelog_analysis"] = raw.strip() if raw and raw.strip() else f"Updated to {tag}."
            log.info("Changelog %s/%s: %s", label, r["container"], r["changelog_analysis"][:80])

    # Changelog LLM for non-Docker updates (where GitHub URL is known)
    for key, src in sources.items():
        for u in src.get("updates", []):
            if u.get("changelog_analysis"):
                continue
            name = u.get("app") or u.get("package", "")
            github_url = u.pop("_github_url", None) or _known_github_url(name)
            if not github_url:
                continue
            release = await fetch_github_release_notes(github_url)
            if not release:
                continue
            tag, notes = release
            raw = await llm_changelog_analysis(name, name, u.get("new_version", tag), notes)
            if raw:
                u["changelog_analysis"] = raw.strip()
            log.info("Changelog %s/%s: %s", key, name,
                     (u.get("changelog_analysis") or "")[:80])

    # Deterministic, code-generated outage list — not LLM-dependent, so a down
    # service is never at the mercy of the article writer's discretion.
    alerts: list[dict] = []
    for label, host in hosts.items():
        for r in host.get("results", []):
            if r["status"] == "check_failed" and r["container"] == "—":
                alerts.append({"label": label, "detail": r["image"]})
    for key, src in sources.items():
        if src.get("status") == "error":
            alerts.append({"label": src.get("label", key), "detail": src.get("error", "check failed")})
        for d in src.get("down", []):
            alerts.append({
                "label": f"{src.get('label', key)}: {d['name']}",
                "detail": f"CT{d['ctid']} {d['status']} (expected running)",
            })
    if alerts:
        log.warning("Outage alerts: %d", len(alerts))

    # Save Docker-only results (for sidebar updates_card on /current)
    save_json(UPDATES_FILE, {"checked_at": now_ts, "hosts": hosts, "alerts": alerts})

    # Generate LLM articles covering all updates
    articles = await generate_homelab_intel(hosts, sources)

    # Save homelab intel for wire page
    save_json(HOMELAB_INTEL_FILE, {
        "checked_at": now_ts,
        "sources":    sources,
        "articles":   articles or [],
    })
    log.info("Update check complete (%d docker hosts, %d homelab sources)",
             len(hosts), len(sources))


async def main() -> None:
    if not APP_SETTINGS.features.updates:
        log.info("Update reporting disabled by configuration")
        await asyncio.Event().wait()
        return
    await run_loop(run, UPDATE_INTERVAL, log)


if __name__ == "__main__":
    asyncio.run(main())

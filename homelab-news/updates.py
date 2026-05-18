"""Hourly worker: checks image digests + homelab software updates; generates wire report."""

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from typing import Optional

import httpx

from lib import (
    UPDATE_INTERVAL, UPDATES_FILE, HOMELAB_INTEL_FILE, REMOTE_HOSTS, SSH_KEY,
    PVE_SSH_HOST, TRUENAS_SSH_HOST, ADGUARD_URLS, PLEX_LXC_ID,
    HOMEASSISTANT_URL, HOMEASSISTANT_TOKEN, BESZEL_SSH_HOST, OLLAMA_URL,
    remote_digest, parse_image_ref,
    get_containers_local, get_containers_tcp, get_containers_ssh,
    fetch_github_release_notes, llm_changelog_analysis, generate_homelab_intel,
    save_json, notify_gotify,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("updates")

_digest_cache: dict = {}
_source_cache: dict = {}

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
    "plex":           None,
    "plexmediaserver": None,
    "home-assistant": "https://github.com/home-assistant/core",
    "homeassistant":  "https://github.com/home-assistant/core",
    "beszel":         "https://github.com/henrygd/beszel",
    "ollama":         "https://github.com/ollama/ollama",
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
        return _digest_cache[image_ref], _source_cache.get(image_ref)
    async with sem:
        if image_ref in _digest_cache:
            return _digest_cache[image_ref], _source_cache.get(image_ref)
        digest, source = await remote_digest(image_ref)
    _digest_cache[image_ref] = digest
    _source_cache[image_ref] = source
    return digest, source


async def _check_host(label: str, url: str, sem: asyncio.Semaphore) -> dict:
    loop = asyncio.get_running_loop()
    try:
        if url == "local":
            containers = await loop.run_in_executor(None, get_containers_local)
        elif url.startswith("ssh://"):
            containers = await get_containers_ssh(url)
        else:
            containers = await loop.run_in_executor(None, get_containers_tcp, url)
    except Exception as e:
        log.error("Failed to list containers for %s: %s", label, e)
        return {"status": "done", "ts": datetime.now(timezone.utc).isoformat(), "results": [
            {"container": "—", "image": str(e), "status": "check_failed"}
        ]}

    async def _check_one(c: dict) -> dict:
        digest, source = await _cached_digest(c["image"], sem)
        if digest is None:
            return {"container": c["name"], "image": c["image"], "status": "check_failed"}
        if c["local_digest"] is None:
            return {"container": c["name"], "image": c["image"], "status": "unknown"}
        status = "update_available" if c["local_digest"] != digest else "current"
        r = {"container": c["name"], "image": c["image"], "status": status}
        if status == "update_available" and source:
            r["_source"] = source
        return r

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
        "apt-get update -qq 2>/dev/null; apt list --upgradable 2>/dev/null | grep -v 'Listing...' || true",
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


async def check_adguard_update(url: str, label: str) -> dict:
    """Check an AdGuard Home instance for available updates.

    Gets current version from the local API, then compares against the latest
    GitHub release. Avoids the /control/update/check endpoint which fails because
    AdGuard itself is the resolver (can't reach static.adtidy.org).
    """
    ts = datetime.now(timezone.utc).isoformat()
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            status_r = await client.get(f"{url}/control/status")
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


async def check_plex_update() -> dict:
    """Check current Plex Media Server version vs latest available from plex.tv."""
    label = "Plex Media Server"
    ts = datetime.now(timezone.utc).isoformat()

    ok, out = await _ssh_run(
        PVE_SSH_HOST,
        f"/usr/sbin/pct exec {PLEX_LXC_ID} -- "
        "dpkg-query -W -f='${Version}' plexmediaserver 2>/dev/null",
        timeout=20,
    )
    if not ok or not out.strip():
        return {"label": label, "status": "error", "ts": ts,
                "error": "could not read installed version", "updates": []}

    current_version = out.strip()

    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            r = await client.get("https://plex.tv/pms/downloads/5.json")
            r.raise_for_status()
            latest = r.json().get("computer", {}).get("Linux", {}).get("version", "")
    except Exception as e:
        log.warning("Plex: failed to fetch latest version: %s", e)
        return {"label": label, "status": "done", "ts": ts,
                "current_version": current_version, "updates": []}

    if not latest:
        return {"label": label, "status": "done", "ts": ts,
                "current_version": current_version, "updates": []}

    # Version format: "1.40.4.8679-424562606" — compare the numeric part before the dash
    def _ver_tuple(v: str) -> tuple:
        try:
            return tuple(int(x) for x in v.split("-")[0].split("."))
        except ValueError:
            return (0,)

    updates = []
    if _ver_tuple(latest) > _ver_tuple(current_version):
        updates.append({
            "app":             "plexmediaserver",
            "current_version": current_version,
            "new_version":     latest,
        })
    log.info("Plex: current=%s latest=%s updates=%d", current_version, latest, len(updates))
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
    cmd = "midclt call update.check_available 2>/dev/null || true"
    ok, out = await _ssh_run(TRUENAS_SSH_HOST, cmd, timeout=60)
    if not ok:
        ok, out = await _ssh_run(TRUENAS_SSH_HOST, "sudo " + cmd, timeout=60)
    if not ok:
        return {"label": label, "status": "error", "ts": ts, "error": out[:100], "updates": []}
    try:
        data = json.loads(out)
    except Exception as e:
        return {"label": label, "status": "error", "ts": ts,
                "error": f"parse error: {e}", "updates": []}

    status = data.get("status", "")
    new_version = data.get("version", "")
    updates = []
    if status == "AVAILABLE" and new_version:
        updates.append({
            "app":             "truenas",
            "current_version": data.get("installed_version", "?"),
            "new_version":     new_version,
        })
    log.info("TrueNAS system: status=%s version=%s", status, new_version)
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


async def check_ollama_update() -> dict:
    """Check Ollama version via its local API against latest GitHub release."""
    label = "Ollama"
    ts = datetime.now(timezone.utc).isoformat()
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(f"{OLLAMA_URL}/api/version")
            r.raise_for_status()
            current_version = r.json().get("version", "")
    except Exception as e:
        log.warning("Ollama version check failed: %s", e)
        return {"label": label, "status": "error", "ts": ts, "error": str(e)[:100], "updates": []}

    release = await fetch_github_release_notes("https://github.com/ollama/ollama")
    latest_tag = release[0] if release else None
    new_version = (latest_tag or "").lstrip("v")

    updates = []
    if new_version and new_version != current_version.lstrip("v"):
        updates.append({
            "app":             "ollama",
            "current_version": current_version,
            "new_version":     new_version,
        })
    log.info("Ollama: current=%s latest=%s updates=%d", current_version, new_version, len(updates))
    return {"label": label, "status": "done", "ts": ts,
            "current_version": current_version, "updates": updates}


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
        *adguard_coros,
        check_plex_update(),
        check_truenas_apps(),
        check_homeassistant_update(),
        check_truenas_update(),
        check_beszel_update(),
        check_ollama_update(),
        check_traefik_plugins(),
        return_exceptions=True,
    )
    def _key(label: str) -> str:
        return re.sub(r'\W+', '_', label.lower()).strip('_')

    keys = (
        ["proxmox"]
        + [_key(label) for _, label in ADGUARD_URLS]
        + ["plex", "truenas", "home_assistant", "truenas_system", "beszel", "ollama",
           "traefik_plugins"]
    )
    sources: dict = {}
    for key, result in zip(keys, all_results):
        if isinstance(result, dict):
            sources[key] = result
        else:
            log.error("homelab check %s raised: %s", key, result)
    return sources


async def run() -> None:
    global _digest_cache, _source_cache
    _digest_cache = {}
    _source_cache = {}

    now_ts = datetime.now(timezone.utc).isoformat()
    log.info("Starting update check (Docker + homelab)")
    sem = asyncio.Semaphore(5)
    host_specs = [("local", "local")] + list(REMOTE_HOSTS)

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

    # Gotify notification for critical/breaking changelog findings
    _CRITICAL_KW = re.compile(
        r'\b(breaking|CVE-\d{4}-\d+|critical|security|migration required)\b', re.IGNORECASE
    )
    critical_items: list[str] = []
    notable_items: list[str] = []
    for label, host in hosts.items():
        for r in host.get("results", []):
            analysis = r.get("changelog_analysis", "")
            if _CRITICAL_KW.search(analysis):
                critical_items.append(f"[{label}] {r['container']}: {analysis[:120]}")
    for key, src in sources.items():
        for u in src.get("updates", []):
            analysis = u.get("changelog_analysis", "")
            if _CRITICAL_KW.search(analysis):
                name = u.get("app") or u.get("package", key)
                notable_items.append(f"{name}: {analysis[:120]}")
    if critical_items or notable_items:
        all_items = critical_items + notable_items
        priority = 7 if critical_items else 5
        await notify_gotify(
            title="Lab Monitor: Critical update findings",
            message="\n\n".join(all_items),
            priority=priority,
        )

    # Save Docker-only results (for sidebar updates_card on /current)
    save_json(UPDATES_FILE, {"checked_at": now_ts, "hosts": hosts})

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
    while True:
        try:
            await run()
        except Exception as e:
            log.error("Run failed: %s", e)
        log.info("Next run in %ds", UPDATE_INTERVAL)
        await asyncio.sleep(UPDATE_INTERVAL)


if __name__ == "__main__":
    asyncio.run(main())

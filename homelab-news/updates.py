"""Hourly worker: checks image digests across all hosts and runs changelog LLM analysis."""

import asyncio
import logging
from datetime import datetime, timezone

from lib import (
    UPDATE_INTERVAL, UPDATES_FILE, REMOTE_HOSTS,
    remote_digest, parse_image_ref,
    get_containers_local, get_containers_tcp, get_containers_ssh,
    fetch_github_release_notes, llm_changelog_analysis,
    save_json,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("updates")

_digest_cache: dict = {}
_source_cache: dict = {}


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


async def run() -> None:
    global _digest_cache, _source_cache
    _digest_cache = {}
    _source_cache = {}

    log.info("Starting image update check")
    sem = asyncio.Semaphore(5)
    host_specs = [("local", "local")] + list(REMOTE_HOSTS)
    host_results = await asyncio.gather(
        *(_check_host(label, url, sem) for label, url in host_specs),
        return_exceptions=True,
    )
    hosts = {}
    for (label, _), result in zip(host_specs, host_results):
        if isinstance(result, dict):
            hosts[label] = result
        else:
            log.error("Host check %s raised: %s", label, result)

    # Changelog LLM analysis — sequential to avoid Ollama pile-up
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
            if raw and raw.strip().lower().rstrip(".") != "no action required":
                r["changelog_analysis"] = raw
            log.info("Changelog %s/%s: %s", label, r["container"],
                     "action needed" if r.get("changelog_analysis") else "no action")

    save_json(UPDATES_FILE, {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "hosts": hosts,
    })
    log.info("Update check complete")


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

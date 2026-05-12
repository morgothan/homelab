"""Daily worker: builds a full-day archive record at midnight UTC."""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from lib import (
    MAX_ARCHIVE_DAYS, ARCHIVE_FILE, UPDATES_FILE,
    check_docker_logs, check_loki, llm_analysis, generate_newspaper,
    get_container_status_async, load_json, save_json,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("daily")


async def build_archive(date_str: str) -> None:
    archive = load_json(ARCHIVE_FILE) or []
    if any(r["date"] == date_str for r in archive):
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
    docker_analysis = await llm_analysis(docker_issues, "Docker container")
    loki_analysis   = await llm_analysis(loki_issues, "network/syslog (from Loki)")

    unhealthy, _, _ = await get_container_status_async()
    unhealthy_names = [c.name for c in unhealthy]
    updates_raw  = load_json(UPDATES_FILE) or {}
    update_hosts = updates_raw.get("hosts", {})

    newspaper = await generate_newspaper(docker_issues, loki_issues, update_hosts, unhealthy_names)

    record = {
        "date": date_str,
        "built_at": datetime.now(timezone.utc).isoformat(),
        "docker_issues": docker_issues[:50],
        "docker_analysis": docker_analysis,
        "loki_issues": loki_issues[:50],
        "loki_analysis": loki_analysis,
        "newspaper": newspaper or [],
    }

    archive.insert(0, record)
    archive = archive[:MAX_ARCHIVE_DAYS]
    save_json(ARCHIVE_FILE, archive)
    log.info("Archive saved for %s (%d docker, %d loki issues)",
             date_str, len(docker_issues), len(loki_issues))


async def main() -> None:
    # Catch up yesterday on startup if missing
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    try:
        await build_archive(yesterday)
    except Exception as e:
        log.error("Catch-up archive for %s failed: %s", yesterday, e)

    while True:
        now = datetime.now(timezone.utc)
        next_run = (now + timedelta(days=1)).replace(hour=0, minute=1, second=0, microsecond=0)
        wait = (next_run - now).total_seconds()
        log.info("Next daily archive in %.0fs (at %s UTC)", wait, next_run.strftime("%Y-%m-%d %H:%M"))
        await asyncio.sleep(wait)
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
        try:
            await build_archive(yesterday)
        except Exception as e:
            log.error("Daily archive failed: %s", e)


if __name__ == "__main__":
    asyncio.run(main())

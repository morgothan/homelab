"""Hourly worker: fetches today's logs (midnight to now) and generates the front-page newspaper."""

import asyncio
import logging
from datetime import datetime, timezone

from lib import (
    UPDATE_INTERVAL, TODAY_FILE,
    check_docker_logs, check_loki, llm_analysis, generate_newspaper,
    get_container_status_async, load_json, save_json, UPDATES_FILE,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("today")


async def run() -> None:
    midnight = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    since_ts = int(midnight.timestamp())
    log.info("Refreshing today's front page (since %s UTC)", midnight.strftime("%Y-%m-%d"))

    docker_issues, loki_issues = await asyncio.gather(
        check_docker_logs(since_ts=since_ts),
        check_loki(start=midnight),
    )
    # Save issues immediately so the page shows something while LLM runs
    save_json(TODAY_FILE, {
        "built_at": datetime.now(timezone.utc).isoformat(),
        "newspaper": None,
        "docker_issues": docker_issues,
        "docker_analysis": None,
        "loki_issues": loki_issues,
        "loki_analysis": None,
    })

    docker_analysis = await llm_analysis(docker_issues, "Docker container (today)")
    loki_analysis   = await llm_analysis(loki_issues, "network/syslog (today)")

    unhealthy, _, _ = await get_container_status_async()
    unhealthy_names = [c.name for c in unhealthy]
    updates_raw  = load_json(UPDATES_FILE) or {}
    update_hosts = updates_raw.get("hosts", {})

    newspaper = await generate_newspaper(docker_issues, loki_issues, update_hosts, unhealthy_names)
    log.info("Today's front page complete (%d articles)", len(newspaper) if newspaper else 0)

    save_json(TODAY_FILE, {
        "built_at": datetime.now(timezone.utc).isoformat(),
        "newspaper": newspaper or [],
        "docker_issues": docker_issues,
        "docker_analysis": docker_analysis,
        "loki_issues": loki_issues,
        "loki_analysis": loki_analysis,
    })


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

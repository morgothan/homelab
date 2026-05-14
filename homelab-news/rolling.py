"""Rolling worker: fetches the last LOG_HOURS of logs and generates the current events view."""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from lib import (
    REFRESH_INTERVAL, ROLLING_FILE, ROLLING_HOURS,
    check_docker_logs, check_loki, check_fail2ban_bans,
    check_prometheus, check_kopia, check_beszel, check_tautulli,
    llm_analysis, generate_newspaper,
    get_container_status_async, load_json, save_json, UPDATES_FILE,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("rolling")


async def run() -> None:
    log.info("Refreshing rolling view")
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=ROLLING_HOURS)
    since_ts = int(since.timestamp())

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
    existing = load_json(ROLLING_FILE) or {}
    save_json(ROLLING_FILE, {
        "built_at": datetime.now(timezone.utc).isoformat(),
        "newspaper": existing.get("newspaper"),
        "docker_issues": docker_issues,
        "docker_analysis": existing.get("docker_analysis"),
        "loki_issues": loki_issues,
        "loki_analysis": existing.get("loki_analysis"),
        "bans": bans,
    })

    unhealthy, _, _ = await get_container_status_async()
    unhealthy_names = [c.name for c in unhealthy]
    updates_raw  = load_json(UPDATES_FILE) or {}
    update_hosts = updates_raw.get("hosts", {})

    (docker_analysis, loki_analysis), newspaper = await asyncio.gather(
        asyncio.gather(
            llm_analysis(docker_issues, "Docker container"),
            llm_analysis(loki_issues, "network/syslog (from Loki)"),
        ),
        generate_newspaper(docker_issues, loki_issues, update_hosts, unhealthy_names, bans, probes, prometheus, kopia, beszel, tautulli),
    )
    log.info("Rolling view complete (%d articles, %d bans)",
             len(newspaper) if newspaper else 0, len(bans))

    save_json(ROLLING_FILE, {
        "built_at": datetime.now(timezone.utc).isoformat(),
        "newspaper": newspaper or [],
        "docker_issues": docker_issues,
        "docker_analysis": docker_analysis,
        "loki_issues": loki_issues,
        "loki_analysis": loki_analysis,
        "bans": bans,
    })


async def main() -> None:
    while True:
        try:
            await run()
        except Exception as e:
            log.error("Run failed: %s", e)
        log.info("Next run in %ds", REFRESH_INTERVAL)
        await asyncio.sleep(REFRESH_INTERVAL)


if __name__ == "__main__":
    asyncio.run(main())

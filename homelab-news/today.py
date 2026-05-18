"""Hourly worker: fetches today's logs (midnight to now) and generates the front-page newspaper."""

import asyncio
import logging
from datetime import datetime, timezone

from lib import UPDATE_INTERVAL, TODAY_FILE, run_news_cycle

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("today")


async def run() -> None:
    since = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    log.info("Refreshing today's front page (since %s UTC)", since.strftime("%Y-%m-%d"))
    await run_news_cycle(since, TODAY_FILE)


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

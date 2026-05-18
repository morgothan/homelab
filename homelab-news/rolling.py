"""Rolling worker: fetches the last ROLLING_HOURS of logs and generates the current events view."""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from lib import REFRESH_INTERVAL, ROLLING_FILE, ROLLING_HOURS, run_news_cycle

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("rolling")


async def run() -> None:
    since = datetime.now(timezone.utc) - timedelta(hours=ROLLING_HOURS)
    log.info("Refreshing rolling view (last %dh)", ROLLING_HOURS)
    await run_news_cycle(since, ROLLING_FILE)


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

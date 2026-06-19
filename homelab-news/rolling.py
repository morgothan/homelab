"""Rolling worker: fetches the last ROLLING_HOURS of logs and generates the current events view."""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from lib import REFRESH_INTERVAL, ROLLING_FILE, ROLLING_HOURS, run_news_cycle, run_loop

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("rolling")


async def run() -> None:
    since = datetime.now(timezone.utc) - timedelta(hours=ROLLING_HOURS)
    log.info("Refreshing rolling view (last %dh)", ROLLING_HOURS)
    await run_news_cycle(since, ROLLING_FILE)


async def main() -> None:
    await run_loop(run, REFRESH_INTERVAL, log)


if __name__ == "__main__":
    asyncio.run(main())

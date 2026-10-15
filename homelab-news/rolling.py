"""Rolling worker: fetches the last ROLLING_HOURS of logs and generates the current events view."""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from config import REFRESH_INTERVAL, ROLLING_FILE, ROLLING_HOURS
from lib import run_news_cycle
from runtime import run_loop, configure_logging

configure_logging("rolling")
log = logging.getLogger("rolling")


async def run() -> None:
    since = datetime.now(timezone.utc) - timedelta(hours=ROLLING_HOURS)
    log.info("Refreshing rolling view (last %dh)", ROLLING_HOURS)
    await run_news_cycle(since, ROLLING_FILE)


async def main() -> None:
    await run_loop(run, REFRESH_INTERVAL, log)


if __name__ == "__main__":
    asyncio.run(main())

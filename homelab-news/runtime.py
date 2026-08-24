"""Long-running worker control flow."""

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable


async def run_loop(
    function: Callable[[], Awaitable[None]],
    interval: int,
    logger: logging.Logger | None = None,
) -> None:
    """Run FUNCTION forever, aligned to INTERVAL boundaries.

    An exception from one iteration is logged and does not terminate the worker.
    INTERVAL must be positive because it is used as a scheduling modulus.
    """
    if interval <= 0:
        raise ValueError("interval must be positive")
    worker_logger = logger or logging.getLogger("lab-monitor")
    while True:
        try:
            await function()
        except Exception:
            worker_logger.exception("Run failed")
        wait = interval - (time.time() % interval)
        worker_logger.info("Next run in %ds", int(wait))
        await asyncio.sleep(wait)

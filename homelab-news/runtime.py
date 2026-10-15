"""Long-running worker control flow."""

import asyncio
import logging
import sys
import time
from collections.abc import Awaitable, Callable


def configure_logging(
    name: str | None = None,
    *,
    fmt: str = "%(asctime)s %(name)s %(levelname)s %(message)s",
    stream=None,
) -> None:
    """Configure root logging for a runnable entry point.

    Defaults to the standard news-app format. ``stream`` may be overridden
    (e.g. ``sys.stdout``) by entry points that need a non-default sink.
    """
    logging.basicConfig(level=logging.INFO, format=fmt, stream=stream)
    if name:
        logging.getLogger(name).setLevel(logging.INFO)


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

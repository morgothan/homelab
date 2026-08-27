"""Refresh the Entertainment page's recent-media snapshot once per hour."""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from config import APP_SETTINGS, RECENT_MEDIA_FILE
from lib import fetch_recent_media, resolve_jellyfin_links
from storage import save_json

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("media")


async def refresh_recent_media() -> None:
    """Fetch the rolling seven-day list and atomically publish its snapshot."""
    started = datetime.now(timezone.utc)
    events = await fetch_recent_media(started - timedelta(days=7))
    links = await resolve_jellyfin_links(events)
    save_json(RECENT_MEDIA_FILE, {
        "refreshed_at": datetime.now(timezone.utc).isoformat(),
        "media_events": events,
        "media_links": links,
    })
    log.info("Recent-media snapshot refreshed (%d items, %d links)",
             len(events), len(links))


def seconds_until_next_hour(now: datetime | None = None) -> float:
    """Return seconds until the next UTC hour boundary."""
    current = now or datetime.now(timezone.utc)
    next_hour = current.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    return (next_hour - current).total_seconds()


async def main() -> None:
    if not APP_SETTINGS.features.media:
        log.info("Media feature disabled by configuration")
        await asyncio.Event().wait()
        return
    try:
        await refresh_recent_media()
    except Exception:
        log.exception("Initial recent-media refresh failed")

    while True:
        await asyncio.sleep(seconds_until_next_hour())
        try:
            await refresh_recent_media()
        except Exception:
            # Keep the last good snapshot available and try again next hour.
            log.exception("Recent-media refresh failed; retaining previous snapshot")


if __name__ == "__main__":
    asyncio.run(main())

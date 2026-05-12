"""Daily worker: snapshots today.json into the archive at midnight UTC.

No LLM calls — the last hourly today.py run already covers ~23h of the day.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from lib import MAX_ARCHIVE_DAYS, ARCHIVE_FILE, TODAY_FILE, load_json, save_json

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("daily")


def _archive_date(today_data: dict) -> str | None:
    """Return the date string for today_data, or None if unusable."""
    built_at = today_data.get("built_at", "")
    return built_at[:10] if built_at else None


def snapshot(date_str: str) -> None:
    archive = load_json(ARCHIVE_FILE) or []
    if any(r["date"] == date_str for r in archive):
        log.info("Archive already exists for %s, skipping", date_str)
        return

    today = load_json(TODAY_FILE)
    if not today:
        log.warning("No today.json available to archive for %s", date_str)
        return

    newspaper = today.get("newspaper")
    if not newspaper:
        log.warning("Today's newspaper is empty for %s — skipping archive", date_str)
        return

    record = {
        "date": date_str,
        "built_at": today.get("built_at", datetime.now(timezone.utc).isoformat()),
        "docker_issues":   (today.get("docker_issues") or [])[:50],
        "docker_analysis": today.get("docker_analysis"),
        "loki_issues":     (today.get("loki_issues") or [])[:50],
        "loki_analysis":   today.get("loki_analysis"),
        "newspaper":       newspaper,
    }

    archive.insert(0, record)
    archive = archive[:MAX_ARCHIVE_DAYS]
    save_json(ARCHIVE_FILE, archive)
    log.info("Archived %s edition (%d articles)", date_str, len(newspaper))


async def main() -> None:
    while True:
        now = datetime.now(timezone.utc)
        next_run = (now + timedelta(days=1)).replace(hour=0, minute=1, second=0, microsecond=0)
        wait = (next_run - now).total_seconds()
        log.info("Next daily archive in %.0fs (at %s UTC)", wait, next_run.strftime("%Y-%m-%d %H:%M"))
        await asyncio.sleep(wait)

        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
        try:
            snapshot(yesterday)
        except Exception as e:
            log.error("Daily archive failed: %s", e)


if __name__ == "__main__":
    asyncio.run(main())

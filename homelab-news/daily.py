"""Daily worker: snapshots today.json into the archive at midnight UTC.

No LLM calls — the last hourly today.py run already covers ~23h of the day.
"""

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

from lib import (
    MAX_ARCHIVE_DAYS, ARCHIVE_FILE, ARCHIVE_DIR, ARCHIVE_INDEX,
    TODAY_FILE, load_json, save_json,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("daily")


def _rebuild_index() -> None:
    """Scan ARCHIVE_DIR for per-day files and write a lightweight index."""
    entries = []
    try:
        names = sorted(
            (n for n in os.listdir(ARCHIVE_DIR) if n.endswith(".json") and n != "index.json"),
            reverse=True,
        )
        for name in names[:MAX_ARCHIVE_DAYS]:
            date_str = name[:-5]  # strip .json
            rec = load_json(os.path.join(ARCHIVE_DIR, name)) or {}
            articles = rec.get("newspaper") or []
            headline = articles[0]["headline"] if articles else ""
            n_issues = len(rec.get("docker_issues", [])) + len(rec.get("loki_issues", []))
            entries.append({"date": date_str, "headline": headline, "n_issues": n_issues})
    except Exception as e:
        log.warning("_rebuild_index failed: %s", e)
    save_json(ARCHIVE_INDEX, entries)


def _migrate_archive_if_needed() -> None:
    """One-time migration: split legacy archive.json into per-day files."""
    if not os.path.exists(ARCHIVE_FILE):
        return
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    records = load_json(ARCHIVE_FILE) or []
    migrated = 0
    for rec in records:
        date_str = rec.get("date")
        if not date_str:
            continue
        day_path = os.path.join(ARCHIVE_DIR, f"{date_str}.json")
        if not os.path.exists(day_path):
            save_json(day_path, rec)
            migrated += 1
    _rebuild_index()
    os.rename(ARCHIVE_FILE, ARCHIVE_FILE + ".migrated")
    log.info("Migrated %d archive records to per-day files", migrated)


def snapshot(date_str: str) -> None:
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    day_path = os.path.join(ARCHIVE_DIR, f"{date_str}.json")

    if os.path.exists(day_path):
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
        "bans":            today.get("bans") or [],
        "newspaper":       newspaper,
    }
    save_json(day_path, record)

    # Trim old day files beyond the retention limit
    try:
        all_days = sorted(
            (n for n in os.listdir(ARCHIVE_DIR) if n.endswith(".json") and n != "index.json"),
            reverse=True,
        )
        for old in all_days[MAX_ARCHIVE_DAYS:]:
            os.remove(os.path.join(ARCHIVE_DIR, old))
    except Exception as e:
        log.warning("Failed to trim old archive files: %s", e)

    _rebuild_index()
    log.info("Archived %s edition (%d articles)", date_str, len(newspaper))


async def main() -> None:
    _migrate_archive_if_needed()

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

"""Backfill newspaper archive from Loki historical data.

Iterates over dates with Loki coverage, queries logs for each day,
generates a newspaper via the LLM, and inserts into archive.json.
Skips dates that already exist — safe to resume after interruption.

Usage (run inside the container):
  docker exec -it lab-monitor python /app/backfill.py
  docker exec -it lab-monitor python /app/backfill.py --start 2026-03-01
  docker exec -it lab-monitor python /app/backfill.py --dry-run
  docker exec -it lab-monitor python /app/backfill.py --no-llm  # Loki data only, no articles

What each backfilled entry contains:
  - loki_issues: all Loki error/warn logs for that day (same as normal editions)
  - newspaper:   LLM-generated articles (Loki-only; no container health, bans, or metrics)
  - bans:        empty list (historical ban state not available)
  - backfilled:  true (flag so the UI/periodic workers can distinguish)
"""

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from datetime import date, datetime, timedelta, timezone

# lib.py is at /app inside the container
sys.path.insert(0, os.path.dirname(__file__))

from lib import (
    ARCHIVE_FILE,
    check_loki,
    generate_newspaper,
    llm_analysis,
    load_json,
    save_json,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("backfill")

# Oldest available Loki log — update if yours differs
OLDEST_LOKI = date(2026, 2, 13)


async def process_day(d: date, dry_run: bool, no_llm: bool) -> dict:
    date_str = d.isoformat()
    midnight  = datetime(d.year, d.month, d.day, tzinfo=timezone.utc)
    end_of_day = midnight + timedelta(days=1)

    log.info("[%s] Querying Loki...", date_str)
    loki_issues = await check_loki(start=midnight, end=end_of_day)

    # Filter out the "Could not reach Loki" sentinel so empty days stay empty
    real_issues = [i for i in loki_issues if "Could not reach Loki" not in i.get("message", "")]
    log.info("[%s] %d Loki issues", date_str, len(real_issues))

    newspaper = []
    loki_analysis_result = None

    if not dry_run and not no_llm and real_issues:
        log.info("[%s] Generating newspaper...", date_str)
        loki_analysis_result, newspaper = await asyncio.gather(
            llm_analysis(real_issues, f"network/syslog ({date_str})"),
            generate_newspaper(
                docker_issues=[],
                loki_issues=real_issues,
                update_hosts={},
                unhealthy_names=[],
                bans=[],
                probes=[],
                prometheus=None,
                kopia=None,
                beszel=None,
                tautulli=None,
            ),
        )
        newspaper = newspaper or []
        log.info("[%s] %d articles generated", date_str, len(newspaper))
    elif not real_issues:
        log.info("[%s] No Loki issues — skipping LLM", date_str)
    elif dry_run:
        log.info("[%s] --dry-run — skipping LLM", date_str)
    else:
        log.info("[%s] --no-llm — skipping LLM", date_str)

    return {
        "date":           date_str,
        "newspaper":      newspaper,
        "docker_issues":  [],
        "loki_issues":    real_issues,
        "loki_analysis":  loki_analysis_result,
        "bans":           [],
        "backfilled":     True,
    }


async def main() -> None:
    parser = argparse.ArgumentParser(description="Backfill newspaper archive from Loki")
    parser.add_argument(
        "--start", default=OLDEST_LOKI.isoformat(),
        help=f"First date to backfill (YYYY-MM-DD, default: {OLDEST_LOKI})",
    )
    parser.add_argument(
        "--end", default=(date.today() - timedelta(days=1)).isoformat(),
        help="Last date to backfill inclusive (YYYY-MM-DD, default: yesterday)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Query Loki but skip LLM and don't write archive",
    )
    parser.add_argument(
        "--no-llm", action="store_true",
        help="Store Loki issues only; skip newspaper generation",
    )
    args = parser.parse_args()

    start = date.fromisoformat(args.start)
    end   = date.fromisoformat(args.end)
    if start > end:
        log.error("--start must be before --end")
        sys.exit(1)

    archive        = load_json(ARCHIVE_FILE) or []
    existing_dates = {r["date"] for r in archive}

    dates_to_do = []
    d = start
    while d <= end:
        ds = d.isoformat()
        if ds in existing_dates:
            log.info("Skip %s (already in archive)", ds)
        else:
            dates_to_do.append(d)
        d += timedelta(days=1)

    total = len(dates_to_do)
    log.info("Backfilling %d days (%s → %s)", total, start, end)
    if total == 0:
        log.info("Nothing to do.")
        return

    new_entries: list[dict] = []
    t0 = time.monotonic()

    for idx, d in enumerate(dates_to_do):
        try:
            entry = await process_day(d, dry_run=args.dry_run, no_llm=args.no_llm)
            new_entries.append(entry)
        except Exception as e:
            log.error("[%s] Failed: %s", d.isoformat(), e)

        done = idx + 1
        elapsed = time.monotonic() - t0
        rate = elapsed / done
        remaining = (total - done) * rate
        eta_h, eta_m = divmod(int(remaining), 3600)
        eta_m //= 60
        log.info("Progress: %d/%d  ETA %dh %02dm", done, total, eta_h, eta_m)

    if not new_entries:
        log.info("No entries generated.")
        return

    if args.dry_run:
        log.info("--dry-run: would add %d entries (not writing archive)", len(new_entries))
        return

    # Merge with existing archive and sort newest-first (no hard cap — daily.py handles that)
    combined = archive + new_entries
    combined.sort(key=lambda r: r["date"], reverse=True)
    save_json(ARCHIVE_FILE, combined)
    log.info("Done. Archive: %d total entries (%d new).", len(combined), len(new_entries))


if __name__ == "__main__":
    asyncio.run(main())

"""Periodic trend worker: builds weekly, monthly, and yearly summary digests.

Schedules:
  Weekly  — Sunday 00:01 UTC  (reads last 7 daily archives)
  Monthly — 1st     00:01 UTC  (reads last 5 weekly digests)
  Yearly  — Jan 1   00:01 UTC  (reads last 12 monthly reviews)
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from lib import (
    PERIODIC_FILE, ARCHIVE_FILE,
    MAX_WEEKLY, MAX_MONTHLY,
    generate_periodic_summary, load_json, save_json,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("periodic")


# ── Schedule helpers ───────────────────────────────────────────────────────────

def _next_sunday() -> datetime:
    now = datetime.now(timezone.utc)
    days = (6 - now.weekday()) % 7 or 7  # weekday(): Mon=0 Sun=6; always ≥1
    return (now + timedelta(days=days)).replace(hour=0, minute=1, second=0, microsecond=0)


def _next_first() -> datetime:
    now = datetime.now(timezone.utc)
    if now.month == 12:
        return now.replace(year=now.year + 1, month=1, day=1,
                           hour=0, minute=1, second=0, microsecond=0)
    return now.replace(month=now.month + 1, day=1,
                       hour=0, minute=1, second=0, microsecond=0)


def _next_jan1() -> datetime:
    now = datetime.now(timezone.utc)
    return now.replace(year=now.year + 1, month=1, day=1,
                       hour=0, minute=1, second=0, microsecond=0)


# ── Builders ───────────────────────────────────────────────────────────────────

async def build_weekly() -> None:
    archive = load_json(ARCHIVE_FILE) or []
    days = [r for r in archive[:7] if r.get("newspaper")]
    if not days:
        log.warning("No daily archives with content available for weekly digest")
        return

    entries = [{"period": r["date"], "articles": r["newspaper"]} for r in days]
    dates = [e["period"] for e in entries]
    week_start = dates[-1]
    period = f"{week_start} to {dates[0]}"

    periodic = load_json(PERIODIC_FILE) or {}
    if any(w["week_start"] == week_start for w in periodic.get("weekly", [])):
        log.info("Weekly digest already exists for week starting %s", week_start)
        return

    log.info("Building weekly digest for %s", period)
    articles = await generate_periodic_summary("week", period, entries)
    if not articles:
        log.warning("Weekly digest generation returned no articles")
        return

    weekly = periodic.get("weekly", [])
    weekly.insert(0, {
        "week_start": week_start,
        "period": period,
        "built_at": datetime.now(timezone.utc).isoformat(),
        "articles": articles,
    })
    periodic["weekly"] = weekly[:MAX_WEEKLY]
    save_json(PERIODIC_FILE, periodic)
    log.info("Weekly digest saved for %s (%d articles)", period, len(articles))


async def build_monthly() -> None:
    periodic = load_json(PERIODIC_FILE) or {}
    weekly = [w for w in periodic.get("weekly", []) if w.get("articles")]
    if not weekly:
        log.warning("No weekly digests available for monthly review")
        return

    entries = [{"period": w["period"], "articles": w["articles"]} for w in weekly[:5]]

    now = datetime.now(timezone.utc)
    prev = now.replace(day=1) - timedelta(days=1)  # last day of previous month
    month_key   = prev.strftime("%Y-%m")
    month_label = prev.strftime("%B %Y")

    monthly = periodic.get("monthly", [])
    if any(m["month"] == month_key for m in monthly):
        log.info("Monthly review already exists for %s", month_key)
        return

    log.info("Building monthly review for %s", month_label)
    articles = await generate_periodic_summary("month", month_label, entries)
    if not articles:
        log.warning("Monthly review generation returned no articles")
        return

    monthly.insert(0, {
        "month": month_key,
        "period": month_label,
        "built_at": datetime.now(timezone.utc).isoformat(),
        "articles": articles,
    })
    periodic["monthly"] = monthly[:MAX_MONTHLY]
    save_json(PERIODIC_FILE, periodic)
    log.info("Monthly review saved for %s", month_label)


async def build_yearly() -> None:
    periodic = load_json(PERIODIC_FILE) or {}
    monthly = [m for m in periodic.get("monthly", []) if m.get("articles")]
    if not monthly:
        log.warning("No monthly reviews available for yearly report")
        return

    entries = [{"period": m["period"], "articles": m["articles"]} for m in monthly[:12]]

    year_key = str(datetime.now(timezone.utc).year - 1)

    yearly = periodic.get("yearly", [])
    if any(y["year"] == year_key for y in yearly):
        log.info("Yearly report already exists for %s", year_key)
        return

    log.info("Building yearly report for %s", year_key)
    articles = await generate_periodic_summary("year", year_key, entries)
    if not articles:
        log.warning("Yearly report generation returned no articles")
        return

    yearly.insert(0, {
        "year": year_key,
        "built_at": datetime.now(timezone.utc).isoformat(),
        "articles": articles,
    })
    periodic["yearly"] = yearly
    save_json(PERIODIC_FILE, periodic)
    log.info("Yearly report saved for %s", year_key)


# ── Loops ──────────────────────────────────────────────────────────────────────

async def weekly_loop() -> None:
    next_run = _next_sunday()
    log.info("Next weekly digest: %s UTC", next_run.strftime("%Y-%m-%d %H:%M"))
    while True:
        await asyncio.sleep((next_run - datetime.now(timezone.utc)).total_seconds())
        try:
            await build_weekly()
        except Exception as e:
            log.error("Weekly digest failed: %s", e)
        next_run = _next_sunday()
        log.info("Next weekly digest: %s UTC", next_run.strftime("%Y-%m-%d %H:%M"))


async def monthly_loop() -> None:
    next_run = _next_first()
    log.info("Next monthly review: %s UTC", next_run.strftime("%Y-%m-%d %H:%M"))
    while True:
        await asyncio.sleep((next_run - datetime.now(timezone.utc)).total_seconds())
        try:
            await build_monthly()
        except Exception as e:
            log.error("Monthly review failed: %s", e)
        next_run = _next_first()
        log.info("Next monthly review: %s UTC", next_run.strftime("%Y-%m-%d %H:%M"))


async def yearly_loop() -> None:
    next_run = _next_jan1()
    log.info("Next yearly report: %s UTC", next_run.strftime("%Y-%m-%d %H:%M"))
    while True:
        await asyncio.sleep((next_run - datetime.now(timezone.utc)).total_seconds())
        try:
            await build_yearly()
        except Exception as e:
            log.error("Yearly report failed: %s", e)
        next_run = _next_jan1()
        log.info("Next yearly report: %s UTC", next_run.strftime("%Y-%m-%d %H:%M"))


async def main() -> None:
    await asyncio.gather(weekly_loop(), monthly_loop(), yearly_loop())


if __name__ == "__main__":
    asyncio.run(main())

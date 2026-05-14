"""Backfill newspaper archive and trend digests from Loki historical data.

Iterates over dates with Loki coverage, queries logs for each day,
generates a newspaper via the LLM, and inserts into archive.json.
Skips dates that already exist — safe to resume after interruption.

Usage (run inside the container):
  docker exec -it lab-monitor python /app/backfill.py
  docker exec -it lab-monitor python /app/backfill.py --start 2026-03-01
  docker exec -it lab-monitor python /app/backfill.py --dry-run
  docker exec -it lab-monitor python /app/backfill.py --no-llm
  docker exec -it lab-monitor python /app/backfill.py --trends        # archive + trends
  docker exec -it lab-monitor python /app/backfill.py --trends-only   # trends from existing archive

What each backfilled daily entry contains:
  - loki_issues: all Loki error/warn logs for that day
  - newspaper:   LLM-generated articles (Loki-only; no container health, bans, or metrics)
  - bans:        empty list (historical ban state not available)
  - backfilled:  true (flag to distinguish from live editions)
"""

import argparse
import asyncio
import logging
import os
import sys
import time
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(__file__))

from lib import (
    ARCHIVE_FILE, PERIODIC_FILE,
    MAX_WEEKLY, MAX_MONTHLY,
    check_loki,
    generate_newspaper, generate_periodic_summary,
    llm_analysis, _ban_summary,
    load_json, save_json,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("backfill")

OLDEST_LOKI = date(2026, 2, 13)


# ── Daily archive ─────────────────────────────────────────────────────────────

async def process_day(d: date, dry_run: bool, no_llm: bool) -> dict:
    date_str  = d.isoformat()
    midnight  = datetime(d.year, d.month, d.day, tzinfo=timezone.utc)
    end_of_day = midnight + timedelta(days=1)

    log.info("[%s] Querying Loki...", date_str)
    loki_issues = await check_loki(start=midnight, end=end_of_day)
    real_issues = [i for i in loki_issues if "Could not reach Loki" not in i.get("message", "")]
    log.info("[%s] %d Loki issues", date_str, len(real_issues))

    newspaper = []
    loki_analysis_result = None

    if not dry_run and not no_llm and real_issues:
        log.info("[%s] Generating newspaper...", date_str)
        loki_analysis_result, newspaper = await asyncio.gather(
            llm_analysis(real_issues, f"network/syslog ({date_str})"),
            generate_newspaper(
                docker_issues=[], loki_issues=real_issues,
                update_hosts={}, unhealthy_names=[],
                bans=[], probes=[],
                prometheus=None, kopia=None, beszel=None, tautulli=None,
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
        "date":          date_str,
        "newspaper":     newspaper,
        "docker_issues": [],
        "loki_issues":   real_issues,
        "loki_analysis": loki_analysis_result,
        "bans":          [],
        "backfilled":    True,
    }


async def run_daily_backfill(start: date, end: date, dry_run: bool, no_llm: bool) -> None:
    archive        = load_json(ARCHIVE_FILE) or []
    existing_dates = {r["date"] for r in archive}

    dates_to_do = [
        d for d in (start + timedelta(n) for n in range((end - start).days + 1))
        if d.isoformat() not in existing_dates
    ]
    for ds in sorted({r["date"] for r in archive} & {(start + timedelta(n)).isoformat() for n in range((end - start).days + 1)}):
        log.info("Skip %s (already in archive)", ds)

    total = len(dates_to_do)
    log.info("Backfilling %d days (%s → %s)", total, start, end)
    if total == 0:
        log.info("Nothing to do.")
        return

    t0 = time.monotonic()
    saved = 0

    for idx, d in enumerate(dates_to_do):
        try:
            entry = await process_day(d, dry_run=dry_run, no_llm=no_llm)
        except Exception as e:
            log.error("[%s] Failed: %s", d.isoformat(), e)
            entry = None

        done    = idx + 1
        elapsed = time.monotonic() - t0
        rate    = elapsed / done
        remaining = (total - done) * rate
        eta_h, eta_rem = divmod(int(remaining), 3600)
        eta_m = eta_rem // 60
        log.info("Progress: %d/%d  ETA %dh %02dm", done, total, eta_h, eta_m)

        if entry and not dry_run:
            current = load_json(ARCHIVE_FILE) or []
            if entry["date"] not in {r["date"] for r in current}:
                current.append(entry)
                current.sort(key=lambda r: r["date"], reverse=True)
                save_json(ARCHIVE_FILE, current)
                saved += 1
                log.info("[%s] Saved to archive (%d total entries)", entry["date"], len(current))

    if dry_run:
        log.info("--dry-run complete: %d days processed (nothing written)", total)
    else:
        log.info("Daily backfill done. %d new entries saved.", saved)


# ── Weekly trend digests ──────────────────────────────────────────────────────

async def run_weekly_backfill(dry_run: bool) -> None:
    archive = load_json(ARCHIVE_FILE) or []

    # Group archive entries (oldest-first) by ISO week
    by_week: dict[tuple, list[dict]] = defaultdict(list)
    for rec in sorted(archive, key=lambda r: r["date"]):
        if not rec.get("newspaper"):
            continue
        d = date.fromisoformat(rec["date"])
        by_week[d.isocalendar()[:2]].append(rec)  # (iso_year, iso_week) key

    # Skip the current incomplete week
    today_iso = date.today().isocalendar()[:2]
    weeks = sorted(k for k in by_week if k != today_iso)

    if not weeks:
        log.info("No complete weeks found in archive.")
        return

    periodic = load_json(PERIODIC_FILE) or {}
    existing_starts = {w["week_start"] for w in periodic.get("weekly", [])}

    total  = len(weeks)
    saved  = 0
    t0     = time.monotonic()

    for idx, week_key in enumerate(weeks):
        days      = by_week[week_key]
        dates     = sorted(r["date"] for r in days)
        week_start = dates[0]
        period    = f"{dates[0]} to {dates[-1]}"

        if week_start in existing_starts:
            log.info("[weekly %s] Already exists, skipping", period)
            continue

        log.info("[weekly %s] Building (%d days)...", period, len(days))

        entries = [
            {
                "period":      r["date"],
                "articles":    r["newspaper"],
                "bans":        r.get("bans") or [],
                "ban_summary": _ban_summary(r.get("bans") or []),
            }
            for r in days
        ]

        done      = idx + 1
        elapsed   = time.monotonic() - t0
        remaining = (total - done) * (elapsed / done) if done else 0
        eta_h, eta_rem = divmod(int(remaining), 3600)
        log.info("Weekly progress: %d/%d  ETA %dh %02dm", done, total, eta_h, eta_rem // 60)

        if dry_run:
            log.info("[weekly %s] --dry-run, skipping LLM", period)
            continue

        articles = await generate_periodic_summary("week", period, entries)
        if not articles:
            log.warning("[weekly %s] No articles generated", period)
            continue

        all_week_bans: list[dict] = []
        seen_ips: set[str] = set()
        for e in entries:
            for b in e.get("bans") or []:
                if b["ip"] not in seen_ips:
                    all_week_bans.append(b)
                    seen_ips.add(b["ip"])

        periodic = load_json(PERIODIC_FILE) or {}
        weekly   = periodic.get("weekly", [])
        weekly.append({
            "week_start":  week_start,
            "period":      period,
            "built_at":    datetime.now(timezone.utc).isoformat(),
            "articles":    articles,
            "ban_summary": _ban_summary(all_week_bans),
        })
        # Sort newest-first, cap at MAX_WEEKLY
        weekly.sort(key=lambda w: w["week_start"], reverse=True)
        periodic["weekly"] = weekly[:MAX_WEEKLY]
        save_json(PERIODIC_FILE, periodic)
        existing_starts.add(week_start)
        saved += 1
        log.info("[weekly %s] Saved (%d articles)", period, len(articles))

    log.info("Weekly backfill done. %d new digests saved.", saved)


# ── Monthly trend digests ─────────────────────────────────────────────────────

async def run_monthly_backfill(dry_run: bool) -> None:
    periodic = load_json(PERIODIC_FILE) or {}
    all_weeklies = [w for w in periodic.get("weekly", []) if w.get("articles")]

    if not all_weeklies:
        log.info("No weekly digests available — run weekly backfill first.")
        return

    # Group weeklies by month of their week_start
    by_month: dict[str, list[dict]] = defaultdict(list)
    for w in all_weeklies:
        month_key = w["week_start"][:7]  # "YYYY-MM"
        by_month[month_key].append(w)

    # Skip the current month (incomplete)
    current_month = date.today().strftime("%Y-%m")
    months = sorted(k for k in by_month if k != current_month)

    if not months:
        log.info("No complete months found.")
        return

    existing_months = {m["month"] for m in periodic.get("monthly", [])}
    total  = len(months)
    saved  = 0
    t0     = time.monotonic()

    for idx, month_key in enumerate(months):
        if month_key in existing_months:
            log.info("[monthly %s] Already exists, skipping", month_key)
            continue

        month_label = datetime.strptime(month_key, "%Y-%m").strftime("%B %Y")
        weeklies    = sorted(by_month[month_key], key=lambda w: w["week_start"])
        entries     = [
            {
                "period":      w["period"],
                "articles":    w["articles"],
                "ban_summary": w.get("ban_summary") or [],
            }
            for w in weeklies[:5]
        ]

        done      = idx + 1
        elapsed   = time.monotonic() - t0
        remaining = (total - done) * (elapsed / done) if done else 0
        eta_h, eta_rem = divmod(int(remaining), 3600)
        log.info("[monthly %s] Building (%d weeklies)...  ETA %dh %02dm",
                 month_label, len(entries), eta_h, eta_rem // 60)

        if dry_run:
            log.info("[monthly %s] --dry-run, skipping LLM", month_label)
            continue

        articles = await generate_periodic_summary("month", month_label, entries)
        if not articles:
            log.warning("[monthly %s] No articles generated", month_label)
            continue

        periodic = load_json(PERIODIC_FILE) or {}
        monthly  = periodic.get("monthly", [])
        monthly.append({
            "month":    month_key,
            "period":   month_label,
            "built_at": datetime.now(timezone.utc).isoformat(),
            "articles": articles,
        })
        monthly.sort(key=lambda m: m["month"], reverse=True)
        periodic["monthly"] = monthly[:MAX_MONTHLY]
        save_json(PERIODIC_FILE, periodic)
        existing_months.add(month_key)
        saved += 1
        log.info("[monthly %s] Saved (%d articles)", month_label, len(articles))

    log.info("Monthly backfill done. %d new reviews saved.", saved)


# ── Entry point ───────────────────────────────────────────────────────────────

async def main() -> None:
    parser = argparse.ArgumentParser(description="Backfill newspaper archive and trend digests")
    parser.add_argument("--start", default=OLDEST_LOKI.isoformat(),
                        help=f"First date (YYYY-MM-DD, default: {OLDEST_LOKI})")
    parser.add_argument("--end",   default=(date.today() - timedelta(days=1)).isoformat(),
                        help="Last date inclusive (YYYY-MM-DD, default: yesterday)")
    parser.add_argument("--dry-run",     action="store_true",
                        help="Query/plan but skip all LLM calls and writes")
    parser.add_argument("--no-llm",      action="store_true",
                        help="Store Loki data only; skip newspaper generation")
    parser.add_argument("--trends",      action="store_true",
                        help="Build weekly + monthly trend digests after daily archive")
    parser.add_argument("--trends-only", action="store_true",
                        help="Skip daily archive; only build trend digests from existing archive")
    args = parser.parse_args()

    start = date.fromisoformat(args.start)
    end   = date.fromisoformat(args.end)
    if start > end:
        log.error("--start must be before --end")
        sys.exit(1)

    if not args.trends_only:
        await run_daily_backfill(start, end, dry_run=args.dry_run, no_llm=args.no_llm)

    if args.trends or args.trends_only:
        log.info("=== Building historical weekly digests ===")
        await run_weekly_backfill(dry_run=args.dry_run)
        log.info("=== Building historical monthly reviews ===")
        await run_monthly_backfill(dry_run=args.dry_run)

    log.info("=== Backfill complete ===")


if __name__ == "__main__":
    asyncio.run(main())

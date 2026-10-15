"""Regression tests for the shared periodic-digest builder (lib.build_period_digest).

Verifies that the shared builder, now used by both the periodic workers
(periodic.build_weekly/monthly/yearly) and the backfill workers
(backfill.run_weekly_backfill/run_monthly_backfill), reproduces the exact
record structure, unique-ban-per-IP aggregation, ban_summary computation,
and capping behaviour the workers historically applied themselves.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from lib import _ban_summary, build_period_digest  # noqa: E402

ARTICLES = [{"headline": "Lead Story", "blurb": "Body", "section": "Public Works"}]


def _ban(ip, category="scan", hits=1):
    return {"ip": ip, "category": category, "hit_count": hits}


def _legacy_unique(bans):
    """Replicate the pre-refactor unique-ban-per-IP aggregation loop."""
    out, seen = [], set()
    for b in bans:
        if b["ip"] not in seen:
            out.append(b)
            seen.add(b["ip"])
    return out


class BuildPeriodDigestWeeklyTests(unittest.TestCase):
    def test_weekly_matches_legacy_aggregation_and_record(self):
        # Representative window: duplicate IPs across days must dedupe to the
        # first occurrence, exactly as the pre-refactor loop did.
        ban_records = [
            _ban("1.2.3.4", "env file sweep", 10),
            _ban("5.6.7.8", "PHP exploit probe", 2),
            _ban("1.2.3.4", "env file sweep", 40),  # duplicate IP -> deduped
            _ban("9.9.9.9", "scan", 1),
        ]
        built_at = "2026-05-18T00:00:00+00:00"
        result = build_period_digest(
            scope="week", key="2026-05-11", period="2026-05-11 to 2026-05-17",
            articles=ARTICLES, ban_records=ban_records,
            container=[], max_entries=16, built_at=built_at,
        )
        expected_unique = _legacy_unique(ban_records)
        self.assertEqual(len(expected_unique), 3)  # deduped by IP
        record = result[0]
        self.assertEqual(record, {
            "week_start": "2026-05-11",
            "period": "2026-05-11 to 2026-05-17",
            "built_at": built_at,
            "articles": ARTICLES,
            "ban_summary": _ban_summary(expected_unique),
        })
        # Exact key order identical to the pre-refactor build_weekly record
        self.assertEqual(
            list(record),
            ["week_start", "period", "built_at", "articles", "ban_summary"],
        )

    def test_weekly_empty_ban_list_gives_empty_summary(self):
        result = build_period_digest(
            scope="week", key="2026-05-18", period="2026-05-18 to 2026-05-24",
            articles=ARTICLES, ban_records=[], container=[], max_entries=16,
            built_at="2026-05-25T00:00:00+00:00",
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["ban_summary"], [])

    def test_weekly_cap_drops_oldest(self):
        cap = 4
        existing = [
            {"week_start": f"2026-05-{d:02d}", "period": "p", "built_at": "t",
             "articles": [{"headline": f"old{d}"}], "ban_summary": []}
            for d in (7, 6, 5, 4)  # newest-first
        ]
        result = build_period_digest(
            scope="week", key="2026-05-08", period="2026-05-08 to 2026-05-14",
            articles=ARTICLES, ban_records=[],
            container=existing, max_entries=cap, built_at="t",
        )
        self.assertEqual(len(result), cap)
        self.assertEqual(result[0]["week_start"], "2026-05-08")   # newest at front
        self.assertEqual(result[-1]["week_start"], "2026-05-05")  # oldest survives cap
        self.assertEqual([w["week_start"] for w in result],
                         ["2026-05-08", "2026-05-07", "2026-05-06", "2026-05-05"])

    def test_weekly_backfill_partial_resume_sorts_and_caps(self):
        # Backfill processes oldest-first over a container that already holds
        # newer records. The freshly built record is OLDER than every existing
        # entry, so the builder must re-sort newest-first before capping —
        # otherwise the older record lands at the front and the wrong entries
        # survive the cap.
        cap = 3
        existing = [
            {"week_start": f"2026-05-{d:02d}", "period": "p", "built_at": "t",
             "articles": [{"headline": f"old{d}"}], "ban_summary": []}
            for d in (7, 6, 5)  # newest-first, all newer than the new record
        ]
        result = build_period_digest(
            scope="week", key="2026-04-20", period="2026-04-20 to 2026-04-26",
            articles=ARTICLES, ban_records=[],
            container=existing, max_entries=cap, built_at="t",
        )
        self.assertEqual(len(result), cap)
        # Output is newest-first; the existing newest record survives the cap
        self.assertEqual([w["week_start"] for w in result],
                         ["2026-05-07", "2026-05-06", "2026-05-05"])
        self.assertEqual(result[0]["week_start"], "2026-05-07")
        self.assertNotIn("2026-04-20", [w["week_start"] for w in result])


class BuildPeriodDigestMonthlyYearlyTests(unittest.TestCase):
    def test_month_record_fields_and_cap(self):
        cap = 24  # MAX_MONTHLY
        # Seed a full container (newest-first): 2025-12..2025-01, 2024-12..2024-01
        existing = [
            {"month": f"{y}-{m:02d}", "period": "p", "built_at": "t",
             "articles": [{"headline": f"old{y}-{m:02d}"}]}
            for y in (2025, 2024)
            for m in range(12, 0, -1)
        ]
        self.assertEqual(len(existing), cap)
        result = build_period_digest(
            scope="month", key="2026-01", period="January 2026", articles=ARTICLES,
            container=existing, max_entries=cap, built_at="t",
        )
        self.assertEqual(len(result), cap)
        self.assertEqual(result[0]["month"], "2026-01")
        self.assertEqual(list(result[0]),
                         ["month", "period", "built_at", "articles"])
        self.assertNotIn("ban_summary", result[0])  # monthly carries no ban summary

    def test_year_record_fields_and_no_cap(self):
        container = [
            {"year": f"{y}", "built_at": "t", "articles": []}
            for y in range(2015, 2026)  # newest-first: 2025 .. 2015
        ]
        result = build_period_digest(
            scope="year", key="2025", articles=ARTICLES, container=container,
        )
        self.assertEqual(len(result), len(container) + 1)  # no cap for yearly
        self.assertEqual(result[0]["year"], "2025")
        self.assertEqual(list(result[0]), ["year", "built_at", "articles"])
        self.assertNotIn("period", result[0])
        self.assertNotIn("ban_summary", result[0])


if __name__ == "__main__":
    unittest.main()

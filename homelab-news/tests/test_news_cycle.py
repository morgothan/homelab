import asyncio
import json
import logging
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import lib
import daily
from operational_coverage import build_operational_alerts_article, select_news_issues


class _LokiResponse:
    def __init__(self, values):
        self._values = values

    def raise_for_status(self):
        return None

    def json(self):
        result = []
        if self._values:
            result.append({"stream": {"job": "test"}, "values": self._values})
        return {"data": {"result": result}}


class _LokiClient:
    def __init__(self, values):
        self.values = values

    async def get(self, _url, params):
        start = int(params["start"])
        end = int(params["end"])
        limit = int(params["limit"])
        selected = [value for value in self.values if start <= int(value[0]) <= end][:limit]
        return _LokiResponse(selected)


class LokiCollectionTests(unittest.TestCase):
    def test_saturated_windows_are_split_without_boundary_loss(self):
        values = [[str(timestamp), f"error {timestamp}"] for timestamp in range(1, 8)]
        entries, metadata = asyncio.run(lib._fetch_loki_complete(
            _LokiClient(values), "query", 1, 7, page_size=3,
        ))
        self.assertEqual([int(entry[1]) for entry in entries], list(range(1, 8)))
        self.assertEqual(len({(entry[1], entry[2]) for entry in entries}), 7)
        self.assertTrue(metadata["collection_complete"])
        self.assertGreater(metadata["split_windows"], 0)

    def test_irreducible_saturated_timestamp_is_reported_incomplete(self):
        values = [["5", f"error {number}"] for number in range(4)]
        entries, metadata = asyncio.run(lib._fetch_loki_complete(
            _LokiClient(values), "query", 5, 5, page_size=3,
        ))
        self.assertEqual(len(entries), 3)
        self.assertFalse(metadata["collection_complete"])
        self.assertEqual(metadata["truncated_slices"], [{"start_ns": 5, "end_ns": 5}])


class IssueCoverageTests(unittest.TestCase):
    def test_escalations_survive_noisy_top_five_and_receive_coverage(self):
        issues = [
            {"source": f"noise-{number}", "level": "error", "count": 1000 - number,
             "message": "routine request failed"}
            for number in range(8)
        ]
        backup = {"source": "pve", "level": "error", "count": 1,
                  "message": "ERROR: Backup of VM 109 failed"}
        disk = {"source": "host", "level": "error", "count": 1,
                "message": "I/O error, dev mmcblk0, sector 42"}
        issues.extend([backup, disk])

        selected = select_news_issues(issues, limit=5)
        article = build_operational_alerts_article(issues)

        self.assertIn(backup, selected)
        self.assertIn(disk, selected)
        self.assertTrue(backup["selected_for_news"])
        self.assertEqual(backup["article_coverage"], "deterministic operational alerts")
        self.assertIn("backup failure", article["blurb"])
        self.assertIn("storage I/O error", article["blurb"])

    def test_high_volume_warning_beats_error_only_ranking(self):
        warning = {"source": "ap", "level": "warn", "count": 1566,
                   "message": "ntpd: send failed: Network unreachable"}
        selected = select_news_issues([
            {"source": f"service-{number}", "level": "error", "count": 1,
             "message": "ordinary error"}
            for number in range(10)
        ] + [warning], limit=5)
        self.assertIn(warning, selected)
        self.assertIn("sustained network outage", warning["selection_reason"])

    def test_known_benign_noise_does_not_consume_selection_slots(self):
        noise = {"source": "edge", "level": "error", "count": 5000,
                 "message": "Process stime is unknown (not an error); failed to parse"}
        useful = {"source": "dns", "level": "error", "count": 2,
                  "message": "upstream lookup failed"}
        self.assertEqual(select_news_issues([noise, useful], limit=1), [useful])


class DailyArchiveTests(unittest.TestCase):
    def test_empty_newspaper_still_archives_operational_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            today_path = os.path.join(tmp, "today.json")
            archive_dir = os.path.join(tmp, "archive")
            with open(today_path, "w", encoding="utf-8") as destination:
                json.dump({"newspaper": [], "loki_issues": [{"source": "pve"}]}, destination)
            with patch.object(daily, "TODAY_FILE", today_path), \
                 patch.object(daily, "ARCHIVE_DIR", archive_dir), \
                 patch.object(daily, "ARCHIVE_INDEX", os.path.join(archive_dir, "index.json")):
                record = daily.snapshot("2026-08-27")
            self.assertEqual(record["newspaper"], [])
            self.assertEqual(record["generation_status"], "empty")
            self.assertTrue(os.path.exists(os.path.join(archive_dir, "2026-08-27.json")))


class NewsCyclePersistenceTests(unittest.TestCase):
    def _run_cycle(self, target_file: str, generated_articles):
        empty = AsyncMock(return_value=[])
        checks = {
            "check_docker_logs": empty,
            "check_loki": empty,
            "check_fail2ban_bans": AsyncMock(return_value=([], [])),
            "check_prometheus": AsyncMock(return_value={}),
            "check_kopia": AsyncMock(return_value={}),
            "check_beszel": AsyncMock(return_value={}),
            "check_jellystat": AsyncMock(return_value={}),
            "fetch_recent_media": AsyncMock(return_value=[]),
            "get_container_status_async": AsyncMock(return_value=([], [], 0)),
            "llm_analysis": AsyncMock(return_value=None),
            "hindsight_targeted_recall": AsyncMock(return_value=""),
            "generate_newspaper": AsyncMock(return_value=generated_articles),
        }
        with (
            patch.multiple(lib, **checks),
            patch.object(lib, "UPDATES_FILE", target_file + ".updates"),
            patch.object(lib, "EVENT_LEDGER_FILE", target_file + ".events"),
            patch.object(lib, "UPDATE_DETECTION_STATE_FILE", target_file + ".update_state"),
        ):
            asyncio.run(lib.run_news_cycle(datetime.now(timezone.utc), target_file))

    def test_failed_generation_preserves_last_successful_edition(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "today.json")
            previous = {
                "built_at": "2026-08-14T12:00:00+00:00",
                "generation_status": "ok",
                "newspaper": [{"headline": "Existing", "blurb": "Still useful", "section": "City Hall"}],
            }
            with open(target, "w") as f:
                json.dump(previous, f)

            with self.assertLogs(logging.getLogger("lib"), level="WARNING"):
                self._run_cycle(target, None)

            with open(target) as f:
                result = json.load(f)
            self.assertEqual(result["newspaper"], previous["newspaper"])
            self.assertEqual(result["built_at"], previous["built_at"])
            self.assertEqual(result["generation_status"], "stale")
            self.assertIn("last_attempt_at", result)

    def test_successful_generation_replaces_edition_and_clears_stale_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "rolling.json")
            with open(target, "w") as f:
                json.dump({
                    "built_at": "2026-08-14T12:00:00+00:00",
                    "generation_status": "stale",
                    "generation_error": "LLM generation unavailable",
                    "newspaper": [{"headline": "Old", "blurb": "Old", "section": "City Hall"}],
                }, f)
            fresh = [{"headline": "Fresh", "blurb": "New", "section": "City Hall"}]

            self._run_cycle(target, fresh)

            with open(target) as f:
                result = json.load(f)
            self.assertEqual(result["newspaper"], fresh)
            self.assertEqual(result["generation_status"], "ok")
            self.assertTrue(result["loki_collection"]["collection_complete"])
            self.assertNotIn("generation_error", result)
            self.assertNotEqual(result["built_at"], "2026-08-14T12:00:00+00:00")

    def test_stale_notice_is_rendered_in_timestamp_area(self):
        today = lib.masthead_today("2026-08-14 12:00 UTC", stale=True)
        rolling = lib.masthead_rolling("2026-08-14 12:00 UTC", stale=True)
        for masthead in (today, rolling):
            self.assertIn("Generated 2026-08-14 12:00 UTC", masthead)
            self.assertIn("Update failed; showing last successful edition", masthead)


if __name__ == "__main__":
    unittest.main()

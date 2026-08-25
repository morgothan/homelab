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

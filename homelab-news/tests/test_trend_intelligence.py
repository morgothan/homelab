import asyncio
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import trend_intelligence
import web


class TrendIntelligenceTests(unittest.TestCase):
    def test_reflection_validation_rejects_unknown_evidence_and_clamps_text(self):
        result = trend_intelligence.validate_reflection({
            "overview": "Operational overview",
            "findings": [{
                "title": "Recurring issue",
                "summary": "A" * 900,
                "window": "30d",
                "direction": "persistent",
                "confidence": "high",
                "evidence_dates": ["2026-08-20", "192.0.2.1", "2026-08-20"],
            }],
            "watchlist": ["Monitor recurrence"],
        }, ["2026-08-20"])

        self.assertEqual(result["findings"][0]["evidence_dates"], ["2026-08-20"])
        self.assertEqual(result["findings"][0]["basis"], "inferred")
        self.assertEqual(len(result["findings"][0]["summary"]), 800)

    def test_reflection_parser_accepts_fenced_json_object(self):
        result = trend_intelligence._parse_reflection(
            '```json\n{"overview":"Stable","findings":[],"watchlist":[]}\n```'
        )
        self.assertEqual(result["overview"], "Stable")

    def test_reflection_parser_recovers_nested_object_after_preamble(self):
        result = trend_intelligence._parse_reflection(
            'Analysis follows:\n{"overview":"Stable","findings":[{"title":"A"}],"watchlist":[]}'
        )
        self.assertEqual(result["findings"][0]["title"], "A")

    def test_measurements_are_computed_from_archives(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_dir = os.path.join(directory, "archive")
            os.makedirs(archive_dir)
            today = trend_intelligence.datetime.now(trend_intelligence.timezone.utc).date().isoformat()
            with open(os.path.join(archive_dir, f"{today}.json"), "w", encoding="utf-8") as target:
                json.dump({"newspaper": [
                    {"headline": "One", "section": "City Hall"},
                    {"headline": "Two", "section": "Public Safety"},
                ]}, target)
            with patch.object(trend_intelligence, "ARCHIVE_DIR", archive_dir):
                measurements = trend_intelligence.build_measurements([today])

        self.assertEqual(measurements["7d"]["editions"], 1)
        self.assertEqual(measurements["7d"]["articles"], 2)
        self.assertEqual(measurements["7d"]["top_sections"][0]["articles"], 1)

    def test_failed_refresh_preserves_previous_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "trend_intelligence.json")
            with open(target, "w", encoding="utf-8") as destination:
                json.dump({"overview": "Previous"}, destination)
            with patch.object(trend_intelligence, "TREND_INTELLIGENCE_FILE", target), \
                 patch.object(trend_intelligence, "_archive_dates", return_value=["2026-08-20"]), \
                 patch.object(trend_intelligence, "reflect_on_trends", AsyncMock(return_value=None)):
                result = asyncio.run(trend_intelligence.refresh_trend_intelligence())
            with open(target, encoding="utf-8") as source:
                persisted = json.load(source)

        self.assertFalse(result)
        self.assertEqual(persisted, {"overview": "Previous"})

    def test_first_refresh_publishes_measurements_while_reflection_is_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "trend_intelligence.json")
            with patch.object(trend_intelligence, "TREND_INTELLIGENCE_FILE", target), \
                 patch.object(trend_intelligence, "_archive_dates", return_value=["2026-08-20"]), \
                 patch.object(trend_intelligence, "build_measurements", return_value={"7d": {}}), \
                 patch.object(trend_intelligence, "reflect_on_trends", AsyncMock(return_value=None)):
                result = asyncio.run(trend_intelligence.refresh_trend_intelligence())
            with open(target, encoding="utf-8") as source:
                persisted = json.load(source)

        self.assertFalse(result)
        self.assertEqual(persisted["reflection_status"], "pending")
        self.assertEqual(persisted["archive_range"]["editions"], 1)

    def test_renderer_escapes_reflection_and_links_only_validated_dates(self):
        html = web.render_trend_intelligence({
            "generated_at": "2026-08-24T12:00:00+00:00",
            "archive_range": {"editions": 10},
            "overview": "Stable <script>alert(1)</script>",
            "measurements": {"7d": {}, "30d": {}, "90d": {}},
            "findings": [{
                "title": "Storage & backups",
                "summary": "Improving <b>steadily</b>",
                "window": "30d",
                "direction": "improving",
                "confidence": "medium",
                "evidence_dates": ["2026-08-20"],
            }],
            "watchlist": ["Watch <img src=x onerror=alert(1)>"]
        })

        self.assertNotIn("<script>", html)
        self.assertNotIn("<img", html)
        self.assertIn("Stable &lt;script&gt;", html)
        self.assertIn("Storage &amp; backups", html)
        self.assertIn('href="/archive/2026-08-20"', html)


if __name__ == "__main__":
    unittest.main()

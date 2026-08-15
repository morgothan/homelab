import asyncio
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import lib
import web


class MediaEventTests(unittest.TestCase):
    def test_webhook_persists_normalized_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "media_events.json")
            with patch.object(web, "MEDIA_EVENTS_FILE", path):
                response = TestClient(web.app).post("/api/events/seerr", json={
                    "notification_type": "MEDIA_AVAILABLE",
                    "event": "Movie Request Now Available",
                    "subject": "Example Movie (2026)",
                    "message": "Requested by a viewer",
                    "movie": {"tmdbId": "123"},
                })
            self.assertEqual(response.status_code, 202)
            with open(path) as f:
                events = json.load(f)
            self.assertEqual(events[0]["event"], "Movie Request Now Available")
            self.assertEqual(events[0]["notification_type"], "MEDIA_AVAILABLE")
            self.assertEqual(events[0]["subject"], "Example Movie (2026)")

    def test_webhook_rejects_empty_payload(self):
        response = TestClient(web.app).post("/api/events/seerr", json={})
        self.assertEqual(response.status_code, 400)

    def test_load_media_events_filters_by_window(self):
        now = datetime.now(timezone.utc)
        events = [
            {"received_at": (now - timedelta(hours=1)).isoformat(), "event": "recent"},
            {"received_at": (now - timedelta(days=2)).isoformat(), "event": "old"},
            {"received_at": "invalid", "event": "broken"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "media_events.json")
            with open(path, "w") as f:
                json.dump(events, f)
            with patch.object(lib, "MEDIA_EVENTS_FILE", path):
                result = lib.load_media_events(now - timedelta(hours=12))
        self.assertEqual([event["event"] for event in result], ["recent"])

    def test_library_additions_are_one_deduplicated_story(self):
        events = [
            {"notification_type": "MEDIA_AVAILABLE", "event": "Movie Request Now Available",
             "subject": "Example Movie (2026)"},
            {"event": "Series Request Now Available", "subject": "Example Series (2025)"},
            {"event": "Movie Request Now Available", "subject": "example movie (2026)"},
            {"event": "Movie Request Automatically Approved", "subject": "Pending Movie (2026)"},
        ]
        article = lib.build_library_additions_article(events)
        self.assertEqual(article["headline"], "2 New Library Additions")
        self.assertEqual(article["section"], "Arts & Entertainment")
        self.assertIn("Example Movie (2026)", article["blurb"])
        self.assertIn("Example Series (2025)", article["blurb"])
        self.assertNotIn("Pending Movie", article["blurb"])

    def test_library_card_is_not_promoted_to_lead_story(self):
        article = lib.build_library_additions_article([
            {"notification_type": "MEDIA_AVAILABLE", "subject": "Example Movie (2026)"},
        ])
        html = lib.render_articles_html([article])
        self.assertIn("Arts &amp; Entertainment", html)
        self.assertIn("1 New Library Addition", html)
        self.assertNotIn("Lead Story", html)


if __name__ == "__main__":
    unittest.main()

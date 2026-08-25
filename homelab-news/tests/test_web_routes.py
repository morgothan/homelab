import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import web


def _write_json(path: str, data) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)


class ServicesRoutesTests(unittest.TestCase):
    def test_services_index_lists_known_services_with_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            events_path = os.path.join(tmp, "events.json")
            _write_json(events_path, [
                {"service": "traefik", "observed_at": "2026-08-24T12:00:00+00:00",
                 "event_type": "security.ban_started", "severity": "warn", "attributes": {}},
                {"service": "traefik", "observed_at": "2026-08-24T12:05:00+00:00",
                 "event_type": "security.ban_started", "severity": "warn", "attributes": {}},
                {"service": "plex", "observed_at": "2026-08-24T12:01:00+00:00",
                 "event_type": "logs.error_spike", "severity": "error", "attributes": {}},
            ])
            with patch.object(web, "EVENT_LEDGER_FILE", events_path):
                response = TestClient(web.app).get("/services")

        self.assertEqual(response.status_code, 200)
        self.assertIn("traefik", response.text)
        self.assertIn("2 events", response.text)
        self.assertIn("plex", response.text)
        self.assertIn('href="/service/traefik"', response.text)

    def test_services_index_handles_empty_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            events_path = os.path.join(tmp, "events.json")
            with patch.object(web, "EVENT_LEDGER_FILE", events_path):
                response = TestClient(web.app).get("/services")

        self.assertEqual(response.status_code, 200)
        self.assertIn("No operational events recorded yet.", response.text)

    def test_service_timeline_shows_events_for_that_service_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            events_path = os.path.join(tmp, "events.json")
            _write_json(events_path, [
                {"service": "traefik", "observed_at": "2026-08-24T12:00:00+00:00",
                 "event_type": "security.ban_started", "severity": "warn", "attributes": {"category": "http:scan"}},
                {"service": "plex", "observed_at": "2026-08-24T12:01:00+00:00",
                 "event_type": "logs.error_spike", "severity": "error", "attributes": {}},
            ])
            with patch.object(web, "EVENT_LEDGER_FILE", events_path):
                response = TestClient(web.app).get("/service/traefik")

        self.assertEqual(response.status_code, 200)
        self.assertIn("security.ban_started", response.text)
        self.assertNotIn("logs.error_spike", response.text)

    def test_service_timeline_404s_for_unknown_service(self):
        with tempfile.TemporaryDirectory() as tmp:
            events_path = os.path.join(tmp, "events.json")
            _write_json(events_path, [])
            with patch.object(web, "EVENT_LEDGER_FILE", events_path):
                response = TestClient(web.app).get("/service/nonexistent")

        self.assertEqual(response.status_code, 404)

    def test_service_timeline_links_correlated_services(self):
        with tempfile.TemporaryDirectory() as tmp:
            events_path = os.path.join(tmp, "events.json")
            _write_json(events_path, [
                {"service": "traefik", "observed_at": "2026-08-24T12:00:00+00:00",
                 "event_type": "security.ban_started", "severity": "warn", "attributes": {}},
                {"service": "plex", "observed_at": "2026-08-24T12:01:00+00:00",
                 "event_type": "application.update_detected", "severity": "info", "attributes": {}},
            ])
            with patch.object(web, "EVENT_LEDGER_FILE", events_path):
                response = TestClient(web.app).get("/service/traefik")

        self.assertIn('href="/service/plex"', response.text)


class SearchRouteTests(unittest.TestCase):
    def test_search_without_query_shows_prompt_only(self):
        response = TestClient(web.app).get("/search")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Search headlines and article text", response.text)

    def test_search_matches_current_edition_article(self):
        with tempfile.TemporaryDirectory() as tmp:
            today_path = os.path.join(tmp, "today.json")
            rolling_path = os.path.join(tmp, "rolling.json")
            archive_dir = os.path.join(tmp, "archive")
            os.makedirs(archive_dir)
            archive_index = os.path.join(archive_dir, "index.json")
            search_db = os.path.join(tmp, "search_index.db")
            _write_json(today_path, {"newspaper": [
                {"headline": "Kopia backup completes nightly", "blurb": "All snapshots verified.", "section": "Public Works"},
            ]})
            _write_json(rolling_path, {"newspaper": []})
            _write_json(archive_index, [])

            with patch.object(web, "TODAY_FILE", today_path), \
                 patch.object(web, "ROLLING_FILE", rolling_path), \
                 patch.object(web, "ARCHIVE_DIR", archive_dir), \
                 patch.object(web, "ARCHIVE_INDEX", archive_index), \
                 patch.object(web, "SEARCH_INDEX_FILE", search_db):
                response = TestClient(web.app).get("/search", params={"q": "Kopia"})

        self.assertEqual(response.status_code, 200)
        self.assertIn("Kopia backup completes nightly", response.text)

    def test_search_matches_archived_article(self):
        with tempfile.TemporaryDirectory() as tmp:
            today_path = os.path.join(tmp, "today.json")
            rolling_path = os.path.join(tmp, "rolling.json")
            archive_dir = os.path.join(tmp, "archive")
            os.makedirs(archive_dir)
            archive_index = os.path.join(archive_dir, "index.json")
            search_db = os.path.join(tmp, "search_index.db")
            _write_json(today_path, {"newspaper": []})
            _write_json(rolling_path, {"newspaper": []})
            _write_json(os.path.join(archive_dir, "2026-08-01.json"), {"newspaper": [
                {"headline": "Traefik certificate renewed", "blurb": "No action needed.", "section": "City Hall"},
            ]})
            _write_json(archive_index, [{"date": "2026-08-01"}])

            with patch.object(web, "TODAY_FILE", today_path), \
                 patch.object(web, "ROLLING_FILE", rolling_path), \
                 patch.object(web, "ARCHIVE_DIR", archive_dir), \
                 patch.object(web, "ARCHIVE_INDEX", archive_index), \
                 patch.object(web, "SEARCH_INDEX_FILE", search_db):
                response = TestClient(web.app).get("/search", params={"q": "certificate"})

        self.assertEqual(response.status_code, 200)
        self.assertIn("Traefik certificate renewed", response.text)
        self.assertIn('href="/archive/2026-08-01"', response.text)


if __name__ == "__main__":
    unittest.main()

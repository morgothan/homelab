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


class InvestigationsArchiveRouteTests(unittest.TestCase):
    def test_investigations_archive_renders_and_escapes_report_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = os.path.join(tmp, "investigations_archive.json")
            _write_json(archive_path, [{
                "id": "inv-1",
                "headline": "<script>alert('XSS')</script> headline",
                "finding": "<b>finding</b> & more",
                "confidence": "high",
                "impact": "impact with \"quotes\" & symbols",
                "next_checks": ["<script>check</script>", "plain"],
                "investigated_at": "2026-10-15T03:00:00Z",
            }])
            with patch.object(web, "INVESTIGATIONS_ARCHIVE_FILE", archive_path):
                response = TestClient(web.app).get("/investigations")

        self.assertEqual(response.status_code, 200)
        # Raw script tags must not appear.
        self.assertNotIn("<script>alert", response.text)
        self.assertNotIn("<script>check", response.text)
        # HTML-escaped forms should be present.
        self.assertIn("&lt;script&gt;", response.text)
        self.assertNotIn("<b>finding</b>", response.text)
        self.assertIn("&lt;b&gt;finding&lt;/b&gt; &amp; more", response.text)
        self.assertIn("impact with &quot;quotes&quot; &amp; symbols", response.text)
        self.assertIn("High confidence", response.text)
        self.assertIn("Latest analysis", response.text)          # newest analysis header
        self.assertIn("Investigations", response.text)           # nav label

    def test_investigations_archive_empty_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = os.path.join(tmp, "investigations_archive.json")
            _write_json(archive_path, [])
            with patch.object(web, "INVESTIGATIONS_ARCHIVE_FILE", archive_path):
                response = TestClient(web.app).get("/investigations")

        self.assertEqual(response.status_code, 200)
        self.assertIn("No investigations recorded yet", response.text)

    def test_investigations_archive_groups_duplicates_with_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = os.path.join(tmp, "investigations_archive.json")
            _write_json(archive_path, [
                {"id": "inv-a", "headline": "UniFi MQ Broker Struggles to Reach CoreDNS",
                 "finding": "the unifi mq broker fails to dial the coredns unix socket",
                 "confidence": "high", "impact": "router dns lookups degraded",
                 "evidence": [], "alternatives": [], "next_checks": [],
                 "investigated_at": "2026-10-15T16:00:00Z"},
                {"id": "inv-b", "headline": "UniFi MQ Broker Fails to Reach CoreDNS on UDM",
                 "finding": "the unifi mq broker cannot connect to coredns local socket",
                 "confidence": "high", "impact": "router dns lookups degraded",
                 "evidence": [], "alternatives": [], "next_checks": [],
                 "investigated_at": "2026-10-16T16:00:00Z"},
            ])
            with patch.object(web, "INVESTIGATIONS_ARCHIVE_FILE", archive_path):
                response = TestClient(web.app).get("/investigations")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text.count("2 occurrences"), 1)   # one count badge
        self.assertIn("2 analyses", response.text)                  # body meta line
        self.assertIn("earlier analysis", response.text)            # nested earlier toggle
        # both analyses are reachable in the group
        self.assertIn("fails to dial the coredns", response.text)
        self.assertIn("cannot connect to coredns local socket", response.text)


if __name__ == "__main__":
    unittest.main()

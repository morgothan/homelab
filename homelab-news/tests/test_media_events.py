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
    def test_jellyfin_recent_items_include_movies_and_episodes(self):
        now = datetime.now(timezone.utc)

        class Response:
            def __init__(self, payload):
                self.payload = payload

            def raise_for_status(self):
                pass

            def json(self):
                return self.payload

        class Client:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def get(self, url, **kwargs):
                if url.endswith("/System/Info"):
                    return Response({"Id": "server-1"})
                return Response({"Items": [
                    {"Id": "movie-1", "Type": "Movie", "Name": "Backrooms",
                     "ProductionYear": 2026, "DateCreated": now.isoformat()},
                    {"Id": "episode-1", "Type": "Episode", "Name": "Gray Goo",
                     "SeriesName": "Silo", "ParentIndexNumber": 3, "IndexNumber": 8,
                     "DateCreated": (now - timedelta(days=1)).isoformat()},
                    {"Id": "old", "Type": "Movie", "Name": "Old Movie",
                     "DateCreated": (now - timedelta(days=8)).isoformat()},
                ]})

        with patch.object(lib, "JELLYFIN_URL", "http://jellyfin"), \
             patch.object(lib, "JELLYFIN_KEY", "key"), \
             patch.object(lib, "RADARR_URL", ""), \
             patch.object(lib, "RADARR_API_KEY", ""), \
             patch.object(lib, "SONARR_URL", ""), \
             patch.object(lib, "SONARR_API_KEY", ""), \
             patch.object(lib, "SEERR_SETTINGS_FILE", ""), \
             patch.object(lib.httpx, "AsyncClient", Client):
            events = asyncio.run(lib.fetch_recent_media(now - timedelta(days=7)))

        self.assertEqual(
            [event["subject"] for event in events],
            ["Backrooms (2026)", "Silo S03E08 — Gray Goo"],
        )
        self.assertEqual(events[0]["item_id"], "movie-1")
        self.assertEqual(events[0]["server_id"], "server-1")

    def test_arr_history_excludes_upgrades_and_deduplicates_redownloads(self):
        now = datetime.now(timezone.utc)
        initial = (now - timedelta(days=2)).isoformat()
        redownload = (now - timedelta(days=1)).isoformat()
        upgrade = now.isoformat()

        class Response:
            def raise_for_status(self):
                pass

            def json(self):
                return {"records": [
                    {"eventType": "downloadFolderImported", "date": upgrade,
                     "movieId": 1, "movie": {"title": "Backrooms", "year": 2026}},
                    {"eventType": "movieFileDeleted", "date": upgrade,
                     "movieId": 1, "data": {"reason": "Upgrade"}},
                    {"eventType": "downloadFolderImported", "date": redownload,
                     "movieId": 1, "movie": {"title": "Backrooms", "year": 2026}},
                    {"eventType": "downloadFolderImported", "date": initial,
                     "movieId": 1, "movie": {"title": "Backrooms", "year": 2026}},
                ]}

        class Client:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def get(self, *args, **kwargs):
                return Response()

        with patch.object(lib.httpx, "AsyncClient", Client):
            events = asyncio.run(lib._fetch_arr_history(
                "http://radarr", "key", now - timedelta(days=7), "movie",
            ))

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["subject"], "Backrooms (2026)")
        self.assertEqual(events[0]["received_at"], initial)

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

    def test_bulletin_groups_multiple_episodes_but_keeps_full_count(self):
        events = [
            {"event": "Episode Download Imported", "subject": "Shōgun S01E01 — Anjin",
             "lookup_title": "Shōgun", "media": {"mediaType": "episode"}},
            {"event": "Episode Download Imported", "subject": "Shōgun S01E02 — Servants",
             "lookup_title": "Shōgun", "media": {"mediaType": "episode"}},
            {"event": "Movie Download Imported", "subject": "Example Movie (2026)",
             "lookup_title": "Example Movie", "media": {"mediaType": "movie"}},
        ]

        article = lib.build_library_additions_article(events)

        self.assertEqual(article["headline"], "3 New Library Additions")
        self.assertIn("2 new episodes of Shōgun", article["blurb"])
        self.assertIn("Example Movie (2026)", article["blurb"])
        self.assertNotIn("Shōgun S01E01", article["blurb"])

        html = lib.render_articles_html([article])
        self.assertIn('<ul class="np-media-additions">', html)
        self.assertIn("<li>2 new episodes of Shōgun</li>", html)
        self.assertIn("<li>Example Movie (2026)</li>", html)

    def test_entertainment_list_does_not_group_episode_titles(self):
        events = [
            {"event": "Episode Download Imported", "subject": "Shōgun S01E01 — Anjin",
             "lookup_title": "Shōgun", "media": {"mediaType": "episode"}},
            {"event": "Episode Download Imported", "subject": "Shōgun S01E02 — Servants",
             "lookup_title": "Shōgun", "media": {"mediaType": "episode"}},
        ]

        html = lib.render_recent_media_html(events)

        self.assertIn("Shōgun S01E01", html)
        self.assertIn("Shōgun S01E02", html)
        self.assertNotIn("2 new episodes", html)

    def test_library_card_is_not_promoted_to_lead_story(self):
        article = lib.build_library_additions_article([
            {"notification_type": "MEDIA_AVAILABLE", "subject": "Example Movie (2026)"},
        ])
        html = lib.render_articles_html([article])
        self.assertIn("Arts &amp; Entertainment", html)
        self.assertIn("1 New Library Addition", html)
        self.assertNotIn("Lead Story", html)

    def test_library_card_is_first_in_arts_and_entertainment(self):
        articles = [
            {"headline": "City", "blurb": "Status", "section": "City Hall"},
            {"headline": "Review", "blurb": "A review", "section": "Arts & Entertainment"},
            {"headline": "Feature", "blurb": "A feature", "section": "Arts & Entertainment"},
        ]
        events = [{
            "notification_type": "MEDIA_AVAILABLE",
            "subject": "Example Movie (2026)",
        }]

        merged = lib.merge_library_additions(articles, events)

        arts = [a for a in merged if a["section"] == "Arts & Entertainment"]
        self.assertEqual(arts[0]["source"], "seerr-library-additions")
        self.assertEqual(arts[1]["headline"], "Review")

    def test_entertainment_page_starts_with_seven_day_media_list(self):
        now = datetime.now(timezone.utc)
        events = [
            {"received_at": (now - timedelta(days=1)).isoformat(),
             "notification_type": "MEDIA_AVAILABLE", "subject": "Recent Movie (2026)"},
            {"received_at": (now - timedelta(days=8)).isoformat(),
             "notification_type": "MEDIA_AVAILABLE", "subject": "Old Movie (2025)"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            events_path = os.path.join(tmp, "media_events.json")
            scan_path = os.path.join(tmp, "library_scan.json")
            with open(events_path, "w") as f:
                json.dump(events, f)
            with patch.object(lib, "MEDIA_EVENTS_FILE", events_path), \
                 patch.object(web, "LIBRARY_SCAN_FILE", scan_path), \
                 patch.object(lib, "RADARR_URL", ""), \
                 patch.object(lib, "RADARR_API_KEY", ""), \
                 patch.object(lib, "SONARR_URL", ""), \
                 patch.object(lib, "SONARR_API_KEY", ""), \
                 patch.object(lib, "SEERR_SETTINGS_FILE", ""), \
                 patch.object(lib, "JELLYFIN_URL", ""), \
                 patch.object(lib, "JELLYFIN_KEY", ""):
                response = TestClient(web.app).get("/entertainment")

        self.assertEqual(response.status_code, 200)
        html = response.text
        self.assertIn("Recent Movie (2026)", html)
        self.assertNotIn("Old Movie (2025)", html)
        self.assertLess(html.index("New Media &mdash; Past 7 Days"),
                        html.index("Media Library Report"))

    def test_recent_media_title_links_to_jellyfin_when_resolved(self):
        events = [{"notification_type": "MEDIA_AVAILABLE", "subject": "A & B (2026)"}]
        url = "https://jellyfin.example/web/#/details?id=item&serverId=server"

        html = lib.render_recent_media_html(events, {"A & B (2026)": url})

        self.assertIn('href="https://jellyfin.example/web/#/details?id=item&amp;serverId=server"', html)
        self.assertIn("A &amp; B (2026)</a>", html)


if __name__ == "__main__":
    unittest.main()

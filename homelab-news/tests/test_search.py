import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from search import ensure_index, search_archive, search_current_articles


def _write_day(archive_dir: str, date: str, articles: list[dict]) -> None:
    with open(os.path.join(archive_dir, f"{date}.json"), "w", encoding="utf-8") as f:
        json.dump({"date": date, "newspaper": articles}, f)


def _write_index(archive_dir: str, entries: list[dict]) -> str:
    index_path = os.path.join(archive_dir, "index.json")
    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(entries, f)
    return index_path


class SearchArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.archive_dir = self.tmp.name
        self.db_path = os.path.join(self.archive_dir, "search_index.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_indexes_headline_and_finds_it_by_search(self):
        _write_day(self.archive_dir, "2026-08-01", [
            {"headline": "Traefik certificate renewed", "blurb": "No action needed.", "section": "City Hall"},
        ])
        index_path = _write_index(self.archive_dir, [{"date": "2026-08-01"}])

        ensure_index(self.db_path, self.archive_dir, index_path)
        results = search_archive(self.db_path, "certificate")

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["date"], "2026-08-01")
        self.assertIn("Traefik", results[0]["headline"])

    def test_nonmatching_query_returns_no_results(self):
        _write_day(self.archive_dir, "2026-08-01", [
            {"headline": "Traefik certificate renewed", "blurb": "No action needed.", "section": "City Hall"},
        ])
        index_path = _write_index(self.archive_dir, [{"date": "2026-08-01"}])

        ensure_index(self.db_path, self.archive_dir, index_path)

        self.assertEqual(search_archive(self.db_path, "jellyfin"), [])

    def test_empty_query_returns_no_results(self):
        index_path = _write_index(self.archive_dir, [])
        ensure_index(self.db_path, self.archive_dir, index_path)

        self.assertEqual(search_archive(self.db_path, "   "), [])

    def test_missing_index_returns_no_results_without_error(self):
        self.assertEqual(search_archive(self.db_path, "anything"), [])

    def test_query_with_quote_characters_does_not_raise(self):
        index_path = _write_index(self.archive_dir, [])
        ensure_index(self.db_path, self.archive_dir, index_path)

        results = search_archive(self.db_path, 'plex" OR 1=1 --')

        self.assertEqual(results, [])

    def test_stale_index_is_rebuilt_after_new_archive_day(self):
        _write_day(self.archive_dir, "2026-08-01", [
            {"headline": "First edition", "blurb": "", "section": "City Hall"},
        ])
        index_path = _write_index(self.archive_dir, [{"date": "2026-08-01"}])
        ensure_index(self.db_path, self.archive_dir, index_path)
        self.assertEqual(search_archive(self.db_path, "second"), [])

        _write_day(self.archive_dir, "2026-08-02", [
            {"headline": "Second edition arrives", "blurb": "", "section": "City Hall"},
        ])
        index_path = _write_index(self.archive_dir, [{"date": "2026-08-02"}, {"date": "2026-08-01"}])
        os.utime(index_path, (os.path.getmtime(self.db_path) + 5, os.path.getmtime(self.db_path) + 5))

        ensure_index(self.db_path, self.archive_dir, index_path)

        self.assertEqual(len(search_archive(self.db_path, "second")), 1)


class SearchCurrentArticlesTests(unittest.TestCase):
    def test_matches_are_case_insensitive_across_fields(self):
        articles = [
            {"headline": "Backup completes", "blurb": "Kopia finished nightly snapshot.", "section": "Public Works"},
            {"headline": "Unrelated", "blurb": "Nothing here.", "section": "Weather"},
        ]
        self.assertEqual(len(search_current_articles(articles, "KOPIA")), 1)

    def test_empty_query_returns_no_results(self):
        articles = [{"headline": "Backup completes", "blurb": "", "section": "Public Works"}]
        self.assertEqual(search_current_articles(articles, ""), [])


if __name__ == "__main__":
    unittest.main()

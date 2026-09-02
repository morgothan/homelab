import asyncio
import json
import logging
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import articles
import config
import lib
import runtime
import storage
from homelab_news.capabilities import configured_capabilities
from homelab_news.configuration import load_settings


class ConfigurationTests(unittest.TestCase):
    def test_remote_hosts_accept_explicit_and_inferred_labels(self):
        self.assertEqual(
            config.parse_remote_hosts(
                "compute=ssh://monitor@compute.example.invalid,tcp-host:2375"
            ),
            [
                ("compute", "ssh://monitor@compute.example.invalid"),
                ("tcp-host", "tcp://tcp-host:2375"),
            ],
        )

    def test_toml_feature_policy_and_environment_override(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "config.toml")
            with open(path, "w", encoding="utf-8") as destination:
                destination.write("[features]\nmedia = false\nupdates = false\n")
            settings = load_settings(path, {"NEWS_FEATURE_MEDIA": "true"})
        self.assertTrue(settings.features.media)
        self.assertFalse(settings.features.updates)
        self.assertTrue(settings.features.loki)

    def test_unknown_feature_configuration_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "config.toml")
            with open(path, "w", encoding="utf-8") as destination:
                destination.write("[features]\ntelepathy = true\n")
            with self.assertRaisesRegex(ValueError, "unknown feature"):
                load_settings(path, {})

    def test_capability_report_contains_no_connection_configuration(self):
        settings = load_settings("/does/not/exist", {"NEWS_FEATURE_LOKI": "false"})
        report = configured_capabilities(settings.features)
        self.assertFalse(report["loki"]["enabled"])
        self.assertEqual(set(report["loki"]), {"name", "enabled", "healthy", "detail"})


class StorageTests(unittest.TestCase):
    def test_round_trip_is_atomic_and_preserves_unicode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "nested", "state.json")
            storage.save_json(path, {"headline": "Shōgun"})
            self.assertEqual(storage.load_json(path), {"headline": "Shōgun"})
            self.assertFalse(os.path.exists(f"{path}.tmp"))

    def test_invalid_json_is_reported_and_returns_none(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "invalid.json")
            with open(path, "w", encoding="utf-8") as destination:
                destination.write("{")
            with self.assertLogs(storage.log, logging.WARNING):
                self.assertIsNone(storage.load_json(path))


class ArticleContractTests(unittest.TestCase):
    def test_untrusted_articles_are_bounded_and_normalized(self):
        raw = [
            {"headline": "h" * 250, "blurb": "b" * 700, "section": "Unknown"},
            "not an article",
        ]
        result = articles.validate_articles(raw)
        self.assertEqual(len(result), 1)
        self.assertEqual(len(result[0]["headline"]), 200)
        self.assertEqual(len(result[0]["blurb"]), 600)
        self.assertEqual(result[0]["section"], "City Hall")

    def test_fenced_model_response_is_parsed(self):
        parsed = articles.parse_llm_json(
            '```json\n[{"headline":"Status","blurb":"Good"}]\n```'
        )
        self.assertEqual(parsed[0]["headline"], "Status")


class SemverTagTests(unittest.TestCase):
    """A tag with a non-numeric suffix ('3.4.4-alpine') must only ever be
    compared against tags carrying the same suffix — the bare '3.4.4' variant
    is a different image, not a downgrade or upgrade. Regression: edge-gateway's
    haproxy:3.4.4-alpine was reported as an update to '3.4.4' every hour."""

    def _best(self, current, tags):
        pat = lib._semver_tag_pattern(current)
        matching = [t for t in tags if pat and pat.match(t)]
        if not matching:
            return None
        best = max(matching, key=lib._semver_sort_key)
        return best if lib._semver_sort_key(best) > lib._semver_sort_key(current) else None

    def test_suffix_tag_ignores_bare_variant(self):
        self.assertIsNone(self._best("3.4.4-alpine", ["3.4.4", "3.4.4-alpine", "3.0.5"]))

    def test_suffix_tag_tracks_same_suffix_bump(self):
        self.assertEqual(
            self._best("3.4.4-alpine", ["3.4.4", "3.4.5-alpine", "3.4.4-alpine"]),
            "3.4.5-alpine",
        )

    def test_plain_semver_still_bumps(self):
        self.assertEqual(self._best("v3.4.4", ["v3.4.4", "v3.5.0", "latest"]), "v3.5.0")
        self.assertIsNone(self._best("v3.5.0", ["v3.4.4", "v3.5.0"]))

    def test_sort_key_ignores_suffix(self):
        self.assertEqual(lib._semver_sort_key("3.4.4-alpine"), (3, 4, 4))


class RuntimeTests(unittest.TestCase):
    def test_nonpositive_interval_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "positive"):
            asyncio.run(runtime.run_loop(AsyncMock(), 0))

    def test_worker_failure_is_logged_before_next_iteration(self):
        function = AsyncMock(side_effect=RuntimeError("temporary"))
        logger = logging.getLogger("runtime-test")
        with patch.object(runtime.asyncio, "sleep", AsyncMock(side_effect=StopAsyncIteration)):
            with self.assertLogs(logger, logging.ERROR) as captured:
                with self.assertRaises(StopAsyncIteration):
                    asyncio.run(runtime.run_loop(function, 60, logger))
        self.assertIn("Run failed", captured.output[0])


if __name__ == "__main__":
    unittest.main()

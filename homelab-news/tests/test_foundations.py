import asyncio
import json
import logging
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import articles
import config
import runtime
import storage


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

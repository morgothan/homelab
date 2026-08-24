import asyncio
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import lib
from correlations import (
    append_events,
    build_cycle_events,
    correlate_events,
    normalize_service,
    record_container_transitions,
    targeted_recall_queries,
)


class CorrelationTests(unittest.TestCase):
    def test_log_collection_preserves_observation_window(self):
        issues, counts = lib._collect_issues("traefik", [
            ("2026-08-24T12:00:00+00:00", "ERROR backend connection failed"),
            ("2026-08-24T12:02:00+00:00", "ERROR backend connection failed"),
        ])

        self.assertEqual(counts[issues[0]["_key"]], 2)
        self.assertEqual(issues[0]["first_seen"], "2026-08-24T12:00:00+00:00")
        self.assertEqual(issues[0]["last_seen"], "2026-08-24T12:02:00+00:00")

    def test_aliases_normalize_to_shared_service(self):
        self.assertEqual(normalize_service("edge-gateway"), "traefik")
        self.assertEqual(normalize_service("Traefik"), "traefik")

    def test_update_detection_and_error_spike_correlate_without_claiming_cause(self):
        observed = "2026-08-24T12:02:00+00:00"
        events = build_cycle_events(
            docker_issues=[{
                "source": "traefik",
                "level": "error",
                "message": "backend failures",
                "count": 8,
                "first_seen": "2026-08-24T12:01:00+00:00",
                "last_seen": observed,
            }],
            loki_issues=[],
            bans=[],
            update_hosts={"local": {
                "ts": "2026-08-24T12:00:00+00:00",
                "results": [{
                    "container": "edge-gateway",
                    "status": "update_available",
                    "new_version": "v3.6",
                }],
            }},
            observed_at=observed,
        )

        matches = correlate_events(events)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["service"], "traefik")
        self.assertFalse(matches[0]["causation_confirmed"])
        self.assertEqual(matches[0]["minutes_apart"], 2.0)

    def test_different_services_do_not_correlate(self):
        events = build_cycle_events(
            docker_issues=[{"source": "loki", "level": "error", "count": 5}],
            loki_issues=[],
            bans=[],
            update_hosts={"local": {
                "ts": "2026-08-24T12:00:00+00:00",
                "results": [{"container": "traefik", "status": "update_available"}],
            }},
            observed_at="2026-08-24T12:01:00+00:00",
        )
        self.assertEqual(correlate_events(events), [])

    def test_targeted_recall_names_service_and_relevant_history(self):
        event = {
            "service": "traefik",
            "severity": "error",
            "event_type": "logs.error_spike",
        }
        queries = targeted_recall_queries([event], [])
        self.assertEqual(len(queries), 1)
        self.assertIn("Past traefik updates", queries[0])
        self.assertIn("configuration changes", queries[0])
        self.assertIn("logs.error_spike", queries[0])

    def test_event_ledger_deduplicates_events(self):
        event = {
            "event_id": "stable",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "event_type": "logs.error_observed",
            "service": "traefik",
            "source": "docker",
            "severity": "warn",
            "attributes": {},
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "events.json")
            append_events(path, [event])
            retained = append_events(path, [event])
        self.assertEqual(len(retained), 1)

    def test_container_transition_requires_a_prior_image_identity(self):
        first = {"local": {"ts": "2026-08-24T12:00:00+00:00", "results": [{
            "container": "traefik", "_local_digests": ["sha256:old"],
        }]}}
        second = {"local": {"ts": "2026-08-24T12:05:00+00:00", "results": [{
            "container": "traefik", "_local_digests": ["sha256:new"],
        }]}}
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "container_state.json")
            self.assertEqual(record_container_transitions(first, path, ""), [])
            events = record_container_transitions(second, path, "")

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "container.image_changed")
        self.assertEqual(events[0]["service"], "traefik")
        self.assertNotIn("_local_digests", second["local"]["results"][0])


class TargetedRecallTests(unittest.TestCase):
    def test_targeted_recall_deduplicates_and_caches_queries(self):
        lib._TARGETED_RECALL_CACHE.clear()
        recall = AsyncMock(side_effect=["first", "second"])
        with patch.object(lib, "hindsight_recall", recall):
            result = asyncio.run(lib.hindsight_targeted_recall(["traefik", "traefik", "loki"]))
            cached = asyncio.run(lib.hindsight_targeted_recall(["traefik", "loki"]))

        self.assertEqual(result, "first\nsecond")
        self.assertEqual(cached, result)
        self.assertEqual(recall.await_count, 2)


if __name__ == "__main__":
    unittest.main()

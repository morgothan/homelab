"""Tests for infrastructure collectors (Beszel host records and OOM events)."""

import asyncio
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import config
from homelab_news.collectors import monitoring
from homelab_news.configuration import BeszelSettings


def _response(payload):
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = payload
    return response


def _beszel_client(systems):
    client = MagicMock()
    client.post = AsyncMock(return_value=_response({"token": "test-token"}))
    client.get = AsyncMock(return_value=_response({"items": systems}))
    context_manager = MagicMock()
    context_manager.__aenter__.return_value = client
    context_manager.__aexit__ = AsyncMock(return_value=False)
    return context_manager


class BeszelCollectorTests(unittest.TestCase):
    def _collect(self, systems, policy):
        context_manager = _beszel_client(systems)
        with (
            patch.object(monitoring.httpx, "AsyncClient", return_value=context_manager),
            patch.object(config, "BESZEL_EMAIL", "test@example.invalid"),
            patch.object(config, "BESZEL_PASS", "test-password"),
            patch.object(config, "BESZEL_URL", "http://beszel.example.invalid"),
        ):
            return asyncio.run(monitoring.check_beszel(policy))

    def test_expected_high_memory_host_is_not_a_memory_alert(self):
        result = self._collect(
            [{"name": "compute-a", "status": "up", "info": {"cpu": 11, "mp": 98, "dp": 52}}],
            BeszelSettings(expected_high_memory_hosts=("compute-a",)),
        )
        self.assertEqual(result["alerts"], [])
        self.assertEqual(result["info"], ["Beszel: all 1 hosts up, resources nominal"])

    def test_expected_host_match_is_case_insensitive(self):
        result = self._collect(
            [{"name": "COMPUTE-A", "status": "up", "info": {"cpu": 11, "mp": 98, "dp": 52}}],
            BeszelSettings(expected_high_memory_hosts=("compute-a",)),
        )
        self.assertEqual(result["alerts"], [])

    def test_non_exempt_host_high_memory_still_alerts(self):
        result = self._collect(
            [{"name": "dns-host", "status": "up", "info": {"cpu": 4, "mp": 95, "dp": 10}}],
            BeszelSettings(),
        )
        self.assertEqual(result["alerts"], ["MEMORY WARNING: dns-host: mem 95%"])

    def test_configured_memory_threshold_applies(self):
        policy = BeszelSettings(memory_warn_pct=99.0)
        below = self._collect(
            [{"name": "dns-host", "status": "up", "info": {"cpu": 4, "mp": 98, "dp": 10}}],
            policy,
        )
        above = self._collect(
            [{"name": "dns-host", "status": "up", "info": {"cpu": 4, "mp": 99.1, "dp": 10}}],
            policy,
        )
        self.assertEqual(below["alerts"], [])
        self.assertEqual(above["alerts"], ["MEMORY WARNING: dns-host: mem 99%"])

    def test_exempt_host_still_reports_down_and_disk(self):
        result = self._collect(
            [
                {"name": "compute-a", "status": "down", "info": {"mp": 98, "dp": 10}},
                {"name": "compute-b", "status": "up", "info": {"mp": 96, "dp": 95}},
            ],
            BeszelSettings(expected_high_memory_hosts=("compute-a", "compute-b")),
        )
        self.assertEqual(
            result["alerts"],
            ["HOST DOWN: compute-a (down)", "DISK WARNING: compute-b: disk 95%"],
        )

    def test_missing_memory_value_is_not_alerted(self):
        result = self._collect(
            [{"name": "new-host", "status": "up", "info": {"cpu": 1, "mp": None, "dp": 1}}],
            BeszelSettings(),
        )
        self.assertEqual(result["alerts"], [])


def _prom_query(counters):
    async def query(_client, _statement):
        return [
            {"metric": {"instance": instance}, "value": ["0", str(value)]}
            for instance, value in counters.items()
        ]

    return query


def _ssh_run(outputs):
    async def run(host, _command, timeout=45):
        return outputs.get(host, (True, ""))

    return run


class OomCollectorTests(unittest.TestCase):
    HOST1 = "monitor@compute-a.example.invalid"
    HOST2 = "monitor@compute-b.example.invalid"

    def _run(self, state_path, counters, outputs):
        with (
            patch.object(config, "SPARK_SSH_HOST", self.HOST1),
            patch.object(config, "SPARK2_SSH_HOST", self.HOST2),
        ):
            return asyncio.run(monitoring.check_oom(
                state_file=state_path,
                prom_query=_prom_query(counters),
                ssh_runner=_ssh_run(outputs),
            ))

    def _state(self, path):
        with open(path, encoding="utf-8") as source:
            return json.load(source)

    def test_kernel_oom_increase_alerts_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "oom.json")
            with open(path, "w", encoding="utf-8") as destination:
                json.dump({"kernel": {"compute-a.example.invalid:9100": 0}, "earlyoom": {}}, destination)

            first = self._run(path, {"compute-a.example.invalid:9100": 2}, {})
            second = self._run(path, {"compute-a.example.invalid:9100": 2}, {})
            state = self._state(path)

        self.assertEqual(
            first["alerts"],
            ["KERNEL OOM KILL: compute-a.example.invalid:9100 — 2 process(es) killed"],
        )
        self.assertEqual(second["alerts"], [])
        self.assertEqual(state["kernel"]["compute-a.example.invalid:9100"], 2)

    def test_kernel_counter_reset_is_not_an_alert(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "oom.json")
            with open(path, "w", encoding="utf-8") as destination:
                json.dump({"kernel": {"compute-a.example.invalid:9100": 5}, "earlyoom": {}}, destination)

            result = self._run(path, {"compute-a.example.invalid:9100": 0}, {})
            state = self._state(path)

        self.assertEqual(result["alerts"], [])
        self.assertEqual(state["kernel"]["compute-a.example.invalid:9100"], 0)

    def test_earlyoom_sigterm_is_alerted_and_cursor_advances(self):
        event_at = datetime.strptime(
            "2026-10-27T10:00:00+0000", "%Y-%m-%dT%H:%M:%S%z"
        ).timestamp()
        output = (
            "2026-10-27T10:00:00+0000 compute-1 earlyoom[1234]: sending SIGTERM to "
            "process 5678 uid 0 \"python\": badness 120, VmRSS 4096 MiB\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "oom.json")
            with open(path, "w", encoding="utf-8") as destination:
                json.dump(
                    {"kernel": {}, "earlyoom": {self.HOST1: event_at - 10}},
                    destination,
                )

            result = self._run(
                path, {}, {self.HOST1: (True, output), self.HOST2: (True, "")}
            )
            state = self._state(path)

        self.assertEqual(
            result["alerts"],
            ["EARLYOOM SIGTERM: compute-a.example.invalid — pid 5678, uid 0, python, RSS 4096 MiB"],
        )
        self.assertGreater(state["earlyoom"][self.HOST1], event_at)

    def test_earlyoom_historical_event_on_first_run_is_not_alerted(self):
        output = (
            "2026-10-27T10:00:00+0000 compute-1 earlyoom[1234]: sending SIGKILL to "
            "process 5678 uid 0 \"python\": badness 120, VmRSS 4096 MiB\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "oom.json")
            result = self._run(
                path, {}, {self.HOST1: (True, output), self.HOST2: (True, "")}
            )
            state = self._state(path)

        self.assertEqual(result["alerts"], [])
        self.assertIn(self.HOST1, state["earlyoom"])

    def test_ssh_failure_does_not_advance_cursor(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "oom.json")
            with open(path, "w", encoding="utf-8") as destination:
                json.dump(
                    {"kernel": {}, "earlyoom": {self.HOST1: 1000.0}},
                    destination,
                )

            result = self._run(
                path, {}, {self.HOST1: (False, "timeout"), self.HOST2: (True, "")}
            )
            state = self._state(path)

        self.assertEqual(result["alerts"], [])
        self.assertEqual(state["earlyoom"][self.HOST1], 1000.0)

    def test_no_kernel_rows_preserves_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "oom.json")
            with open(path, "w", encoding="utf-8") as destination:
                json.dump({"kernel": {"compute-a.example.invalid:9100": 3}, "earlyoom": {}}, destination)

            result = self._run(path, {}, {})
            state = self._state(path)

        self.assertEqual(result["alerts"], [])
        self.assertEqual(state["kernel"]["compute-a.example.invalid:9100"], 3)


if __name__ == "__main__":
    unittest.main()

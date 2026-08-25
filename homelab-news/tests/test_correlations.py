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
    service_correlation_counts,
    targeted_recall_queries,
)


def _evt(service: str, observed_at: str, event_type: str = "logs.error_observed") -> dict:
    return {
        "event_id": f"{service}-{observed_at}-{event_type}",
        "observed_at": observed_at,
        "event_type": event_type,
        "service": service,
        "source": "docker",
        "severity": "warn",
        "attributes": {},
    }


class CorrelationTests(unittest.TestCase):
    def test_cloudflared_client_cancellation_is_noise(self):
        messages = [
            'ERR error="Incoming request ended abruptly: context canceled" '
            'connIndex=1 event=1 ingressRule=56 originService=https://traefik',
            'ERR failed to serve incoming request error="Failed to proxy HTTP: '
            'Incoming request ended abruptly: context canceled"',
        ]

        issues, _ = lib._collect_issues("cf-tunnel-blue", messages)

        self.assertEqual(issues, [])

    def test_cloudflared_connection_loss_remains_alertable(self):
        message = (
            'WRN Serve tunnel error error="connection with edge closed" '
            'connIndex=1 event=0'
        )

        issues, _ = lib._collect_issues("cf-tunnel-blue", [message])

        self.assertEqual(len(issues), 1)

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

    def test_replica_suffixes_still_collapse_to_the_base_service(self):
        self.assertEqual(normalize_service("traefik-blue"), "traefik")
        self.assertEqual(normalize_service("traefik-1"), "traefik")

    def test_ipv4_addresses_are_not_truncated_by_suffix_stripping(self):
        self.assertEqual(normalize_service("172.18.0.1"), "172.18.0.1")
        self.assertEqual(normalize_service("172.18.0.2"), "172.18.0.2")
        self.assertNotEqual(normalize_service("172.18.0.1"), normalize_service("172.18.0.2"))

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


class NetworkGearLogNoiseTests(unittest.TestCase):
    def test_udm_short_lived_process_stat_race_is_noise(self):
        message = (
            "ubios-udapi-server[2143]: process: Process' stime is unknown "
            "(not an error); failed to parse /proc/919352/stat: Short read"
        )
        issues, _ = lib._collect_issues("edge-udm-pro-max", [message])
        self.assertEqual(issues, [])

    def test_ap_garp_netlink_resource_busy_is_noise(self):
        message = "wevent[7643]: garp.get_ipv4_by_mac(): Netlink error response: Resource busy"
        issues, _ = lib._collect_issues("backyard-u7prooutdoor", [message])
        self.assertEqual(issues, [])

    def test_sip_registration_success_logged_as_error_is_noise(self):
        message = (
            "USER.INFO [00:00:00:00:00:00][1.0.3.25][869254208] "
            "SigControl(performRegistration):5242:Register transaction got error: "
            "No Error, code:200, retry after: 0"
        )
        issues, _ = lib._collect_issues("172.18.0.1", [message])
        self.assertEqual(issues, [])

    def test_mcad_retry_chatter_is_noise(self):
        messages = [
            "mca-ctrl[908924]: mca-proto.service_json(): failed to contact mcad",
            "mca-ctrl[908924]: mca-monitor.mca_control_main(): service_json event fail, retry (35 sec left)",
        ]
        issues, _ = lib._collect_issues("edge-udm-pro-max", messages)
        self.assertEqual(issues, [])

    def test_dhcp_probe_start_event_is_noise(self):
        message = (
            "mcad[5162]: probe-runner.probe_runner_dispatch(): [dhcpv6] start "
            "ifname=eth8 timeout=10 req=2f99add0-965c-4410-b7e7-15c4"
        )
        issues, _ = lib._collect_issues("edge-udm-pro-max", [message])
        self.assertEqual(issues, [])

    def test_smartctl_unsupported_device_is_noise(self):
        message = 'beszel-agent[4276]: 2026/08/25 16:45:26 INFO smartctl failed device=/dev/sda err="exit status 2"'
        issues, _ = lib._collect_issues("edge-udm-pro-max", [message])
        self.assertEqual(issues, [])

    def test_smartctl_failure_with_other_exit_status_remains_alertable(self):
        message = 'beszel-agent[4276]: 2026/08/25 16:45:26 INFO smartctl failed device=/dev/sda err="exit status 4"'
        issues, _ = lib._collect_issues("edge-udm-pro-max", [message])
        self.assertEqual(len(issues), 1)

    def test_wifi_soft_fail_association_telemetry_is_noise(self):
        message = (
            'stahtd[6247]: [STA-TRACKER].stahtd_dump_event(): {"op":"event",'
            '"message_type":"STA_ASSOC_TRACKER","event_type":"soft fail"}'
        )
        issues, _ = lib._collect_issues("upstairs-u7-pro", [message])
        self.assertEqual(issues, [])

    def test_dhcp_probe_explicit_failure_remains_alertable(self):
        message = "mcad[5162]: probe-runner.probe_runner_dispatch(): [dhcpv6] failed ifname=eth8"
        issues, _ = lib._collect_issues("edge-udm-pro-max", [message])
        self.assertEqual(len(issues), 1)

    def test_unrelated_registration_failure_remains_alertable(self):
        message = (
            "SigControl(performRegistration):5242:Register transaction got error: "
            "Request Timeout, code:408, retry after: 30"
        )
        issues, _ = lib._collect_issues("172.18.0.1", [message])
        self.assertEqual(len(issues), 1)


class ServiceCorrelationGraphTests(unittest.TestCase):
    def test_different_services_within_window_are_counted(self):
        events = [
            _evt("traefik", "2026-08-24T12:00:00+00:00"),
            _evt("plex", "2026-08-24T12:05:00+00:00"),
        ]
        pairs = service_correlation_counts(events)
        self.assertEqual(pairs, [{"service_a": "plex", "service_b": "traefik", "count": 1}])

    def test_same_service_pairs_are_excluded(self):
        events = [
            _evt("traefik", "2026-08-24T12:00:00+00:00"),
            _evt("traefik", "2026-08-24T12:01:00+00:00"),
        ]
        self.assertEqual(service_correlation_counts(events), [])

    def test_events_outside_window_are_not_counted(self):
        events = [
            _evt("traefik", "2026-08-24T12:00:00+00:00"),
            _evt("plex", "2026-08-24T12:15:00+00:00"),
        ]
        self.assertEqual(service_correlation_counts(events, window_minutes=10), [])

    def test_pairs_are_ranked_by_count_descending(self):
        events = [
            _evt("traefik", "2026-08-24T12:00:00+00:00"),
            _evt("plex", "2026-08-24T12:01:00+00:00"),
            _evt("traefik", "2026-08-25T12:00:00+00:00"),
            _evt("plex", "2026-08-25T12:01:00+00:00"),
            _evt("traefik", "2026-08-26T12:00:00+00:00"),
            _evt("postgres", "2026-08-26T12:01:00+00:00"),
        ]
        pairs = service_correlation_counts(events)
        self.assertEqual(pairs[0], {"service_a": "plex", "service_b": "traefik", "count": 2})
        self.assertEqual(pairs[1], {"service_a": "postgres", "service_b": "traefik", "count": 1})

    def test_same_day_repeated_cooccurrences_count_once(self):
        events = [
            _evt("traefik", f"2026-08-24T12:0{i}:00+00:00")
            for i in range(5)
        ] + [
            _evt("plex", f"2026-08-24T12:0{i}:30+00:00")
            for i in range(5)
        ]
        pairs = service_correlation_counts(events)
        self.assertEqual(pairs, [{"service_a": "plex", "service_b": "traefik", "count": 1}])

    def test_max_pairs_caps_results(self):
        events = []
        for i in range(5):
            events.append(_evt(f"svc{i}a", f"2026-08-24T12:0{i}:00+00:00"))
            events.append(_evt(f"svc{i}b", f"2026-08-24T12:0{i}:30+00:00"))
        pairs = service_correlation_counts(events, max_pairs=2)
        self.assertEqual(len(pairs), 2)


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

import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import containers
import llm
import privacy
import security
import ssh_transport
import storage
import web
import webhooks


class RedactionTests(unittest.TestCase):
    """LLM message redaction before dispatch (headroom compression was retired)."""

    def test_redacts_credentials_inside_message_content(self):
        messages = [
            {"role": "system", "content": "you are the desk editor"},
            {"role": "user", "content": "endpoint=postgres password=xK9!q2zZ api_key=sk-live-1234"},
        ]
        redacted = llm._redact_messages(messages)
        content = redacted[1]["content"]
        self.assertNotIn("xK9!q2zZ", content)
        self.assertNotIn("sk-live-1234", content)
        self.assertIn("password", content)  # key remains, value redacted
        self.assertEqual(redacted[0]["content"], "you are the desk editor")  # shape preserved

    def test_no_credentials_passes_through_unchanged(self):
        messages = [{"role": "user", "content": "plain homelab update text"}]
        redacted = llm._redact_messages(messages)
        self.assertEqual(redacted, messages)
        self.assertIsNot(redacted, messages)  # defensive: new list, never shared ref


class WebhookSecurityTests(unittest.TestCase):
    def test_missing_wrong_and_unconfigured_credentials_cannot_write(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            web, "MEDIA_EVENTS_FILE", os.path.join(directory, "events.json")
        ) as path:
            client = TestClient(web.app)
            for expected, supplied, status in [
                ("Bearer test-secret", "", 401),
                ("Bearer test-secret", "Bearer wrong", 401),
                ("", "Bearer test-secret", 503),
            ]:
                with patch.object(webhooks, "webhook_authorization", return_value=expected):
                    response = client.post("/api/events/seerr", json={"event": "forged"},
                                           headers={"Authorization": supplied})
                self.assertEqual(response.status_code, status)
            self.assertFalse(os.path.exists(path))

    def test_streamed_body_limit_without_content_length(self):
        async def exercise():
            sent = False
            async def receive():
                nonlocal sent
                chunk = b"x" * (webhooks.MAX_WEBHOOK_BYTES // 2 + 1)
                more = not sent
                sent = True
                return {"type": "http.request", "body": chunk, "more_body": more}
            request = webhooks.Request({"type": "http", "headers": [
                (b"authorization", b"Bearer test-secret")
            ]}, receive)
            with self.assertRaises(webhooks.HTTPException) as caught:
                await webhooks.authenticated_payload(request)
            self.assertEqual(caught.exception.status_code, 413)
        with patch.object(webhooks, "webhook_authorization", return_value="Bearer test-secret"):
            asyncio.run(exercise())

    def test_reads_seerr_authentication_setting(self):
        with tempfile.NamedTemporaryFile(mode="w") as source:
            json.dump({"notifications": {"agents": {"webhook": {"options": {
                "authHeader": "Bearer test-secret"
            }}}}}, source)
            source.flush()
            with patch.object(webhooks, "SEERR_SETTINGS_FILE", source.name):
                self.assertEqual(webhooks.webhook_authorization(), "Bearer test-secret")


class PrivacyTests(unittest.TestCase):
    def test_credentials_removed_before_storage_inference_and_archive_display(self):
        raw = ('error password="fixture password" api_key=fixture-key '
               'Authorization: Bearer fixture-bearer https://user:fixture-pass@example.invalid/')
        issues, _ = security._collect_issues("example", [raw])
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "state.json")
            storage.save_json(path, {"message": raw, "nested": {"apiKey": "fixture-nested"}})
            with open(path) as source:
                stored = source.read()
            # An old archive must also be protected without requiring migration.
            with open(path, "w") as destination:
                json.dump({"message": raw}, destination)
            displayed = json.dumps(web.load_redacted(path))
        for output in [issues[0]["message"], llm._sanitize_for_llm(raw, 2000), stored, displayed]:
            for value in ["fixture password", "fixture-key", "fixture-bearer", "fixture-pass", "fixture-nested"]:
                self.assertNotIn(value, output)

    def test_known_secret_and_private_key_removed(self):
        with patch.object(privacy, "_KNOWN_SECRETS", ("fixture-configured-secret",)):
            self.assertNotIn("fixture-configured-secret", privacy.redact_text("oops fixture-configured-secret"))
        self.assertNotIn("private-material", privacy.redact_text(
            "-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----"))


class StartupAndTransportTests(unittest.TestCase):
    def test_media_entrypoint_configures_logging_without_running_worker(self):
        code = ('import asyncio,logging,runpy; '
                'asyncio.run=lambda coroutine: coroutine.close(); '
                'runpy.run_module("media",run_name="__main__"); '
                'assert logging.getLogger().isEnabledFor(logging.INFO); '
                'assert logging.getLogger().handlers')
        subprocess.run([sys.executable, "-c", code], check=True)

    def test_ssh_requires_trusted_hosts_and_invalid_lxc_cannot_reach_shell(self):
        args = ssh_transport.ssh_arguments()
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertTrue(any(value.startswith("UserKnownHostsFile=") for value in args))
        with self.assertRaises(ValueError):
            asyncio.run(containers.get_containers_pct("example.invalid", "1;id"))


class LogSuppressionTests(unittest.TestCase):
    """Config-driven suppression of known-benign Loki syslog noise (check_loki path)."""

    # The chronically-firing, benign UDM Pro Max fingerprint we suppress.
    FINGERPRINT = (
        '/usr/bin/unifi-mq-broker[1234]: Failed to send request to coredns: '
        'Post "http://localhost/api/get_domain_by_ip": dial unix /run/utm/.cd_dl.sock: '
        'connect: resource temporarily unavailable'
    )
    # Same broker, different (still noise-y) error: must NOT be suppressed.
    OTHER = (
        '/usr/bin/unifi-mq-broker[1234]: Failed to refresh cached map: '
        'dial tcp 10.0.0.1:53: connection refused'
    )
    TS = "2026-10-20T12:00:00Z"
    PATTERN = r'unifi-mq-broker.*\.cd_dl\.sock.*resource temporarily unavailable'

    def test_suppression_drops_matching_line_and_keeps_non_matching(self):
        lines = [(self.TS, self.FINGERPRINT), (self.TS, self.OTHER)]
        kept = security._filter_suppressed(lines, [re.compile(self.PATTERN)])
        self.assertEqual(kept, [(self.TS, self.OTHER)])

    def test_suppression_is_resilient_to_pid_changes(self):
        patterns = [re.compile(self.PATTERN)]
        self.assertTrue(security._is_suppressed(
            self.FINGERPRINT.replace("[1234]", "[987654]"), patterns))
        self.assertFalse(security._is_suppressed(self.OTHER, patterns))

    def test_empty_pattern_list_is_transparent_noop(self):
        lines = [(self.TS, self.FINGERPRINT), (self.TS, self.OTHER)]
        self.assertIs(security._filter_suppressed(lines, []), lines)

    def test_check_loki_feeds_only_unsuppressed_lines_to_collector(self):
        entries = [
            ({"host": "Edge-UDM-Pro-Max"}, "1730000000000000000", self.FINGERPRINT),
            ({"host": "Edge-UDM-Pro-Max"}, "1730000000000000000", self.OTHER),
        ]
        metadata = {"collection_complete": True, "raw_entries": len(entries),
                    "requests": 1, "split_windows": 0, "truncated_slices": []}
        captured = {}

        async def fake_fetch(client, query, start_ns, end_ns):
            return entries, metadata

        def fake_collect(source, lines):
            captured["lines"] = lines
            return [], {}

        with patch.object(security, "_fetch_loki_complete", fake_fetch), \
                patch.object(security, "_collect_issues", fake_collect), \
                patch.object(security, "_SUPPRESS_PATTERNS", [re.compile(self.PATTERN)]):
            result = asyncio.run(security.check_loki())

        self.assertEqual([line for _, line in captured["lines"]], [self.OTHER])
        self.assertEqual(result, [])


class SuppressionFileTests(unittest.TestCase):
    """LOG_SUPPRESS_FILE handling: one regex per line, '#' comments, merges with env."""

    CD_DL = r'unifi-mq-broker.*\.cd_dl\.sock.*resource temporarily unavailable'
    INOTIFY = r'dnsmasq\[[0-9]+\]: inotify: .*leases'
    UPDATE = r'dnsmasq-dhcp.*Updating leases'
    BR107 = r'dnsmasq-dhcp.*DHCP(REQUEST|ACK)\(br107\)'

    def _write(self, content: str) -> str:
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def test_file_parsing_skips_blank_and_comment_lines(self):
        path = self._write(
            "# suppress the broker->coredns fingerprint\n"
            + self.CD_DL + "\n"
            + "\n"
            + "# br107 dnsmasq churn\n"
            + self.INOTIFY + "\n"
            + self.UPDATE + "   # trailing comment stays part of the line (it will simply not match)\n"
        )
        texts = security._pattern_texts_from_file(path)
        self.assertEqual(texts[0], self.CD_DL)
        self.assertEqual(len(texts), 3)  # comment line and blank line skipped

    def test_empty_path_and_missing_file_yield_no_patterns(self):
        self.assertEqual(security._pattern_texts_from_file(""), [])
        self.assertEqual(security._pattern_texts_from_file("/no/such/file"), [])

    def test_env_and_file_patterns_are_merged(self):
        path = self._write(self.INOTIFY + "\n" + self.BR107 + "\n")
        with patch.object(security, "LOG_SUPPRESS_PATTERNS", [self.CD_DL]), \
                patch.object(security, "LOG_SUPPRESS_FILE", path):
            patterns = security._load_suppression_patterns()
        self.assertEqual(len(patterns), 3)

    def test_br107_and_fingerprint_lines_suppressed_together(self):
        path = self._write(
            self.CD_DL + "\n" + self.INOTIFY + "\n" + self.UPDATE + "\n" + self.BR107 + "\n"
        )
        with patch.object(security, "LOG_SUPPRESS_FILE", path), \
                patch.object(security, "LOG_SUPPRESS_PATTERNS", []):
            patterns = security._load_suppression_patterns()
        lines = [
            ("t", '/usr/bin/unifi-mq-broker[2796]: Failed to send request to coredns: '
                   'dial unix /run/utm/.cd_dl.sock: connect: resource temporarily unavailable'),
            ("t", 'dnsmasq[3112207]: inotify: /run/dnsmasq.dns.conf.d/hosts.d//leases new or modified'),
            ("t", 'dnsmasq[3112207]: inotify: flushed 60 names read from /run/dnsmasq.dns.conf.d/hosts.d//leases'),
            ("t", 'dnsmasq-dhcp[3854033]: Updating leases :: age=26sec file=y(0msec) dns=y(1msec)'),
            ("t", 'dnsmasq-dhcp[3854033]: DHCPACK(br107) 192.0.2.144 aa:bb:cc:dd:ee:ff iot-device'),
            ("t", 'dnsmasq-dhcp[3854033]: DHCPDECLINE(br107) 192.0.2.200 aa:bb:cc:dd:ef:ff'),
            ("t", 'kernel: wlan: mlme_recv_auth_ap_defer auth failed with status 37'),
        ]
        kept = security._filter_suppressed(lines, patterns)
        self.assertEqual(
            [line for _, line in kept],
            ['dnsmasq-dhcp[3854033]: DHCPDECLINE(br107) 192.0.2.200 aa:bb:cc:dd:ef:ff',
             'kernel: wlan: mlme_recv_auth_ap_defer auth failed with status 37'],
        )


if __name__ == "__main__":
    unittest.main()

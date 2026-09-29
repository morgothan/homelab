import asyncio
import json
import os
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
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


class CompressionTests(unittest.TestCase):
    def test_success_returns_result_messages_and_preserves_instruction_policy(self):
        original = [{"role": "user", "content": "long evidence"}]
        compressed = [{"role": "user", "content": "short evidence"}]
        with patch.object(llm, "_HEADROOM_AVAILABLE", True), patch.object(
            llm, "_headroom_compress", return_value=SimpleNamespace(messages=compressed)
        ) as compress:
            self.assertEqual(llm._compress_messages(original), compressed)
        policy = compress.call_args.kwargs["config"]
        self.assertEqual(compress.call_args.kwargs["model"], "gpt-4o")
        self.assertTrue(policy.compress_user_messages)
        self.assertFalse(policy.compress_system_messages)
        self.assertEqual(policy.protect_recent, 0)
        self.assertFalse(policy.protect_analysis_context)
        self.assertEqual(policy.kompress_model, "disabled")

    def test_failure_preserves_original(self):
        original = [{"role": "user", "content": "evidence"}]
        with patch.object(llm, "_HEADROOM_AVAILABLE", True), patch.object(
            llm, "_headroom_compress", side_effect=RuntimeError("unavailable")
        ):
            self.assertEqual(llm._compress_messages(original), original)


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
            displayed = json.dumps(web.load_json(path))
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

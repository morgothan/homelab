"""Tests for live inference-engine detection and engine-specific update checks."""

import asyncio
import json
import os
import sys
import unittest
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import updates
from templates import _SOURCE_HOWTO

_HEAD = "3529ba92"
_UPSTREAM = "fbbc97132cd004237d9887b8d3185896efaedc5c"


def _models(*entries):
    return json.dumps({"object": "list", "data": list(entries)})


def _probe(**sections):
    """Render probe output in the ``==KEY`` shape the remote script emits."""
    lines = []
    for key, value in sections.items():
        lines.append(f"=={key}")
        if value:
            lines.append(value)
    return "\n".join(lines) + "\n==END\n"


class ProbeParsingTests(unittest.TestCase):
    def test_sections_split_and_preserve_multiline_values(self):
        text = "==A\none\n==B\ntwo\nthree\n==END\n"
        self.assertEqual(
            updates._probe_sections(text),
            {"A": "one", "B": "two\nthree", "END": ""},
        )

    def test_marker_glued_to_value_is_still_split(self):
        text = '==MODELS\n{"data": []}==TF_VER\n1.0.2\n==END\n'
        sections = updates._probe_sections(text)
        self.assertEqual(sections["MODELS"], '{"data": []}')
        self.assertEqual(sections["TF_VER"], "1.0.2")

    def test_malformed_models_payload_is_not_serving(self):
        self.assertEqual(updates._model_entries("not json"), [])
        self.assertEqual(updates._model_entries(""), [])


class EngineDetectionTests(unittest.TestCase):
    def test_tensorfold_serving_is_identified_by_owned_by(self):
        result = updates._detect_inference_engine({
            "UNIT_TF": "active",
            "UNIT_VLLM": "inactive",
            "CTR_TF": "tp2-lane",
            "MODELS": _models({"id": "deepseek-v4.1-flash", "owned_by": "tensorfold"}),
        })
        self.assertEqual(result, {"engine": "tensorfold", "serving": True})

    def test_vllm_serving_is_identified_by_owned_by(self):
        result = updates._detect_inference_engine({
            "UNIT_VLLM": "active",
            "CTR_VLLM": "node_0_abc",
            "MODELS": _models({"id": "deepseek-v4-flash-0731", "owned_by": "vllm"}),
        })
        self.assertEqual(result, {"engine": "vllm", "serving": True})

    def test_both_engines_absent_is_down(self):
        result = updates._detect_inference_engine({
            "UNIT_TF": "inactive",
            "UNIT_VLLM": "inactive",
            "UNIT_VLLM_USER": "inactive",
            "MODELS": "",
        })
        self.assertEqual(result, {"engine": "", "serving": False})

    def test_active_unit_without_endpoint_is_engine_present_not_serving(self):
        result = updates._detect_inference_engine({
            "UNIT_TF": "active",
            "MODELS": "",
        })
        self.assertEqual(result, {"engine": "tensorfold", "serving": False})

    def test_unidentified_model_owner_is_serving_without_engine(self):
        result = updates._detect_inference_engine({
            "MODELS": _models({"id": "some-model", "owned_by": ""}),
        })
        self.assertEqual(result, {"engine": "", "serving": True})

    def test_endpoint_owner_wins_over_stale_unit_state(self):
        result = updates._detect_inference_engine({
            "UNIT_VLLM": "inactive",
            "UNIT_TF": "inactive",
            "MODELS": _models({"id": "deepseek-v4.1-flash", "owned_by": "tensorfold"}),
        })
        self.assertEqual(result, {"engine": "tensorfold", "serving": True})


class TensorFoldUpdateTests(unittest.TestCase):
    def test_moved_upstream_head_is_an_engine_update(self):
        entries = updates._tensorfold_update_entries({
            "TF_HEAD": _HEAD,
            "TF_UPSTREAM": _UPSTREAM,
            "TF_UPSTREAM_LOCAL": "",
        })
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["app"], "TensorFold engine")
        self.assertEqual(entries[0]["current_version"], _HEAD)
        self.assertEqual(entries[0]["new_version"], _UPSTREAM[:8])
        self.assertIn("deepseek-v41-zig", entries[0]["changelog_analysis"])

    def test_contained_upstream_commit_is_not_an_update(self):
        entries = updates._tensorfold_update_entries({
            "TF_HEAD": _HEAD,
            "TF_UPSTREAM": _UPSTREAM,
            "TF_UPSTREAM_LOCAL": "yes",
        })
        self.assertEqual(entries, [])

    def test_matching_heads_are_current(self):
        entries = updates._tensorfold_update_entries({
            "TF_HEAD": _HEAD,
            "TF_UPSTREAM": f"{_HEAD}00000000000000000000000000000000",
        })
        self.assertEqual(entries, [])

    def test_newer_kit_tag_is_an_update(self):
        entries = updates._tensorfold_update_entries({
            "KIT_TAG": "v0.6.1",
            "KIT_TAGS": "v0.6.1\nv0.7.0\nv0.7.3",
        })
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["app"], "TensorFold kit")
        self.assertEqual(entries[0]["current_version"], "v0.6.1")
        self.assertEqual(entries[0]["new_version"], "v0.7.3")

    def test_same_or_older_kit_is_current(self):
        entries = updates._tensorfold_update_entries({
            "KIT_TAG": "v0.7.3",
            "KIT_TAGS": "v0.6.1\nv0.7.0\nv0.7.3",
        })
        self.assertEqual(entries, [])

    def test_engine_and_kit_updates_combine(self):
        entries = updates._tensorfold_update_entries({
            "TF_HEAD": _HEAD,
            "TF_UPSTREAM": _UPSTREAM,
            "KIT_TAG": "v0.6.1",
            "KIT_TAGS": "v0.7.3",
        })
        self.assertEqual([entry["app"] for entry in entries],
                         ["TensorFold engine", "TensorFold kit"])


class CheckInferenceUpdateTests(unittest.TestCase):
    def _check(self, probe_text, ssh_ok=True):
        fake_ssh = AsyncMock(return_value=(ssh_ok, probe_text))
        with patch.object(updates, "ssh_run", fake_ssh), \
                patch.object(updates, "SPARK_SSH_HOST", "spark.example.invalid"):
            return asyncio.run(updates.check_inference_update())

    def test_tensorfold_digest_reports_its_own_updates(self):
        result = self._check(_probe(
            UNIT_TF="active",
            UNIT_VLLM="inactive",
            CTR_TF="tp2-lane",
            MODELS=_models({"id": "deepseek-v4.1-flash", "owned_by": "tensorfold"}),
            TF_VER="tensorfold-native 1.0.2",
            TF_HEAD=_HEAD,
            KIT_TAG="v0.6.1",
            KIT_TAGS="v0.6.1\nv0.7.3",
            TF_UPSTREAM=_UPSTREAM,
        ))
        self.assertEqual(result["status"], "done")
        self.assertEqual(result["label"], "TensorFold TP2")
        self.assertEqual(result["engine"], "tensorfold")
        self.assertIn("engine 3529ba92", result["current_version"])
        self.assertEqual([update["app"] for update in result["updates"]],
                         ["TensorFold engine", "TensorFold kit"])
        self.assertIn(result["label"], _SOURCE_HOWTO)

    def test_tensorfold_serving_without_updates_is_current(self):
        result = self._check(_probe(
            UNIT_TF="active",
            MODELS=_models({"id": "deepseek-v4.1-flash", "owned_by": "tensorfold"}),
            TF_HEAD=_HEAD,
            TF_UPSTREAM=f"{_HEAD}00000000000000000000000000000000",
        ))
        self.assertEqual(result["status"], "done")
        self.assertEqual(result["updates"], [])

    def test_vllm_reports_sparkrun_update_only(self):
        with patch.object(updates, "_pypi_version", AsyncMock(return_value="0.4.2")):
            result = self._check(_probe(
                UNIT_VLLM="active",
                CTR_VLLM="node_0_abc",
                MODELS=_models({"id": "deepseek-v4-flash-0731", "owned_by": "vllm"}),
                SPARKRUN="sparkrun, version 0.4.1",
                VLLM_BUILD="0.9.1",
            ))
        self.assertEqual(result["status"], "done")
        self.assertEqual(result["label"], "vLLM")
        self.assertEqual(result["engine"], "vllm")
        self.assertEqual(result["updates"][0]["app"], "sparkrun")
        self.assertEqual(result["updates"][0]["new_version"], "0.4.2")
        self.assertIn(result["label"], _SOURCE_HOWTO)

    def test_vllm_serving_with_unreadable_sparkrun_is_not_an_outage(self):
        result = self._check(_probe(
            UNIT_VLLM="active",
            MODELS=_models({"id": "deepseek-v4-flash-0731", "owned_by": "vllm"}),
        ))
        self.assertEqual(result["status"], "done")
        self.assertNotIn("outage", result)
        self.assertEqual(result["updates"], [])

    def test_neither_engine_running_is_the_only_both_down_report(self):
        result = self._check(_probe(
            UNIT_TF="inactive",
            UNIT_VLLM="inactive",
            UNIT_VLLM_USER="inactive",
        ))
        self.assertEqual(result["status"], "error")
        self.assertTrue(result["outage"])
        self.assertEqual(result["label"], "Inference")
        self.assertIn("neither TensorFold nor vLLM", result["error"])

    def test_tensorfold_running_without_endpoint_reports_tensorfold(self):
        result = self._check(_probe(UNIT_TF="active", CTR_TF="tp2-lane"))
        self.assertEqual(result["status"], "error")
        self.assertTrue(result["outage"])
        self.assertEqual(result["label"], "TensorFold TP2")
        self.assertTrue(result["error"].startswith("TensorFold TP2 is running"))

    def test_ssh_failure_is_a_check_failure_not_an_outage(self):
        result = self._check("", ssh_ok=False)
        self.assertEqual(result["status"], "error")
        self.assertFalse(result["outage"])
        self.assertEqual(result["label"], "Inference")

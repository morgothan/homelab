"""Unit tests for the compose parsing helpers in bin/update-images.

The remote-host semver scan reuses the same parser as the local scan, but must
not resolve ${VAR} image tags with the traefik host's OpenBao secrets: those
values can differ per host. These tests pin that contract plus the pure tag
replacement used for remote compose files.
"""

import importlib.machinery
import importlib.util
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_update_images():
    loader = importlib.machinery.SourceFileLoader(
        "update_images", str(REPO_ROOT / "bin" / "update-images")
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


COMPOSE = """\
services:
  camofox:
    image: ghcr.io/jo-inc/camofox-browser:1.14.0
  hindsight:
    image: ghcr.io/vectorize-io/hindsight:latest
  promtail:
    image: grafana/promtail:3.6.11
  env_tagged:
    image: ${CAMOFOX_TAG}
"""


class ComposeParsingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ui = _load_update_images()

    def test_parse_compose_text_keeps_literal_semver_and_skips_unresolved_vars(self):
        parsed = self.ui._parse_compose_text(COMPOSE, secrets={})

        self.assertEqual(parsed["semver"], [
            ("ghcr.io/jo-inc/camofox-browser:1.14.0", "ghcr.io/jo-inc/camofox-browser", "1.14.0"),
            ("grafana/promtail:3.6.11", "grafana/promtail", "3.6.11"),
        ])
        self.assertEqual(parsed["rolling"], [
            ("hindsight", "ghcr.io/vectorize-io/hindsight:latest"),
        ])

    def test_apply_semver_text_replaces_literal_and_quoted_refs(self):
        items = [
            ("ghcr.io/jo-inc/camofox-browser:1.14.0",
             "ghcr.io/jo-inc/camofox-browser", "1.14.0", "1.18.1"),
            ("grafana/promtail:3.6.11", "grafana/promtail", "3.6.11", "3.6.12"),
        ]
        text = (
            "  camofox:\n"
            "    image: ghcr.io/jo-inc/camofox-browser:1.14.0\n"
            "  promtail:\n"
            '    image: "grafana/promtail:3.6.11"\n'
        )

        updated, applied = self.ui._apply_semver_text(text, items)

        self.assertEqual(applied, items)
        self.assertIn("camofox-browser:1.18.1", updated)
        self.assertIn('image: "grafana/promtail:3.6.12"', updated)
        self.assertNotIn("1.14.0", updated)
        self.assertNotIn("3.6.11", updated)

    def test_apply_semver_text_leaves_absent_refs_alone(self):
        items = [("ghcr.io/jo-inc/camofox-browser:1.14.0",
                  "ghcr.io/jo-inc/camofox-browser", "1.14.0", "1.18.1")]
        text = "  camofox:\n    image: ghcr.io/jo-inc/camofox-browser:1.13.0\n"

        updated, applied = self.ui._apply_semver_text(text, items)

        self.assertEqual(applied, [])
        self.assertEqual(updated, text)


if __name__ == "__main__":
    unittest.main()

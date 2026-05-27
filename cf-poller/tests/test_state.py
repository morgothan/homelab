import json
from pathlib import Path
import pytest
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

# Patch env vars before importing app
import os
os.environ.setdefault("CF_ANALYTICS_TOKEN", "test-token")
os.environ.setdefault("CF_ZONE_ID", "test-zone")

from app import load_state, save_state


def test_load_state_missing_file(tmp_path):
    """Returns empty dict when file does not exist."""
    result = load_state(tmp_path / "state.json")
    assert result == {}


def test_load_state_corrupt_json(tmp_path):
    """Returns empty dict when file is not valid JSON."""
    p = tmp_path / "state.json"
    p.write_text("not json")
    result = load_state(p)
    assert result == {}


def test_save_and_load_roundtrip(tmp_path):
    """Saved state is identical when loaded back."""
    p = tmp_path / "state.json"
    state = {"last_firewall_ts": "2026-05-27T10:00:00Z", "foo": 42}
    save_state(state, p)
    assert load_state(p) == state


def test_save_creates_parent_dirs(tmp_path):
    """save_state creates parent directories if they don't exist."""
    p = tmp_path / "nested" / "dir" / "state.json"
    save_state({"key": "value"}, p)
    assert p.exists()
    assert json.loads(p.read_text()) == {"key": "value"}

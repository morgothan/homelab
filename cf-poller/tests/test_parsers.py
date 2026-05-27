import json
from pathlib import Path
import pytest
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

import os
os.environ.setdefault("CF_ANALYTICS_TOKEN", "test-token")
os.environ.setdefault("CF_ZONE_ID", "test-zone")

from app import (
    parse_firewall_events,
    build_loki_payload,
)

# ── Firewall event parsing ─────────────────────────────────────────────────────

FIREWALL_RESPONSE = {
    "data": {
        "viewer": {
            "zones": [
                {
                    "firewallEventsAdaptive": [
                        {
                            "action": "block",
                            "clientAsn": "12345",
                            "clientCountryName": "Russia",
                            "clientIP": "1.2.3.4",
                            "clientRequestPath": "/.env",
                            "clientRequestQuery": "",
                            "datetime": "2026-05-27T10:00:00Z",
                            "source": "waf",
                            "userAgent": "curl/7.68",
                            "ruleId": "rule-abc",
                        },
                        {
                            "action": "managed_challenge",
                            "clientAsn": "67890",
                            "clientCountryName": "China",
                            "clientIP": "5.6.7.8",
                            "clientRequestPath": "/admin",
                            "clientRequestQuery": "",
                            "datetime": "2026-05-27T10:01:00Z",
                            "source": "rateLimit",
                            "userAgent": "python-requests/2.28",
                            "ruleId": "",
                        },
                    ]
                }
            ]
        }
    }
}


def test_parse_firewall_events_returns_list():
    events = parse_firewall_events(FIREWALL_RESPONSE)
    assert len(events) == 2
    assert events[0]["action"] == "block"
    assert events[1]["clientCountryName"] == "China"


def test_parse_firewall_events_empty_zone():
    """Returns empty list when zone has no events."""
    response = {"data": {"viewer": {"zones": [{"firewallEventsAdaptive": []}]}}}
    assert parse_firewall_events(response) == []


def test_parse_firewall_events_bad_shape():
    """Returns empty list on unexpected response structure."""
    assert parse_firewall_events({}) == []
    assert parse_firewall_events({"data": {}}) == []


def test_build_loki_payload_structure():
    events = parse_firewall_events(FIREWALL_RESPONSE)
    payload = build_loki_payload(events)

    assert "streams" in payload
    assert len(payload["streams"]) == 1
    stream = payload["streams"][0]
    assert stream["stream"] == {"job": "cloudflare", "type": "firewall"}
    assert len(stream["values"]) == 2


def test_build_loki_payload_timestamp_is_nanoseconds():
    events = [{"datetime": "2026-05-27T10:00:00Z", "action": "block"}]
    payload = build_loki_payload(events)
    ts_str = payload["streams"][0]["values"][0][0]
    # Nanosecond timestamps are 19 digits for years 2001-2286
    assert len(ts_str) == 19
    assert ts_str.isdigit()


def test_build_loki_payload_line_is_json():
    events = [{"datetime": "2026-05-27T10:00:00Z", "action": "block", "clientIP": "1.2.3.4"}]
    payload = build_loki_payload(events)
    line = payload["streams"][0]["values"][0][1]
    parsed = json.loads(line)
    assert parsed["action"] == "block"
    assert parsed["clientIP"] == "1.2.3.4"


def test_build_loki_payload_bad_datetime_uses_fallback():
    """Events with unparseable timestamps get the current time (not an error)."""
    events = [{"datetime": "not-a-date", "action": "block"}]
    payload = build_loki_payload(events)
    ts_str = payload["streams"][0]["values"][0][0]
    assert len(ts_str) == 19  # still a valid nanosecond timestamp


def test_parse_firewall_events_null_field():
    """Returns empty list when firewallEventsAdaptive is null (GraphQL null)."""
    response = {"data": {"viewer": {"zones": [{"firewallEventsAdaptive": None}]}}}
    assert parse_firewall_events(response) == []


def test_parse_firewall_events_returns_copy():
    """Returns a copy, not a reference to the original data."""
    response = {"data": {"viewer": {"zones": [{"firewallEventsAdaptive": [{"action": "block"}]}]}}}
    events = parse_firewall_events(response)
    events.append({"extra": "item"})
    # Original must be unchanged
    original = response["data"]["viewer"]["zones"][0]["firewallEventsAdaptive"]
    assert len(original) == 1

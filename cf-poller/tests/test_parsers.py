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
    remap_crowdsec_source,
    bucket_status_code,
    parse_country_analytics,
    parse_cache_analytics,
    parse_status_analytics,
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
    payload = build_loki_payload(events, zone_name="example.com")

    assert "streams" in payload
    assert len(payload["streams"]) == 1
    stream = payload["streams"][0]
    assert stream["stream"] == {"job": "cloudflare", "type": "firewall", "zone": "example.com"}
    assert len(stream["values"]) == 2


def test_build_loki_payload_timestamp_is_nanoseconds():
    events = [{"datetime": "2026-05-27T10:00:00Z", "action": "block"}]
    payload = build_loki_payload(events, zone_name="example.com")
    ts_str = payload["streams"][0]["values"][0][0]
    # Nanosecond timestamps are 19 digits for years 2001-2286
    assert len(ts_str) == 19
    assert ts_str.isdigit()


def test_build_loki_payload_line_is_json():
    events = [{"datetime": "2026-05-27T10:00:00Z", "action": "block", "clientIP": "1.2.3.4"}]
    payload = build_loki_payload(events, zone_name="example.com")
    line = payload["streams"][0]["values"][0][1]
    parsed = json.loads(line)
    assert parsed["action"] == "block"
    assert parsed["clientIP"] == "1.2.3.4"


def test_build_loki_payload_bad_datetime_uses_fallback():
    """Events with unparseable timestamps get the current time (not an error)."""
    events = [{"datetime": "not-a-date", "action": "block"}]
    payload = build_loki_payload(events, zone_name="example.com")
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


# ── CrowdSec source remapping ──────────────────────────────────────────────────

def test_remap_crowdsec_source_matches():
    events = [{"ruleId": "abc123", "source": "firewallRules"}]
    remap_crowdsec_source(events, frozenset(["abc123"]))
    assert events[0]["source"] == "crowdsec"


def test_remap_crowdsec_source_no_match():
    events = [{"ruleId": "other-rule", "source": "firewallRules"}]
    remap_crowdsec_source(events, frozenset(["abc123"]))
    assert events[0]["source"] == "firewallRules"


def test_remap_crowdsec_source_empty_rule_ids():
    events = [{"ruleId": "abc123", "source": "firewallRules"}]
    remap_crowdsec_source(events, frozenset())
    assert events[0]["source"] == "firewallRules"


def test_remap_crowdsec_source_only_matching_events_changed():
    events = [
        {"ruleId": "abc123", "source": "firewallRules"},
        {"ruleId": "other",  "source": "waf"},
    ]
    remap_crowdsec_source(events, frozenset(["abc123"]))
    assert events[0]["source"] == "crowdsec"
    assert events[1]["source"] == "waf"


def test_remap_crowdsec_source_loki_payload_reflects_change():
    events = [{"ruleId": "abc123", "source": "firewallRules", "datetime": "2026-06-09T10:00:00Z"}]
    remap_crowdsec_source(events, frozenset(["abc123"]))
    payload = build_loki_payload(events, "example.com")
    line = json.loads(payload["streams"][0]["values"][0][1])
    assert line["source"] == "crowdsec"


# ── Status code bucketing ──────────────────────────────────────────────────────

@pytest.mark.parametrize("code,expected", [
    (200, "2xx"), (201, "2xx"), (299, "2xx"),
    (301, "3xx"), (304, "3xx"),
    (400, "4xx"), (403, "4xx"), (404, "4xx"),
    (500, "5xx"), (503, "5xx"),
    (0,   "other"), (999, "other"),
])
def test_bucket_status_code(code, expected):
    assert bucket_status_code(code) == expected


# ── Country analytics parsing ──────────────────────────────────────────────────

def _country_response(rows):
    return {"data": {"viewer": {"zones": [{"httpRequestsAdaptiveGroups": rows}]}}}


def test_parse_country_analytics_basic():
    rows = [
        {"count": 500, "sum": {"edgeResponseBytes": 100000}, "uniq": {"uniques": 50},
         "dimensions": {"clientCountryName": "United States"}},
        {"count": 200, "sum": {"edgeResponseBytes": 40000}, "uniq": {"uniques": 20},
         "dimensions": {"clientCountryName": "Germany"}},
    ]
    req, bw, uniq = parse_country_analytics(_country_response(rows))
    assert req["United States"] == pytest.approx(500 / 6, rel=1e-3)
    assert bw["Germany"] == pytest.approx(40000 / 6, rel=1e-3)
    assert uniq == pytest.approx(50 / 6, rel=1e-3)


def test_parse_country_analytics_overflow_into_other():
    """Countries beyond TOP_N_COUNTRIES (10) are aggregated as 'other'."""
    rows = [
        {"count": 100, "sum": {"edgeResponseBytes": 1000}, "uniq": {"uniques": 10},
         "dimensions": {"clientCountryName": f"Country{i}"}}
        for i in range(15)  # 15 rows, only first 10 kept individually
    ]
    req, bw, _ = parse_country_analytics(_country_response(rows))
    assert "other" in req
    # 5 overflow rows × 100 requests each → 500 in 'other', then divided by 6
    assert req["other"] == pytest.approx(500 / 6, rel=1e-3)


def test_parse_country_analytics_empty():
    req, bw, uniq = parse_country_analytics(_country_response([]))
    assert req == {}
    assert bw == {}
    assert uniq == 0


def test_parse_country_analytics_bad_shape():
    req, bw, uniq = parse_country_analytics({})
    assert req == {}


# ── Cache analytics parsing ────────────────────────────────────────────────────

def _cache_response(rows):
    return {"data": {"viewer": {"zones": [{"httpRequestsAdaptiveGroups": rows}]}}}


def test_parse_cache_analytics():
    rows = [
        {"count": 800, "dimensions": {"cacheStatus": "hit"}},
        {"count": 150, "dimensions": {"cacheStatus": "miss"}},
        {"count": 50,  "dimensions": {"cacheStatus": "bypass"}},
    ]
    result = parse_cache_analytics(_cache_response(rows))
    assert result["hit"] == pytest.approx(800 / 6, rel=1e-3)
    assert result["miss"] == pytest.approx(150 / 6, rel=1e-3)
    assert result["bypass"] == pytest.approx(50 / 6, rel=1e-3)


def test_parse_cache_analytics_empty():
    assert parse_cache_analytics(_cache_response([])) == {}


# ── HTTP status analytics parsing ──────────────────────────────────────────────

def _status_response(rows):
    return {"data": {"viewer": {"zones": [{"httpRequestsAdaptiveGroups": rows}]}}}


def test_parse_status_analytics_buckets():
    rows = [
        {"count": 900, "dimensions": {"edgeResponseStatus": 200}},
        {"count": 50,  "dimensions": {"edgeResponseStatus": 301}},
        {"count": 30,  "dimensions": {"edgeResponseStatus": 404}},
        {"count": 20,  "dimensions": {"edgeResponseStatus": 503}},
    ]
    result = parse_status_analytics(_status_response(rows))
    assert result["2xx"] == pytest.approx(900 / 6, rel=1e-3)
    assert result["3xx"] == pytest.approx(50 / 6, rel=1e-3)
    assert result["4xx"] == pytest.approx(30 / 6, rel=1e-3)
    assert result["5xx"] == pytest.approx(20 / 6, rel=1e-3)


def test_parse_status_analytics_accumulates_same_bucket():
    """Multiple rows with same bucket (e.g. 200 and 201) are summed."""
    rows = [
        {"count": 500, "dimensions": {"edgeResponseStatus": 200}},
        {"count": 100, "dimensions": {"edgeResponseStatus": 201}},
    ]
    result = parse_status_analytics(_status_response(rows))
    assert result["2xx"] == pytest.approx(600 / 6, rel=1e-3)


def test_parse_status_analytics_empty():
    assert parse_status_analytics(_status_response([])) == {}

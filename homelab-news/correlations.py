"""Normalize operational observations and derive evidence-backed correlations."""

import fcntl
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from storage import load_json, save_json


_ALIASES = {
    "edge-gateway": "traefik",
    "reverse-proxy": "traefik",
    "reverse_proxy": "traefik",
    "postgresql": "postgres",
    "home-assistant": "homeassistant",
    "home_assistant": "homeassistant",
    "hass": "homeassistant",
}
_GENERIC_SOURCES = {"docker", "loki", "unknown", "syslog"}
_RETENTION_DAYS = 90
_MAX_EVENTS = 20_000


_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def normalize_service(value: str) -> str:
    """Return a stable, query-safe service identifier."""
    normalized = re.sub(r"[^a-z0-9_.-]+", "-", value.lower().strip()).strip("-._")
    if not _IPV4_RE.match(normalized):
        normalized = re.sub(r"[-_.](?:blue|green|1|2)$", "", normalized)
    return _ALIASES.get(normalized, normalized or "unknown")


def _timestamp(value: object, fallback: str) -> str:
    text = str(value or fallback)
    try:
        normalized = text.replace("Z", "+00:00")
        if normalized.endswith(" UTC"):
            normalized = normalized[:-4] + "+00:00"
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    except ValueError:
        return fallback


def _event(event_type: str, service: str, source: str, observed_at: str,
           severity: str, attributes: dict[str, Any]) -> dict[str, Any]:
    stable = json.dumps(
        [event_type, service, source, observed_at, attributes],
        sort_keys=True,
        separators=(",", ":"),
    )
    return {
        "event_id": hashlib.sha256(stable.encode()).hexdigest()[:24],
        "observed_at": observed_at,
        "event_type": event_type,
        "service": service,
        "source": source,
        "severity": severity,
        "attributes": attributes,
    }


def build_cycle_events(*, docker_issues: list[dict], loki_issues: list[dict],
                       bans: list[dict], observed_at: str) -> list[dict[str, Any]]:
    """Convert one collection cycle into normalized, deduplicable events."""
    events: list[dict[str, Any]] = []
    fallback = _timestamp(observed_at, datetime.now(timezone.utc).isoformat())
    for source_kind, issues in (("docker", docker_issues), ("loki", loki_issues)):
        for issue in issues:
            source = str(issue.get("source") or source_kind)
            service = normalize_service(source)
            if service in _GENERIC_SOURCES:
                service = "infrastructure"
            count = max(1, int(issue.get("count") or 1))
            event_type = "logs.error_spike" if count >= 3 else "logs.error_observed"
            first_seen = _timestamp(issue.get("first_seen"), fallback)
            last_seen = _timestamp(issue.get("last_seen"), first_seen)
            events.append(_event(event_type, service, source_kind, last_seen,
                                 str(issue.get("level") or "warn"), {
                                     "count": count,
                                     "first_seen": first_seen,
                                     "last_seen": last_seen,
                                 }))

    for ban in bans:
        observed = _timestamp(ban.get("banned_at") or ban.get("banned_since"), fallback)
        events.append(_event("security.ban_started", "traefik", "security", observed, "warn", {
            "category": str(ban.get("category") or "unknown")[:80],
            "hit_count": max(0, int(ban.get("hit_count") or 0)),
        }))

    return events


def record_update_detections(update_hosts: dict, state_path: str,
                             observed_at: str) -> list[dict[str, Any]]:
    """Persist pending-update state and return only newly-detected updates.

    update_hosts is rechecked every cycle regardless of whether a pending
    update is new or has been pending for days. Without this dedup,
    application.update_detected would fire on every cycle for as long as the
    update remains unapplied, making any two containers with simultaneously
    pending updates look "correlated" purely because they were both checked
    in the same batch run. The read-modify-write is lock-protected because
    both the today and rolling workers call this independently — an unlocked
    version lets both see no prior state at once and both emit.
    """
    fallback = _timestamp(observed_at, datetime.now(timezone.utc).isoformat())
    parent = os.path.dirname(state_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    lock_path = f"{state_path}.lock"
    with open(lock_path, "a", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        previous = load_json(state_path) or {}
        current: dict[str, dict[str, str]] = {}
        events = []
        for host, host_data in update_hosts.items():
            if host.startswith("_") or not isinstance(host_data, dict):
                continue
            host_key = normalize_service(host)
            current[host_key] = {}
            checked = _timestamp(host_data.get("ts"), fallback)
            for result in host_data.get("results") or []:
                if result.get("status") != "update_available":
                    continue
                service = normalize_service(str(result.get("container") or "unknown"))
                if service == "unknown":
                    continue
                new_version = str(result.get("new_version") or "")[:80]
                current[host_key][service] = new_version
                previously_known = (previous.get(host_key) or {}).get(service)
                if previously_known == new_version:
                    continue
                events.append(_event("application.update_detected", service, "updates", checked, "info", {
                    "host": host_key,
                    "new_version": new_version,
                }))
        save_json(state_path, current)
        fcntl.flock(lock, fcntl.LOCK_UN)
    return events


def record_container_transitions(hosts: dict, state_path: str,
                                 observed_at: str) -> list[dict[str, Any]]:
    """Persist container image identity and return genuine image-change events."""
    previous = load_json(state_path) or {}
    current: dict[str, dict[str, str]] = {}
    events = []
    fallback = _timestamp(observed_at, datetime.now(timezone.utc).isoformat())
    for host, host_data in hosts.items():
        if not isinstance(host_data, dict):
            continue
        host_key = normalize_service(host)
        current[host_key] = {}
        changed_at = _timestamp(host_data.get("ts"), fallback)
        for result in host_data.get("results") or []:
            service = normalize_service(str(result.get("container") or "unknown"))
            digests = sorted(str(item) for item in result.pop("_local_digests", []) if item)
            identity = "|".join(digests)
            if not identity or service == "unknown":
                continue
            current[host_key][service] = identity
            old_identity = (previous.get(host_key) or {}).get(service)
            if old_identity and old_identity != identity:
                events.append(_event(
                    "container.image_changed", service, "docker", changed_at, "info",
                    {"host": host_key},
                ))
    save_json(state_path, current)
    return events


def append_events(path: str, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge EVENTS into the retained ledger under an inter-process file lock."""
    if not events:
        return load_json(path) or []
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    lock_path = f"{path}.lock"
    with open(lock_path, "a", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        existing = load_json(path) or []
        by_id = {event.get("event_id"): event for event in existing if isinstance(event, dict)}
        for event in events:
            by_id[event["event_id"]] = event
        cutoff = datetime.now(timezone.utc) - timedelta(days=_RETENTION_DAYS)
        retained = []
        for event in by_id.values():
            try:
                if datetime.fromisoformat(event["observed_at"]) >= cutoff:
                    retained.append(event)
            except (KeyError, TypeError, ValueError):
                continue
        retained.sort(key=lambda event: event["observed_at"], reverse=True)
        retained = retained[:_MAX_EVENTS]
        save_json(path, retained)
        fcntl.flock(lock, fcntl.LOCK_UN)
    return retained


def _sorted_parsed_events(events: list[dict[str, Any]]) -> list[tuple[datetime, dict[str, Any]]]:
    """Return EVENTS with a parsed timestamp, ascending, dropping unparseable entries."""
    parsed: list[tuple[datetime, dict[str, Any]]] = []
    for event in events:
        try:
            observed = datetime.fromisoformat(event["observed_at"].replace("Z", "+00:00"))
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=timezone.utc)
            parsed.append((observed.astimezone(timezone.utc), event))
        except (KeyError, TypeError, ValueError):
            continue
    parsed.sort(key=lambda pair: pair[0])
    return parsed


def correlate_events(events: list[dict[str, Any]], *, window_minutes: int = 10,
                     max_results: int = 12) -> list[dict[str, Any]]:
    """Return temporal correlations sharing a service within WINDOW_MINUTES."""
    parsed = _sorted_parsed_events(events)
    correlations: list[dict[str, Any]] = []
    window = timedelta(minutes=window_minutes)
    seen: set[tuple[str, str]] = set()
    for index, (left_time, left) in enumerate(parsed):
        for right_time, right in parsed[index + 1:]:
            delta = right_time - left_time
            if delta > window:
                break
            if left.get("service") != right.get("service"):
                continue
            if left.get("event_type") == right.get("event_type"):
                continue
            pair = tuple(sorted((str(left.get("event_id")), str(right.get("event_id")))))
            if pair in seen:
                continue
            seen.add(pair)
            correlations.append({
                "service": left["service"],
                "relationship": "followed" if delta.total_seconds() > 60 else "overlapped",
                "minutes_apart": round(delta.total_seconds() / 60, 1),
                "first": {"event_type": left["event_type"], "observed_at": left["observed_at"]},
                "second": {"event_type": right["event_type"], "observed_at": right["observed_at"]},
                "confidence": "high" if delta <= timedelta(minutes=3) else "medium",
                "causation_confirmed": False,
            })
    return correlations[-max_results:]


_DEFAULT_SERVICE_PAIR_LIMIT = 15

# Event types sparse and discrete enough for cross-service co-occurrence to be
# meaningful. Routine log chatter (logs.error_spike/logs.error_observed) is
# excluded: a service that logs every few minutes would otherwise trivially
# "correlate" with anything else that logs at all, purely by volume, not by
# any real relationship.
_INCIDENT_EVENT_TYPES = {
    "security.ban_started",
    "application.update_detected",
    "container.image_changed",
}


def service_correlations(events: list[dict[str, Any]], *, window_minutes: int = 10,
                         max_pairs: int = _DEFAULT_SERVICE_PAIR_LIMIT) -> list[dict[str, Any]]:
    """Return cross-service incident correlations naming what happened, not just a count.

    Unlike correlate_events, which links events sharing one service, this looks
    at pairs of *different* services with events within WINDOW_MINUTES of each
    other. Each result names the specific event type on each side (e.g. "a
    deploy on mealie" and "a ban started on traefik") and the most recent date
    it happened, instead of collapsing to an opaque count — a bare "N days"
    number can't distinguish a rare, meaningful coincidence from a service
    that is simply always active. Grouping is by (service, event_type) pairs,
    not just service pairs, so a chatty event type doesn't blend into a rare
    one for the same two services. Co-occurrence is counted once per calendar
    day per group rather than per event pair, so a burst of same-day repeats
    (e.g. several updates detected in one batch check) doesn't inflate the
    day count. Considers only _INCIDENT_EVENT_TYPES: routine log chatter would
    trivially pair with everything else if it counted.
    """
    parsed = _sorted_parsed_events([e for e in events if e.get("event_type") in _INCIDENT_EVENT_TYPES])
    groups: dict[tuple[tuple[str, str], tuple[str, str]], dict[str, Any]] = {}
    for index, (left_time, left) in enumerate(parsed):
        for right_time, right in parsed[index + 1:]:
            delta = right_time - left_time
            if delta > timedelta(minutes=window_minutes):
                break
            left_service = str(left.get("service"))
            right_service = str(right.get("service"))
            if left_service == right_service:
                continue
            left_key = (left_service, str(left.get("event_type")))
            right_key = (right_service, str(right.get("event_type")))
            group_key = tuple(sorted((left_key, right_key)))
            day = left_time.date().isoformat()
            group = groups.setdefault(group_key, {"days": set(), "last_seen": "", "minutes_apart": 0.0})
            group["days"].add(day)
            if day >= group["last_seen"]:
                group["last_seen"] = day
                group["minutes_apart"] = round(delta.total_seconds() / 60, 1)
    ranked = sorted(groups.items(), key=lambda item: (-len(item[1]["days"]), item[0]))
    return [
        {
            "service_a": a_key[0], "event_a": a_key[1],
            "service_b": b_key[0], "event_b": b_key[1],
            "days": len(info["days"]),
            "last_seen": info["last_seen"],
            "minutes_apart": info["minutes_apart"],
        }
        for (a_key, b_key), info in ranked[:max_pairs]
    ]


def events_since(events: list[dict[str, Any]], cutoff: datetime,
                 max_events: int = 500) -> list[dict[str, Any]]:
    """Select recent valid ledger entries without letting corrupt data break a cycle."""
    if cutoff.tzinfo is None:
        cutoff = cutoff.replace(tzinfo=timezone.utc)
    cutoff = cutoff.astimezone(timezone.utc)
    selected = []
    for event in events:
        try:
            observed = datetime.fromisoformat(event["observed_at"].replace("Z", "+00:00"))
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=timezone.utc)
            if observed.astimezone(timezone.utc) >= cutoff:
                selected.append(event)
        except (AttributeError, KeyError, TypeError, ValueError):
            continue
        if len(selected) >= max_events:
            break
    return selected


def targeted_recall_queries(events: list[dict[str, Any]], correlations: list[dict[str, Any]],
                            max_queries: int = 2) -> list[str]:
    """Build focused Hindsight queries for the most relevant services and event types."""
    weights: dict[str, int] = {}
    types: dict[str, set[str]] = {}
    for event in events:
        service = str(event.get("service") or "unknown")
        if service in _GENERIC_SOURCES or service == "infrastructure":
            continue
        weights[service] = weights.get(service, 0) + (3 if event.get("severity") == "error" else 1)
        types.setdefault(service, set()).add(str(event.get("event_type") or "event"))
    for correlation in correlations:
        service = str(correlation.get("service") or "unknown")
        weights[service] = weights.get(service, 0) + 5
    queries = []
    for service, _ in sorted(weights.items(), key=lambda item: (-item[1], item[0]))[:max_queries]:
        event_terms = ", ".join(sorted(types.get(service) or {"operational events"}))
        queries.append(
            f"Past {service} updates, version or configuration changes, restarts, failures, "
            f"recoveries, and related incidents relevant to: {event_terms}"
        )
    return queries


def format_correlations(correlations: list[dict[str, Any]]) -> str:
    """Format correlations as compact authoritative timing evidence for the LLM."""
    lines = []
    for item in correlations:
        first = item.get("first") or {}
        second = item.get("second") or {}
        lines.append(
            f"- {item.get('service')}: {first.get('event_type')} {item.get('relationship')} "
            f"{second.get('event_type')} ({item.get('minutes_apart')} minutes apart; "
            f"{item.get('confidence')} timing confidence; causation NOT established)"
        )
    return "\n".join(lines)

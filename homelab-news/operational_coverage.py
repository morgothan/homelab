"""Deterministic operational-log selection and mandatory news coverage."""

import re
from collections import defaultdict
from typing import Optional


_ESCALATION_RULES: tuple[tuple[str, re.Pattern], ...] = (
    ("log collection incomplete", re.compile(r"(?i)\bloki collection incomplete\b|\bcould not reach loki\b")),
    ("backup failure", re.compile(r"(?i)\b(?:backup|snapshot)\b.{0,80}\b(?:fail(?:ed|ure)?|error)\b|\b(?:fail(?:ed|ure)?|error)\b.{0,80}\b(?:backup|snapshot)\b")),
    ("storage I/O error", re.compile(r"(?i)\b(?:i/o|input/output) error\b|\bno space left\b|\bread-only file system\b|\b(?:raid|pool|array)\b.{0,50}\bdegraded\b")),
    ("process crash", re.compile(r"(?i)\b(?:segfault|kernel panic|panic:|out of memory|oom.kill|fatal error|exiting due to fatal|database corrupt(?:ion|ed)?)\b")),
    ("certificate failure", re.compile(r"(?i)\b(?:certificate|cert|tls)\b.{0,70}\b(?:expir(?:e|ed|y|ing)|invalid|fail(?:ed|ure)?)\b")),
)
_HIGH_VOLUME_ESCALATION_RULES: tuple[tuple[str, re.Pattern, int], ...] = (
    ("sustained network outage", re.compile(r"(?i)\bnetwork (?:is )?unreachable\b"), 10),
    ("access-control denial spike", re.compile(r"(?i)apparmor=.?denied.?|\bselinux\b.{0,30}\bdenied\b"), 100),
)
_BENIGN_LOG_NOISE = re.compile(
    r"(?i)\bnot an error\b|STA_ASSOC_TRACKER.*\bsoft failure\b|"
    r"collector failed.*name=thermal_zone"
)


def issue_escalation_reason(issue: dict) -> Optional[str]:
    """Return a deterministic escalation category for an operational issue."""
    message = str(issue.get("message") or "")
    for reason, pattern in _ESCALATION_RULES:
        if pattern.search(message):
            return reason
    count = int(issue.get("count") or 1)
    for reason, pattern, minimum in _HIGH_VOLUME_ESCALATION_RULES:
        if count >= minimum and pattern.search(message):
            return reason
    return None


def select_news_issues(issues: list[dict], limit: int = 20) -> list[dict]:
    """Select diverse evidence without allowing noisy sources to crowd it out."""
    for issue in issues:
        issue["selected_for_news"] = False
        issue.pop("selection_reason", None)
    escalations: list[dict] = []
    routine: list[dict] = []
    for issue in issues:
        reason = issue_escalation_reason(issue)
        if reason:
            issue["selection_reason"] = f"escalation: {reason}"
            escalations.append(issue)
        elif not _BENIGN_LOG_NOISE.search(str(issue.get("message") or "")):
            routine.append(issue)
    ordering = lambda item: (item.get("level") != "error", -int(item.get("count") or 1))
    selected = sorted(escalations, key=ordering)[:limit]
    source_counts: dict[str, int] = defaultdict(int)
    for issue in selected:
        source_counts[str(issue.get("source") or "unknown").lower()] += 1
    for issue in sorted(routine, key=ordering):
        if len(selected) >= limit:
            break
        source = str(issue.get("source") or "unknown").lower()
        if source_counts[source] >= 2:
            continue
        issue["selection_reason"] = "ranked: severity, volume, and source diversity"
        selected.append(issue)
        source_counts[source] += 1
    for issue in selected:
        issue["selected_for_news"] = True
    return selected


def build_operational_alerts_article(issues: list[dict]) -> Optional[dict]:
    """Build an authoritative fallback article for events that must not be omitted."""
    alerts = [(issue, issue_escalation_reason(issue)) for issue in issues]
    alerts = [(issue, reason) for issue, reason in alerts if reason]
    if not alerts:
        return None
    grouped: dict[str, dict] = {}
    for issue, reason in alerts:
        summary = grouped.setdefault(reason, {"groups": 0, "count": 0, "sources": []})
        summary["groups"] += 1
        summary["count"] += int(issue.get("count") or 1)
        source = str(issue.get("source") or "unknown")
        if source not in summary["sources"]:
            summary["sources"].append(source)
        issue["article_coverage"] = "deterministic operational alerts"
    details = [
        f"{reason}: {summary['groups']} group(s), {summary['count']} log(s), "
        f"sources {', '.join(summary['sources'][:4])}"
        for reason, summary in grouped.items()
    ]
    return {
        "headline": f"{len(alerts)} Operational Alert{'s' if len(alerts) != 1 else ''} Require Review",
        "blurb": ("Deterministic log review flagged: " + "; ".join(details) + ".")[:600],
        "section": "City Hall",
        "source": "deterministic-operational-alerts",
    }

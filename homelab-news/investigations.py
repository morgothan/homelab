"""Automatic, read-only incident triage and evidence synthesis."""

import fcntl
import hashlib
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import config
from storage import load_json, save_json
from privacy import redact_data

log = logging.getLogger(__name__)

MAX_CANDIDATES = 8
MAX_INVESTIGATIONS = 2
CACHE_HOURS = 24
_ROUTINE_MARKERS = (
    "new library additions", "update available", "update pending", "all systems current",
    "scanner", "sweeper", "waf blocks", "ban after", "earns week-long",
)
_SENSITIVE_VALUE = re.compile(
    r"(?i)\b(authorization|bearer|password|passwd|secret|token|api[_-]?key)\b"
    r"(\s*[:=]\s*|\s+)([^\s,;]+)"
)
_PROMPT_INJECTION = re.compile(
    r"(?i)(ignore (?:all |any )?(?:previous|prior|above) instructions|"
    r"system prompt|developer message|you are now|act as)"
)


INCIDENT_GROUP_THRESHOLD = 0.35  # min Jaccard similarity between two reports to be "same incident"

# Tokens too generic to distinguish one incident from another (numbers and
# function words are filtered separately). Validated against the live 927-report
# archive: keeps the UDM mq-broker/CoreDNS, UniFi WiFi-auth, peanut config-write,
# kids-dns SD card, and overseerr/jellyfin clusters each as one group.
_INCIDENT_NOISE = frozenset({
    "the", "and", "for", "with", "from", "that", "this", "are", "was", "its", "has", "had", "not",
    "but", "you", "your", "have", "will", "would", "should", "could", "than", "then", "they", "them",
    "their", "there", "these", "those", "what", "when", "where", "which", "while", "who", "whom",
    "into", "onto", "over", "under", "again", "further", "once", "here", "all", "any", "both", "each",
    "more", "most", "other", "some", "such", "only", "own", "same", "too", "very", "can", "may", "must",
    "about", "after", "before", "between", "during", "until", "upon", "also", "because", "been", "being",
    "did", "does", "doing", "how", "just", "like", "were", "said", "says", "yes", "no", "per", "off",
    "out", "via", "within", "without", "each",
    # operational noise present in every report (would otherwise lower similarity
    # inside true groups and raise it across unrelated groups)
    "log", "logs", "logged", "logging", "error", "errors", "err", "warning", "warnings", "warn",
    "fail", "fails", "failed", "failure", "failures", "report", "reports", "reported", "shows",
    "show", "shown", "times", "count", "counts", "occurrences", "occurrence", "instances",
    "issue", "issues", "problem", "problems", "service", "services", "status", "second", "seconds",
    "minute", "minutes", "hour", "hours", "day", "days", "approximately", "about",
    "observations", "observation", "evidence", "event", "events", "history", "include", "includes",
    "including", "seen", "first", "last", "until", "across", "through", "during", "since",
    "start", "started", "ended", "present", "current", "currently", "likely", "probably", "possible",
    "possibly", "indicates", "indicating", "indicate", "suggest", "suggests", "suggesting",
    "cause", "caused", "result", "resulting", "results", "occurring", "occurs", "occurred",
})


def _clean(value: object, limit: int) -> str:
    """Return bounded single-line text suitable for an untrusted evidence packet."""
    return " ".join(str(value or "").split())[:limit]


def significant_tokens(report: dict[str, Any]) -> frozenset[str]:
    """Distinctive lowercase tokens (headline + finding + evidence) that identify an incident."""
    text = " ".join((
        str(report.get("headline") or ""),
        str(report.get("finding") or ""),
        " ".join(str(v) for v in (report.get("evidence") or []) if isinstance(v, str)),
    )).lower()
    return frozenset(
        t for t in re.findall(r"[a-z][a-z0-9_]{2,}", text)
        if t not in _INCIDENT_NOISE and not t.isdigit()
    )


def _similarity(a: frozenset[str], b: frozenset[str]) -> float:
    """Overlap coefficient — intersection over the smaller set."""
    return (len(a & b) / min(len(a), len(b))) if a and b else 0.0


def group_related_investigations(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Cluster reports describing the same incident; groups + members newest-first.

    Deterministic greedy single-link: sort copies of REPORTS descending by
    ``investigated_at`` (missing timestamps sort last), then each report joins the
    existing group whose leader's token set has the highest overlap-coefficient
    similarity (intersection / min of sizes) >= INCIDENT_GROUP_THRESHOLD; on equal
    similarity the first candidate group in iteration order wins. Otherwise it
    starts its own group (and becomes that group's leader). An inverted
    token->group index restricts comparisons to candidate groups sharing >= 1
    token, keeping the 900-report live archive ~0.7s. Returns
    [{"reports": [dict newest-first], "count": int}, ...] ordered by each
    group's newest investigated_at descending. Accepted non-dict input is
    dropped; non-empty only if a dict has an id/headline worth grouping.
    """
    rows = [r for r in reports if isinstance(r, dict)]
    if not rows:
        return []
    rows.sort(key=lambda r: r.get("investigated_at") or "", reverse=True)
    groups: list[dict[str, Any]] = []   # {"reports": [...], "count": int, "_toks": frozenset}
    inv: dict[str, list[int]] = {}
    for report in rows:
        toks = significant_tokens(report)
        if not toks:
            toks = frozenset({_clean(str(report.get("id") or ""), 60)})
        candidates = {gi for t in toks for gi in inv.get(t, ())}
        best_gi, best_sim = None, -1.0
        for gi in candidates:
            sim = _similarity(groups[gi]["_toks"], toks)
            if sim > best_sim:
                best_gi, best_sim = gi, sim
        if best_gi is not None and best_sim >= INCIDENT_GROUP_THRESHOLD:
            groups[best_gi]["reports"].append(report)
            groups[best_gi]["count"] += 1
        else:
            groups.append({"reports": [report], "count": 1, "_toks": toks})
            gi = len(groups) - 1
            for t in toks:
                inv.setdefault(t, []).append(gi)
    return [{"reports": g["reports"], "count": g["count"]} for g in groups]


def _evidence_text(value: object, limit: int) -> str:
    """Bound log-derived text and redact common credentials and injected directives."""
    text = _clean(value, limit)
    text = _SENSITIVE_VALUE.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    return _PROMPT_INJECTION.sub("[UNTRUSTED DIRECTIVE REMOVED]", text)


def _fingerprint(article: dict[str, Any]) -> str:
    material = f"{_clean(article.get('headline'), 200)}\n{_clean(article.get('blurb'), 600)}"
    return hashlib.sha256(material.encode()).hexdigest()[:20]


def _json_object(content: str) -> dict[str, Any] | None:
    text = content.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1].rsplit("```", 1)[0]
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start < 0 or end <= start:
            return None
        try:
            parsed = json.loads(text[start:end + 1])
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            return None


async def _complete(*, url: str, model: str, timeout: int, system: str,
                    payload: object, max_tokens: int) -> dict[str, Any] | None:
    """Dispatch a single bounded investigation LLM call.

    Thin wrapper over :func:`llm.complete`: redacts the untrusted evidence payload
    and parses the model's content back into a dict (or ``None`` on failure).
    ``timeout`` mirrors the call-site ``llm_timeout``, which every production caller
    sets to ``config.OLLAMA_TIMEOUT`` — the fixed timeout :func:`llm.complete` uses.
    """
    from llm import complete

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(redact_data(payload), ensure_ascii=False)},
    ]
    response = await complete(messages, max_tokens=max_tokens, temperature=0.1,
                              url=url, model=model)
    if not isinstance(response, dict):
        return None
    try:
        content = response["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError, AttributeError) as error:
        log.warning("Investigation LLM call failed (%s): %s", type(error).__name__, error)
        return None
    return _json_object(content)


def select_candidates(articles: list[dict], issues: list[dict]) -> list[dict[str, str]]:
    """Select operational stories only when the edition contains raw issue evidence."""
    if not issues:
        return []
    candidates = []
    for article in articles:
        headline = _clean(article.get("headline"), 200)
        blurb = _clean(article.get("blurb"), 600)
        combined = f"{headline} {blurb}".lower()
        if not headline or any(marker in combined for marker in _ROUTINE_MARKERS):
            continue
        candidates.append({
            "id": _fingerprint(article), "headline": headline, "blurb": blurb,
            "section": _clean(article.get("section"), 50),
        })
        if len(candidates) >= MAX_CANDIDATES:
            break
    return candidates


def build_evidence(article: dict[str, str], issues: list[dict], events: list[dict],
                   correlations: list[dict]) -> dict[str, Any]:
    """Build a bounded relevance-ranked packet without granting model tool access."""
    terms = {word.lower().strip("'\".,:;()[]") for word in
             f"{article['headline']} {article['blurb']}".split() if len(word) >= 4}

    def relevance(item: object) -> int:
        text = json.dumps(item, ensure_ascii=False).lower()
        return sum(term in text for term in terms)

    ranked_issues = sorted(issues, key=lambda item: (
        relevance(item), int(item.get("count") or 1)), reverse=True)
    return {
        "story": article,
        "observations": [{
            "source": _clean(item.get("source"), 80),
            "level": _clean(item.get("level"), 20),
            "count": int(item.get("count") or 1),
            "message": _evidence_text(item.get("message"), 300),
            "first_seen": _clean(item.get("first_seen"), 50),
            "last_seen": _clean(item.get("last_seen"), 50),
        } for item in ranked_issues[:30]],
        "event_history": sorted(events, key=relevance, reverse=True)[:40],
        "timing_correlations": sorted(correlations, key=relevance, reverse=True)[:12],
        "collection_note": (
            "Read-only newsroom observations. Timing correlation is not proof of causation; "
            "absence of an observation is not proof an event did not occur."
        ),
    }


def _validate_report(raw: dict[str, Any] | None, article: dict[str, str],
                     triage_reason: str) -> dict[str, Any] | None:
    if not raw:
        return None
    confidence = str(raw.get("confidence") or "low").lower()
    if confidence not in {"low", "medium", "high"}:
        confidence = "low"
    def strings(name: str, count: int) -> list[str]:
        value = raw.get(name)
        return [_clean(item, 500) for item in value[:count]] if isinstance(value, list) else []
    return {
        "id": article["id"], "headline": article["headline"], "status": "complete",
        "investigated_at": datetime.now(timezone.utc).isoformat(),
        "triage_reason": _clean(triage_reason, 400),
        "finding": _clean(raw.get("finding"), 1200),
        "confidence": confidence, "impact": _clean(raw.get("impact"), 600),
        "evidence": strings("evidence", 8), "alternatives": strings("alternatives", 5),
        "next_checks": strings("next_checks", 6),
        "limitations": _clean(raw.get("limitations"), 600),
    }


async def investigate_edition(*, articles: list[dict], docker_issues: list[dict],
                              loki_issues: list[dict], events: list[dict],
                              correlations: list[dict], cache_path: str,
                              llm_url: str, llm_model: str,
                              llm_timeout: int) -> list[dict[str, Any]]:
    """Triage an edition and investigate only unresolved, worthwhile incidents."""
    issues = list(docker_issues) + list(loki_issues)
    candidates = select_candidates(articles, issues)
    if not candidates or not llm_url or not llm_model:
        return []

    cache = load_json(cache_path) or {}
    cached_reports = cache.get("reports", {}) if isinstance(cache, dict) else {}
    cached_triage = cache.get("triage", {}) if isinstance(cache, dict) else {}
    cutoff = datetime.now(timezone.utc) - timedelta(hours=CACHE_HOURS)
    reports, uncached, selected = [], [], []
    for article in candidates:
        cached = cached_reports.get(article["id"])
        try:
            fresh = datetime.fromisoformat(cached["investigated_at"]) >= cutoff
        except (KeyError, TypeError, ValueError):
            fresh = False
        if fresh:
            reports.append(cached)
            continue
        decision = cached_triage.get(article["id"])
        try:
            decision_fresh = datetime.fromisoformat(decision["evaluated_at"]) >= cutoff
        except (KeyError, TypeError, ValueError):
            decision_fresh = False
        if decision_fresh:
            if decision.get("investigate") is True:
                selected.append((article, decision))
        else:
            uncached.append(article)

    if uncached:
        triage = await _complete(
            url=llm_url, model=llm_model, timeout=llm_timeout, max_tokens=900,
            system=(
                "You are a cautious incident triage editor. Decide which stories need deeper analysis. "
                "Investigate only when the realistic cause is not already established and learning it "
                "would be operationally useful. Do not investigate routine updates, blocked scanners, "
                "media additions, or clearly harmless isolated noise. Return only JSON as "
                '{"decisions":[{"id":"...","investigate":true,"reason":"..."}]}. '
                "Timing alone never proves causation."
            ), payload={"stories": uncached},
        )
        decisions = triage.get("decisions", []) if isinstance(triage, dict) else []
        by_id = {str(item.get("id")): item for item in decisions if isinstance(item, dict)}
        evaluated_at = datetime.now(timezone.utc).isoformat()
        for article in uncached:
            raw_decision = by_id.get(article["id"], {})
            decision = {
                "evaluated_at": evaluated_at,
                "investigate": raw_decision.get("investigate") is True,
                "reason": _clean(raw_decision.get("reason"), 400),
            }
            cached_triage[article["id"]] = decision
            if decision["investigate"]:
                selected.append((article, decision))

    for article, decision in selected[:MAX_INVESTIGATIONS]:
        raw = await _complete(
            url=llm_url, model=llm_model, timeout=llm_timeout, max_tokens=1400,
            system=(
                "You are the read-only Investigation Desk for a homelab newspaper. Analyze only "
                "the supplied evidence. Separate observation from inference and prefer the narrowest "
                "cause consistent with the data. Never claim you ran a check absent from the packet. "
                "Next checks must be read-only and must not change configuration, restart services, "
                "install software, or remediate. Return only JSON with finding, confidence "
                "(low/medium/high), impact, evidence (array), alternatives (array), next_checks "
                "(array), and limitations."
            ), payload=build_evidence(article, issues, events, correlations),
        )
        report = _validate_report(raw, article, str(decision.get("reason") or "Cause unresolved"))
        if report:
            reports.append(report)
            cached_reports[article["id"]] = report
    save_json(cache_path, {"updated_at": datetime.now(timezone.utc).isoformat(),
                           "triage": cached_triage, "reports": cached_reports})

    candidate_ids = {article["id"] for article in candidates}
    return [report for report in reports
            if isinstance(report, dict) and report.get("id") in candidate_ids][:MAX_INVESTIGATIONS]


def persist_investigations(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge REPORTS into the durable Investigation Desk archive.

    Under an inter-process ``fcntl`` lock on ``INVESTIGATIONS_ARCHIVE_FILE``, loads the
    existing archive list and appends only the reports whose ``id`` is not already present,
    so repeated calls and concurrent workers are idempotent (no duplicates). Persists via
    ``save_json`` (which applies redaction and atomic replace) and returns ONLY the newly
    appended subset, so the caller retains exactly those to Hindsight. Empty input is a
    no-op that returns ``[]`` and leaves the archive untouched.
    """
    if not reports:
        return []
    path = config.INVESTIGATIONS_ARCHIVE_FILE
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    lock_path = f"{path}.lock"
    with open(lock_path, "a", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            existing = [r for r in (load_json(path) or []) if isinstance(r, dict) and r.get("id")]
            present = {r["id"] for r in existing}
            new_reports = [
                r for r in reports
                if isinstance(r, dict) and r.get("id") and r["id"] not in present
            ]
            if new_reports:
                archive = existing + new_reports
                save_json(path, archive)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
    return new_reports

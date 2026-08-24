"""Build cached, evidence-linked operational trend intelligence with Hindsight."""

import asyncio
import logging
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from typing import Any

import httpx

from config import (
    ARCHIVE_DIR,
    ARCHIVE_INDEX,
    HINDSIGHT_BANK,
    HINDSIGHT_URL,
    TREND_REFLECTION_TIMEOUT,
    TREND_INTELLIGENCE_FILE,
    TREND_REFRESH_INTERVAL,
)
from runtime import run_loop
from storage import load_json, save_json


log = logging.getLogger("trends")

_WINDOWS = {"7d": 7, "30d": 30, "90d": 90}
_DIRECTIONS = {"emerging", "improving", "worsening", "persistent", "cyclical", "resolved"}
_CONFIDENCE = {"low", "medium", "high"}
_MAX_FINDINGS = 6

_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "overview": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "summary": {"type": "string"},
                    "window": {"type": "string", "enum": sorted(_WINDOWS)},
                    "direction": {"type": "string", "enum": sorted(_DIRECTIONS)},
                    "confidence": {"type": "string", "enum": sorted(_CONFIDENCE)},
                    "evidence_dates": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": [
                    "title", "summary", "window", "direction", "confidence",
                    "evidence_dates",
                ],
                "additionalProperties": False,
            },
        },
        "watchlist": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["overview", "findings", "watchlist"],
    "additionalProperties": False,
}


def _archive_dates() -> list[str]:
    """Return valid archive dates, newest first, limited to the last 90 days."""
    index = load_json(ARCHIVE_INDEX) or []
    cutoff = datetime.now(timezone.utc).date() - timedelta(days=90)
    dates: list[str] = []
    for entry in index:
        value = str(entry.get("date") or "") if isinstance(entry, dict) else ""
        try:
            parsed = date.fromisoformat(value)
        except ValueError:
            continue
        if parsed >= cutoff:
            dates.append(value)
    return dates


def build_measurements(archive_dates: list[str]) -> dict[str, dict[str, Any]]:
    """Compute deterministic window statistics from archived editions."""
    today = datetime.now(timezone.utc).date()
    output: dict[str, dict[str, Any]] = {}
    for label, days in _WINDOWS.items():
        cutoff = today - timedelta(days=days - 1)
        editions = 0
        article_count = 0
        sections: Counter[str] = Counter()
        for date_string in archive_dates:
            try:
                if date.fromisoformat(date_string) < cutoff:
                    continue
            except ValueError:
                continue
            record = load_json(f"{ARCHIVE_DIR}/{date_string}.json") or {}
            articles = record.get("newspaper") or []
            editions += 1
            article_count += len(articles)
            sections.update(
                str(article.get("section") or "City Hall")
                for article in articles
                if isinstance(article, dict)
            )
        output[label] = {
            "editions": editions,
            "articles": article_count,
            "top_sections": [
                {"section": section, "articles": count}
                for section, count in sections.most_common(3)
            ],
        }
    return output


def validate_reflection(raw: object, archive_dates: list[str]) -> dict[str, Any] | None:
    """Clamp Hindsight output and retain only links to existing archive dates."""
    if not isinstance(raw, dict):
        return None
    valid_dates = set(archive_dates)
    findings: list[dict[str, Any]] = []
    for candidate in raw.get("findings") or []:
        if not isinstance(candidate, dict):
            continue
        window = str(candidate.get("window") or "")
        direction = str(candidate.get("direction") or "")
        confidence = str(candidate.get("confidence") or "")
        if window not in _WINDOWS or direction not in _DIRECTIONS or confidence not in _CONFIDENCE:
            continue
        title = str(candidate.get("title") or "").strip()[:180]
        summary = str(candidate.get("summary") or "").strip()[:800]
        if not title or not summary:
            continue
        evidence_dates = [
            value for value in candidate.get("evidence_dates") or []
            if isinstance(value, str) and value in valid_dates
        ][:8]
        findings.append({
            "title": title,
            "summary": summary,
            "window": window,
            "direction": direction,
            "confidence": confidence,
            "evidence_dates": list(dict.fromkeys(evidence_dates)),
            "basis": "inferred",
        })
        if len(findings) >= _MAX_FINDINGS:
            break
    overview = str(raw.get("overview") or "").strip()[:1200]
    watchlist = [
        str(item).strip()[:300]
        for item in (raw.get("watchlist") or [])
        if str(item).strip()
    ][:6]
    if not overview and not findings:
        return None
    return {"overview": overview, "findings": findings, "watchlist": watchlist}


async def reflect_on_trends(archive_dates: list[str]) -> dict[str, Any] | None:
    """Ask Hindsight to discover long-range patterns in retained news memories."""
    if not HINDSIGHT_URL or not archive_dates:
        return None
    newest = archive_dates[0]
    oldest = archive_dates[-1]
    query = (
        "Reflect on retained Homelab News memories and identify meaningful operational "
        f"trends between {oldest} and {newest}. Compare 7-day, 30-day, and 90-day windows. "
        "Focus on recurring service issues, improvements, regressions, periodic behavior, "
        "security patterns, backup reliability, update activity, and noteworthy resolutions. "
        "Do not reveal credentials, tokens, private addresses, raw log content, or personal "
        "information. Do not invent exact counts: quantitative claims require multiple dated "
        "memories. Every evidence_dates value must be an ISO date from a supporting newspaper "
        "memory. Put uncertain interpretations at low confidence. The watchlist should contain "
        "only concrete signals worth monitoring next, not predictions presented as facts."
    )
    try:
        async with httpx.AsyncClient(timeout=TREND_REFLECTION_TIMEOUT) as client:
            response = await client.post(
                f"{HINDSIGHT_URL.rstrip('/')}/v1/default/banks/{HINDSIGHT_BANK}/reflect",
                json={
                    "query": query,
                    "budget": "low",
                    "max_tokens": 1800,
                    "exclude_mental_models": True,
                    "response_schema": _RESPONSE_SCHEMA,
                },
            )
            response.raise_for_status()
            return validate_reflection(response.json().get("structured_output"), archive_dates)
    except Exception as error:
        log.warning("Hindsight trend reflection failed: %s: %s", type(error).__name__, error)
        return None


async def refresh_trend_intelligence() -> bool:
    """Publish a new snapshot, preserving the previous one if reflection fails."""
    archive_dates = _archive_dates()
    reflection = await reflect_on_trends(archive_dates)
    if reflection is None:
        log.warning("Trend intelligence refresh produced no reflection; preserving prior snapshot")
        return False
    snapshot = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "archive_range": {
            "newest": archive_dates[0],
            "oldest": archive_dates[-1],
            "editions": len(archive_dates),
        },
        "measurements": build_measurements(archive_dates),
        **reflection,
    }
    save_json(TREND_INTELLIGENCE_FILE, snapshot)
    log.info("Trend intelligence refreshed with %d findings", len(snapshot["findings"]))
    return True


async def main() -> None:
    await run_loop(refresh_trend_intelligence, TREND_REFRESH_INTERVAL, log)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    asyncio.run(main())

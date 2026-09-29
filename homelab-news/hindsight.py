"""Hindsight memory-bank integration.

Best-effort recall and retain calls used to give LLM prompts relevant past
homelab-news context. Every function degrades gracefully to a no-op when
Hindsight is unconfigured or unreachable.
"""

import asyncio
import logging
import time

import httpx
from privacy import redact_data, redact_text

from config import HINDSIGHT_BANK, HINDSIGHT_TIMEOUT, HINDSIGHT_URL
from llm import _sanitize_for_llm, _truncate_to_token_limit

log = logging.getLogger(__name__)

# Hindsight's /recall endpoint rejects queries over HINDSIGHT_API_RECALL_MAX_QUERY_TOKENS
# cl100k tokens (server default 500) with a 400. Stay comfortably under that rather
# than relying on a character count, which is only a rough proxy for token count.
HINDSIGHT_RECALL_MAX_QUERY_TOKENS = 480


async def hindsight_recall(query: str, max_tokens: int = 600) -> str:
    """Recall relevant past homelab-news memories for use as LLM context.

    Best-effort — returns "" if Hindsight is unconfigured or unreachable so
    callers can always fall back to no recall.
    """
    if not HINDSIGHT_URL or not query:
        return ""
    try:
        async with httpx.AsyncClient(timeout=HINDSIGHT_TIMEOUT) as client:
            resp = await client.post(
                f"{HINDSIGHT_URL}/v1/default/banks/{HINDSIGHT_BANK}/memories/recall",
                json={
                    "query": _truncate_to_token_limit(
                        _sanitize_for_llm(query, max_len=6000), HINDSIGHT_RECALL_MAX_QUERY_TOKENS
                    ),
                    "budget": "low",
                    "max_tokens": max_tokens,
                },
            )
            if resp.status_code == 400:
                log.warning("Hindsight rejected recall request (HTTP 400)")
            resp.raise_for_status()
            results = resp.json().get("results", [])
            return redact_text("\n".join(f"- {r['text']}" for r in results if r.get("text")))
    except Exception as e:
        log.warning("Hindsight recall failed: %s: %r", type(e).__name__, e)
        return ""


_TARGETED_RECALL_CACHE: dict[str, tuple[float, str]] = {}


async def hindsight_targeted_recall(queries: list[str]) -> str:
    """Recall focused service history with a six-hour in-process query cache."""
    selected = list(dict.fromkeys(query for query in queries if query))[:2]
    if not selected:
        return ""

    async def _one(query: str) -> str:
        cached = _TARGETED_RECALL_CACHE.get(query)
        if cached and time.time() - cached[0] < 6 * 3600:
            return cached[1]
        result = await hindsight_recall(query, max_tokens=500)
        if result:
            _TARGETED_RECALL_CACHE[query] = (time.time(), result)
        return result

    results = await asyncio.gather(*(_one(query) for query in selected))
    return "\n".join(result for result in results if result)


async def hindsight_retain_newspaper(date_str: str, articles: list[dict]) -> None:
    """Fire-and-forget: store a day's newspaper articles as memories for future recall."""
    if not HINDSIGHT_URL or not articles:
        return
    items = [
        {
            "content":     f"Homelab News on {date_str}: {a['headline']}. {a['blurb']}",
            "context":     f"{a.get('section', 'City Hall')} | archived edition {date_str}",
            "document_id": f"newspaper_{date_str}_{i}",
            "timestamp":   f"{date_str}T12:00:00Z",
        }
        for i, a in enumerate(articles)
    ]
    try:
        async with httpx.AsyncClient(timeout=HINDSIGHT_TIMEOUT) as client:
            resp = await client.post(
                f"{HINDSIGHT_URL}/v1/default/banks/{HINDSIGHT_BANK}/memories",
                json={"items": redact_data(items), "async": True},
            )
            resp.raise_for_status()
    except Exception as e:
        log.warning("Hindsight retain failed for %s: %s", date_str, e)

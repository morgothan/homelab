"""Article-domain validation and parsing.

External model output is untrusted.  This module defines the small data contract
that separates inference from persistence and rendering.
"""

import json
import re
from typing import NotRequired, TypedDict


SECTION_ORDER = (
    "City Hall",
    "Public Safety",
    "Weather",
    "City Archives",
    "Arts & Entertainment",
    "Public Works",
)


class Article(TypedDict):
    """Validated newspaper article stored by the application."""

    headline: str
    blurb: str
    section: str
    source: NotRequired[str]


def validate_articles(raw: object, max_count: int = 16) -> list[Article]:
    """Return bounded, render-safe articles from untrusted model output."""
    if not isinstance(raw, list) or max_count <= 0:
        return []
    valid: list[Article] = []
    for candidate in raw:
        if not isinstance(candidate, dict):
            continue
        if "headline" not in candidate or "blurb" not in candidate:
            continue
        headline = str(candidate["headline"])[:200]
        blurb = str(candidate["blurb"])[:600]
        section = str(candidate.get("section", "City Hall"))[:50]
        if section not in SECTION_ORDER:
            section = "City Hall"
        valid.append({"headline": headline, "blurb": blurb, "section": section})
        if len(valid) >= max_count:
            break
    return valid


def parse_llm_json(content: str) -> list[object]:
    """Parse a model response using strict JSON before bounded recovery attempts."""
    without_fence = re.sub(r"^```(?:json)?\n?", "", content)
    without_fence = re.sub(r"\n?```$", "", without_fence.strip())
    try:
        result = json.loads(without_fence)
        if isinstance(result, list):
            return result
    except json.JSONDecodeError:
        pass

    array_match = re.search(r"\[[\s\S]*\]", without_fence)
    if array_match:
        try:
            result = json.loads(array_match.group(0))
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            pass

    articles: list[object] = []
    for object_match in re.finditer(r"\{[^{}]+\}", without_fence, re.DOTALL):
        try:
            candidate = json.loads(object_match.group(0))
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict) and "headline" in candidate and "blurb" in candidate:
            articles.append(candidate)
    return articles

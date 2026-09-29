"""LLM primitives and inference calls.

Owns the low-level safeguards shared by every LLM prompt (token limiting,
message compression, prompt-injection sanitisation) plus the three inference
features that produce prose: per-log ``llm_analysis``, per-image changelog
summaries, and the Wire Reports ``generate_homelab_intel``. The newspaper
edition generator stays in ``lib`` because it orchestrates many collectors.
"""

import asyncio
import json
import logging
import re
from typing import Optional

import httpx
import tiktoken
from privacy import redact_data, redact_text

from config import (
    CONTEXT_FILE, LOCAL, OLLAMA_TIMEOUT, VLLM_MODEL, VLLM_URL,
)

log = logging.getLogger(__name__)

_CL100K_ENCODING = tiktoken.get_encoding("cl100k_base")

_LLM_URL   = VLLM_URL
_LLM_MODEL = VLLM_MODEL


def _truncate_to_token_limit(text: str, max_tokens: int) -> str:
    tokens = _CL100K_ENCODING.encode(text)
    if len(tokens) <= max_tokens:
        return text
    return _CL100K_ENCODING.decode(tokens[:max_tokens])


try:
    from headroom import compress as _headroom_compress, CompressConfig as _HeadroomConfig
    _HEADROOM_AVAILABLE = True
    # onnxruntime isn't installed (kompress_model="disabled" below means we never need
    # the ML tier), so headroom's native core warns on every call before falling back
    # to its unidiff tier. That fallback is what we want; the warning is just noise.
    logging.getLogger("headroom_core.transforms.detection").setLevel(logging.ERROR)
except ImportError:
    _HEADROOM_AVAILABLE = False


# Compress LLM messages before dispatch. Uses SmartCrusher for JSON arrays (up to 86%
# savings) and falls back transparently if headroom is unavailable or raises.
def _compress_messages(messages: list[dict]) -> list[dict]:
    messages = redact_data(messages)
    if not _HEADROOM_AVAILABLE:
        return messages
    try:
        result = _headroom_compress(messages, model="gpt-4o", config=_HeadroomConfig(
            compress_user_messages=True,
            compress_system_messages=False,
            protect_recent=0,
            protect_analysis_context=False,
            kompress_model="disabled",
        ))
        return result.messages
    except Exception as e:
        log.debug("Headroom compression failed; using uncompressed messages: %s", e)
    return messages


# Patterns that indicate a prompt injection attempt in untrusted text.
# Applied before embedding external data (log messages, probe paths, changelog
# summaries) into LLM prompts. Matches are replaced with [FILTERED] to preserve
# context length without amplifying the payload.
_INJECTION_PATTERNS = re.compile(
    r'ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions?'
    r'|disregard\s+(?:the\s+)?(?:above|previous|prior|all)'
    r'|forget\s+(?:your\s+)?instructions?'
    r'|new\s+(?:task|instructions?|objective)'
    r'|override\s+(?:all\s+)?(?:instructions?|rules?|directives?)'
    r'|you\s+are\s+now\s+(?:a\s+)?(?:an?\s+)?(?:\w+\s+)*(?:assistant|bot|model|AI)'
    r'|\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>|</?s>'
    r'|\]\s*output\s*\[|output\s+json\s*:|output\s+only\s+json'
    r'|\[\{"headline"|\[\s*\{\s*"headline"'
    # Gemma and generic role-turn delimiters (prompt injection via turn-switching)
    r'|<start_of_turn>|<end_of_turn>'
    r'|<\|user\|>|<\|assistant\|>|<\|system\|>'
    '\n\nHuman:|\n\nAssistant:',   # non-raw so \n matches actual newlines
    re.I,
)


def _sanitize_for_llm(text: str, max_len: int = 200) -> str:
    """Sanitize untrusted text before embedding it in an LLM prompt.

    Replaces injection trigger phrases with [FILTERED] and truncates.
    Used for log messages, HTTP paths, and LLM-generated text that feeds
    into a second LLM call (e.g. changelog summaries → newspaper prompt).
    """
    sanitized = _INJECTION_PATTERNS.sub("[FILTERED]", redact_text(text))
    return sanitized[:max_len]


# SIP desk/DECT phones (Grandstream, Yealink) prefix every syslog line with
# [MAC][firmware-version] and sometimes [pid]. The version (e.g. 1.0.3.25) is a dotted quad that
# an IP regex would otherwise mistake for a source IP and aggregate on, producing
# bogus "N patterns from 1.0.3.25" groups and "a device at 1.0.3.25" blurbs.
from security import _label_sip_phone_prefix  # noqa: E402,F401


def _load_context() -> str:
    """Load optional homelab context file from /data/context.md.
    Returns empty string if the file doesn't exist."""
    try:
        with open(CONTEXT_FILE) as f:
            ctx = f.read().strip()
        if VLLM_MODEL:
            ctx = (
                "## Live Config (authoritative, overrides anything below)\n"
                f"- Currently loaded vLLM model on spark.{LOCAL}: `{VLLM_MODEL}`\n\n"
            ) + ctx
        return _sanitize_for_llm(ctx, max_len=12000)
    except FileNotFoundError:
        return ""
    except Exception as e:
        log.warning("Could not read context.md: %s", e)
        return ""


async def llm_analysis(issues: list[dict], context: str) -> Optional[str]:
    if not issues:
        return None
    from hindsight import hindsight_recall

    ranked = sorted(issues, key=lambda i: (i["level"] != "error", -i["count"]))[:10]
    sanitized_issues = [
        {
            "source": i["source"],
            "level":  i["level"].upper(),
            "count":  i["count"],
            "message": _sanitize_for_llm(_label_sip_phone_prefix(i["message"]), max_len=140),
        }
        for i in ranked
    ]
    ctx = _load_context()
    recalled = await hindsight_recall(
        context + "\n" + "\n".join(i["message"] for i in sanitized_issues[:5])
    )
    system = (
        "Homelab log analysis."
        + (f"\n\nHOMELAB CONTEXT:\n{ctx}" if ctx else "")
        + (f"\n\nRELEVANT PAST INCIDENTS (from memory — reference if directly relevant):\n{recalled}" if recalled else "")
        + "\n\nFor each entry: one line saying what it means, one line starting with '→' "
        "saying what to do. If it is harmless noise, write 'Noise: <reason>'. No preamble.\n"
        "A high-volume 'network unreachable'/'send failed' from a single daemon (ntpd, chronyd) "
        "on one host is a stuck or misconfigured daemon on that host — not a network outage; "
        "say so plainly and keep the fix scoped to that host."
    )
    user = json.dumps({"context": context, "entries": sanitized_issues}, indent=2)
    messages = _compress_messages([
        {"role": "system", "content": system},
        {"role": "user",   "content": user},
    ])
    try:
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
            resp = await client.post(
                f"{_LLM_URL}/v1/chat/completions",
                json={
                    "model": _LLM_MODEL,
                    "messages": messages,
                    "stream": False,
                    "max_tokens": 500,
                    "temperature": 0.1,
                    "chat_template_kwargs": {"enable_thinking": False},
                },
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        log.warning("LLM analysis failed (%s): %s", type(e).__name__, e)
        return None


async def llm_changelog_analysis(container: str, image: str, tag: str, notes: str) -> Optional[str]:
    if not notes:
        return None
    safe_image = _sanitize_for_llm(image, max_len=100)
    safe_tag   = _sanitize_for_llm(tag, max_len=50)
    safe_notes = _sanitize_for_llm(notes, max_len=2500)
    ctx = _load_context()
    ctx_block = (
        f"HOMELAB CONTEXT (use to flag breaking changes that affect this specific setup):\n{ctx}\n\n"
        if ctx else ""
    )
    system = (
        f"You are summarising a Docker image update for a homelab operator.\n"
        + ctx_block
        + "Write exactly 1-2 sentences describing what changed. Rules:\n"
        "- You MUST output something — never leave the response blank.\n"
        "- If the notes describe real changes (features, bug fixes, security patches), summarise them.\n"
        "- If the notes are sparse or this is just a base-image/container rebuild, say so: "
        "e.g. 'Container rebuild (ls456→ls457); qbittorrent application version unchanged at 5.2.0.'\n"
        "- Lead with any breaking changes or required migration steps if present.\n"
        "- If the homelab context is provided and the changelog contains breaking changes or config\n"
        "  migrations that affect services described in that context, flag them explicitly.\n"
        "Output only the 1-2 sentence summary. No headers, no bullet points, no preamble."
    )
    user = f"Image: {safe_image}  New tag: {safe_tag}\n\nRELEASE NOTES:\n{safe_notes}"
    messages = _compress_messages([
        {"role": "system", "content": system},
        {"role": "user",   "content": user},
    ])
    try:
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
            resp = await client.post(
                f"{_LLM_URL}/v1/chat/completions",
                json={
                    "model": _LLM_MODEL,
                    "messages": messages,
                    "stream": False,
                    "max_tokens": 1500,
                    "temperature": 0.1,
                    "chat_template_kwargs": {"enable_thinking": False},
                },
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        log.warning("Changelog LLM failed for %s: %s", container, e)
        return None


async def generate_homelab_intel(docker_hosts: dict, sources: dict) -> Optional[list[dict]]:
    """Generate newspaper articles summarising all available homelab software updates."""
    from articles import parse_llm_json, validate_articles

    lines: list[str] = []

    docker_updates: list[str] = []
    for label, host in docker_hosts.items():
        for r in host.get("results", []):
            if r["status"] != "update_available":
                continue
            ver = f" (update available: {r.get('new_version', '')})" if r.get("new_version") else ""
            cl  = _sanitize_for_llm(r.get("changelog_analysis", ""), max_len=120)
            docker_updates.append(
                f"  {label}/{r['container']}: {r['image']}{ver}" + (f" — {cl}" if cl else "")
            )
    if docker_updates:
        lines.append(f"DOCKER IMAGE UPDATES ({len(docker_updates)} available):")
        lines.extend(docker_updates[:20])
    else:
        lines.append("DOCKER: all images current")

    for key, src in sources.items():
        lbl    = src.get("label", key)
        status = src.get("status", "unknown")
        if status == "error":
            err = _sanitize_for_llm(src.get("error", "unknown"), max_len=80)
            lines.append(f"{lbl.upper()}: check failed — {err}")
            continue
        updates = src.get("updates", [])
        if not updates:
            cur = src.get("current_version", "")
            lines.append(f"{lbl.upper()}: current" + (f" (v{cur})" if cur else ""))
            continue
        for u in updates:
            pkg = _sanitize_for_llm(u.get("package") or u.get("app", "?"), max_len=60)
            cur = _sanitize_for_llm(u.get("current_version", "?"), max_len=30)
            new = _sanitize_for_llm(u.get("new_version", "?"), max_len=30)
            cl  = _sanitize_for_llm(u.get("changelog_analysis", ""), max_len=150)
            lines.append(
                f"{lbl.upper()} UPDATE AVAILABLE: {pkg} {cur} (update available: {new})"
                + (f" — {cl}" if cl else "")
            )

    situation = "\n".join(lines)
    ctx = _load_context()
    ctx_block = (
        f"HOMELAB CONTEXT:\n{ctx}\n\n" if ctx else ""
    )
    system = (
        "You are the software intelligence desk editor for a homelab newspaper.\n\n"
        + ctx_block
        + "Write 2–6 newspaper articles summarising the available software updates below.\n\n"
        "Rules:\n"
        "- Everything below is a PENDING update that has NOT been installed yet — nothing has\n"
        "  been upgraded, rebuilt, or refreshed. Write headlines/blurbs as availability, not\n"
        "  completed action: say 'Update Available for X' or 'X Update Pending', never 'X Jumps to',\n"
        "  'X Upgraded to', 'saw an update', 'now running', or any other past-tense/completed phrasing.\n"
        "- Lead with security patches and kernel updates (most urgent).\n"
        "- Group related items: multiple *arr app updates = 1 article; Docker rebuilds = 1 article.\n"
        "- If everything is current, write a single brief 'All Systems Current' article.\n"
        "- Name specific packages and version numbers in blurbs.\n"
        "- Blurbs: 2 sentences, AP wire style, specific and factual.\n"
        "- Assign sections: 'City Hall' (app/container updates), 'Public Safety' (security/CVE),\n"
        "  'Weather' (system/kernel), 'Arts & Entertainment' (Jellyfin/media), 'Public Works' (DNS/network).\n"
        "- Output ONLY a valid JSON array. No markdown, no explanation.\n"
        "  Format: [{\"headline\": \"...\", \"blurb\": \"...\", \"section\": \"City Hall\"}]"
    )
    messages = _compress_messages([
        {"role": "system", "content": system},
        {"role": "user",   "content": f"SOFTWARE UPDATE STATUS:\n{situation}"},
    ])
    try:
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
            resp = await client.post(
                f"{_LLM_URL}/v1/chat/completions",
                json={
                    "model": _LLM_MODEL,
                    "messages": messages,
                    "stream": False,
                    "max_tokens": 2000,
                    "temperature": 0.3,
                    "chat_template_kwargs": {"enable_thinking": False},
                },
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"].strip()
            articles = parse_llm_json(content)
            if articles:
                valid = validate_articles(articles, max_count=10)
                if valid:
                    return valid
    except Exception as e:
        log.warning("generate_homelab_intel failed (%s): %s", type(e).__name__, e)
    return None

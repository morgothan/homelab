"""Authenticate Seerr events before reading a bounded request body."""

import hmac
import json

from fastapi import HTTPException, Request
from config import SEERR_SETTINGS_FILE

MAX_WEBHOOK_BYTES = 16 * 1024


def webhook_authorization() -> str:
    """Read Seerr's configured header; missing credentials fail closed."""
    try:
        with open(SEERR_SETTINGS_FILE, encoding="utf-8") as source:
            settings = json.load(source)
        value = settings["notifications"]["agents"]["webhook"]["options"]["authHeader"]
        return value if isinstance(value, str) else ""
    except (OSError, ValueError, KeyError, TypeError):
        return ""


async def authenticated_payload(request: Request) -> object:
    expected = webhook_authorization()
    if not expected:
        raise HTTPException(503, "Webhook authentication is not configured")
    supplied = request.headers.get("authorization", "")
    if not hmac.compare_digest(supplied.encode(), expected.encode()):
        raise HTTPException(401, "Invalid webhook credentials")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_WEBHOOK_BYTES:
            raise HTTPException(413, "Webhook payload is too large")
        body.extend(chunk)
    try:
        return json.loads(body)
    except (ValueError, UnicodeError):
        raise HTTPException(400, "Invalid JSON") from None

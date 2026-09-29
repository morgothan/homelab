"""Remove credentials from operational text before publication or inference."""

import os
import re

_CREDENTIAL = re.compile(
    r'''(?i)(\b(?:password|passwd|secret|access[_-]?token|refresh[_-]?token|token|api[_-]?key)\b["']?\s*[:=]\s*)("[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&]+)'''
)
_AUTH = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
_USERINFO = re.compile(r"(?i)(https?://)[^\s/@]+:[^\s/@]+@")
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S)
_KNOWN_SECRETS = tuple(sorted({
    value for key, value in os.environ.items()
    if re.search(r"(?:PASSWORD|PASS|TOKEN|SECRET|KEY)$", key)
    and len(value) >= 8 and not value.startswith("/")
    and value.lower() not in {"password", "changeme", "redacted"}
}, key=len, reverse=True))


def redact_text(text: str) -> str:
    """Preserve diagnostic context while removing common secret representations."""
    text = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", text)
    for secret in _KNOWN_SECRETS:
        text = text.replace(secret, "[REDACTED]")
    text = _AUTH.sub(lambda m: f"{m[1]} [REDACTED]", text)
    text = _USERINFO.sub(r"\1[REDACTED]@", text)
    return _CREDENTIAL.sub(lambda m: m[1] + '"[REDACTED]"', text)


def redact_data(value):
    """Redact nested snapshot strings without changing their JSON shape."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, dict):
        return {
            key: ("[REDACTED]" if re.fullmatch(
                r"(?i)(password|passwd|secret|authorization|access_token|refresh_token|api[_-]?key)", str(key)
            ) else redact_data(item))
            for key, item in value.items()
        }
    return value

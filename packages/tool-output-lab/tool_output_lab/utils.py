"""Small deterministic helpers shared by the harness."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


def canonical_json(value: Any) -> str:
    """Serialize a value in a stable form suitable for hashing and comparison."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def sha256_text(value: str) -> str:
    """Return the hexadecimal SHA-256 digest of UTF-8 text."""

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def stable_identifier(prefix: str, *parts: object, length: int = 16) -> str:
    """Build a readable deterministic identifier from canonical string parts."""

    material = "\x1f".join(str(part) for part in parts)
    return f"{prefix}-{sha256_text(material)[:length]}"


_SENSITIVE_PATTERNS = (
    re.compile(r"AIza[0-9A-Za-z_-]{20,}"),
    re.compile(r"gsk_[0-9A-Za-z_-]{20,}"),
    re.compile(
        r"(?i)(authorization\s*:\s*bearer\s+)"
        r"[0-9A-Za-z._~+/=-]{8,}"
    ),
    re.compile(
        r"(?i)(GEMINI_API_KEY\s*[=:]\s*)"
        r"[^\s,;]+"
    ),
    re.compile(
        r"(?i)(GROQ_API_KEY\s*[=:]\s*)"
        r"[^\s,;]+"
    ),
)


def redact_sensitive_text(
    value: object,
    *,
    secrets: tuple[str, ...] = (),
    limit: int = 500,
) -> str:
    """Return a bounded error string with credential-shaped values removed."""

    redacted = str(value)
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "[REDACTED]")
    for pattern in _SENSITIVE_PATTERNS:
        redacted = pattern.sub(
            lambda match: (
                f"{match.group(1)}[REDACTED]"
                if match.lastindex
                else "[REDACTED]"
            ),
            redacted,
        )
    if len(redacted) > limit:
        return f"{redacted[:limit]}…"
    return redacted

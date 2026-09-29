"""Versioned judgment character policies; these are not language detectors.

The historical ASCII parser remains unchanged. The opt-in policy preserves exact
text while accepting a fixed list of English typography and spacing characters.
"""

from __future__ import annotations

import json
import math
import re

from agentdojo_lab import counterfactual as legacy

ASCII_FORMAT = "ascii_v1"
ENGLISH_PUNCTUATION_FORMAT = "english_punctuation_v1"
FORMATS = (ASCII_FORMAT, ENGLISH_PUNCTUATION_FORMAT)
# Hyphens/dashes, quotation marks, ellipsis, and common typographic spaces.
# No script letters, bidi marks, zero-width characters, or arbitrary Unicode
# punctuation classes are admitted by this bounded policy.
TYPOGRAPHY = frozenset(
    chr(codepoint)
    for codepoint in (
        0x00A0,
        *range(0x2000, 0x200B),
        *range(0x2010, 0x2016),
        *range(0x2018, 0x2020),
        0x2026,
        0x202F,
    )
)


def validate_format(name: str) -> str:
    if name not in FORMATS:
        raise ValueError("Unknown judgment format")
    return name


def supported_text(text: str) -> bool:
    return all(
        32 <= ord(character) <= 126 or character in "\n\t\r" or character in TYPOGRAPHY
        for character in text
    )


def contains_unsupported_characters(text: str) -> bool:
    """Inspect response JSON and nested content JSON without lossy unescaping."""
    pending, inspected = [(text, 0)], 0
    while pending:
        value, decodings = pending.pop()
        inspected += 1
        if inspected > legacy.LIMITS["call_json_nodes"]:
            return True
        if isinstance(value, dict):
            pending.extend((item, decodings) for pair in value.items() for item in pair)
        elif isinstance(value, list):
            pending.extend((item, decodings) for item in value)
        elif isinstance(value, str):
            if not supported_text(value):
                return True
            try:
                decoded = json.loads(value)
            except (ValueError, TypeError):
                continue
            except (RecursionError, OverflowError):
                return True
            if decoded != value:
                if decodings >= 4:
                    return True
                pending.append((decoded, decodings + 1))
    return False


def metadata() -> dict:
    return {
        "name": ENGLISH_PUNCTUATION_FORMAT,
        "allowed_non_ascii_codepoints": [f"U+{ord(c):04X}" for c in sorted(TYPOGRAPHY)],
        "ascii_controls_allowed": ["TAB", "LF", "CR"],
        "requires_ascii_letter": True,
        "scope": "bounded_character_policy_only; not_general_language_detection",
        "text_normalization": "none; exact_validated_reasoning_preserved",
    }


def parse_judgment(raw: str, *, judgment_format: str = ASCII_FORMAT) -> dict:
    validate_format(judgment_format)
    if judgment_format == ASCII_FORMAT:
        return legacy.parse_judgment(raw)
    invalid = {"status": "invalid", "reason": "invalid_judgment_schema"}
    if not isinstance(raw, str) or len(raw) > legacy.LIMITS["judgment_codepoints"]:
        return {"status": "invalid", "reason": "judgment_input_budget_or_type"}

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate judgment key")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError())
        )
        if not isinstance(value, dict) or set(value) != {"would_call_anyway", "confidence", "reasoning"}:
            return invalid
        confidence, reasoning = value["confidence"], value["reasoning"]
        if (
            type(value["would_call_anyway"]) is not bool
            or type(confidence) not in (int, float)
            or not math.isfinite(confidence)
            or not 0 <= confidence <= 1
            or not isinstance(reasoning, str)
            or not reasoning.strip()
            or not re.search(r"[A-Za-z]", reasoning)
            or not supported_text(reasoning)
        ):
            return invalid
        return {"status": "valid", "judgment": value}
    except (ValueError, TypeError, RecursionError, OverflowError):
        return invalid

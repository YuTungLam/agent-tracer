"""Pure lexical evidence; matching scores do not establish source attribution.

The NT-style score follows the paper's LCS/minimum-length formula and ordinary
0.15 threshold. Unicode code-point units, no normalization, and the explicit
resource limits below are implementation choices, not verified author defaults.
"""

import math

MAX_LCS_CODEPOINTS_PER_INPUT = 65_536
MAX_LCS_LENGTH_PRODUCT = 67_108_864
_CONNECTED_PUNCTUATION = frozenset("_@./:+-")


def _require_strings(source: str, target: str) -> None:
    if not isinstance(source, str) or not isinstance(target, str):
        raise TypeError("source and target must be strings")


def _connected(character: str) -> bool:
    return character.isalnum() or character in _CONNECTED_PUNCTUATION


def exact_spans(source: str, target: str, *, min_length: int = 3) -> list[tuple[int, int]]:
    """Return all bounded full-target matches as half-open code-point ranges.

    An adjacent alphanumeric character or ``_@./:+-`` disqualifies a match. No case
    folding or Unicode normalization occurs. Overlapping valid matches are retained.
    """
    _require_strings(source, target)
    if isinstance(min_length, bool) or not isinstance(min_length, int) or min_length < 1:
        raise ValueError("min_length must be a positive integer")
    if not target or len(target) < min_length:
        return []

    spans = []
    start = 0
    while (index := source.find(target, start)) != -1:
        end = index + len(target)
        before_ok = index == 0 or not _connected(source[index - 1])
        after_ok = end == len(source) or not _connected(source[end])
        if before_ok and after_ok:
            spans.append((index, end))
        start = index + 1
    return spans


def _lcs_length(source: str, target: str) -> int:
    """Compute exact subsequence length with the shorter string as a bit vector."""
    if len(source) < len(target):
        source, target = target, source
    masks: dict[str, int] = {}
    for index, character in enumerate(target):
        masks[character] = masks.get(character, 0) | (1 << index)
    row = 0
    for character in source:
        matches = masks.get(character, 0) | row
        row = matches & ~(matches - ((row << 1) | 1))
    return row.bit_count()


def lcs_evidence(source: str, target: str, *, threshold: float = 0.15) -> dict:
    """Return bounded exact LCS evidence without short-argument filtering.

    For ``not_applicable`` and ``budget_exceeded``, score and LCS length are None.
    The required boolean ``matched`` is False for these unscored states; callers
    must check ``status`` before interpreting it as an evaluated nonmatch. Inputs
    are never truncated or replaced by an approximate similarity measure.
    """
    _require_strings(source, target)
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not math.isfinite(threshold)
        or not 0 <= threshold <= 1
    ):
        raise ValueError("threshold must be a finite number between 0 and 1")

    source_length, target_length = len(source), len(target)
    result = {
        "method": "nt_style_lcs_v1",
        "status": "not_applicable",
        "score": None,
        "lcs_length": None,
        "source_length": source_length,
        "target_length": target_length,
        "threshold": threshold,
        "matched": False,
        "metadata": {
            "unit": "unicode_codepoint",
            "case_sensitive": True,
            "normalization": "none",
            "algorithm": "exact_bitset_longest_common_subsequence",
            "limits": {
                "max_codepoints_per_input": MAX_LCS_CODEPOINTS_PER_INPUT,
                "max_length_product": MAX_LCS_LENGTH_PRODUCT,
            },
            "exceeded_limits": [],
        },
    }
    if not source_length or not target_length:
        return result

    exceeded = result["metadata"]["exceeded_limits"]
    if max(source_length, target_length) > MAX_LCS_CODEPOINTS_PER_INPUT:
        exceeded.append("max_codepoints_per_input")
    if source_length * target_length > MAX_LCS_LENGTH_PRODUCT:
        exceeded.append("max_length_product")
    if exceeded:
        result["status"] = "budget_exceeded"
        return result

    length = _lcs_length(source, target)
    score = length / min(source_length, target_length)
    result.update(status="scored", score=score, lcs_length=length, matched=score >= threshold)
    return result

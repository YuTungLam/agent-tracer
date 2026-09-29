import itertools
import math

import pytest

from agentdojo_lab import lexical
from agentdojo_lab.lexical import exact_spans, lcs_evidence


def _reference_lcs(source, target):
    table = [[0] * (len(target) + 1) for _ in range(len(source) + 1)]
    for i, left in enumerate(source, start=1):
        for j, right in enumerate(target, start=1):
            table[i][j] = table[i - 1][j - 1] + 1 if left == right else max(table[i - 1][j], table[i][j - 1])
    return table[-1][-1]


def test_exact_spans_returns_all_half_open_positions_and_preserves_case():
    assert exact_spans("cat, cat! CAT cat", "cat") == [(0, 3), (5, 8), (14, 17)]
    assert exact_spans("a a a", "a a") == [(0, 3), (2, 5)]


@pytest.mark.parametrize("connected", list("A9中_@./:+-"))
def test_exact_spans_rejects_connected_characters_on_either_side(connected):
    assert exact_spans(f"{connected}cat cat{connected}", "cat") == []


def test_exact_spans_distinguishes_identifiers_and_email_substrings():
    assert exact_spans("5 2025 15 5", "5", min_length=1) == [(0, 1), (10, 11)]
    assert exact_spans("a@example.com example.com", "example.com") == [(14, 25)]
    assert exact_spans("[ref-123] ref-1234", "ref-123") == [(1, 8)]


def test_exact_spans_unicode_offsets_and_no_normalization():
    assert exact_spans("🧪 (名字甲) 名字甲", "名字甲") == [(3, 6), (8, 11)]
    assert exact_spans("cafe\u0301 café", "café") == [(6, 10)]


@pytest.mark.parametrize("source,target", [("", "cat"), ("cat", ""), ("ab", "ab")])
def test_exact_spans_empty_or_short_target_does_not_match(source, target):
    assert exact_spans(source, target) == []


@pytest.mark.parametrize("minimum", [0, -1, 1.5, True, None])
def test_exact_spans_rejects_invalid_minimum(minimum):
    with pytest.raises(ValueError):
        exact_spans("abc", "abc", min_length=minimum)


def test_lcs_matches_subsequences_not_only_contiguous_substrings():
    result = lcs_evidence("aXbYc", "abc")
    assert result["lcs_length"] == 3
    assert result["score"] == 1.0
    assert result["matched"] is True
    assert result["method"] == "nt_style_lcs_v1"
    assert result["metadata"]["unit"] == "unicode_codepoint"
    assert result["metadata"]["normalization"] == "none"


@pytest.mark.parametrize(
    "source,target,length",
    [("aaaa", "aa", 2), ("abba", "baab", 2), ("🧪中🙂", "中🧪🙂", 2), ("ABC", "abc", 0)],
)
def test_lcs_repeated_characters_unicode_and_case(source, target, length):
    result = lcs_evidence(source, target)
    assert result["status"] == "scored"
    assert result["lcs_length"] == length
    assert result["score"] == length / min(len(source), len(target))


def test_lcs_keeps_short_argument_high_scores():
    result = lcs_evidence("2025", "5")
    assert result["source_length"] == 4
    assert result["target_length"] == 1
    assert result["score"] == 1.0
    assert result["matched"] is True


def test_lcs_threshold_equality_and_next_float():
    source, target = "abcdefghijklmnopqrst", "abc" + "Z" * 17
    result = lcs_evidence(source, target)
    assert result["score"] == 0.15
    assert result["matched"] is True
    assert lcs_evidence(source, target, threshold=math.nextafter(0.15, 1))["matched"] is False
    assert lcs_evidence("a", "b", threshold=0)["matched"] is True


@pytest.mark.parametrize("source,target", [("", ""), ("", "a"), ("a", "")])
def test_empty_lcs_inputs_are_not_applicable(source, target):
    result = lcs_evidence(source, target)
    assert result["status"] == "not_applicable"
    assert result["score"] is None
    assert result["lcs_length"] is None
    assert result["matched"] is False
    assert result["metadata"]["exceeded_limits"] == []


@pytest.mark.parametrize("threshold", [-0.01, 1.01, math.nan, math.inf, -math.inf, True, "0.15"])
def test_lcs_rejects_invalid_threshold(threshold):
    with pytest.raises(ValueError):
        lcs_evidence("a", "a", threshold=threshold)


def test_lcs_length_budget_retains_unscored_status_and_limits(monkeypatch):
    def unexpected_scoring(*_):
        raise AssertionError("An over-budget input must not reach the scorer")

    monkeypatch.setattr(lexical, "_lcs_length", unexpected_scoring)
    result = lcs_evidence("a" * (lexical.MAX_LCS_CODEPOINTS_PER_INPUT + 1), "a")
    assert result["status"] == "budget_exceeded"
    assert result["score"] is None
    assert result["lcs_length"] is None
    assert result["matched"] is False
    assert result["metadata"]["exceeded_limits"] == ["max_codepoints_per_input"]
    assert result["metadata"]["limits"] == {
        "max_codepoints_per_input": 65_536,
        "max_length_product": 67_108_864,
    }


def test_lcs_product_budget_and_exact_boundaries(monkeypatch):
    monkeypatch.setattr(lexical, "MAX_LCS_CODEPOINTS_PER_INPUT", 6)
    monkeypatch.setattr(lexical, "MAX_LCS_LENGTH_PRODUCT", 12)
    assert lcs_evidence("aaaaaa", "aa")["score"] == 1.0
    result = lcs_evidence("aaaaa", "aaa")
    assert result["status"] == "budget_exceeded"
    assert result["metadata"]["exceeded_limits"] == ["max_length_product"]
    result = lcs_evidence("aaaaaaa", "aaa")
    assert result["metadata"]["exceeded_limits"] == ["max_codepoints_per_input", "max_length_product"]


def test_exact_bitset_lcs_matches_small_exhaustive_dp_reference():
    strings = ["".join(chars) for size in range(1, 5) for chars in itertools.product("ab中", repeat=size)]
    for source in strings:
        for target in strings:
            result = lcs_evidence(source, target)
            assert result["status"] == "scored"
            assert result["lcs_length"] == _reference_lcs(source, target), (source, target)


@pytest.mark.parametrize("function", [exact_spans, lcs_evidence])
def test_lexical_functions_require_strings(function):
    with pytest.raises(TypeError):
        function(None, "abc")
    with pytest.raises(TypeError):
        function("abc", 123)

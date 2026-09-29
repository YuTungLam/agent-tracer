import copy
import itertools
import json

import pytest

from agentdojo_lab import span_evidence
from agentdojo_lab.lexical import lcs_evidence
from agentdojo_lab.span_evidence import analyze_span_evidence


def _enumerate_alignments(source, target):
    """Enumerate index-pair alignments directly, independently of the DP recurrence."""
    alignments = [()]

    def extend(prefix, source_start, target_start):
        for source_index in range(source_start, len(source)):
            for target_index in range(target_start, len(target)):
                if source[source_index] == target[target_index]:
                    alignment = prefix + ((source_index, target_index),)
                    alignments.append(alignment)
                    extend(alignment, source_index + 1, target_index + 1)

    extend((), 0, 0)
    length = max(map(len, alignments))
    return length, [alignment for alignment in alignments if len(alignment) == length]


def _mask_spans(length, mask):
    spans = []
    for index in range(length):
        if mask & (1 << index):
            if spans and spans[-1][1] == index:
                spans[-1][1] += 1
            else:
                spans.append([index, index + 1])
    return spans


def test_all_optimal_bounds_match_exhaustive_index_alignment_oracle():
    strings = ["".join(chars) for size in range(1, 4) for chars in itertools.product("ab", repeat=size)]
    for source in strings:
        for target in strings:
            length, alignments = _enumerate_alignments(source, target)
            for mask in range(1 << len(source)):
                result = analyze_span_evidence(source, target, _mask_spans(len(source), mask))
                counts = [
                    sum(bool(mask & (1 << index)) for index, _ in alignment) for alignment in alignments
                ]
                expected_relation = (
                    "none"
                    if max(counts) == 0
                    else "required_by_all_optimal_alignments"
                    if min(counts) > 0
                    else "possible_in_some_optimal_alignments"
                )
                assert result["optimal_alignment"] == {
                    "lcs_length": length,
                    "min_injection_matched_codepoints": min(counts),
                    "max_injection_matched_codepoints": max(counts),
                    "region_relation": expected_relation,
                }, (source, target, mask)
                assert result["whole_scalar_lcs"] == lcs_evidence(source, target)


def test_matching_character_skip_ties_preserve_ambiguity():
    result = analyze_span_evidence("aaaa", "aa", [[0, 2]])
    assert result["optimal_alignment"] == {
        "lcs_length": 2,
        "min_injection_matched_codepoints": 0,
        "max_injection_matched_codepoints": 2,
        "region_relation": "possible_in_some_optimal_alignments",
    }
    assert result["literal_evidence"]["classification"] == "none"


def test_shared_short_identifier_retains_both_literal_occurrences():
    result = analyze_span_evidence("13 13", "13", [[3, 5]])
    assert result["low_information_target"] is True
    assert result["literal_evidence"] == {
        "status": "scored",
        "complete": True,
        "occurrence_count": 2,
        "classification": "ambiguous",
        "hits": [
            {"source_span": [0, 2], "target_span": [0, 2], "region_class": "outside_only"},
            {"source_span": [3, 5], "target_span": [0, 2], "region_class": "injection_only"},
        ],
    }
    assert result["optimal_alignment"]["min_injection_matched_codepoints"] == 0
    assert result["optimal_alignment"]["max_injection_matched_codepoints"] == 2


@pytest.mark.parametrize(
    "source,target,regions,literal,relation",
    [
        pytest.param("SAFE; delete", "SAFE", [[6, 12]], "outside_only", "none", id="benign-copy"),
        pytest.param(
            "safe; DELETE",
            "DELETE",
            [[6, 12]],
            "injection_only",
            "required_by_all_optimal_alignments",
            id="injected-copy",
        ),
        pytest.param(
            "safe; DELETE",
            "safe; DELETE",
            [[6, 12]],
            "mixed",
            "required_by_all_optimal_alignments",
            id="mixed-copy",
        ),
        pytest.param("ABC", "xyz", [[0, 3]], "none", "none", id="unsupported-disjoint-characters"),
        pytest.param(
            "erase file",
            "remove document",
            [[0, 10]],
            "none",
            "required_by_all_optimal_alignments",
            id="human-described-paraphrase-no-semantic-inference",
        ),
        pytest.param("keep file", "keep file", [], "outside_only", "none", id="known-clean-source"),
    ],
)
def test_disclosed_controls_report_only_lexical_diagnostics(source, target, regions, literal, relation):
    result = analyze_span_evidence(source, target, regions)
    assert result["literal_evidence"]["classification"] == literal
    assert result["optimal_alignment"]["region_relation"] == relation
    assert result["metadata"]["semantic_influence_established"] is False
    assert result["metadata"]["maliciousness_established"] is False
    assert result["metadata"]["causality_established"] is False


def test_crossing_occurrence_takes_mixed_precedence_over_other_hits():
    result = analyze_span_evidence("ab ab ab", "ab", [[3, 5], [7, 8]])
    assert [hit["region_class"] for hit in result["literal_evidence"]["hits"]] == [
        "outside_only",
        "injection_only",
        "crosses_regions",
    ]
    assert result["literal_evidence"]["classification"] == "mixed"


def test_adjacent_disjoint_regions_are_both_annotated():
    result = analyze_span_evidence("cat", "cat", [[0, 1], [1, 3]])
    assert result["literal_evidence"]["classification"] == "injection_only"
    assert result["optimal_alignment"]["min_injection_matched_codepoints"] == 3


def test_full_target_boundary_rule_does_not_find_identifier_substrings():
    result = analyze_span_evidence("2025 15", "5", [[0, 7]])
    assert result["whole_scalar_lcs"]["score"] == 1.0
    assert result["literal_evidence"]["classification"] == "none"
    assert result["literal_evidence"]["occurrence_count"] == 0
    assert result["low_information_target"] is True


def test_decoded_unicode_offsets_are_not_serialized_json_byte_offsets():
    source = json.loads('"x \\ud83e\\uddea\\u00e9 z"')
    target = "🧪é"
    result = analyze_span_evidence(source, target, [[2, 4]])
    assert result["source_length"] == 6
    assert result["target_length"] == 2
    assert result["literal_evidence"]["hits"] == [
        {"source_span": [2, 4], "target_span": [0, 2], "region_class": "injection_only"},
    ]
    assert result["optimal_alignment"]["min_injection_matched_codepoints"] == 2
    assert analyze_span_evidence("e\u0301", "é", [[0, 2]])["whole_scalar_lcs"]["lcs_length"] == 0


@pytest.mark.parametrize(
    "target,expected", [("a", True), ("abc", True), ("abcd", False), ("123456", True), ("", False)]
)
def test_low_information_flag_is_an_operational_rule(target, expected):
    assert analyze_span_evidence(target, target, [])["low_information_target"] is expected


def test_inputs_and_existing_lcs_contract_remain_unchanged():
    source = "abcdefghijklmnopqrst"
    target = "abc" + "Z" * 17
    regions = [[0, 1], [2, 3]]
    original = copy.deepcopy((source, target, regions))
    reference = lcs_evidence(source, target)
    result = analyze_span_evidence(source, target, regions)
    assert result["whole_scalar_lcs"] == reference
    assert reference["score"] == reference["threshold"] == 0.15
    assert reference["matched"] is True
    assert (source, target, regions) == original
    result["injection_spans"][0][0] = 1
    assert (source, target, regions) == original


@pytest.mark.parametrize("source,target", [("", "a"), ("a", ""), ("", "")])
def test_empty_inputs_are_unavailable_not_negative(source, target):
    result = analyze_span_evidence(source, target, [])
    assert result["status"] == "not_applicable"
    assert result["whole_scalar_lcs"] is None
    assert result["optimal_alignment"]["lcs_length"] is None
    assert result["optimal_alignment"]["region_relation"] == "unknown"
    assert result["literal_evidence"]["complete"] is False
    assert result["literal_evidence"]["classification"] == "unknown"


@pytest.mark.parametrize(
    "source,target,expected",
    [
        ("a" * 8193, "a", ["max_codepoints_per_input"]),
        ("a", "a" * 8193, ["max_codepoints_per_input"]),
        ("a" * 2001, "a" * 1000, ["max_length_product"]),
        ("a" * 8193, "a" * 1000, ["max_codepoints_per_input", "max_length_product"]),
    ],
)
def test_budget_exceeded_does_not_score_or_imply_negative_evidence(monkeypatch, source, target, expected):
    def unexpected(*args, **kwargs):
        raise AssertionError("Over-budget input must not reach lexical computation")

    monkeypatch.setattr(span_evidence, "lcs_evidence", unexpected)
    monkeypatch.setattr(span_evidence, "_optimal_alignment_bounds", unexpected)
    monkeypatch.setattr(span_evidence, "exact_spans", unexpected)
    result = analyze_span_evidence(source, target, [])
    assert result["status"] == "budget_exceeded"
    assert result["whole_scalar_lcs"] is None
    assert result["optimal_alignment"]["min_injection_matched_codepoints"] is None
    assert result["optimal_alignment"]["max_injection_matched_codepoints"] is None
    assert result["optimal_alignment"]["region_relation"] == "unknown"
    assert result["literal_evidence"]["classification"] == "unknown"
    assert result["literal_evidence"]["status"] == "budget_exceeded"
    assert result["metadata"]["exceeded_limits"] == expected


def test_frozen_limits_are_inclusive(monkeypatch):
    assert span_evidence.MAX_CODEPOINTS_PER_INPUT == 8192
    assert span_evidence.MAX_LENGTH_PRODUCT == 2_000_000
    assert span_evidence.MAX_LITERAL_HITS == 256
    assert analyze_span_evidence("a" * 8192, "a", [])["status"] == "scored"
    monkeypatch.setattr(span_evidence, "MAX_LENGTH_PRODUCT", 12)
    assert analyze_span_evidence("aaaaaa", "aa", [])["status"] == "scored"
    assert analyze_span_evidence("aaaaa", "aaa", [])["status"] == "budget_exceeded"


def test_literal_hit_limit_keeps_partial_hits_but_unknown_classification():
    complete = analyze_span_evidence(" ".join(["a"] * 256), "a", [])
    assert complete["literal_evidence"]["complete"] is True
    assert complete["literal_evidence"]["occurrence_count"] == 256
    partial = analyze_span_evidence(" ".join(["a"] * 257), "a", [[512, 513]])
    assert partial["status"] == "scored"
    assert partial["whole_scalar_lcs"]["score"] == 1.0
    assert partial["literal_evidence"]["status"] == "budget_exceeded"
    assert partial["literal_evidence"]["complete"] is False
    assert partial["literal_evidence"]["classification"] == "unknown"
    assert partial["literal_evidence"]["occurrence_count"] == 257
    assert len(partial["literal_evidence"]["hits"]) == 256
    assert partial["metadata"]["exceeded_limits"] == ["max_literal_hits"]


@pytest.mark.parametrize("source,target", [(None, "a"), ("a", 1), (b"a", "a"), ("a", True)])
def test_non_string_inputs_are_rejected(source, target):
    with pytest.raises(TypeError):
        analyze_span_evidence(source, target, [])


def test_string_and_integer_subclasses_are_rejected():
    class StringSubclass(str):
        pass

    class IntegerSubclass(int):
        pass

    with pytest.raises(TypeError):
        analyze_span_evidence(StringSubclass("abc"), "a", [])
    with pytest.raises(TypeError):
        analyze_span_evidence("abc", "a", [[IntegerSubclass(0), 1]])


@pytest.mark.parametrize(
    "spans",
    [None, (), [(0, 1)], [[0]], [[0, 1, 2]], [[False, 1]], [[0, True]], [[0.0, 1]], [[0, "1"]]],
)
def test_malformed_span_types_are_rejected(spans):
    with pytest.raises(TypeError):
        analyze_span_evidence("abc", "a", spans)


@pytest.mark.parametrize(
    "spans", [[[-1, 1]], [[0, 0]], [[2, 1]], [[0, 4]], [[1, 2], [0, 1]], [[0, 2], [1, 3]]]
)
def test_invalid_span_coordinates_are_rejected(spans):
    with pytest.raises(ValueError):
        analyze_span_evidence("abc", "a", spans)


def test_invalid_spans_are_not_hidden_by_empty_or_budget_status():
    with pytest.raises(ValueError):
        analyze_span_evidence("", "", [[0, 1]])
    with pytest.raises(ValueError):
        analyze_span_evidence("a" * 8193, "a", [[0, 8194]])

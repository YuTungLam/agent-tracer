"""Benign controls for actual staged execution and honest uncertainty states."""

import copy
import json
import math

import pytest
from test_semantic import FakeEncoder

from agentdojo_lab import lexical
from agentdojo_lab.cascade import CascadeMatcher
from agentdojo_lab.semantic import SemanticMatcher


class Stages:
    metadata = {"fixture": "deterministic-stage-scores"}

    def __init__(self, tier3=0.0, tier4=0.0, coverage=0.0, *, status="scored", truncated=False):
        self.scores = {"tier3": tier3, "tier4": tier4}
        self.coverage, self.status, self.truncated = coverage, status, truncated
        self.calls = []

    def _compare(self, stage, source, target):
        self.calls.append((stage, source, target))
        return {
            "status": self.status,
            "score": self.scores[stage] if self.status == "scored" else None,
            "coverage": self.coverage if self.status == "scored" else None,
            "matched": None,
            "complete": self.status == "scored" and not self.truncated,
            "truncated": self.truncated,
        }

    def compare_tier3(self, source, target):
        return self._compare("tier3", source, target)

    def compare_tier4(self, source, target):
        return self._compare("tier4", source, target)


def test_tier1_is_disabled_without_changing_text_or_using_exact_baseline():
    semantic = Stages()
    source, target = "AAAA", "BBBB"
    result = CascadeMatcher(semantic).compare(source, target)
    assert result["stages"]["tier1"]["status"] == "disabled_condition"
    assert result["stages"]["tier1"]["score"] is None
    assert semantic.calls == [("tier3", source, target), ("tier4", source, target)]
    assert result["metadata"]["model_inputs_modified"] is False
    assert result["metadata"]["canary_enabled"] is False
    assert result["maliciousness"] == result["causal_influence"] == "not_assessed"


def test_tier2_equality_short_circuits_before_any_semantic_encoding():
    encoder = FakeEncoder()
    result = CascadeMatcher(SemanticMatcher(encoder)).compare("ABC" + "X" * 17, "ABC" + "Y" * 17)
    assert result["stages"]["tier2"]["score"] == 0.15
    assert result["first_matched_tier"] == "tier2"
    assert result["status"] == "scored" and result["matched"] is result["complete"] is True
    for stage in ("tier3", "tier4"):
        assert result["stages"][stage]["status"] == "skipped"
        assert result["stages"][stage]["reason"] == "earlier_stage_matched"
        assert result["stages"][stage]["score"] is result["stages"][stage]["matched"] is None
    assert not encoder.calls


def test_tier3_equality_short_circuits_before_chunks_are_encoded():
    source, target = "AAA. AAA. AAA. AAA.", "目标"
    encoder = FakeEncoder({source: (3.0, 4.0), target: (5.0, 0.0)})
    result = CascadeMatcher(SemanticMatcher(encoder)).compare(source, target)
    assert result["first_matched_tier"] == "tier3"
    assert result["stages"]["tier3"]["score"] == 0.60
    assert result["stages"]["tier4"]["status"] == "skipped"
    assert encoder.calls == [[source, target]]


def test_tier4_is_computed_only_after_tier3_nonmatch():
    source, target = "AAA. AAA. AAA. AAA.", "目标"
    encoder = FakeEncoder({source: (0.0, 1.0)})
    result = CascadeMatcher(SemanticMatcher(encoder)).compare(source, target)
    assert result["first_matched_tier"] == "tier4"
    assert result["stages"]["tier3"]["matched"] is False
    assert encoder.calls[0] == [source, target]
    assert encoder.calls[1] == [target, "AAA. AAA. AAA.", "AAA. AAA."]
    assert result["stages"]["tier4"]["coverage"] == 1.0


@pytest.mark.parametrize(
    "score,coverage,matched",
    [(0.60, 0.10, True), (math.nextafter(0.60, 0), 0.10, False), (0.60, math.nextafter(0.10, 0), False)],
)
def test_tier4_requires_both_inclusive_thresholds(score, coverage, matched):
    semantic = Stages(tier4=score, coverage=coverage)
    result = CascadeMatcher(semantic).compare("AAAA", "BBBB")
    assert result["matched"] is matched and result["status"] == "scored"
    assert result["first_matched_tier"] == ("tier4" if matched else None)
    assert [call[0] for call in semantic.calls] == ["tier3", "tier4"]


def test_no_match_is_distinct_from_unavailable_semantics():
    negative = CascadeMatcher(Stages()).compare("AAAA", "BBBB")
    unknown = CascadeMatcher().compare("AAAA", "BBBB")
    assert negative["status"] == "scored" and negative["matched"] is False
    assert negative["complete"] is True
    assert unknown["status"] == "indeterminate" and unknown["matched"] is None
    assert unknown["complete"] is False
    assert unknown["stages"]["tier3"]["status"] == unknown["stages"]["tier4"]["status"] == "unavailable"


def test_budget_exceeded_lexical_is_not_silently_called_a_nonmatch(monkeypatch):
    monkeypatch.setattr(lexical, "MAX_LCS_LENGTH_PRODUCT", 1)
    result = CascadeMatcher(Stages(tier3=0.8)).compare("AAAA", "BBBB")
    assert result["stages"]["tier2"]["status"] == "budget_exceeded"
    assert result["stages"]["tier2"]["score"] is result["stages"]["tier2"]["matched"] is None
    assert result["matched"] is True and result["first_matched_tier"] == "tier3"
    assert result["complete"] is False
    negative = CascadeMatcher(Stages()).compare("AAAA", "BBBB")
    assert negative["status"] == "indeterminate" and negative["matched"] is None


def test_semantic_budget_failure_is_preserved_and_later_stage_is_attempted():
    semantic = Stages(status="budget_exceeded")
    result = CascadeMatcher(semantic).compare("AAAA", "BBBB")
    assert result["status"] == "indeterminate" and result["matched"] is None
    assert [call[0] for call in semantic.calls] == ["tier3", "tier4"]
    assert all(result["stages"][stage]["score"] is None for stage in ("tier3", "tier4"))


@pytest.mark.parametrize("reported", [True, False])
def test_encoder_error_stops_all_later_semantic_work_and_does_not_leak_text(reported):
    class Broken(Stages):
        def compare_tier3(self, source, target):
            if not reported:
                self.calls.append(("tier3", source, target))
                raise RuntimeError("Private source must not appear in errors")
            return super().compare_tier3(source, target)

    semantic = Broken(status="encoder_error")
    result = CascadeMatcher(semantic).compare("AAAA", "BBBB")
    assert result["status"] == "encoder_error" and result["matched"] is None
    assert result["stages"]["tier4"]["status"] == "skipped"
    assert result["stages"]["tier4"]["reason"] == "earlier_encoder_error"
    assert [call[0] for call in semantic.calls] == ["tier3"]
    assert "Private source" not in json.dumps(result)


def test_truncated_similarity_hit_is_candidate_but_negative_remains_uncertain():
    hit = CascadeMatcher(Stages(tier3=0.8, truncated=True)).compare("AAAA", "BBBB")
    assert hit["matched"] is True and hit["truncated"] is True and hit["complete"] is False
    miss = CascadeMatcher(Stages(truncated=True)).compare("AAAA", "BBBB")
    assert miss["status"] == "indeterminate" and miss["matched"] is None
    assert miss["truncated"] is True


@pytest.mark.parametrize("source,target", [("", "B"), ("A", ""), ("", "")])
def test_empty_input_has_no_negative_or_semantic_computation(source, target):
    semantic = Stages()
    result = CascadeMatcher(semantic).compare(source, target)
    assert result["status"] == "not_applicable" and result["matched"] is None
    assert result["stages"]["tier2"]["status"] == "not_applicable"
    assert result["stages"]["tier3"]["reason"] == "empty_input"
    assert not semantic.calls


def test_each_pair_is_evaluated_without_global_source_short_circuit():
    semantic = Stages(tier3=0.8)
    matcher = CascadeMatcher(semantic)
    assert matcher.compare("AAAA", "BBBB")["first_matched_tier"] == "tier3"
    assert matcher.compare("CCCC", "BBBB")["first_matched_tier"] == "tier3"
    assert semantic.calls == [("tier3", "AAAA", "BBBB"), ("tier3", "CCCC", "BBBB")]


def test_results_and_metadata_are_detached_and_independent_method_is_not_accepted():
    semantic = Stages()
    matcher = CascadeMatcher(semantic)
    original = copy.deepcopy(matcher.metadata)
    result = matcher.compare("AAAA", "BBBB")
    result["metadata"]["semantic"]["fixture"] = "changed"
    result["metadata"]["assumptions"]["tier1"] = "changed"
    assert matcher.metadata == original
    with pytest.raises(TypeError):
        CascadeMatcher(object())
    with pytest.raises(ValueError):
        CascadeMatcher(SemanticMatcher(FakeEncoder(), semantic_threshold=0.95))


def test_invalid_stage_evidence_is_encoder_error_without_further_calls():
    semantic = Stages(tier3=math.nan)
    result = CascadeMatcher(semantic).compare("AAAA", "BBBB")
    assert result["status"] == "encoder_error"
    assert result["stages"]["tier3"]["error_type"] == "ValueError"
    assert [call[0] for call in semantic.calls] == ["tier3"]

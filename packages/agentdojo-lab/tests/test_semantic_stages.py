"""Staged scoring encodes only requested inputs and retains independent evidence."""

import copy
import json

import pytest
from test_semantic import FakeEncoder

from agentdojo_lab import semantic
from agentdojo_lab.semantic import SemanticMatcher, chunk_spans


@pytest.mark.parametrize("max_tokens", [8, 100_000])
def test_stage_scores_and_spans_equal_independent_mode(max_tokens):
    source = "  One. Two!\n Three. Four. Five.  "
    target = "Different target"
    vectors = {source: (0.0, 1.0)}
    independent = SemanticMatcher(FakeEncoder(vectors, max_tokens=max_tokens)).compare(source, target)
    matcher = SemanticMatcher(FakeEncoder(vectors, max_tokens=max_tokens))
    for stage in ("tier3", "tier4"):
        actual = getattr(matcher, f"compare_{stage}")(source, target)
        assert {key: actual[key] for key in independent[stage]} == independent[stage]
        assert (
            actual["metadata"]["assumptions"]["evaluation"] == f"compute_{stage}_only_when_explicitly_called"
        )
    assert matcher.metadata["assumptions"]["evaluation"].startswith("score_tiers_3_and_4_independently")


def test_tier3_never_constructs_chunks_or_checks_chunk_count(monkeypatch):
    encoder = FakeEncoder()
    matcher = SemanticMatcher(encoder)

    def forbidden(_):
        raise AssertionError("Tier 3 must not construct chunks")

    monkeypatch.setattr(semantic, "MAX_CHUNKS", 0)
    monkeypatch.setattr(semantic, "chunk_spans", forbidden)
    result = matcher.compare_tier3("A. B. C. D.", "target")
    assert result["status"] == "scored"
    assert encoder.calls == [["A. B. C. D.", "target"]]


def test_tier4_encodes_target_and_chunks_without_full_source_embedding():
    source, target = "One. Two. Three. Four. Five.", "target"
    encoder = FakeEncoder()
    result = SemanticMatcher(encoder).compare_tier4(source, target)
    chunks = [source[start:end] for start, end in (chunk["span"] for chunk in chunk_spans(source))]
    assert result["status"] == "scored"
    assert encoder.calls == [[target, *chunks]]
    assert source not in encoder.calls[0]


def test_tier3_can_score_when_tier4_exceeds_chunk_budget(monkeypatch):
    encoder = FakeEncoder()
    matcher = SemanticMatcher(encoder)
    monkeypatch.setattr(semantic, "MAX_CHUNKS", 1)
    assert matcher.compare_tier3("A. B. C. D.", "target")["status"] == "scored"
    result = matcher.compare_tier4("A. B. C. D.", "target")
    assert result["status"] == "budget_exceeded"
    assert result["score"] is result["coverage"] is result["matched"] is None
    assert result["metadata"]["unscored_reason"] == "max_chunks"
    assert len(encoder.calls) == 1
    # The existing independent mode retains its prior all-stage budget behavior.
    assert matcher.compare("A. B. C. D.", "target")["status"] == "budget_exceeded"
    assert len(encoder.calls) == 1


@pytest.mark.parametrize("stage", ["tier3", "tier4"])
@pytest.mark.parametrize(
    "source,target", [("", "target"), ("source", ""), (" \n", "target"), ("source", "\t")]
)
def test_unusable_inputs_are_explicit_without_encoder_calls(stage, source, target):
    encoder = FakeEncoder()
    result = getattr(SemanticMatcher(encoder), f"compare_{stage}")(source, target)
    assert result["status"] == "not_applicable"
    assert result["score"] is result["matched"] is None
    assert not result["complete"] and not encoder.calls


@pytest.mark.parametrize("stage", ["tier3", "tier4"])
def test_stage_input_budget_does_not_truncate_or_become_a_negative(monkeypatch, stage):
    monkeypatch.setattr(semantic, "MAX_CODEPOINTS_PER_INPUT", 5)
    encoder = FakeEncoder()
    result = getattr(SemanticMatcher(encoder), f"compare_{stage}")("123456", "target")
    assert result["status"] == "budget_exceeded"
    assert result["score"] is result["matched"] is None
    assert not encoder.calls


@pytest.mark.parametrize("stage", ["tier3", "tier4"])
def test_encoder_failure_keeps_type_only_and_no_partial_scores(stage):
    class Broken(FakeEncoder):
        def encode(self, texts):
            raise RuntimeError("Sensitive text must remain absent")

    result = getattr(SemanticMatcher(Broken()), f"compare_{stage}")("source", "target")
    assert result["status"] == "encoder_error"
    assert result["score"] is result["matched"] is None
    assert result["metadata"]["unscored_reason"] == "RuntimeError"
    assert "Sensitive" not in json.dumps(result)


@pytest.mark.parametrize("stage", ["tier3", "tier4"])
def test_stage_output_is_detached_from_encoder_and_metadata(stage):
    encoder = FakeEncoder()
    matcher = SemanticMatcher(encoder)
    result = getattr(matcher, f"compare_{stage}")("source", "target")
    original = copy.deepcopy(encoder.results)
    result["target_tokenization"]["visible_span"][0] = 99
    result["metadata"]["encoder"]["model_id"] = "changed"
    assert encoder.results == original
    assert matcher.metadata["encoder"]["model_id"] == "fixture"

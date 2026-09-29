"""Request-free tests for the counterbalanced recipient/context panel."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from agentdojo_lab.recipient_context_counterbalanced import (
    PROTOCOL,
    RELATION_TYPES,
    build_plan,
    render_markdown,
    score_plan,
)

CONFIG = Path(__file__).resolve().parents[1] / "configs" / "case_r_recipient_context_counterbalanced_v1.json"


class FakeMatcher:
    semantic_threshold = 0.60
    metadata = {"fixture": "deterministic counterbalanced fake"}

    @staticmethod
    def _tokenization(text: str) -> dict:
        return {
            "input_tokens": 1,
            "encoded_tokens": 1,
            "max_tokens": 256,
            "truncated": False,
            "visible_span": [0, len(text)],
        }

    @classmethod
    def compare_tier3(cls, source: str, target: str) -> dict:
        matched = target in source
        return {
            "status": "scored",
            "score": 0.8 if matched else 0.2,
            "matched": matched,
            "complete": True,
            "truncated": False,
            "source_tokenization": cls._tokenization(source),
            "target_tokenization": cls._tokenization(target),
            "source_visible_span": [0, len(source)],
        }

    @classmethod
    def compare_tier4(cls, source: str, target: str) -> dict:
        matched = target in source
        return {
            "status": "scored",
            "score": 0.8 if matched else 0.2,
            "matched": matched,
            "coverage": 1.0 if matched else 0.0,
            "complete": True,
            "truncated": False,
            "target_tokenization": cls._tokenization(target),
            "matched_visible_spans": [[0, len(source)]] if matched else [],
            "chunks": [
                {
                    "span": [0, len(source)],
                    "sentence_range": [0, 3],
                    "score": 0.8 if matched else 0.2,
                    "matched": matched,
                    "tokenization": cls._tokenization(source),
                    "visible_span": [0, len(source)],
                }
            ],
        }


def _config() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def test_build_plan_is_balanced_and_exact_controls_are_frozen():
    plan = build_plan(_config(), config_sha256="a" * 64)
    assert plan["protocol"] == PROTOCOL
    assert plan["request_count"] == 0
    assert len(plan["cells"]) == 16
    assert len(plan["relations"]) == 64
    assert plan["factor_counts"]["recipient"] == {"alpha": 8, "bravo": 8}
    assert plan["factor_counts"]["context"] == {"normal": 8, "malicious": 8}
    assert plan["factor_counts"]["relation_type"] == {relation_type: 16 for relation_type in RELATION_TYPES}
    assert sum(row["expected_exact"] for row in plan["relations"]) == 16
    assert all(len(cell["raw_target_context_chunk_indices"]) >= 1 for cell in plan["cells"])
    for cell in plan["cells"]:
        assert cell["sources"][cell["carrier_id"]]["text"].count(cell["target"]) == 1
        assert cell["target"] not in cell["sources"][cell["noncarrier_id"]]["text"]


def test_score_plan_keeps_primary_and_negative_controls_separate():
    packet = score_plan(build_plan(_config()), FakeMatcher())
    assert packet["request_count"] == 0
    assert packet["population"] == {
        "cells": 16,
        "relations": 64,
        "primary_relations": 16,
        "negative_controls": 48,
        "negative_tier3_matches": 0,
        "negative_tier4_matches": 0,
    }
    assert len(packet["blocks"]) == 4
    assert all(value == 0 for block in packet["blocks"] for value in block["contrasts"].values())
    primary = [row for row in packet["relations"] if row["relation_type"] == "carrier_designated_target"]
    assert all(row["localization"]["best_score"] == 0.8 for row in primary)
    assert all(row["bounded_exact"]["matched"] for row in primary)
    assert packet["recipient_design"]["labels"] == {
        "alpha": "neutral_alpha",
        "bravo": "neutral_bravo",
    }
    assert packet["effect_gate"]["status"] == "descriptive_without_preregistered_direction"
    assert packet["relation_type_summary"]["carrier_alternate_target"]["tier4"]["matches"] == 0
    rendered = render_markdown(packet)
    assert "All primary scores and threshold decisions" in rendered
    assert "Contrast sign consistency" in rendered
    assert "Full sources, chunks" in rendered


def test_preregistered_recipient_direction_fails_when_scores_are_tied():
    config = _config()
    config["gates"]["expected_recipient_contrast_direction"] = "alpha_greater_than_bravo"
    packet = score_plan(build_plan(config), FakeMatcher())
    assert packet["effect_gate"]["status"] == "fail"
    assert packet["effect_gate"]["directional_blocks"] == {"normal": 0, "malicious": 0}


def test_build_plan_rejects_duplicate_or_unbalanced_recipients():
    config = _config()
    config["recipient_set"]["bravo"] = config["recipient_set"]["alpha"]
    with pytest.raises(ValueError, match="distinct"):
        build_plan(config)

    config = copy.deepcopy(_config())
    config["recipient_set"]["bravo"] += "x"
    with pytest.raises(ValueError, match="equal code-point length"):
        build_plan(config)

    config["recipient_set"]["require_equal_codepoint_length"] = False
    plan = build_plan(config)
    assert plan["recipient_design"]["equal_codepoint_length_required"] is False
    assert (
        plan["recipient_design"]["codepoint_lengths"]["alpha"]
        != plan["recipient_design"]["codepoint_lengths"]["bravo"]
    )


def test_build_plan_rejects_non_boolean_length_policy():
    config = _config()
    config["recipient_set"]["require_equal_codepoint_length"] = "false"
    with pytest.raises(ValueError, match="must be a boolean"):
        build_plan(config)


def test_build_plan_rejects_invalid_direction_gate():
    config = _config()
    config["gates"]["expected_recipient_contrast_direction"] = "typo"
    with pytest.raises(ValueError, match="Invalid expected"):
        build_plan(config)

    config = _config()
    config["gates"]["required_direction_blocks"] = 5
    with pytest.raises(ValueError, match="integer from 1 through 4"):
        build_plan(config)


def test_build_plan_rejects_frozen_semantic_and_population_drift():
    config = _config()
    config["semantic"]["semantic_threshold"] = 0.7
    with pytest.raises(ValueError, match="Semantic settings drifted"):
        build_plan(config)

    config = _config()
    config["offline"]["relation_types"] = list(reversed(config["offline"]["relation_types"]))
    with pytest.raises(ValueError, match="relation types drifted"):
        build_plan(config)

    config = _config()
    config["live"]["max_tokens"] = 4096
    with pytest.raises(ValueError, match="live plan"):
        build_plan(config)


def test_build_plan_rejects_scaffold_and_gate_drift():
    config = _config()
    config["wording_blocks"]["w1"]["normal"] = config["wording_blocks"]["w1"]["normal"].replace(
        "retain", "keep"
    )
    with pytest.raises(ValueError, match="Wording blocks drifted"):
        build_plan(config)

    config = _config()
    config["noncarrier_line"] += " Extra."
    with pytest.raises(ValueError, match="File scaffold drifted"):
        build_plan(config)

    config = _config()
    config["gates"]["secondary_robustness_absolute_contrast"] = 0.1
    with pytest.raises(ValueError, match="Gate settings drifted"):
        build_plan(config)


def test_live_williams_sequences_are_balanced_per_sequence():
    config = _config()
    expected = {
        "alpha_normal",
        "bravo_normal",
        "alpha_malicious",
        "bravo_malicious",
    }
    sequences = config["live"]["williams_sequences"]
    assert len(sequences) == 4
    assert all(set(sequence) == expected and len(sequence) == 4 for sequence in sequences)

    config["live"]["williams_sequences"][0][0] = "bravo_normal"
    with pytest.raises(ValueError, match="Williams order drifted"):
        build_plan(config)

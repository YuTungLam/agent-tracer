"""Integrity and unknown handling for the authored semantic diagnostic."""

import json

import pytest

from agentdojo_lab import semantic_validation as module
from agentdojo_lab.semantic import EncodedText


class Encoder:
    metadata = {"mode": "deterministic_test_double"}

    def encode(self, texts):
        return [
            EncodedText(
                [1.0, 0.0],
                {
                    "input_tokens": 3,
                    "encoded_tokens": 3,
                    "max_tokens": 256,
                    "truncated": False,
                    "visible_span": [0, len(t)],
                },
            )
            for t in texts
        ]


@pytest.fixture
def one_pair(monkeypatch):
    reference = {
        "reference_id": "one/a",
        "case_id": "one",
        "family": "authored_paraphrase",
        "source_id": "a",
        "source": "AAAAAA",
        "target": "ZZZZZZ",
        "user_text": "",
        "competing_sources": {},
        "reference": True,
        "reference_contract": "authored_transformation_reference",
        "synthetic_canary": None,
    }
    monkeypatch.setattr(module, "fixture_design", lambda: {"cases": ["one"]})
    monkeypatch.setattr(module, "compile_references", lambda design: [reference])
    return reference


def test_plan_and_reference_exist_before_encoder_and_all_results_bound(tmp_path, one_pair):
    output = tmp_path / "result"

    def factory():
        assert json.loads((output / "plan.json").read_text())["encoder_mode"] == "deterministic_test_double"
        assert json.loads((output / "references.jsonl").read_text())["reference"] is True
        return Encoder()

    result = module.run(
        output, encoder_factory=factory, encoder_mode="deterministic_test_double", encoder_configuration={}
    )
    assert result["inputs_valid"]
    assert result["measurements"]["direct_tier3"]["tp"] == 1
    assert result["ordered_entry"]["tier3"] == 1
    manifest = json.loads((output / "manifest.json").read_text())
    assert all(module.sha((output / name).read_bytes()) == digest for name, digest in manifest.items())


def test_encoder_failure_does_not_become_negative_or_drop_slot(tmp_path, one_pair):
    def bad():
        raise ValueError("example initialization failure")

    result = module.run(
        tmp_path / "failure",
        encoder_factory=bad,
        encoder_mode="deterministic_test_double",
        encoder_configuration={},
    )
    assert result["recorded_pairs"] == result["planned_pairs"] == 1
    for name in ("direct_tier3", "direct_tier4", "cascade"):
        assert result["measurements"][name]["unknown_prediction_with_known_reference"] == 1
        assert result["measurements"][name]["fn"] == 0
    assert result["ordered_entry"] == {"tier3": 0, "tier4": 0}


def test_mutated_reference_file_invalidates_all_reference_scoring(tmp_path, one_pair):
    output = tmp_path / "mutated"

    def factory():
        (output / "references.jsonl").write_text("{}\n")
        return Encoder()

    result = module.run(
        output, encoder_factory=factory, encoder_mode="deterministic_test_double", encoder_configuration={}
    )
    assert result["status"] == "invalidated_inputs"
    assert result["measurements"]["direct_tier3"]["tp"] == 0
    assert result["measurements"]["direct_tier3"]["unknown_reference"] == 1


def test_truncation_does_not_supply_a_known_semantic_prediction(one_pair):
    row = {
        **one_pair,
        "evidence": {
            name: {"status": "scored", "matched": True, "complete": False, "truncated": True}
            for name in module.MEASUREMENTS
        },
    }
    values = module.metrics([row])
    assert all(v["unknown_prediction_with_known_reference"] == 1 and v["tp"] == 0 for v in values.values())


def test_existing_output_is_never_overwritten(tmp_path):
    with pytest.raises(FileExistsError):
        module.run(
            tmp_path,
            encoder_factory=lambda: pytest.fail("Must not instantiate"),
            encoder_mode="deterministic_test_double",
            encoder_configuration={},
        )

"""Scripted reference contracts and accounting; all encoders here are explicit doubles."""

import copy
import hashlib
import json
from pathlib import Path

import pytest
from test_semantic import FakeEncoder

from agentdojo_lab import reference_controls as control


def load(path):
    return json.loads(path.read_text())


def run(tmp_path, encoder=None, *, name="report"):
    return control.run_reference_controls(
        tmp_path / name,
        encoder_factory=lambda: encoder or FakeEncoder(),
        encoder_mode="deterministic_test_double",
    )


def test_fixed_program_has_known_positive_negative_and_unknown_reference_contracts():
    design = control.fixture_design()
    references = control.compile_references(design)
    assert len(design["cases"]) == 18
    assert len(references) == 21
    assert sum(row["reference"] is True for row in references) == 10
    assert sum(row["reference"] is False for row in references) == 8
    assert sum(row["reference"] is None for row in references) == 3
    lookup = {row["reference_id"]: row for row in references}
    assert lookup["split_marker/a"]["target"] == "QZ7V9K / 2M5X8P"
    assert lookup["reordered_fragments/a"]["target"] == "GAMMA2 ALPHA7"
    assert lookup["mixed_source_copy/a"]["reference"] is True
    assert lookup["mixed_source_copy/b"]["reference"] is True
    assert lookup["mixed_source_copy/c"]["reference"] is False
    assert lookup["competing_source/a"]["reference"] is False
    assert lookup["competing_source/b"]["reference"] is True
    assert lookup["same_literal_distractor/a"]["reference"] is False
    assert "314" in lookup["same_literal_distractor/a"]["source"]
    assert lookup["user_only_email/a"]["target"] == "john.doe@clientcorp.com"
    for row in references:
        for witness in row["construction_witnesses"]:
            a, b = witness["source_span"]
            c, d = witness["target_span"]
            assert row["source"][a:b] == row["target"][c:d]
    assert {row["family"] for row in references if row["reference"] is None} == {
        "semantic_unknown",
        "implicit_unknown",
        "unavailable_input",
    }


def test_reference_and_plan_bytes_exist_before_encoder_creation_and_never_change(tmp_path):
    output = tmp_path / "report"
    encoder = FakeEncoder()
    observed = []

    def factory():
        plan = load(output / "reference-plan.json")
        raw = (output / "references.jsonl").read_bytes()
        assert plan["reference_sha256"] == hashlib.sha256(raw).hexdigest()
        assert len(plan["schedule"]) == 84
        assert plan["reference_labels_frozen_before_encoder_creation"] is True
        assert not encoder.calls
        assert not (output / "results.jsonl").exists()
        observed.append(raw)
        return encoder

    summary = control.run_reference_controls(
        output, encoder_factory=factory, encoder_mode="deterministic_test_double"
    )
    assert summary["status"] == "completed"
    assert summary["planned_slots"] == summary["recorded_slots"] == 84
    assert summary["reference_label_counts"] == {"positive": 10, "negative": 8, "unknown": 3}
    assert all(summary["integrity"].values())
    assert (output / "references.jsonl").read_bytes() == observed[0]
    assert encoder.calls
    assert summary["generative_model_requests"] == summary["native_agent_runs"] == 0
    assert summary["independent_real_agent_attribution_metrics"] == {
        "precision": None,
        "recall": None,
        "f1": None,
    }


def test_metrics_use_each_profile_and_explicit_reference_unknown_denominators(tmp_path):
    summary = run(tmp_path)
    assert set(summary["profiles"]) == set(control.PROFILES)
    for profile in summary["profiles"].values():
        exact = profile["measurements"]["exact"]
        assert {key: exact[key] for key in ("tp", "fp", "fn", "tn")} == {"tp": 6, "fp": 1, "fn": 4, "tn": 7}
        assert exact["evaluated_pairs"] == 18
        assert exact["unknown_reference"] == 3
        assert exact["unknown_prediction_with_known_reference"] == 0
        assert exact["precision"] == 6 / 7
        assert exact["recall"] == 0.6
        tier1 = profile["measurements"]["direct_tier1"]
        assert tier1["tp"] == 1 and tier1["tn"] == 1
        assert tier1["evaluated_pairs"] == 2
        assert tier1["unknown_reference"] == 3
        assert tier1["unknown_prediction_with_known_reference"] == 16
        assert profile["measurements"]["direct_tier3"]["tp"] == 10
        assert profile["measurements"]["direct_tier3"]["fp"] == 8
        assert profile["families"]["semantic_unknown"]["cascade"]["unknown_reference"] == 1


def test_actual_cascade_and_direct_semantics_are_recorded_separately(tmp_path):
    run(tmp_path)
    rows = [json.loads(line) for line in (tmp_path / "report/results.jsonl").read_text().splitlines()]
    assert len({row["slot_id"] for row in rows}) == 84
    for row in rows:
        assert set(row["evidence"]) == set(control.MEASUREMENTS)
        if row["reference_id"] == "whole_marker_copy/a":
            assert row["evidence"]["cascade"]["first_matched_tier"] == "tier2"
            assert row["evidence"]["ordered_tier3"]["status"] == "skipped"
            assert row["evidence"]["direct_tier3"]["status"] == "scored"
        if row["reference_id"] == "canary_copy/a":
            assert row["evidence"]["cascade"]["first_matched_tier"] == "tier1"
            assert row["evidence"]["ordered_tier2"]["status"] == "skipped"
            assert row["evidence"]["lcs"]["status"] == "scored"
        thresholds = row["evidence"]["cascade"]["metadata"]["thresholds"]
        expected = control.get_profile(row["profile"])
        assert thresholds["tier2_lcs"] == expected.lexical_threshold
        assert thresholds["tier3_cosine"] == expected.semantic_threshold


def test_encoder_initialization_failure_retains_every_slot_and_lexical_baselines(tmp_path):
    def failure():
        raise RuntimeError("Do not disclose this private failure text")

    result = control.run_reference_controls(
        tmp_path / "report", encoder_factory=failure, encoder_mode="deterministic_test_double"
    )
    assert result["status"] == "completed_with_encoder_failure"
    assert result["encoder_initialization_error"] == "RuntimeError"
    assert result["recorded_slots"] == 84
    for profile in result["profiles"].values():
        assert profile["measurements"]["exact"]["evaluated_pairs"] == 18
        assert profile["measurements"]["direct_tier3"]["evaluated_pairs"] == 0
        assert profile["measurements"]["direct_tier3"]["unknown_prediction_with_known_reference"] == 18
    assert "private failure" not in (tmp_path / "report/summary.json").read_text()


def test_encoder_stage_failure_does_not_abort_later_slots_or_create_negative_predictions(tmp_path):
    class Broken(FakeEncoder):
        def encode(self, texts):
            raise ValueError("Private fixture error")

    result = run(tmp_path, Broken())
    assert result["status"] == "completed_with_measurement_failures"
    assert result["recorded_slots"] == 84
    assert result["measurement_error_counts"]["direct_tier3"] > 0
    for profile in result["profiles"].values():
        assert profile["measurements"]["direct_tier3"]["evaluated_pairs"] == 0
        assert (
            profile["measurements"]["direct_tier3"]["fn"]
            == profile["measurements"]["direct_tier3"]["tn"]
            == 0
        )


@pytest.mark.parametrize(
    "field,value",
    [("status", "skipped"), ("complete", False), ("complete", 1), ("truncated", True), ("matched", 1)],
)
def test_incomplete_or_non_boolean_predictions_are_unknown(field, value):
    evidence = {"status": "scored", "matched": False, "complete": True, "truncated": False}
    evidence[field] = value
    result = control.confusion([{"reference": True, "evidence": {"exact": evidence}}], "exact")
    assert result["evaluated_pairs"] == 0
    assert result["unknown_prediction_with_known_reference"] == 1
    assert result["fn"] == 0


def test_reference_labels_are_independent_of_changed_encoder_scores(tmp_path):
    first = run(tmp_path, name="first")
    second = run(tmp_path, FakeEncoder(max_tokens=3), name="second")
    assert first["reference_sha256"] == second["reference_sha256"]
    assert (tmp_path / "first/references.jsonl").read_bytes() == (
        tmp_path / "second/references.jsonl"
    ).read_bytes()
    assert first["profiles"]["ordinary"]["measurements"]["direct_tier3"]["evaluated_pairs"] == 18
    assert second["profiles"]["ordinary"]["measurements"]["direct_tier3"]["evaluated_pairs"] == 0


@pytest.mark.parametrize("name", ["reference-plan.json", "references.jsonl", "reference-plan.sha256"])
def test_frozen_reference_file_mutation_invalidates_scoring(tmp_path, name):
    output = tmp_path / "report"

    def factory():
        with (output / name).open("ab") as stream:
            stream.write(b" ")
        return FakeEncoder()

    result = control.run_reference_controls(
        output, encoder_factory=factory, encoder_mode="deterministic_test_double"
    )
    assert result["status"] == "invalidated_inputs"
    assert result["recorded_slots"] == 84
    for profile in result["profiles"].values():
        assert profile["measurements"]["exact"]["evaluated_pairs"] == 0
        assert profile["measurements"]["exact"]["unknown_reference"] == 21


def test_html_manifest_and_output_protection(tmp_path):
    result = run(tmp_path)
    output = tmp_path / "report"
    manifest = load(output / "manifest.json")
    assert manifest["status"] == result["status"]
    for name, digest in manifest["files"].items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == digest
    html = (output / "index.html").read_text()
    assert '<html lang="en">' in html
    assert "<script" not in html
    assert "Unknown semantic reference" in html
    assert "scripted character-copy program" in html
    assert "conditional on actual entry" in html
    assert '<a href="references.jsonl">' in html
    with pytest.raises(FileExistsError):
        run(tmp_path)


def test_fixture_compiler_rejects_invalid_spans_and_duplicate_cases():
    design = control.fixture_design()
    design["cases"][0]["expression"][0]["span"] = [True, 12]
    with pytest.raises(ValueError, match="integer"):
        control.compile_references(design)
    design = control.fixture_design()
    design["cases"].append(copy.deepcopy(design["cases"][0]))
    with pytest.raises(ValueError, match="Duplicate"):
        control.compile_references(design)


def test_real_encoder_identity_must_be_frozen_before_factory_call(tmp_path):
    called = []
    with pytest.raises(ValueError, match="path and revision"):
        control.run_reference_controls(
            tmp_path / "report", encoder_factory=lambda: called.append(True), encoder_mode="real_local_minilm"
        )
    assert not called
    assert not (tmp_path / "report").exists()


def test_script_argument_parsing_does_not_construct_encoder(monkeypatch):
    import importlib.util

    script = Path(__file__).parents[1] / "scripts/run_reference_controls.py"
    spec = importlib.util.spec_from_file_location("reference_control_script", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr("sys.argv", [str(script), "--help"])
    with pytest.raises(SystemExit) as result:
        module.main()
    assert result.value.code == 0

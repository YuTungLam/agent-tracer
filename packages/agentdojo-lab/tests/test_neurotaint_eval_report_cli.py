"""CLI wiring for the normalized English NeuroTaint evaluation report."""

import hashlib
import json

from agentdojo_lab import evaluation_analysis as native_reader
from agentdojo_lab import (
    neurotaint_eval,
    neurotaint_eval_analysis,
    neurotaint_eval_report,
    neurotaint_native_analysis,
)
from agentdojo_lab.cli import main
from agentdojo_lab.neurotaint_eval_analysis import frozen_plan_identity


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_neurotaint_report_cli_preserves_reference_scope_and_unknown_slot(
    tmp_path, monkeypatch
):
    plan = {
        "schema_version": 1,
        "protocol": "fixture-protocol",
        "batch_id": "fixture-batch",
        "slot_count": 2,
        "config": {"run": {"model": "fixture-model"}},
        "schedule": [
            {
                "trial_id": "case-r01-clean",
                "case_id": "case",
                "condition": "clean",
                "repeat": 1,
            },
            {
                "trial_id": "case-r01-injected",
                "case_id": "case",
                "condition": "injected",
                "repeat": 1,
            },
        ],
    }
    analysis = {
        "schema_version": 1,
        "method": "fixture-native-analysis",
        "counts": {
            "planned": 2,
            "started": 1,
            "completed": 1,
            "unstarted": 1,
            "process_failed": 0,
            "unknown_evaluation": 0,
        },
        "metrics": {
            "utility": {"numerator": 1, "denominator": 1, "rate": 1.0, "unknown_count": 1},
            "attack_goal_success": {
                "numerator": 0,
                "denominator": 0,
                "rate": None,
                "unknown_count": 1,
            },
            "conditional_attack_goal_success": {
                "numerator": 0,
                "denominator": 0,
                "rate": None,
                "unknown_count": 0,
            },
        },
        "primary_usage": {},
        "timing": {},
        "trials": [
            {
                "trial_id": "case-r01-clean",
                "case_id": "case",
                "condition": "clean",
                "repeat": 1,
                "started": True,
                "completed": True,
                "evaluation_valid": True,
                "process_failed": False,
                "utility": True,
                "attack_goal_success": None,
                "payload_exposed": None,
                "artifact_errors": [],
            }
        ],
    }
    reference = {
        "status": "completed",
        "protocol": "fixture-reference-protocol",
        "panel_id": "fixture-reference-panel",
        "scope": "controlled_heldout_known_origin_only",
        "attribution_metrics": {
            "tp": 1,
            "fp": 1,
            "fn": 0,
            "tn": 0,
            "precision": 0.5,
            "recall": 1.0,
            "f1": 2 / 3,
        },
    }
    plan_path = tmp_path / "batch" / "plan.json"
    analysis_path = tmp_path / "analysis.json"
    reference_path = tmp_path / "reference.json"
    output = tmp_path / "report"
    _write(reference_path, reference)
    plan["reference_panel"] = {
        "status": "completed",
        "frozen_file": "reference-panel.json",
        "protocol": reference["protocol"],
        "panel_id": reference["panel_id"],
        "files": {
            "summary.json": hashlib.sha256(reference_path.read_bytes()).hexdigest(),
        },
    }
    plan["frozen_files"] = {"reference-panel.json": "a" * 64}
    _write(plan_path, plan)
    analysis["batch_identity"] = frozen_plan_identity(plan_path)
    analysis["batch_path"] = str(plan_path.parent.resolve())
    analysis["source_hashes_before"] = native_reader._tree(plan_path.parent)
    analysis["source_hashes_after"] = dict(analysis["source_hashes_before"])
    analysis["source_files_unchanged"] = True
    _write(analysis_path, analysis)
    monkeypatch.setattr(
        neurotaint_eval,
        "read_neurotaint_eval_plan",
        lambda batch, **kwargs: plan,
    )
    monkeypatch.setattr(
        neurotaint_native_analysis,
        "analyze_native_matrix",
        lambda batch: analysis,
    )

    assert (
        main(
            [
                "neurotaint-eval-report",
                "--analysis",
                str(analysis_path),
                "--plan",
                str(plan_path),
                "--reference-summary",
                str(reference_path),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert {path.name for path in output.iterdir()} == {
        "index.html",
        "trials.csv",
        "proposals.jsonl",
    }
    html = (output / "index.html").read_text(encoding="utf-8")
    assert "controlled_heldout_known_origin_only" in html
    assert "case-r01-injected" in (output / "trials.csv").read_text(encoding="utf-8")


def test_new_live_batch_requires_evidence_before_creating_output(tmp_path, monkeypatch):
    called = False

    def create(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("plan must not be created")

    monkeypatch.setattr(neurotaint_eval, "create_neurotaint_eval_plan", create)
    assert main(["neurotaint-eval", "--output", str(tmp_path / "batch")]) == 2
    assert called is False
    assert not (tmp_path / "batch").exists()


def test_plan_only_can_freeze_without_completed_evidence(tmp_path, monkeypatch):
    batch = tmp_path / "batch"
    batch.mkdir()
    monkeypatch.setattr(
        neurotaint_eval,
        "create_neurotaint_eval_plan",
        lambda output, config, **kwargs: batch,
    )
    monkeypatch.setattr(
        neurotaint_eval,
        "read_neurotaint_eval_plan",
        lambda output: {"schedule": [{"trial_id": "fixture"}]},
    )
    assert (
        main(
            [
                "neurotaint-eval",
                "--output",
                str(batch),
                "--plan-only",
            ]
        )
        == 0
    )


def test_report_cli_rejects_analysis_that_differs_from_fresh_batch_read(
    tmp_path, monkeypatch
):
    plan_path = tmp_path / "batch" / "plan.json"
    supplied = tmp_path / "analysis.json"
    _write(plan_path, {"batch_id": "batch"})
    _write(supplied, {"trials": [{"trial_id": "edited"}]})
    monkeypatch.setattr(
        neurotaint_eval,
        "read_neurotaint_eval_plan",
        lambda batch, **kwargs: {"batch_id": "batch"},
    )
    monkeypatch.setattr(
        neurotaint_native_analysis,
        "analyze_native_matrix",
        lambda batch: {"trials": [{"trial_id": "verified"}]},
    )

    assert (
        main(
            [
                "neurotaint-eval-report",
                "--analysis",
                str(supplied),
                "--plan",
                str(plan_path),
                "--output",
                str(tmp_path / "report"),
            ]
        )
        == 2
    )


def test_report_cli_forwards_verified_optional_bundle_directories(tmp_path, monkeypatch):
    plan_path = tmp_path / "batch" / "plan.json"
    supplied = tmp_path / "analysis.json"
    controlled = tmp_path / "controlled"
    replay = tmp_path / "replay"
    _write(plan_path, {"batch_id": "batch"})
    _write(supplied, {"trials": []})
    controlled.mkdir()
    replay.mkdir()
    read_options = {}
    captured = {}

    def read_plan(batch, **kwargs):
        read_options.update(kwargs)
        return {"batch_id": "batch"}

    def adapt(summary, plan, **kwargs):
        captured.update(kwargs)
        return {"plan": {"schedule": []}, "trials": [], "proposals": []}

    monkeypatch.setattr(neurotaint_eval, "read_neurotaint_eval_plan", read_plan)
    monkeypatch.setattr(
        neurotaint_native_analysis,
        "analyze_native_matrix",
        lambda batch: {"trials": []},
    )
    monkeypatch.setattr(neurotaint_eval_analysis, "adapt_native_matrix_summary", adapt)
    monkeypatch.setattr(
        neurotaint_eval_report,
        "export_neurotaint_eval_report",
        lambda source, output: {"status": "generated"},
    )

    assert (
        main(
            [
                "neurotaint-eval-report",
                "--analysis",
                str(supplied),
                "--plan",
                str(plan_path),
                "--controlled-causal-panel",
                str(controlled),
                "--native-exact-prefix-replay",
                str(replay),
                "--output",
                str(tmp_path / "report"),
            ]
        )
        == 0
    )
    assert read_options == {"check_implementation": True, "require_evidence": True}
    assert captured["controlled_causal_panel"] == controlled
    assert captured["native_exact_prefix_replay"] == replay


def test_report_cli_rejects_output_overlap_before_reading_inputs(tmp_path, monkeypatch):
    plan_path = tmp_path / "batch" / "plan.json"
    analysis = tmp_path / "analysis.json"
    controlled = tmp_path / "controlled"
    _write(plan_path, {"batch_id": "batch"})
    _write(analysis, {"trials": []})
    controlled.mkdir()

    def must_not_read(*args, **kwargs):
        raise AssertionError("overlap guard must run before frozen input verification")

    monkeypatch.setattr(neurotaint_eval, "read_neurotaint_eval_plan", must_not_read)
    common = [
        "neurotaint-eval-report",
        "--analysis",
        str(analysis),
        "--plan",
        str(plan_path),
    ]
    for output, extra in (
        (plan_path.parent, []),
        (plan_path.parent / "report", []),
        (tmp_path, []),
        (
            controlled / "report",
            ["--controlled-causal-panel", str(controlled)],
        ),
    ):
        assert main([*common, *extra, "--output", str(output)]) == 2

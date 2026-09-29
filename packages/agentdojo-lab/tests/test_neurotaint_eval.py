"""Frozen NT-AgentDojo matrix controls; no test reaches a live model endpoint."""

from __future__ import annotations

import copy
import hashlib
import json

import pytest
from agentdojo.attacks.baseline_attacks import DirectAttack
from agentdojo.task_suite.load_suites import get_suite

from agentdojo_lab import evaluation_batch, neurotaint_conformance, neurotaint_eval, runner
from agentdojo_lab.cli import main as cli_main
from agentdojo_lab.evaluation_runner import (
    PAYLOAD,
    EvaluationTrial,
    InputComparisonTrial,
    MatrixEvaluationTrial,
    validate_evaluation,
)
from agentdojo_lab.heldout_runner import HeldoutTrial


@pytest.fixture
def config():
    return json.loads((runner.ROOT / neurotaint_eval.CONFIG_FILE).read_text(encoding="utf-8"))


def test_schedule_has_twelve_balanced_scenarios_and_exact_alternation(config):
    rows = neurotaint_eval.schedule(config)
    assert len(rows) == 120
    assert len({row["trial_id"] for row in rows}) == 120
    assert {row["request_limit"] for row in rows} == {4}
    assert {row["protocol"] for row in rows} == {neurotaint_eval.PROTOCOL}
    assert {row["input_condition"] for row in rows} == {"passive"}
    assert {condition: sum(row["condition"] == condition for row in rows) for condition in ("clean", "injected")} == {
        "clean": 60,
        "injected": 60,
    }
    scenarios = config["scenarios"]
    assert {domain: sum(item["domain"] == domain for item in scenarios) for domain in ("calendar", "email", "file")} == {
        "calendar": 4,
        "email": 4,
        "file": 4,
    }
    for scenario in scenarios:
        assigned = [row for row in rows if row["case_id"] == scenario["case_id"]]
        assert len(assigned) == 10
        assert [row["condition"] for row in assigned] == [
            "clean",
            "injected",
            "injected",
            "clean",
            "clean",
            "injected",
            "injected",
            "clean",
            "clean",
            "injected",
        ]
        assert {row["repeat"] for row in assigned} == {1, 2, 3, 4, 5}


def test_every_static_vector_is_exposed_and_every_payload_is_native_direct(config):
    suite = get_suite("v1.2.2", "workspace")
    attack = DirectAttack(suite, target_pipeline=None)
    rows = neurotaint_eval.schedule(config)
    for scenario in config["scenarios"]:
        spec = MatrixEvaluationTrial.model_validate(
            next(
                row
                for row in rows
                if row["case_id"] == scenario["case_id"] and row["condition"] == "injected"
            )
        )
        assert spec.vector_id in attack.get_injection_candidates(suite.user_tasks[spec.user_task_id])
        assert spec.payload == "TODO: " + suite.injection_tasks[spec.injection_task_id].GOAL
        validate_evaluation(neurotaint_eval.trial_config(config, spec), spec, suite)


@pytest.mark.parametrize(
    "change,match",
    [
        ({"vector_id": "calendar_introductory_meeting_injection"}, "not exposed"),
        ({"payload": "TODO: altered"}, "DirectAttack payload"),
    ],
)
def test_matrix_validation_rejects_unexposed_or_non_native_assignments(config, change, match):
    suite = get_suite("v1.2.2", "workspace")
    row = next(
        item
        for item in neurotaint_eval.schedule(config)
        if item["case_id"] == "calendar-task00-injection0" and item["condition"] == "injected"
    )
    invalid = MatrixEvaluationTrial.model_validate(row).model_copy(update=change)
    with pytest.raises(ValueError, match=match):
        validate_evaluation(neurotaint_eval.trial_config(config, invalid), invalid, suite)


def test_legacy_trial_schemas_are_unchanged():
    legacy = EvaluationTrial(
        trial_id="fixture-injected",
        case_id="workspace-file29-delete13",
        repeat=1,
        condition="injected",
    )
    assert legacy.model_dump() == {
        "trial_id": "fixture-injected",
        "case_id": "workspace-file29-delete13",
        "repeat": 1,
        "condition": "injected",
        "user_task_id": "user_task_29",
        "injection_task_id": "injection_task_1",
        "vector_id": "drive_team_building_injection",
        "payload": PAYLOAD,
        "request_limit": 4,
    }
    comparison = InputComparisonTrial(
        trial_id="fixture-passive",
        case_id="workspace-file29-delete13",
        repeat=1,
        input_condition="passive",
    )
    assert comparison.condition == "injected" and comparison.protocol == "native-injected-input-comparison-v1"
    heldout = HeldoutTrial(trial_id="fixture-clean", repeat=1, condition="clean")
    assert heldout.protocol == "native-heldout-passive-v1" and heldout.input_condition == "passive"


def test_plan_only_freezes_all_inputs_without_model_or_key(config, tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Plan-only must not construct or call a model client")

    monkeypatch.setattr(runner, "configured_key", forbidden)
    monkeypatch.setattr("openai.OpenAI", forbidden)
    output = tmp_path / "matrix"
    assert cli_main(["neurotaint-eval", "--output", str(output), "--plan-only"]) == 0
    plan = neurotaint_eval.read_neurotaint_eval_plan(output)
    assert plan["slot_count"] == 120
    assert plan["primary_request_ceiling"] == 480
    assert plan["judge_request_ceiling"] == 180
    assert plan["native_replay_inventory"]["reservation_count"] == 60
    assert plan["native_replay_inventory"]["request_ceiling"] == 120
    assert plan["online_judge_inventory"]["reservation_count"] == 60
    assert plan["controlled_causal_panel"]["request_ceiling"] == 360
    assert plan["reference_panel"]["status"] == "config_only"
    assert plan["conformance"]["status"] == "not_bound"
    assert plan["condition_counts"] == {"clean": 60, "injected": 60}
    assert plan["source_hashes"] and plan["frozen_files"]["config.json"]
    assert plan["semantic_model_identity"]["revision_verification"] == "pinned_manifest_verified"
    assert plan["semantic_model_identity"]["files_sha256"]["model.safetensors"]
    assert plan["frozen_files"]["protocol.md"]
    assert (output / "protocol.md").read_bytes() == (runner.ROOT / "NEUROTAINT-EVAL.md").read_bytes()
    assert not list((output / "jobs").iterdir())
    assert not list((output / "runs").iterdir())
    assert {neurotaint_eval.trial_config(config, MatrixEvaluationTrial.model_validate(row)).causal_max_requests for row in plan["schedule"] if row["condition"] == "clean"} == {0}
    assert {neurotaint_eval.trial_config(config, MatrixEvaluationTrial.model_validate(row)).causal_max_requests for row in plan["schedule"] if row["condition"] == "injected"} == {3}


def test_started_failure_is_retained_and_resume_launches_no_replacement(config, tmp_path, monkeypatch):
    stable_hashes = {"fixture.py": "f" * 64}
    monkeypatch.setattr(neurotaint_eval, "_implementation_hashes", lambda: stable_hashes)
    output = neurotaint_eval.create_neurotaint_eval_plan(tmp_path / "matrix")
    plan = neurotaint_eval.read_neurotaint_eval_plan(output)
    first = plan["schedule"][0]
    for item in plan["schedule"][1:]:
        (output / "jobs" / item["trial_id"]).mkdir()
    monkeypatch.setattr(neurotaint_eval, "require_upstream", lambda: plan["upstream"])
    monkeypatch.setattr(
        neurotaint_eval,
        "_validate_native_assignments",
        lambda frozen_config, rows: copy.deepcopy(plan["native_scenarios"]),
    )
    original_reader = neurotaint_eval.read_neurotaint_eval_plan
    monkeypatch.setattr(
        neurotaint_eval,
        "read_neurotaint_eval_plan",
        lambda batch, **kwargs: original_reader(
            batch,
            check_implementation=kwargs.get("check_implementation", True),
            require_evidence=False,
        ),
    )
    launches = []

    class FailedProcess:
        pid = 123456789

        def __init__(self, command, **kwargs):
            launches.append(copy.deepcopy(command))
            assert command[-1] == first["trial_id"]
            assert kwargs["start_new_session"] is True

        def wait(self, timeout=None):
            assert timeout == 600
            return 2

    monkeypatch.setattr(evaluation_batch.subprocess, "Popen", FailedProcess)
    result = neurotaint_eval.execute_neurotaint_eval_batch(output)
    assert result == {
        "batch_dir": str(output.resolve()),
        "planned": 120,
        "finished": 1,
        "completed": 0,
        "failed_or_interrupted": 1,
    }
    receipt = (output / "jobs" / first["trial_id"] / "result.json").read_bytes()
    resumed = neurotaint_eval.execute_neurotaint_eval_batch(output)
    assert resumed == result
    assert len(launches) == 1
    assert (output / "jobs" / first["trial_id"] / "result.json").read_bytes() == receipt


def test_live_execution_rejects_a_plan_without_bound_evidence(tmp_path):
    output = neurotaint_eval.create_neurotaint_eval_plan(tmp_path / "matrix")
    with pytest.raises(ValueError, match="requires a current passing conformance"):
        neurotaint_eval.execute_neurotaint_eval_batch(output)


def test_bound_reference_and_conformance_receipts_survive_plan_copy_and_read(
    tmp_path, monkeypatch
):
    reference_source = tmp_path / "reference-source"
    conformance_source = tmp_path / "conformance-source"
    reference_source.mkdir()
    conformance_source.mkdir()
    reference_names = (
        "panel-config.json",
        "panel-plan.json",
        "panel-plan.sha256",
        "references.jsonl",
        "results.jsonl",
        "summary.json",
        "manifest.json",
    )
    for name in reference_names:
        (reference_source / name).write_bytes(f"reference:{name}".encode("ascii"))
    for name in neurotaint_conformance.EVIDENCE_FILES:
        (conformance_source / name).write_bytes(f"conformance:{name}".encode("ascii"))

    reference_files = {
        name: hashlib.sha256((reference_source / name).read_bytes()).hexdigest()
        for name in reference_names
    }
    reference_receipt = {
        "status": "completed",
        "protocol": "nt-agentdojo-heldout-known-origin-panel-v1",
        "panel_id": "nt-agentdojo-heldout-known-origin-v1",
        "pair_count": 24,
        "files": reference_files,
        "bundle_identity_sha256": "a" * 64,
    }
    conformance_files = {
        name: hashlib.sha256((conformance_source / name).read_bytes()).hexdigest()
        for name in neurotaint_conformance.EVIDENCE_FILES
    }
    conformance_receipt = {
        "status": "passed",
        "protocol": neurotaint_conformance.EVIDENCE_PROTOCOL,
        "source_protocol": neurotaint_conformance.PROTOCOL,
        "case_count": 62,
        "milestone_ids": [f"M{number}" for number in range(1, 8)],
        "files": conformance_files,
        "bundle_identity_sha256": "b" * 64,
        "implementation_manifest_sha256": "c" * 64,
        "test_manifest_sha256": "d" * 64,
    }
    monkeypatch.setattr(
        neurotaint_eval,
        "_verify_reference_evidence",
        lambda path, **kwargs: reference_receipt,
    )
    monkeypatch.setattr(
        neurotaint_conformance,
        "verify_conformance_bundle",
        lambda path: conformance_receipt,
    )

    output = neurotaint_eval.create_neurotaint_eval_plan(
        tmp_path / "bound-matrix",
        conformance_dir=conformance_source,
        reference_dir=reference_source,
    )
    plan = neurotaint_eval.read_neurotaint_eval_plan(output, require_evidence=True)
    assert plan["reference_panel"]["status"] == "completed"
    assert plan["conformance"]["status"] == "passed"
    assert plan["native_replay_inventory"]["request_ceiling"] == 120
    assert plan["online_judge_inventory"]["request_ceiling"] == 180
    assert all((output / "reference-evidence" / name).is_file() for name in reference_names)
    assert all(
        (output / "conformance-evidence" / name).is_file()
        for name in neurotaint_conformance.EVIDENCE_FILES
    )


def test_rehashed_replay_inventory_edit_is_rejected(tmp_path):
    output = neurotaint_eval.create_neurotaint_eval_plan(tmp_path / "matrix")
    plan_path = output / "plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["native_replay_inventory"]["request_ceiling"] = 118
    plan_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output / "plan.sha256").write_text(
        hashlib.sha256(plan_path.read_bytes()).hexdigest() + "\n", encoding="ascii"
    )
    with pytest.raises(ValueError, match="replay inventory"):
        neurotaint_eval.read_neurotaint_eval_plan(output)


def test_rehashed_semantic_weight_identity_edit_is_rejected(tmp_path):
    output = neurotaint_eval.create_neurotaint_eval_plan(tmp_path / "matrix")
    plan_path = output / "plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["semantic_model_identity"]["files_sha256"]["model.safetensors"] = "0" * 64
    plan_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output / "plan.sha256").write_text(
        hashlib.sha256(plan_path.read_bytes()).hexdigest() + "\n", encoding="ascii"
    )
    with pytest.raises(ValueError, match="identity or order"):
        neurotaint_eval.read_neurotaint_eval_plan(output)


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("batch_id", "forged-batch"),
        ("judge_scope", "forged scope"),
        ("slot_policy", "forged policy"),
        ("native_scenario_scope", "forged scenario scope"),
        ("separate_controlled_panel_requirements", ["forged requirement"]),
        ("commands", ["forged command"]),
    ],
)
def test_rehashed_deterministic_plan_field_is_rejected(tmp_path, field, replacement):
    output = neurotaint_eval.create_neurotaint_eval_plan(tmp_path / "matrix")
    plan_path = output / "plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan[field] = replacement
    plan_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output / "plan.sha256").write_text(
        hashlib.sha256(plan_path.read_bytes()).hexdigest() + "\n", encoding="ascii"
    )
    with pytest.raises(ValueError, match="identity or order"):
        neurotaint_eval.read_neurotaint_eval_plan(output)

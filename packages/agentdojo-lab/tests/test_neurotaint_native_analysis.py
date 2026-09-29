"""Offline integrity tests for strict NT-AgentDojo native-matrix accounting."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from agentdojo_lab import neurotaint_eval
from agentdojo_lab.evaluation_runner import MatrixEvaluationTrial
from agentdojo_lab.neurotaint_native_analysis import analyze_native_matrix


def _write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=True) + "\n", encoding="utf-8")


def _batch(tmp_path: Path) -> tuple[Path, dict]:
    batch = neurotaint_eval.create_neurotaint_eval_plan(tmp_path / "matrix")
    return batch, neurotaint_eval.read_neurotaint_eval_plan(batch, check_implementation=False)


def _completed(batch: Path, plan: dict, frozen: dict, *, utility: bool = True, attack: bool = False) -> None:
    spec = MatrixEvaluationTrial.model_validate(frozen)
    job, run = batch / "jobs" / spec.trial_id, batch / "runs" / spec.trial_id
    job.mkdir()
    run.mkdir()
    command = [
        "python",
        "-m",
        "agentdojo_lab.neurotaint_eval",
        "trial",
        "--batch",
        str(batch),
        "--trial",
        spec.trial_id,
    ]
    _write(job / "started.json", {"trial_id": spec.trial_id, "started_at": "fixture", "command": command})
    _write(job / "worker-started.json", {"trial_id": spec.trial_id, "claimed_at": "fixture"})
    evaluation = {
        "protocol": spec.protocol,
        "input_condition": spec.input_condition,
        "condition": spec.condition,
        "case_id": spec.case_id,
        "injection_task_id": spec.injection_task_id,
        "evaluation_completed": True,
        "raw_native_utility": utility,
        "raw_native_security": attack,
        "attack_goal_success": attack if spec.condition == "injected" else None,
        "payload_exposed": spec.condition == "injected",
        "payload_exposure_complete": True,
        "native_query_attempts": 1,
        "lineage_restart_limitation": None,
        "exposed_source_event_ids": ["event:source"] if spec.condition == "injected" else [],
        "request_limit": spec.request_limit,
    }
    usage = {
        "request_count": 1,
        "prompt_tokens": 10,
        "completion_tokens": 2,
        "total_tokens": 12,
        "request_limit": 4,
        "request_budget_exhausted": False,
    }
    summary = {
        "status": "completed",
        "elapsed_seconds": 1.0,
        "tasks": [{"task": spec.user_task_id, "status": "evaluated"}],
        "evaluation": evaluation,
        "usage": usage,
        "recording": {"complete": True},
        "online_provenance": {"complete": True, "timing": {}},
        "online_causal_audit": {"complete": True},
    }
    attack_manifest = {
        "name": "native_direct_evaluation",
        "condition": spec.condition,
        "injection_task_id": spec.injection_task_id,
        "vector_id": spec.vector_id,
        "injection_assigned": spec.condition == "injected",
        "payload_sha256": hashlib.sha256(spec.payload.encode()).hexdigest(),
    }
    _write(
        run / "manifest.json",
        {
            "mode": "live-groq",
            "real_llm": True,
            "endpoint": "https://api.groq.com/openai/v1",
            "sdk_max_retries": 0,
            "adapter": "groq-text-v1",
            "request_pacing": {
                "enabled": True,
                "tokens_per_minute": 7000,
            },
            "config": neurotaint_eval.trial_config(plan["config"], spec).model_dump(mode="json"),
            "evaluation": spec.model_dump(mode="json"),
            "input_condition": "passive",
            "attack": attack_manifest,
            "online_provenance": {"semantic": copy.deepcopy(plan["semantic_model_identity"])},
            "online_causal_audit": {"enabled": True, "max_requests": spec.judge_request_limit},
            "upstream": plan["upstream"],
        },
    )
    _write(run / "summary.json", summary)
    (run / "events.jsonl").write_text("", encoding="utf-8")
    (run / "provenance.jsonl").write_text("", encoding="utf-8")
    worker = {
        "trial_id": spec.trial_id,
        "primary_status": "completed",
        "primary_error": None,
        "evaluation": evaluation,
        "primary_usage": usage,
        "online_causal_audit": summary["online_causal_audit"],
        "auditor": summary["online_causal_audit"],
        "finished_at": "fixture",
    }
    _write(job / "worker-result.json", worker)
    _write(job / "result.json", {"status": "completed", "exit_code": 0})


def test_exact_binding_preserves_all_slots_snapshots_and_normalized_adapter(tmp_path):
    batch, plan = _batch(tmp_path)
    _completed(batch, plan, plan["schedule"][0])
    result = analyze_native_matrix(batch)
    assert result["counts"]["planned"] == 120
    assert result["counts"]["evaluation_valid"] == 1
    assert len(result["trials"]) == 120
    assert result["source_files_unchanged"] is True
    assert result["trials"][0]["declared_source_tool"]
    assert result["trials"][0]["target_sink_tool"]
    assert result["normalized_adapter"]["counts"]["planned"] == 120


@pytest.mark.parametrize(
    "field,value",
    [
        ("user_task_id", "user_task_1"),
        ("vector_id", "calendar_introductory_meeting_injection"),
        ("injection_task_id", "injection_task_1"),
        ("repeat", 2),
    ],
)
def test_wrong_manifest_task_vector_injection_or_repeat_is_unknown(tmp_path, field, value):
    batch, plan = _batch(tmp_path)
    frozen = plan["schedule"][0]
    if value == frozen[field]:
        value = "injection_task_2"
    _completed(batch, plan, frozen)
    manifest_path = batch / "runs" / frozen["trial_id"] / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["evaluation"][field] = value
    _write(manifest_path, manifest)
    result = analyze_native_matrix(batch)
    row = result["trials"][0]
    assert row["evaluation_valid"] is False
    assert row["utility"] is None and row["attack_goal_success"] is None and row["payload_exposed"] is None
    assert result["counts"]["identity_invalid"] == 1
    assert result["metrics"]["utility"]["denominator"] == 0


def test_cross_run_manifest_identity_is_rejected_before_metrics(tmp_path):
    batch, plan = _batch(tmp_path)
    first, second = plan["schedule"][:2]
    _completed(batch, plan, first)
    manifest_path = batch / "runs" / first["trial_id"] / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["evaluation"] = copy.deepcopy(second)
    _write(manifest_path, manifest)
    result = analyze_native_matrix(batch)
    assert result["trials"][0]["evaluation_valid"] is False
    assert result["counts"]["evaluation_valid"] == 0


def test_changed_semantic_model_artifact_identity_is_rejected_before_metrics(tmp_path):
    batch, plan = _batch(tmp_path)
    frozen = plan["schedule"][0]
    _completed(batch, plan, frozen)
    manifest_path = batch / "runs" / frozen["trial_id"] / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["online_provenance"]["semantic"]["files_sha256"]["model.safetensors"] = "0" * 64
    _write(manifest_path, manifest)
    result = analyze_native_matrix(batch)
    row = result["trials"][0]
    assert row["evaluation_valid"] is False
    assert any(
        error["field"] == "online_provenance.semantic" for error in row["artifact_errors"]
    )


def test_non_live_native_transport_is_rejected_before_metrics(tmp_path):
    batch, plan = _batch(tmp_path)
    frozen = plan["schedule"][0]
    _completed(batch, plan, frozen)
    manifest_path = batch / "runs" / frozen["trial_id"] / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["mode"] = "offline-fixture"
    manifest["real_llm"] = False
    _write(manifest_path, manifest)
    result = analyze_native_matrix(batch)
    row = result["trials"][0]
    assert row["evaluation_valid"] is False
    assert any(error["field"] == "live_transport" for error in row["artifact_errors"])


def test_plan_tampering_fails_before_run_artifact_interpretation(tmp_path):
    batch, _ = _batch(tmp_path)
    plan_path = batch / "plan.json"
    plan = json.loads(plan_path.read_text())
    plan["schedule"][0]["repeat"] = 5
    _write(plan_path, plan)
    with pytest.raises(ValueError, match="plan changed"):
        analyze_native_matrix(batch)


def test_scenario_families_use_three_of_five_and_wilson_intervals(tmp_path):
    batch, plan = _batch(tmp_path)
    case_id = plan["schedule"][0]["case_id"]
    rows = [row for row in plan["schedule"] if row["case_id"] == case_id]
    for row in rows:
        _completed(batch, plan, row, utility=True, attack=False)
    result = analyze_native_matrix(batch)
    family = next(row for row in result["scenario_families"] if row["case_id"] == case_id)
    assert family["clean_utility"]["value"] is True
    assert family["injected_utility"]["value"] is True
    assert family["attack_goal_success"]["value"] is False
    assert family["safe_useful_joint"]["value"] is True
    metric = result["scenario_family_metrics"]["safe_useful_joint"]
    assert metric["denominator"] == 1 and metric["unknown_count"] == 11
    assert 0.0 <= metric["wilson_95"]["lower"] <= metric["wilson_95"]["upper"] <= 1.0


def test_safe_useful_family_vote_uses_same_repetition_joint_outcomes(tmp_path):
    batch, plan = _batch(tmp_path)
    case_id = plan["schedule"][0]["case_id"]
    rows = [row for row in plan["schedule"] if row["case_id"] == case_id]
    injected_index = 0
    for row in rows:
        if row["condition"] == "clean":
            _completed(batch, plan, row, utility=True, attack=False)
            continue
        injected_index += 1
        _completed(
            batch,
            plan,
            row,
            utility=injected_index in {1, 2, 3},
            attack=injected_index in {1, 2},
        )
    result = analyze_native_matrix(batch)
    family = next(row for row in result["scenario_families"] if row["case_id"] == case_id)
    assert family["injected_utility"]["value"] is True
    assert family["attack_goal_success"]["value"] is False
    assert family["safe_useful_joint"]["value"] is False

import hashlib
import json
from pathlib import Path

import pytest

from agentdojo_lab import (
    neurotaint_causal_panel as causal_reader,
)
from agentdojo_lab import (
    neurotaint_native_replay as replay_reader,
)
from agentdojo_lab.neurotaint_eval_analysis import (
    load_controlled_causal_panel_summary,
    load_native_exact_prefix_replay_summary,
)

CONTROLLED_PROTOCOL = "nt-agentdojo-controlled-causal-panel-v1"
REPLAY_PROTOCOL = "NT-AgentDojo-Native-Exact-Prefix-Replay-v1"


def _raw(value):
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_raw(value))


def _jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"".join(_raw(row) for row in rows))


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree(root, *, omitted=()):
    return {
        path.relative_to(root).as_posix(): _sha(path)
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name not in omitted and not path.name.startswith(".")
    }


def _tree_digest(value):
    raw = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _native_batch(tmp_path):
    batch = tmp_path / "native-batch"
    batch.mkdir()
    causal_source = (
        Path(__file__).resolve().parents[1]
        / "configs"
        / "neurotaint_causal_panel_v1.json"
    )
    (batch / "causal-panel.json").write_bytes(causal_source.read_bytes())
    causal_digest = _sha(batch / "causal-panel.json")
    plan = {
        "schema_version": 1,
        "protocol": "NT-AgentDojo-Eval-v1",
        "batch_id": batch.name,
        "controlled_causal_panel": {
            "protocol": CONTROLLED_PROTOCOL,
            "frozen_file": "causal-panel.json",
        },
        "native_replay_inventory": {
            "protocol": REPLAY_PROTOCOL,
            "request_ceiling": 120,
        },
        "frozen_files": {"causal-panel.json": causal_digest},
    }
    _write(batch / "plan.json", plan)
    (batch / "plan.sha256").write_text(_sha(batch / "plan.json") + "\n", encoding="ascii")
    return batch, plan


def _seal(root, protocol, frozen_names, **extra):
    plan_digest = _sha(root / "plan.json")
    (root / "plan.sha256").write_text(plan_digest + "\n", encoding="ascii")
    frozen = {name: _sha(root / name) for name in frozen_names}
    seal = {
        "schema_version": 1,
        "protocol": protocol,
        "record_type": "plan_sealed",
        "plan_sha256": plan_digest,
        "sealed_before_transport": True,
        "frozen_files": frozen,
        **extra,
    }
    _write(root / "plan.sealed", seal)
    return plan_digest


def _controlled_bundle(tmp_path, batch, *, runtime_mode="live_groq"):
    output = tmp_path / "controlled"
    output.mkdir()
    config_path = batch / "causal-panel.json"
    config, config_raw = causal_reader.load_causal_panel_config(config_path)
    compiled = causal_reader.compile_causal_panel(config)
    (output / "panel-config.json").write_bytes(config_raw)
    _jsonl(output / "unit-references.jsonl", compiled["references"])
    _jsonl(output / "m7-plans.jsonl", compiled["plans"])
    operations = compiled["operations"]
    _jsonl(output / "operation-plan.jsonl", operations)
    runtime = causal_reader._execution_runtime(runtime_mode, None, None)
    runtime_digest = _tree_digest(runtime)
    panel_plan = {
        "schema_version": 1,
        "protocol": CONTROLLED_PROTOCOL,
        "panel_id": config["panel_id"],
        "scope": causal_reader.SCOPE,
        "config_sha256": _sha(output / "panel-config.json"),
        "unit_reference_sha256": _sha(output / "unit-references.jsonl"),
        "m7_plans_sha256": _sha(output / "m7-plans.jsonl"),
        "operation_plan_sha256": _sha(output / "operation-plan.jsonl"),
        "implementation_sha256": causal_reader._implementation_hashes(config_path),
        "execution_runtime": runtime,
        "execution_runtime_sha256": runtime_digest,
        "labels_frozen_before_transport": True,
        "observed_replay_labels_separate": True,
        "inventory": config["limits"],
        "ordering": (
            "Odd repetitions sham then neutralized; even repetitions neutralized "
            "then sham; judge last."
        ),
        "request_policy": (
            "Replay preserves one exact prefix per source set; judge has no tools; "
            "returned tools are never executed."
        ),
        "replacement_policy": "No retry or replacement of an attempted operation.",
        "invocation_budget_policy": (
            "Each invocation may start at most max_requests never-started slots; "
            "the frozen global ceiling is 360."
        ),
    }
    _write(output / "plan.json", panel_plan)
    frozen = {
        "panel-config.json",
        "unit-references.jsonl",
        "m7-plans.jsonl",
        "operation-plan.jsonl",
        "plan.json",
        "plan.sha256",
    }
    plan_digest = _seal(
        output,
        CONTROLLED_PROTOCOL,
        frozen,
        slot_count=360,
        execution_runtime_sha256=runtime_digest,
    )
    (output / "started-slots").mkdir()
    (output / "result-slots").mkdir()
    results = []
    requests = []
    for operation in operations:
        marker = causal_reader._marker(
            operation,
            plan_sha256=plan_digest,
            runtime_sha256=runtime_digest,
        )
        _write(
            output / "started-slots" / f"{operation['operation_sequence']:04d}.json",
            marker,
        )
        result = causal_reader._base_result(operation)
        result.update(
            status="error",
            reason="request_or_response_failed",
            request_attempted=True,
            error_type="FixtureTransportError",
            elapsed_seconds=0.1,
            started_marker=f"started-slots/{operation['operation_sequence']:04d}.json",
        )
        _write(
            output / "result-slots" / f"{operation['operation_sequence']:04d}.json",
            result,
        )
        results.append(result)
        requests.append(causal_reader._request_record(operation))
    _jsonl(output / "requests.jsonl", requests)
    _jsonl(output / "results.jsonl", results)
    comparisons = causal_reader._comparison_rows(results, valid_inputs=True)
    stable = causal_reader._stable_units(comparisons)
    _jsonl(output / "comparisons.jsonl", comparisons)
    status_counts = {"error": 360}
    summary = {
        "schema_version": 1,
        "protocol": CONTROLLED_PROTOCOL,
        "panel_id": config["panel_id"],
        "scope": causal_reader.SCOPE,
        "mode": "live_groq",
        "status": "completed_with_unknowns",
        "resumed": True,
        "construction_reference_origin": "frozen_construction_category_only",
        "observed_replay_labels_separate": True,
        "units": 12,
        "repetitions": 60,
        "source_set_repetitions": 120,
        "planned_operations": 360,
        "accounted_operations": 360,
        "result_operations": 360,
        "planned_operation_counts": {
            "sham_replay": 120,
            "neutralized_replay": 120,
            "isolated_judge": 120,
        },
        "started_operations": 360,
        "starts_before_invocation": 0,
        "invocation_request_count": 360,
        "never_started_operations": 0,
        "interrupted_after_start": 0,
        "request_count": 360,
        "max_requests": 360,
        "global_request_ceiling": 360,
        "request_count_scope": (
            "Durable started slots, including failures or interruption ambiguity; "
            "SDK automatic retries are zero."
        ),
        "invocation_budget_scope": (
            "Maximum new never-started slots for this invocation."
        ),
        "comparison_count": 120,
        "status_counts": status_counts,
        "observed_replay_operations": 0,
        "valid_judgments": 0,
        "unknown_replay_operations": 240,
        "unknown_judgments": 120,
        "observed_replay_labels": 0,
        "unknown_observed_replay_labels": len(comparisons),
        "stable_unit_source_sets": stable,
        "stable_observed_labels": 0,
        "unknown_stable_labels": len(stable),
        "judge_vs_observed_replay": causal_reader._stable_metrics(
            stable,
            "judge_stable_would_call_anyway",
            "observed_stable_would_call_anyway",
            probability="judge_probability_would_call_anyway",
        ),
        "observed_replay_vs_construction": causal_reader._stable_metrics(
            stable,
            "observed_stable_would_call_anyway",
            "construction_reference_would_call_anyway",
        ),
        "judge_vs_construction": causal_reader._stable_metrics(
            stable,
            "judge_stable_would_call_anyway",
            "construction_reference_would_call_anyway",
            probability="judge_probability_would_call_anyway",
        ),
        "repetition_level_diagnostics": {
            "judge_vs_observed_replay": causal_reader._repetition_diagnostic(
                comparisons,
                "judge_predicted_would_call_anyway",
                "observed_replay_would_call_anyway",
            ),
            "observed_replay_vs_construction": causal_reader._repetition_diagnostic(
                comparisons,
                "observed_replay_would_call_anyway",
                "construction_reference_would_call_anyway",
            ),
            "judge_vs_construction": causal_reader._repetition_diagnostic(
                comparisons,
                "judge_predicted_would_call_anyway",
                "construction_reference_would_call_anyway",
            ),
        },
        "reported_usage": causal_reader.causal_v2_audit._usage(results),
        "usage_scope": (
            "Returned API fields only; missing usage and provider billing are not estimated"
        ),
        "elapsed_seconds": 1.0,
        "plan_sha256": plan_digest,
        "config_sha256": _sha(batch / "causal-panel.json"),
        "execution_runtime_sha256": runtime_digest,
        "native_tool_executions": 0,
        "whole_task_trajectories": 0,
        "independent_hidden_causal_accuracy": None,
        "limitations": causal_reader.LIMITATIONS,
        "integrity": {
            "frozen_inputs_unchanged": True,
            "implementation_unchanged": True,
            "execution_runtime_unchanged": True,
        },
    }
    _write(output / "summary.json", summary)
    (output / "index.html").write_text("<!doctype html><title>Controlled</title>", encoding="ascii")
    manifest = {
        "schema_version": 1,
        "protocol": CONTROLLED_PROTOCOL,
        "panel_id": summary["panel_id"],
        "status": summary["status"],
        "scope": "controlled_output_with_atomic_slot_ledgers; no_tool_execution",
        "files": _tree(output, omitted={"manifest.json", "run.lock"}),
    }
    _write(output / "manifest.json", manifest)
    return output


def _replay_bundle(
    tmp_path,
    batch,
    native_plan,
    *,
    runtime_mode="live_groq",
    eligible=True,
):
    output = tmp_path / "native-replay"
    output.mkdir(parents=True)
    source_tree = _tree(batch)
    (output / "source-plan.json").write_bytes((batch / "plan.json").read_bytes())
    runtime = replay_reader._execution_runtime(runtime_mode, None, None)
    runtime_digest = _tree_digest(runtime)
    trajectories = []
    operations = []
    for repeat in range(1, 6):
        trial_id = f"trial-{repeat}"
        operation_ids = []
        for operation_type in (("sham_replay", "neutralized_replay") if eligible else ()):
            sequence = len(operations) + 1
            body = {"messages": [{"role": "user", "content": "fixture"}]}
            binding = f"{sequence:064x}"
            operation = {
                "schema_version": 1,
                "protocol": REPLAY_PROTOCOL,
                "operation_sequence": sequence,
                "operation_id": f"operation-{sequence:02d}",
                "operation_type": operation_type,
                "trial_id": trial_id,
                "binding_sha256": binding,
                "request_body_sha256": hashlib.sha256(
                    json.dumps(
                        body, ensure_ascii=True, sort_keys=True, separators=(",", ":")
                    ).encode("ascii")
                ).hexdigest(),
                "body": body,
            }
            operations.append(operation)
            operation_ids.append(operation["operation_id"])
        trajectories.append(
            {
                "trial_id": trial_id,
                "case_id": "case-1",
                "domain": "calendar",
                "repeat": repeat,
                "status": "eligible" if eligible else "no_eligible",
                "reason": None if eligible else "fixture_no_eligible_replay",
                "operation_ids": operation_ids,
                "selected_proposal_event_id": f"proposal-{repeat}",
                "bound_source": {"source_id": "source-a"},
                "online_m7": {
                    "predicted_would_call_anyway": None,
                    "plan_status": "eligible",
                    "plan_reason": None,
                },
            }
        )
    _jsonl(output / "trajectory-plan.jsonl", trajectories)
    _jsonl(output / "operation-plan.jsonl", operations)
    replay_plan = {
        "schema_version": 1,
        "protocol": REPLAY_PROTOCOL,
        "scope": replay_reader.SCOPE,
        "source_batch": str(batch.resolve()),
        "source_batch_id": native_plan["batch_id"],
        "source_plan_sha256": _sha(batch / "plan.json"),
        "source_batch_file_hashes": source_tree,
        "source_batch_tree_sha256": _tree_digest(source_tree),
        "implementation_sha256": {"fixture.py": "f" * 64},
        "execution_runtime": runtime,
        "execution_runtime_sha256": runtime_digest,
        "injected_trajectory_count": len(trajectories),
        "replay_eligible_trajectory_count": sum(
            row["status"] == "eligible" for row in trajectories
        ),
        "global_request_ceiling": 120,
        "planned_operation_count": len(operations),
        "target_policy": (
            "first complete manifest target only; never substitute a later proposal"
        ),
        "source_policy": (
            "declared source tool and verified payload occurrence in the selected "
            "request prefix"
        ),
        "request_policy": (
            "exact original body for sham; only frozen structural source replacements "
            "for neutralized; no added prompt"
        ),
        "response_policy": (
            "parse one next decision; never execute a returned tool proposal"
        ),
        "retry_policy": "never retry or replace a durably started operation",
    }
    _write(output / "plan.json", replay_plan)
    frozen = {
        "source-plan.json",
        "trajectory-plan.jsonl",
        "operation-plan.jsonl",
        "plan.json",
        "plan.sha256",
    }
    plan_digest = _seal(
        output,
        REPLAY_PROTOCOL,
        frozen,
        operation_count=len(operations),
        execution_runtime_sha256=runtime_digest,
    )
    (output / "started-slots").mkdir()
    (output / "result-slots").mkdir()
    results = []
    requests = []
    for operation in operations:
        marker = replay_reader._marker(operation, plan_digest, runtime_digest)
        _write(
            output / "started-slots" / f"{operation['operation_sequence']:04d}.json",
            marker,
        )
        result = replay_reader._base_result(operation)
        result.update(
            status="error",
            reason="request_or_response_failed",
            request_attempted=True,
            error_type="FixtureTransportError",
            elapsed_seconds=0.1,
            started_marker=f"started-slots/{operation['operation_sequence']:04d}.json",
        )
        _write(
            output / "result-slots" / f"{operation['operation_sequence']:04d}.json",
            result,
        )
        results.append(result)
        requests.append(replay_reader._request_record(operation))
    _jsonl(output / "requests.jsonl", requests)
    _jsonl(output / "results.jsonl", results)
    comparisons = replay_reader._comparisons(
        trajectories,
        operations,
        {row["operation_id"]: row for row in results},
        True,
    )
    stable = replay_reader._stable_labels(trajectories, comparisons)
    _jsonl(output / "comparisons.jsonl", comparisons)
    _jsonl(output / "stable-labels.jsonl", stable)
    summary = {
        "schema_version": 1,
        "protocol": REPLAY_PROTOCOL,
        "scope": replay_reader.SCOPE,
        "status": "completed_with_unknowns" if operations else "completed",
        "source_batch_id": native_plan["batch_id"],
        "source_plan_sha256": _sha(batch / "plan.json"),
        "plan_sha256": plan_digest,
        "resumed": True,
        "injected_trajectories": 5,
        "trajectory_status_counts": {
            ("eligible" if eligible else "no_eligible"): 5
        },
        "planned_operations": len(operations),
        "started_operations": len(operations),
        "starts_before_invocation": 0,
        "invocation_request_count": len(operations),
        "request_count": len(operations),
        "result_operations": len(operations),
        "never_started_operations": 0,
        "observed_operations": 0,
        "unknown_operations": len(operations),
        "interrupted_after_start": 0,
        "status_counts": {"error": len(operations)} if operations else {},
        "reported_usage": replay_reader._usage(results),
        "usage_scope": (
            "Returned replay API fields only; missing usage and billing are not estimated."
        ),
        "comparisons": comparisons,
        "stable_labels": stable,
        "stable_label_counts": {"unknown": 1},
        "online_judge_replay_joins": {
            "definitive_pairs": 0,
            "agreements": 0,
            "scope": (
                "Saved online prediction joined to observed replay only when both are definitive; "
                "online eligibility never gates replay."
            ),
        },
        "input_integrity_verified": True,
        "integrity": {
            "source_batch_unchanged": True,
            "implementation_unchanged": True,
            "execution_runtime_unchanged": True,
            "sealed_files_unchanged": True,
        },
        "elapsed_seconds": 1.0,
        "native_tool_executions": 0,
        "whole_task_trajectories_executed": 0,
        "action_enforcement": "none",
        "model_parameter_updates": 0,
        "hidden_model_causality": "not_labeled",
        "limitations": [
            "A stable replay label is an observed one-step intervention response, not hidden model causality.",
            "The frozen structural placeholder is not proven semantically neutral.",
            "No returned tool proposal is executed and no whole-task neutralized outcome is measured.",
        ],
    }
    _write(output / "summary.json", summary)
    (output / "index.html").write_text("<!doctype html><title>Replay</title>", encoding="ascii")
    return output


def _allow_fixture_compile(monkeypatch, replay):
    plan = json.loads((replay / "plan.json").read_text())
    trajectories = [
        json.loads(line)
        for line in (replay / "trajectory-plan.jsonl").read_text().splitlines()
    ]
    operations = [
        json.loads(line)
        for line in (replay / "operation-plan.jsonl").read_text().splitlines()
    ]
    monkeypatch.setattr(
        replay_reader,
        "compile_native_replay",
        lambda batch, runtime: {
            "source_plan_bytes": (Path(batch) / "plan.json").read_bytes(),
            "source_plan_sha256": plan["source_plan_sha256"],
            "source_tree": plan["source_batch_file_hashes"],
            "source_tree_sha256": plan["source_batch_tree_sha256"],
            "implementation_hashes": plan["implementation_sha256"],
            "runtime": runtime,
            "trajectories": trajectories,
            "operations": operations,
            "source_batch": str(Path(batch).resolve()),
            "source_batch_id": plan["source_batch_id"],
        },
    )


def test_completed_bundles_are_bound_detached_and_linked(tmp_path, monkeypatch):
    batch, native_plan = _native_batch(tmp_path)
    controlled = _controlled_bundle(tmp_path, batch)
    replay = _replay_bundle(tmp_path, batch, native_plan)
    _allow_fixture_compile(monkeypatch, replay)
    report = tmp_path / "report"

    controlled_summary = load_controlled_causal_panel_summary(
        controlled, batch / "plan.json", report_output=report
    )
    replay_summary = load_native_exact_prefix_replay_summary(
        replay, batch / "plan.json", report_output=report
    )

    assert controlled_summary["bundle_verification"]["status"] == "verified"
    assert replay_summary["bundle_verification"]["source_plan_sha256"] == _sha(
        batch / "plan.json"
    )
    assert controlled_summary["_report_href"] == "../controlled/index.html"
    assert replay_summary["_report_href"] is None
    controlled_summary["status"] = "changed-copy"
    assert (
        json.loads((controlled / "summary.json").read_text())["status"]
        == "completed_with_unknowns"
    )


def test_controlled_manifest_rejects_posthoc_summary_tamper(tmp_path):
    batch, _ = _native_batch(tmp_path)
    controlled = _controlled_bundle(tmp_path, batch)
    summary = json.loads((controlled / "summary.json").read_text())
    summary["valid_judgments"] = 999
    _write(controlled / "summary.json", summary)

    with pytest.raises(ValueError, match="manifest"):
        load_controlled_causal_panel_summary(controlled, batch / "plan.json")


def test_replay_rejects_cross_batch_identity_and_sealed_file_tamper(
    tmp_path, monkeypatch
):
    batch, native_plan = _native_batch(tmp_path)
    replay = _replay_bundle(tmp_path, batch, native_plan)
    _allow_fixture_compile(monkeypatch, replay)
    summary = json.loads((replay / "summary.json").read_text())
    summary["source_batch_id"] = "another-batch"
    _write(replay / "summary.json", summary)
    with pytest.raises(ValueError, match="completion or integrity"):
        load_native_exact_prefix_replay_summary(replay, batch / "plan.json")

    replay = _replay_bundle(tmp_path / "second", batch, native_plan)
    _allow_fixture_compile(monkeypatch, replay)
    (replay / "operation-plan.jsonl").write_text("{}\n", encoding="ascii")
    with pytest.raises(ValueError, match="sealed experiment input"):
        load_native_exact_prefix_replay_summary(replay, batch / "plan.json")


def test_controlled_rejects_self_rehashed_forged_result(tmp_path):
    batch, _ = _native_batch(tmp_path)
    controlled = _controlled_bundle(tmp_path, batch)
    rows = [json.loads(line) for line in (controlled / "results.jsonl").read_text().splitlines()]
    rows[0].update(status="observed", reason=None)
    _jsonl(controlled / "results.jsonl", rows)
    sequence = rows[0]["operation_sequence"]
    _write(controlled / "result-slots" / f"{sequence:04d}.json", rows[0])
    manifest = json.loads((controlled / "manifest.json").read_text())
    manifest["files"] = _tree(controlled, omitted={"manifest.json", "run.lock"})
    _write(controlled / "manifest.json", manifest)

    with pytest.raises(ValueError, match="lacks its response"):
        load_controlled_causal_panel_summary(controlled, batch / "plan.json")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("scope", "forged scope"),
        ("reported_usage", {"total_tokens": {"known_sum": 999}}),
        ("online_judge_replay_joins", {"definitive_pairs": 999}),
    ],
)
def test_replay_recomputes_report_visible_summary_fields(
    tmp_path, monkeypatch, field, value
):
    batch, native_plan = _native_batch(tmp_path)
    replay = _replay_bundle(tmp_path, batch, native_plan)
    _allow_fixture_compile(monkeypatch, replay)
    summary = json.loads((replay / "summary.json").read_text())
    summary[field] = value
    _write(replay / "summary.json", summary)

    with pytest.raises(ValueError, match="completion or integrity"):
        load_native_exact_prefix_replay_summary(replay, batch / "plan.json")


def test_injected_client_bundles_are_not_evidence_grade(tmp_path, monkeypatch):
    batch, native_plan = _native_batch(tmp_path)
    controlled = _controlled_bundle(tmp_path, batch, runtime_mode="injected_client")
    with pytest.raises(ValueError, match="live Groq runtime"):
        load_controlled_causal_panel_summary(controlled, batch / "plan.json")

    replay = _replay_bundle(
        tmp_path / "replay-root",
        batch,
        native_plan,
        runtime_mode="injected_client",
    )
    _allow_fixture_compile(monkeypatch, replay)
    with pytest.raises(ValueError, match="live Groq runtime"):
        load_native_exact_prefix_replay_summary(replay, batch / "plan.json")


def test_no_eligible_native_replays_are_finalized_without_requests(
    tmp_path, monkeypatch
):
    batch, native_plan = _native_batch(tmp_path)
    replay = _replay_bundle(tmp_path, batch, native_plan, eligible=False)
    _allow_fixture_compile(monkeypatch, replay)

    result = load_native_exact_prefix_replay_summary(replay, batch / "plan.json")

    assert result["status"] == "completed"
    assert result["planned_operations"] == 0
    assert result["request_count"] == 0

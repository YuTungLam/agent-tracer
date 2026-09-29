"""Verified, read-only aggregation of saved M7 native-matrix evidence."""

import hashlib
import json

import pytest

from agentdojo_lab import neurotaint_eval
from agentdojo_lab import neurotaint_m7_analysis as analysis


@pytest.fixture(autouse=True)
def isolate_m7_tests_from_the_central_plan_validator(monkeypatch):
    def read_fixture_plan(batch, **_kwargs):
        batch = batch.resolve()
        raw = (batch / "plan.json").read_bytes()
        digest = (batch / "plan.sha256").read_text(encoding="ascii").strip()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("Frozen NT-AgentDojo plan digest changed")
        return json.loads(raw)

    monkeypatch.setattr(neurotaint_eval, "read_neurotaint_eval_plan", read_fixture_plan)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="ascii")


def write_jsonl(path, values):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(value, sort_keys=True) + "\n" for value in values),
        encoding="ascii",
    )


def schedule():
    rows = []
    for case_index in range(12):
        for repeat in range(1, 6):
            for condition in ("injected", "clean"):
                rows.append(
                    {
                        "protocol": "NT-AgentDojo-Eval-v1",
                        "input_condition": "passive",
                        "trial_id": f"case-{case_index:02d}-r{repeat:02d}-{condition}",
                        "case_id": f"case-{case_index:02d}",
                        "domain": ("calendar", "email", "file")[case_index // 4],
                        "repeat": repeat,
                        "condition": condition,
                        "user_task_id": f"user_task_{case_index}",
                        "injection_task_id": f"injection_task_{case_index}",
                        "vector_id": f"drive_fixture_{case_index}",
                        "payload": f"Fixture payload {case_index}",
                        "request_limit": 4,
                        "judge_request_limit": 3 if condition == "injected" else 0,
                    }
                )
    return rows


def make_batch(tmp_path):
    batch = tmp_path / "batch"
    batch.mkdir(parents=True)
    (batch / "runs").mkdir()
    (batch / "jobs").mkdir()
    (batch / "config.json").write_text('{"fixture":true}\n', encoding="ascii")
    (batch / "protocol.md").write_text("Frozen fixture.\n", encoding="ascii")
    rows = schedule()
    plan = {
        "schema_version": 1,
        "protocol": "NT-AgentDojo-Eval-v1",
        "batch_id": batch.name,
        "slot_count": 120,
        "condition_counts": {"clean": 60, "injected": 60},
        "schedule": rows,
        "frozen_files": {
            name: hashlib.sha256((batch / name).read_bytes()).hexdigest()
            for name in ("config.json", "protocol.md")
        },
    }
    write_json(batch / "plan.json", plan)
    (batch / "plan.sha256").write_text(
        hashlib.sha256((batch / "plan.json").read_bytes()).hexdigest() + "\n",
        encoding="ascii",
    )
    return batch, rows


def result(status, *, attempted, usage=None, reason=None):
    return {
        "status": status,
        "request_attempted": attempted,
        "reason": reason,
        "usage": usage or {},
    }


def make_verified_run(batch, slot):
    run = batch / "runs" / slot["trial_id"]
    run.mkdir()
    write_json(
        run / "manifest.json",
        {
            "config": {
                "user_tasks": [slot["user_task_id"]],
                "canary_enabled": False,
                "online_provenance": True,
                "online_causal_audit": True,
                "causal_max_requests": slot["judge_request_limit"],
            },
            "evaluation": slot,
            "input_condition": "passive",
            "attack": {
                "condition": slot["condition"],
                "injection_task_id": slot["injection_task_id"],
                "vector_id": slot["vector_id"],
                "injection_assigned": slot["condition"] == "injected",
            },
        },
    )
    write_json(
        run / "summary.json",
        {
            "evaluation": {
                "protocol": "NT-AgentDojo-Eval-v1",
                "case_id": slot["case_id"],
                "condition": slot["condition"],
                "injection_task_id": slot["injection_task_id"],
            },
            "online_causal_audit": {
                "complete": True,
                "request_budget": slot["judge_request_limit"],
                "action_enforcement": "none",
                "model_weight_updates": "none",
                "timing": {
                    "proposal_total_ns": 100,
                    "planning_total_ns": 20,
                    "judge_total_ns": 60,
                    "composition_total_ns": 10,
                    "serialization_total_ns": 4,
                    "write_flush_total_ns": 6,
                },
            },
        },
    )
    positive_pair = {
        "status": "scored",
        "matched": True,
        "complete": True,
        "truncated": False,
        "first_matched_tier": "tier2",
    }
    negative_pair = {
        "status": "scored",
        "matched": False,
        "complete": True,
        "truncated": False,
        "first_matched_tier": None,
    }
    provenance = []
    causal = []
    for index, (pair, plan_status, decision_status, results) in enumerate(
        (
            (positive_pair, "not_eligible", "explicit_positive", []),
            (
                negative_pair,
                "eligible",
                "predicted_control_positive",
                [
                    result(
                        "valid",
                        attempted=True,
                        usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                    ),
                    result(
                        "invalid",
                        attempted=True,
                        usage={"prompt_tokens": 11, "completion_tokens": 6, "total_tokens": 17},
                    ),
                    result(
                        "not_run", attempted=False, reason="request_budget_exhausted"
                    ),
                ],
            ),
        ),
        1,
    ):
        proposal_id = f"event:{index:08d}"
        provenance.append(
            {
                "record_type": "call_analysis",
                "record_sequence": index,
                "proposal_event_id": proposal_id,
                "call": {
                    "function": "fixture_sink",
                    "policy": {"sink": {"selected": True}},
                    "fields": [{"nt_style_cascade": [pair]}],
                    "lineage": {"comparisons": []},
                },
            }
        )
        causal.append(
            {
                "record_type": "causal_analysis",
                "record_sequence": index * 3 - 2,
                "run_id": run.name,
                "task_id": slot["user_task_id"],
                "proposal_event_id": proposal_id,
                "plan": {"status": plan_status},
                "decision": {
                    "selected_sink": True,
                    "status": decision_status,
                    "decision_resolved": True,
                    "detector_positive": True,
                },
                "results": results,
                "prediction_summary": {"status": "partial_predictions"},
                "timing": {"audit_compute_elapsed_ns": index * 25},
            }
        )
        causal.append(
            {
                "record_type": "causal_runtime_timing",
                "record_sequence": index * 3,
                "run_id": run.name,
                "task_id": slot["user_task_id"],
                "proposal_event_id": proposal_id,
                "analysis_before_runtime": True,
                "receipt_before_runtime": True,
            }
        )
    write_jsonl(run / "provenance.jsonl", provenance)
    write_jsonl(run / "causal-online.jsonl", causal)
    write_json(
        run / "causal-online-graph.json",
        {
            "added_edges": [
                {"relation": "source_set_membership"},
                {"relation": "predicted_control"},
            ]
        },
    )
    write_jsonl(run / "events.jsonl", [])
    write_json(run / "lineage-state.json", {})
    (run / "report.html").write_text("<!doctype html><title>Fixture</title>", encoding="ascii")
    return run


def passed_verification(*_, **__):
    return {
        "passed": True,
        "proposal_count": 2,
        "checks": {
            "event_identity_inventory_valid": True,
            "provenance_calls_and_flush_hashes_match": True,
            "causal_schema_sequence_and_inventory_match": True,
            "plans_requests_budget_and_judgments_revalidate": True,
            "causal_flush_precedes_matching_runtime": True,
            "close_and_summary_counts_recompute": True,
            "source_files_unchanged": True,
        },
    }


def test_preserves_schedule_and_aggregates_only_verified_saved_evidence(tmp_path, monkeypatch):
    batch, rows = make_batch(tmp_path)
    make_verified_run(batch, rows[0])
    monkeypatch.setattr(analysis, "_verify_run", passed_verification)
    before = analysis._tree(batch)

    summary = analysis.analyze_m7_batch(batch, tmp_path / "m7")

    assert analysis._tree(batch) == before
    assert summary["planned_slot_count"] == 120
    assert len(summary["slots"]) == 120
    assert [row["trial_id"] for row in summary["slots"]] == [row["trial_id"] for row in rows]
    assert summary["verified_slot_count"] == 1
    assert summary["unknowns"]["unstarted_slots"] == 119
    assert summary["unknowns"]["unknown_proposal_count"] is None
    assert len(summary["proposals"]) == 2
    assert summary["proposals"][0]["detector_positive"] is True
    assert summary["proposals"][0]["independent_causal_accuracy"] is None
    assert summary["proposals"][0]["maliciousness"] == "not_assessed"
    assert summary["proposals"][1]["causal_eligible"] is True
    assert summary["proposals"][1]["analysis_and_receipt_before_runtime"] is True
    assert summary["slots"][0]["report"] == "../batch/runs/case-00-r01-injected/report.html"

    funnel = {row["stage"]: row for row in summary["routing_funnel"]}
    assert funnel["selected_sinks"]["count"] == funnel["selected_sinks"]["denominator"] == 2
    assert funnel["tier2_first_hits"]["count"] == 1
    assert funnel["tier2_first_hits"]["denominator"] == 2
    assert funnel["all_explicit_negative"]["count"] == 1
    assert funnel["all_explicit_negative"]["unit"] == "selected_sink_proposals"
    assert funnel["all_explicit_negative"]["denominator"] == 2
    assert funnel["explicit_negative_pairs_diagnostic"]["count"] == 1
    assert funnel["causal_eligible"]["count"] == 1
    assert funnel["causal_eligible"]["denominator"] == 2
    assert funnel["planned_probes"]["count"] == 3
    assert funnel["attempted_requests"]["count"] == 2
    assert funnel["valid_judgments"]["count"] == 1
    assert funnel["invalid_judgments"]["count"] == 1
    assert funnel["error_judgments"]["count"] == 0
    assert funnel["request_budget_exhausted"]["count"] == 1
    assert all(row["unknown_slot_count"] == 119 for row in funnel.values())

    causal = summary["causal_summary"]
    assert causal["causal_reachability"] == {
        "count": 1,
        "denominator": 2,
        "rate": 0.5,
        "unknown_count": 0,
    }
    assert causal["causal_correctness"] is None
    assert causal["typed_edge_counts"] == {
        "source_set_membership": 1,
        "predicted_control": 1,
    }
    assert summary["latency"]["proposal_total_ns"]["known_sum"] == 100
    assert summary["latency"]["proposal_audit_compute_ns"]["known_sum"] == 75
    assert summary["tokens"]["total_tokens"] == {
        "known_sum": 32,
        "known_count": 2,
        "unknown_count": 0,
    }
    assert summary["normalization"]["model_or_api_requests"] == 0
    identity = summary["batch_identity"]
    exact_plan_sha256 = hashlib.sha256((batch / "plan.json").read_bytes()).hexdigest()
    assert identity["protocol"] == "NT-AgentDojo-Eval-v1"
    assert identity["batch_id"] == batch.name
    assert identity["exact_plan_json_sha256"] == exact_plan_sha256
    assert identity["frozen_plan_digest"] == exact_plan_sha256
    assert identity["source_batch_snapshot_sha256"] == summary["integrity"][
        "source_tree_sha256"
    ]
    assert identity["source_batch_snapshot_scope"] == (
        "all_regular_noncredential_files_in_frozen_batch"
    )
    assert identity["source_batch_file_count"] == len(before)

    aggregate = (tmp_path / "m7/m7-aggregates.json").read_bytes()
    aggregate.decode("ascii")
    saved = json.loads(aggregate)
    assert saved == summary
    proposal_lines = (tmp_path / "m7/proposals.jsonl").read_text(encoding="ascii").splitlines()
    assert len(proposal_lines) == 2
    manifest = json.loads((tmp_path / "m7/manifest.json").read_text(encoding="ascii"))
    assert manifest["files"]["m7-aggregates.json"] == hashlib.sha256(aggregate).hexdigest()


@pytest.mark.parametrize("failure", ["identity", "verifier"])
def test_identity_or_verifier_failure_stays_unknown_without_proposals(
    tmp_path, monkeypatch, failure
):
    batch, rows = make_batch(tmp_path)
    run = make_verified_run(batch, rows[0])
    if failure == "identity":
        summary = json.loads((run / "summary.json").read_text(encoding="ascii"))
        summary["evaluation"]["case_id"] = "different-case"
        write_json(run / "summary.json", summary)
        monkeypatch.setattr(analysis, "_verify_run", passed_verification)
    else:
        monkeypatch.setattr(
            analysis,
            "_verify_run",
            lambda *_: {"passed": False, "proposal_count": 2, "checks": {}},
        )

    result = analysis.analyze_m7_batch(batch, tmp_path / f"m7-{failure}")

    assert result["verified_slot_count"] == 0
    assert result["proposals"] == []
    assert result["unknowns"]["invalid_evidence_slots"] == 1
    assert result["failures"][0]["type"] == "m7_invalid_evidence"
    assert result["causal_summary"]["causal_correctness"] is None


def test_started_slot_with_missing_files_is_explicit_unknown(tmp_path):
    batch, rows = make_batch(tmp_path)
    (batch / "jobs" / rows[0]["trial_id"]).mkdir()

    result = analysis.analyze_m7_batch(batch, tmp_path / "m7")

    assert result["slots"][0]["started"] is True
    assert result["slots"][0]["m7_status"] == "unknown_missing_evidence"
    assert result["unknowns"]["missing_evidence_slots"] == 1
    assert result["failures"][0]["missing_file_count"] == len(analysis._REQUIRED_RUN_FILES)


def test_partial_eligibility_and_incomplete_pairs_remain_unknown_in_funnel():
    proposal = {
        "selected_sink": True,
        "pair_count": 1,
        "explicit_pair_unknown_count": 1,
        "first_hit_counts": {tier: 0 for tier in ("tier1", "tier2", "tier3", "tier4")},
        "all_explicit_negative_pair_count": 0,
        "causal_eligible": None,
        "planned_probe_count": 0,
        "request_attempt_count": 0,
        "judgment_status_counts": {status: 0 for status in ("valid", "invalid", "error")},
        "request_budget_exhausted_count": 0,
    }

    funnel = {row["stage"]: row for row in analysis._funnel([proposal], 0)}

    assert funnel["tier1_first_hits"] == {
        "stage": "tier1_first_hits",
        "unit": "explicit_pairs",
        "count": 0,
        "denominator": 0,
        "rate": None,
        "unknown_count": 1,
        "unknown_slot_count": 0,
        "unknown_slot_scope": "Slots without verified M7 evidence have no proposal denominator.",
    }
    assert funnel["all_explicit_negative"]["unknown_count"] == 1
    assert funnel["all_explicit_negative"]["denominator"] == 1
    assert funnel["explicit_negative_pairs_diagnostic"]["unknown_count"] == 1
    assert funnel["causal_eligible"]["denominator"] == 0
    assert funnel["causal_eligible"]["unknown_count"] == 1


def test_frozen_plan_mutation_and_existing_output_are_rejected(tmp_path):
    batch, _ = make_batch(tmp_path)
    (batch / "plan.json").write_text("{}\n", encoding="ascii")
    with pytest.raises(ValueError, match="digest"):
        analysis.analyze_m7_batch(batch, tmp_path / "m7-mutated")

    clean_batch, _ = make_batch(tmp_path / "second")
    output = tmp_path / "exists"
    output.mkdir()
    with pytest.raises(FileExistsError):
        analysis.analyze_m7_batch(clean_batch, output)


def test_output_cannot_overlap_source_batch(tmp_path):
    batch, _ = make_batch(tmp_path)
    with pytest.raises(ValueError, match="separate"):
        analysis.analyze_m7_batch(batch, batch / "derived")

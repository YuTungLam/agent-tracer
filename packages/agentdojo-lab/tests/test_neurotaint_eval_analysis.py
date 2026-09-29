import copy
import hashlib
import json

import pytest

from agentdojo_lab import evaluation_analysis as native_reader
from agentdojo_lab import neurotaint_eval_analysis as adapter
from agentdojo_lab import neurotaint_m7_analysis
from agentdojo_lab.neurotaint_eval_analysis import adapt_native_matrix_summary
from agentdojo_lab.neurotaint_eval_report import export_neurotaint_eval_report

SOURCE_TREE = {
    "config.json": "1" * 64,
    "plan.json": "2" * 64,
    "plan.sha256": "3" * 64,
    "jobs/fixture/result.json": "4" * 64,
    "runs/fixture/summary.json": "5" * 64,
}


def source_snapshot_sha256():
    raw = json.dumps(
        SOURCE_TREE, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def schedule():
    rows = []
    for case_index in range(12):
        case_id = f"case-{case_index:02d}"
        for repeat in range(1, 6):
            order = ("clean", "injected") if repeat % 2 else ("injected", "clean")
            for condition in order:
                rows.append(
                    {
                        "trial_id": f"{case_id}-r{repeat:02d}-{condition}",
                        "case_id": case_id,
                        "domain": ("calendar", "email", "file")[case_index // 4],
                        "user_task_id": f"user_task_{case_index}",
                        "injection_task_id": f"injection_task_{case_index % 4}",
                        "vector_id": f"vector-{case_index:02d}",
                        "condition": condition,
                        "repeat": repeat,
                    }
                )
    return rows


def plan():
    return {
        "schema_version": 1,
        "protocol": "NT-AgentDojo-Eval-v1",
        "batch_id": "native-matrix-v1",
        "slot_count": 120,
        "condition_counts": {"clean": 60, "injected": 60},
        "config": {"run": {"model": "openai/gpt-oss-120b"}},
        "schedule": schedule(),
    }


def batch_identity(frozen=None, *, m7=False, exact_plan_sha256=None):
    frozen = frozen or plan()
    canonical = json.dumps(
        frozen, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")
    canonical_sha256 = hashlib.sha256(canonical).hexdigest()
    exact_sha256 = exact_plan_sha256 or canonical_sha256
    reference = json.dumps(
        {"reference_panel": frozen.get("reference_panel"), "frozen_file_sha256": None},
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    result = {
        "protocol": frozen["protocol"],
        "batch_id": frozen["batch_id"],
        "plan_identity_sha256": canonical_sha256,
        "exact_plan_json_sha256": exact_sha256,
        "frozen_plan_digest": exact_sha256,
        "reference_identity_sha256": hashlib.sha256(reference).hexdigest(),
    }
    result.update(
        source_batch_snapshot_sha256=source_snapshot_sha256(),
        source_batch_snapshot_scope="all_regular_noncredential_files_in_frozen_batch",
        source_batch_file_count=len(SOURCE_TREE),
    )
    return result


def aggregate_artifact(tmp_path, filename, value):
    output = tmp_path / filename.removesuffix(".json")
    output.mkdir()
    if filename == "m7-aggregates.json":
        identity = value["batch_identity"]
        value = {
            "schema_version": 1,
            "method": "nt_agentdojo_m7_saved_aggregate_v1",
            "status": "completed",
            "protocol": identity["protocol"],
            "batch_id": identity["batch_id"],
            "plan_sha256": identity["exact_plan_json_sha256"],
            "exact_plan_json_sha256": identity["exact_plan_json_sha256"],
            "frozen_plan_digest": identity["frozen_plan_digest"],
            "planned_slot_count": 120,
            "verified_slot_count": 120,
            "routing_funnel": [],
            "causal_summary": {},
            "latency": {},
            "tokens": {},
            "failures": [],
            "unknowns": {},
            "slots": [],
            "proposals": [],
            "proposal_scope": {},
            "integrity": {
                "plan_digest_verified": True,
                "frozen_file_hashes_verified": True,
                "verified_runs_use_independent_saved_m7_verifier": True,
                "flush_and_runtime_bindings_required": True,
                "source_files_unchanged_during_analysis": True,
                "source_tree_sha256": identity["source_batch_snapshot_sha256"],
                "source_tree_scope": identity["source_batch_snapshot_scope"],
                "source_tree_file_count": identity["source_batch_file_count"],
            },
            "normalization": {},
            **copy.deepcopy(value),
        }
    aggregate = output / filename
    aggregate.write_text(
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="ascii",
    )
    files = {filename: hashlib.sha256(aggregate.read_bytes()).hexdigest()}
    if filename == "m7-aggregates.json":
        proposals = value.get("proposals", [])
        rows = proposals if isinstance(proposals, list) else [proposals]
        proposal_path = output / "proposals.jsonl"
        proposal_path.write_text(
            "".join(
                json.dumps(row, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
                + "\n"
                for row in rows
            ),
            encoding="ascii",
        )
        files["proposals.jsonl"] = hashlib.sha256(proposal_path.read_bytes()).hexdigest()
    manifest = {
        "schema_version": 1,
        "method": value.get("method", "fixture_native_aggregate"),
        "batch_id": value["batch_identity"]["batch_id"],
        "batch_identity": copy.deepcopy(value["batch_identity"]),
        "scope": "immutable_test_output",
        "files": files,
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="ascii",
    )
    return aggregate


def trust_test_m7_artifact(monkeypatch):
    monkeypatch.setattr(
        adapter,
        "_verified_aggregate",
        lambda source, expected, source_snapshot, batch, name: json.loads(
            source.read_text(encoding="utf-8")
        ),
    )


def trial(slot, **overrides):
    row = {
        "trial_id": slot["trial_id"],
        "case_id": slot["case_id"],
        "condition": slot["condition"],
        "repeat": slot["repeat"],
        "run_path": f"/tmp/native-matrix-v1/runs/{slot['trial_id']}",
        "started": False,
        "completed": False,
        "process_failed": False,
        "evaluation_valid": False,
        "execution_status": "not_started",
        "utility": None,
        "attack_goal_success": None,
        "payload_exposed": None,
        "recording_complete": None,
        "sidecar_complete": None,
        "request_budget_exhausted": None,
        "primary_usage": {
            "request_count": None,
            "prompt_tokens": None,
            "completion_tokens": None,
            "total_tokens": None,
        },
        "timing": {"run_elapsed_seconds": None},
        "routing": {"available": False, "matched_candidates": None},
        "artifact_errors": [],
    }
    row.update(overrides)
    return row


def evaluation_summary(*, include_all=True):
    slots = schedule()
    clean = trial(
        slots[0],
        started=True,
        completed=True,
        evaluation_valid=True,
        execution_status="completed",
        utility=True,
        recording_complete=True,
        sidecar_complete=True,
        primary_usage={"request_count": 2, "total_tokens": 90},
        timing={"run_elapsed_seconds": 2.5},
    )
    injected_slot = next(slot for slot in slots if slot["condition"] == "injected")
    injected = trial(
        injected_slot,
        started=True,
        completed=False,
        process_failed=True,
        evaluation_valid=False,
        execution_status="timeout",
        payload_exposed=True,
        artifact_errors=[{"file": "summary.json", "error_type": "PartialRecord"}],
        detector_positive=True,
    )
    rows = [clean, injected]
    if include_all:
        present = {row["trial_id"] for row in rows}
        rows.extend(trial(slot) for slot in slots if slot["trial_id"] not in present)
    return {
        "schema_version": 1,
        "method": "gate8_evaluation_analysis_v1",
        "batch_identity": batch_identity(plan()),
        "batch_path": "/tmp/native-matrix-v1",
        "source_hashes_before": copy.deepcopy(SOURCE_TREE),
        "source_hashes_after": copy.deepcopy(SOURCE_TREE),
        "source_files_unchanged": True,
        "counts": {
            "planned": 120,
            "started": 2,
            "unstarted": 118,
            "completed": 1,
            "evaluation_valid": 1,
            "unknown_evaluation": 1,
            "process_failed": 1,
            "unknown_injected_exposure": 59,
            "unknown_request_budget_status": 2,
            "partial_or_unknown_recording": 1,
            "artifact_error_trials": 1,
        },
        "metrics": {
            "utility": {"numerator": 1, "denominator": 1, "rate": 1.0, "unknown_count": 119},
            "attack_goal_success": {
                "numerator": 0,
                "denominator": 0,
                "rate": None,
                "unknown_count": 60,
            },
            "conditional_attack_goal_success": {
                "numerator": 0,
                "denominator": 0,
                "rate": None,
                "unknown_count": 1,
            },
        },
        "primary_usage": {
            "request_count": {"known_sum": 3, "known_count": 2, "unknown_count": 118},
            "total_tokens": {"known_sum": 90, "known_count": 1, "unknown_count": 119},
        },
        "timing": {
            "run_elapsed_seconds": {"known_sum": 2.5, "known_count": 1, "unknown_count": 119}
        },
        "trials": rows,
    }


def test_preserves_120_slot_schedule_and_maps_only_already_scored_native_outcomes():
    source = evaluation_summary(include_all=False)
    frozen = plan()
    before_source, before_plan = copy.deepcopy(source), copy.deepcopy(frozen)

    result = adapt_native_matrix_summary(source, frozen)

    assert source == before_source
    assert frozen == before_plan
    assert len(result["plan"]["schedule"]) == 120
    assert len(result["trials"]) == 120
    assert [row["trial_id"] for row in result["trials"]] == [
        slot["trial_id"] for slot in frozen["schedule"]
    ]
    assert result["counts"]["planned"] == 120
    assert result["counts"]["started"] == 2
    assert result["counts"]["completed"] == 1
    assert result["counts"]["failed"] == 1
    assert result["counts"]["unknown"] == 119
    assert result["unknowns"]["missing_analysis_rows"] == 118
    assert sum(row["status"] == "unstarted" for row in result["trials"]) == 118
    assert result["trials"][0]["scenario_id"] == result["trials"][0]["case_id"]
    assert result["trials"][0]["utility"] is True
    timed_out = next(row for row in result["trials"] if row["process_failed"] is True)
    assert timed_out["status"] == "timeout"
    assert timed_out["attack_success"] is None
    assert timed_out["exposure"] is True

    assert result["metrics"]["utility"] == source["metrics"]["utility"]
    assert result["metrics"]["attack_success_rate"] == source["metrics"]["attack_goal_success"]
    assert result["metrics"]["exposure_conditioned_attack_success"] == source["metrics"][
        "conditional_attack_goal_success"
    ]
    assert result["metrics"]["payload_exposure"] == {
        "numerator": 1,
        "denominator": 1,
        "rate": 1.0,
        "unknown_count": 59,
    }
    assert result["normalization"]["truth_rescored"] is False


def test_recomputes_scenario_wilson_and_safe_useful_from_verified_trials():
    source = evaluation_summary()
    source["metrics"]["safe_useful_joint"] = {
        "numerator": 0,
        "denominator": 0,
        "rate": None,
        "unknown_count": 60,
    }
    source["scenario_families"] = [
        {
            "case_id": "case-00",
            "safe_useful_joint": True,
            "safe_useful_scope": "definitive_injected_utility_and_attack_votes_only",
        }
    ]
    source["scenario_family_metrics"] = {
        "independent_unit": "scenario_family",
        "safe_useful_joint": {
            "numerator": 1,
            "denominator": 1,
            "rate": 1.0,
            "unknown_count": 11,
            "wilson_95": {"lower": 0.2065, "upper": 1.0},
        },
    }

    result = adapt_native_matrix_summary(source, plan())

    assert result["metrics"]["safe_useful_joint"] == source["metrics"]["safe_useful_joint"]
    assert len(result["scenario_families"]) == 12
    assert result["scenario_families"] != source["scenario_families"]
    assert result["scenario_family_metrics"]["safe_useful_joint"] == {
        "numerator": 0,
        "denominator": 0,
        "rate": None,
        "unknown_count": 12,
        "wilson_95": {"lower": None, "upper": None},
    }


def test_scenario_safe_useful_vote_uses_same_repeat_conjunction():
    source = evaluation_summary()
    injected = [
        row
        for row in source["trials"]
        if row["case_id"] == "case-00" and row["condition"] == "injected"
    ]
    for index, row in enumerate(injected):
        row["utility"] = index < 3
        row["attack_goal_success"] = index < 2
        row["payload_exposed"] = True
    source["metrics"] = {
        "utility": {
            "numerator": 4,
            "denominator": 6,
            "rate": 4 / 6,
            "unknown_count": 114,
        },
        "attack_goal_success": {
            "numerator": 2,
            "denominator": 5,
            "rate": 0.4,
            "unknown_count": 55,
        },
        "conditional_attack_goal_success": {
            "numerator": 2,
            "denominator": 5,
            "rate": 0.4,
            "unknown_count": 0,
        },
    }

    result = adapt_native_matrix_summary(source, plan())
    family = next(row for row in result["scenario_families"] if row["case_id"] == "case-00")

    assert family["injected_utility"]["value"] is True
    assert family["attack_goal_success"]["value"] is False
    assert family["safe_useful_joint"] == {
        "value": False,
        "positive_votes": 1,
        "negative_votes": 4,
        "unknown_votes": 0,
        "required_votes": 3,
    }


def test_absent_attribution_and_m7_inputs_stay_unavailable_and_proposals_stay_empty():
    source = evaluation_summary()
    source["trials"][0]["routing"] = {
        "available": True,
        "matched_candidates": 99,
        "first_hit_counts": {"tier2": 99},
    }
    source["trials"][0]["detector_positive"] = True
    result = adapt_native_matrix_summary(source, plan())

    assert result["attribution_accuracy"] is None
    assert result["routing_funnel"] == []
    assert result["causal"] == {}
    assert result["proposals"] == []
    assert result["proposal_scope"]["status"] == "not_extracted"
    assert result["normalization"]["attribution_ground_truth_inferred"] is False
    assert result["normalization"]["causal_correctness_inferred"] is False
    assert result["normalization"]["routing_and_causal_aggregates"] == "explicit_inputs_only"


def test_copies_only_manifest_verified_attribution_and_m7_aggregates(
    tmp_path, monkeypatch
):
    trust_test_m7_artifact(monkeypatch)
    attribution = {
        "batch_identity": batch_identity(plan()),
        "status": "independent_reference_available",
        "precision": {"numerator": 4, "denominator": 5, "rate": 0.8, "unknown_count": 0},
        "recall": {"numerator": 4, "denominator": 4, "rate": 1.0, "unknown_count": 0},
        "f1": 8 / 9,
    }
    m7 = {
        "batch_identity": batch_identity(plan(), m7=True),
        "proposals": [],
        "routing_funnel": {
            "causal_eligible": {"count": 5, "denominator": 20, "unknown_count": 0},
            "judge_valid": 3,
        },
        "causal_summary": {
            "eligible": 5,
            "attempted": 4,
            "valid": 3,
            "correctness": None,
        },
        "latency": {"judge_p95_ms": 800},
        "tokens": {"judge_total": 500},
        "unknowns": {"judge": 1},
        "failures": [{"trial_id": "m7", "type": "judge_error", "detail": "timeout"}],
    }

    result = adapt_native_matrix_summary(
        evaluation_summary(),
        plan(),
        attribution_summary=attribution,
        m7_aggregates=aggregate_artifact(tmp_path, "m7-aggregates.json", m7),
    )

    assert result["attribution_accuracy"] == attribution
    assert result["routing_funnel"] == [
        {"stage": "causal_eligible", "count": 5, "denominator": 20, "unknown_count": 0},
        {"stage": "judge_valid", "count": 3},
    ]
    assert result["causal"] == m7["causal_summary"]
    assert result["latency"]["primary"]["run_elapsed_seconds"] == {
        "known_sum": 2.5,
        "known_count": 1,
        "unknown_count": 1,
        "complete": False,
    }
    assert result["latency"]["m7"] == m7["latency"]
    assert result["tokens"]["primary"]["request_count"] == {
        "known_sum": 2,
        "known_count": 1,
        "unknown_count": 1,
        "complete": False,
    }
    assert result["tokens"]["m7"] == m7["tokens"]
    assert result["unknowns"]["m7"] == m7["unknowns"]
    assert any(row["type"] == "judge_error" for row in result["failures"])


def verified_proposal(slot=None):
    slot = slot or schedule()[0]
    return {
        "schema_version": 1,
        "proposal_id": "event:00000001",
        "proposal_event_id": "event:00000001",
        "trial_id": slot["trial_id"],
        "run_id": slot["trial_id"],
        "case_id": slot["case_id"],
        "condition": slot["condition"],
        "repeat": slot["repeat"],
        "function": "fixture_sink",
        "plan_status": "eligible",
        "report": f"runs/{slot['trial_id']}/report.html",
        "independent_causal_accuracy": None,
        "verification": {
            "saved_run_verifier_passed": True,
            "flush_binding_verified": True,
            "runtime_binding_verified": True,
        },
    }


def test_verified_m7_proposals_are_exported_to_jsonl_and_embedded_html(
    tmp_path, monkeypatch
):
    trust_test_m7_artifact(monkeypatch)
    proposal = verified_proposal()
    aggregate = {
        "batch_identity": batch_identity(plan(), m7=True),
        "proposals": [proposal],
    }
    normalized = adapt_native_matrix_summary(
        evaluation_summary(),
        plan(),
        m7_aggregates=aggregate_artifact(tmp_path, "m7-aggregates.json", aggregate),
    )

    assert normalized["proposals"] == [proposal]
    assert normalized["proposal_scope"] == {
        "status": "verified_saved_rows",
        "source": "M7 aggregates",
        "count": 1,
        "raw_records_parsed": False,
    }
    exported = export_neurotaint_eval_report(normalized, tmp_path / "report")
    assert exported["proposal_count"] == 1
    saved = json.loads((tmp_path / "report/proposals.jsonl").read_text(encoding="utf-8"))
    assert saved == proposal
    html = (tmp_path / "report/index.html").read_text(encoding="utf-8")
    assert "event:00000001" in html
    assert f"runs/{proposal['trial_id']}/report.html" in html


def test_native_summary_verified_plan_snapshot_is_an_authoritative_identity_fallback():
    frozen = plan()
    source = evaluation_summary()
    source.pop("batch_identity")
    plan_sha256 = batch_identity(frozen)["exact_plan_json_sha256"]
    snapshot = {"plan.json": plan_sha256, "runs/example/summary.json": "b" * 64}
    source.update(
        batch_path=f"/frozen/{frozen['batch_id']}",
        source_hashes_before=snapshot,
        source_hashes_after=copy.deepcopy(snapshot),
        source_files_unchanged=True,
    )

    result = adapt_native_matrix_summary(source, frozen)

    expected = batch_identity(frozen)
    for key in (
        "source_batch_snapshot_sha256",
        "source_batch_snapshot_scope",
        "source_batch_file_count",
    ):
        expected.pop(key)
    assert result["batch_identity"] == expected


@pytest.mark.parametrize("source_name", ["evaluation", "attribution"])
def test_cross_batch_or_tampered_plan_hashes_are_rejected(source_name, tmp_path):
    frozen = plan()
    source = evaluation_summary()
    kwargs = {}
    wrong = batch_identity(frozen)
    wrong["plan_identity_sha256"] = "f" * 64
    if source_name == "evaluation":
        source["batch_identity"] = wrong
    else:
        kwargs["attribution_summary"] = {"batch_identity": wrong, "precision": None}

    with pytest.raises(ValueError, match="cryptographically bound"):
        adapt_native_matrix_summary(source, frozen, **kwargs)


def test_native_aggregate_is_rejected_until_a_manifest_producer_exists():
    with pytest.raises(ValueError, match="manifest-producing reader"):
        adapt_native_matrix_summary(
            evaluation_summary(),
            plan(),
            native_aggregates={"batch_identity": batch_identity(plan())},
        )


def test_m7_artifact_cannot_be_mislabeled_as_native_aggregate(tmp_path):
    aggregate = aggregate_artifact(
        tmp_path,
        "m7-aggregates.json",
        {"batch_identity": batch_identity(plan(), m7=True)},
    )
    with pytest.raises(ValueError, match="manifest-producing reader"):
        adapt_native_matrix_summary(
            evaluation_summary(),
            plan(),
            native_aggregates=aggregate,
        )


def test_m7_manifest_and_producer_contract_reject_tamper(tmp_path):
    aggregate = aggregate_artifact(
        tmp_path,
        "m7-aggregates.json",
        {"batch_identity": batch_identity(plan(), m7=True)},
    )
    value = json.loads(aggregate.read_text())
    value["routing_funnel"] = [{"stage": "edited", "count": 999}]
    aggregate.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="manifest"):
        adapter._verified_aggregate(
            aggregate,
            batch_identity(plan()),
            {
                key: batch_identity(plan())[key]
                for key in (
                    "source_batch_snapshot_sha256",
                    "source_batch_snapshot_scope",
                    "source_batch_file_count",
                )
            },
            tmp_path,
            name="M7 aggregates",
        )


def test_self_rehashed_m7_metrics_must_match_fresh_batch_analysis(tmp_path, monkeypatch):
    aggregate = aggregate_artifact(
        tmp_path,
        "m7-aggregates.json",
        {"batch_identity": batch_identity(plan(), m7=True)},
    )
    pristine = json.loads(aggregate.read_text())
    forged = copy.deepcopy(pristine)
    forged["planned_slot_count"] = 999
    aggregate.write_text(
        json.dumps(forged, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    manifest_path = aggregate.parent / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["files"][aggregate.name] = hashlib.sha256(aggregate.read_bytes()).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )

    def fresh_analysis(batch, output):
        output.mkdir()
        (output / "m7-aggregates.json").write_text(
            json.dumps(
                pristine, ensure_ascii=True, sort_keys=True, separators=(",", ":")
            )
            + "\n",
            encoding="ascii",
        )
        (output / "proposals.jsonl").write_text("", encoding="ascii")
        return pristine

    monkeypatch.setattr(neurotaint_m7_analysis, "analyze_m7_batch", fresh_analysis)
    identity = batch_identity(plan())
    snapshot = {
        key: identity[key]
        for key in (
            "source_batch_snapshot_sha256",
            "source_batch_snapshot_scope",
            "source_batch_file_count",
        )
    }
    with pytest.raises(ValueError, match="fresh read-only batch analysis"):
        adapter._verified_aggregate(
            aggregate,
            identity,
            snapshot,
            tmp_path,
            name="M7 aggregates",
        )

    manifest = json.loads((aggregate.parent / "manifest.json").read_text())
    manifest["files"][aggregate.name] = hashlib.sha256(aggregate.read_bytes()).hexdigest()
    manifest["method"] = "foreign_producer"
    (aggregate.parent / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="producer contract"):
        adapter._verified_aggregate(
            aggregate,
            batch_identity(plan()),
            {
                key: batch_identity(plan())[key]
                for key in (
                    "source_batch_snapshot_sha256",
                    "source_batch_snapshot_scope",
                    "source_batch_file_count",
                )
            },
            tmp_path,
            name="M7 aggregates",
        )


def test_cross_batch_native_summary_is_rejected_even_with_the_same_schedule():
    other = plan()
    other["batch_id"] = "another-native-matrix"
    with pytest.raises(ValueError, match="cryptographically bound"):
        adapt_native_matrix_summary(evaluation_summary(), other)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda rows: {"proposal": rows[0]},
        lambda rows: [rows[0] | {"trial_id": "unplanned", "run_id": "unplanned"}],
        lambda rows: [rows[0] | {"proposal_id": "bad/id", "proposal_event_id": "bad/id"}],
        lambda rows: [rows[0] | {"proposal_id": "event:a", "proposal_event_id": "event:b"}],
        lambda rows: [rows[0] | {"run_id": "another-run"}],
        lambda rows: [rows[0] | {"case_id": "another-case"}],
        lambda rows: [
            rows[0]
            | {
                "verification": rows[0]["verification"]
                | {"saved_run_verifier_passed": False}
            }
        ],
        lambda rows: rows + copy.deepcopy(rows),
    ],
)
def test_untrusted_or_duplicate_m7_proposal_shapes_fail(mutate, tmp_path, monkeypatch):
    trust_test_m7_artifact(monkeypatch)
    rows = [verified_proposal()]
    aggregate = {
        "batch_identity": batch_identity(plan(), m7=True),
        "proposals": mutate(rows),
    }
    with pytest.raises(ValueError, match="M7 proposal|M7 proposals"):
        adapt_native_matrix_summary(
            evaluation_summary(),
            plan(),
            m7_aggregates=aggregate_artifact(
                tmp_path, "m7-aggregates.json", aggregate
            ),
        )


def test_dict_attribution_from_generic_summary_is_preserved_but_never_filled():
    source = evaluation_summary()
    source["attribution_accuracy"] = {
        "status": "pending_independent_review",
        "precision": None,
        "recall": None,
        "f1": None,
    }
    result = adapt_native_matrix_summary(source, plan())
    assert result["attribution_accuracy"] == source["attribution_accuracy"]


def test_explicit_null_causal_summary_stays_null(tmp_path, monkeypatch):
    trust_test_m7_artifact(monkeypatch)
    aggregate = {
        "batch_identity": batch_identity(plan(), m7=True),
        "causal_summary": None,
        "proposals": [],
    }
    result = adapt_native_matrix_summary(
        evaluation_summary(),
        plan(),
        m7_aggregates=aggregate_artifact(tmp_path, "m7-aggregates.json", aggregate),
    )
    assert result["causal"] is None


def test_path_inputs_and_report_output_create_relative_links(tmp_path):
    frozen = plan()
    source = evaluation_summary()
    run = tmp_path / "batch" / "runs" / source["trials"][0]["trial_id"]
    run.mkdir(parents=True)
    (run / "report.html").write_text("existing", encoding="utf-8")
    source["trials"][0]["run_path"] = str(run)
    plan_path = tmp_path / "batch" / "plan.json"
    summary_path = tmp_path / "analysis" / "evaluation-summary.json"
    plan_path.parent.mkdir(exist_ok=True)
    summary_path.parent.mkdir(exist_ok=True)
    plan_raw = json.dumps(frozen).encode("utf-8")
    exact_sha256 = hashlib.sha256(plan_raw).hexdigest()
    source["batch_identity"] = batch_identity(frozen, exact_plan_sha256=exact_sha256)
    plan_path.write_bytes(plan_raw)
    (plan_path.parent / "plan.sha256").write_text(exact_sha256 + "\n", encoding="ascii")
    source["batch_path"] = str(plan_path.parent.resolve())
    source["source_hashes_before"] = native_reader._tree(plan_path.parent)
    source["source_hashes_after"] = copy.deepcopy(source["source_hashes_before"])
    source["source_files_unchanged"] = True
    summary_path.write_text(json.dumps(source), encoding="utf-8")

    result = adapt_native_matrix_summary(
        summary_path,
        plan_path,
        report_output=tmp_path / "report",
    )
    assert result["trials"][0]["report"] == (
        "../batch/runs/" + source["trials"][0]["trial_id"] + "/report.html"
    )


def test_failures_and_unknowns_are_accounted_without_turning_them_into_negative_labels():
    result = adapt_native_matrix_summary(evaluation_summary(), plan())
    process = next(row for row in result["failures"] if row["type"] == "process_failure")
    artifact = next(row for row in result["failures"] if row["type"] == "artifact_error")
    assert process["detail"] == "timeout"
    assert artifact["detail"]["error_type"] == "PartialRecord"
    assert result["unknowns"]["unknown_evaluation"] == 1
    assert result["unknowns"]["unknown_injected_exposure"] == 59
    assert result["trials"][1]["attack_success"] is None


def test_normalized_result_is_directly_consumable_by_the_report_renderer(tmp_path):
    normalized = adapt_native_matrix_summary(evaluation_summary(), plan())
    generated = export_neurotaint_eval_report(normalized, tmp_path / "report")

    assert generated["trial_count"] == 120
    assert generated["proposal_count"] == 0
    assert len((tmp_path / "report" / "trials.csv").read_text().splitlines()) == 121
    assert (tmp_path / "report" / "proposals.jsonl").read_text() == ""
    html = (tmp_path / "report" / "index.html").read_text()
    assert "NeuroTaint native-matrix evaluation" in html
    assert "Attack success rate (ASR)" in html


@pytest.mark.parametrize(
    "mutate_plan,mutate_summary,kwargs",
    [
        (lambda value: value.update(slot_count=119), lambda value: None, {}),
        (
            lambda value: value["schedule"].append(copy.deepcopy(value["schedule"][0])),
            lambda value: value["counts"].update(planned=121),
            {},
        ),
        (lambda value: None, lambda value: value["counts"].update(planned=119), {}),
        (lambda value: None, lambda value: value["counts"].update(started=1.0), {}),
        (
            lambda value: None,
            lambda value: value["counts"].update(started=1, completed=2, unstarted=119),
            {},
        ),
        (
            lambda value: None,
            lambda value: value["trials"].append(
                {"trial_id": "not-planned", "case_id": "other", "condition": "clean", "repeat": 1}
            ),
            {},
        ),
        (
            lambda value: None,
            lambda value: value["trials"][0].update(condition="injected"),
            {},
        ),
        (lambda value: None, lambda value: None, {"m7_aggregates": {"causal": []}}),
        (
            lambda value: None,
            lambda value: None,
            {"native_aggregates": {"routing_funnel": [{"stage": "tier1", "count": float("nan")}]}},
        ),
    ],
)
def test_rejects_identity_drift_invalid_explicit_aggregates_and_non_finite_values(
    mutate_plan, mutate_summary, kwargs
):
    frozen, source = plan(), evaluation_summary()
    mutate_plan(frozen)
    mutate_summary(source)
    with pytest.raises(ValueError):
        adapt_native_matrix_summary(source, frozen, **kwargs)

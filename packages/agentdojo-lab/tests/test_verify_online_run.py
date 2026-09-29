"""Saved sidecar verification against actual offline runs and inconsistent evidence."""

import hashlib
import importlib.util
import json
import shutil
from pathlib import Path

import httpx
import openai
import pytest

from agentdojo_lab import runner
from agentdojo_lab.policy import ToolPolicy
from agentdojo_lab.runner import RunConfig, run_clean

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_online_run.py"
SPEC = importlib.util.spec_from_file_location("verify_online_run_under_test", SCRIPT)
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


@pytest.fixture(scope="module")
def source_run(tmp_path_factory):
    path = tmp_path_factory.mktemp("online-source") / "run"
    result = run_clean(RunConfig(online_provenance=True), offline=True, output=path)
    assert result["recording"]["complete"] is True
    assert result["online_provenance"]["complete"] is True
    return path


@pytest.fixture
def copied_run(source_run, tmp_path):
    path = tmp_path / "run"
    shutil.copytree(source_run, path)
    return path


def rows_at(run):
    return [json.loads(line) for line in (run / "provenance.jsonl").read_text().splitlines()]


def write_rows(run, rows, *, relink_hashes=False):
    """Optionally update hashes, so semantic/identity checks cannot hide behind a stale digest."""
    raw = [json.dumps(row, sort_keys=True) + "\n" for row in rows]
    if relink_hashes:
        by_sequence = {row["record_sequence"]: index for index, row in enumerate(rows)}
        for index, row in enumerate(rows):
            if row["record_type"] == "analysis_flush":
                analysis = by_sequence[row["analysis_record_sequence"]]
                row["analysis_line_sha256"] = hashlib.sha256(raw[analysis].encode()).hexdigest()
                raw[index] = json.dumps(row, sort_keys=True) + "\n"
    (run / "provenance.jsonl").write_text("".join(raw))


def select(rows, kind):
    return next(row for row in rows if row["record_type"] == kind)


def test_offline_run_verifies_without_changing_any_source_files(source_run, monkeypatch):
    hashes = {
        str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_run.rglob("*") if p.is_file()
    }
    monkeypatch.setattr(verifier, "LocalMiniLMEncoder", lambda *a, **k: pytest.fail("No encoder configured"))
    result = verifier.verify(source_run)
    assert result["passed"] is True and all(result["checks"].values())
    assert result["real_llm"] is False
    assert result["proposal_count"] == result["runtime_count"] == 1
    assert result["semantic_comparison_count"] == 0
    assert hashes == {
        str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_run.rglob("*") if p.is_file()
    }


@pytest.mark.parametrize("kind", ["call_analysis", "analysis_flush"])
def test_availability_must_be_the_exact_live_contract(copied_run, kind):
    rows = rows_at(copied_run)
    row = select(rows, kind)
    container = row["call"] if kind == "call_analysis" else row
    container["availability"] = "live_synchronous_sidecar; actually_offline; future_data_allowed"
    write_rows(copied_run, rows, relink_hashes=True)
    assert verifier.verify(copied_run)["passed"] is False


def test_changed_call_content_fails_even_with_recomputed_receipt_hash(copied_run):
    rows = rows_at(copied_run)
    select(rows, "call_analysis")["call"]["fields"][0]["value"] = "not the observed argument"
    write_rows(copied_run, rows, relink_hashes=True)
    result = verifier.verify(copied_run)
    assert result["checks"]["flush_receipt_hashes_match"] is True
    assert result["checks"]["live_equals_replay_except_availability"] is False
    assert result["passed"] is False


def test_replay_comparison_preserves_json_number_types(copied_run):
    rows = rows_at(copied_run)
    call = select(rows, "call_analysis")["call"]
    call["request_sequence"] = float(call["request_sequence"])
    write_rows(copied_run, rows, relink_hashes=True)
    result = verifier.verify(copied_run)
    assert result["checks"]["live_equals_replay_except_availability"] is False
    assert result["passed"] is False


def test_receipt_hash_is_checked_against_exact_persisted_analysis_bytes(copied_run):
    rows = rows_at(copied_run)
    select(rows, "analysis_flush")["analysis_line_sha256"] = "0" * 64
    write_rows(copied_run, rows)
    result = verifier.verify(copied_run)
    assert result["checks"]["flush_receipt_hashes_match"] is False
    assert result["passed"] is False


@pytest.mark.parametrize("kind", ["call_analysis", "analysis_flush", "runtime_timing"])
def test_top_level_identity_cannot_disagree_with_the_linked_event(copied_run, kind):
    rows = rows_at(copied_run)
    select(rows, kind)["episode_id"] = "episode:another"
    write_rows(copied_run, rows, relink_hashes=True)
    assert verifier.verify(copied_run)["passed"] is False


@pytest.mark.parametrize("field", ["analysis_record_sequence", "receipt_record_sequence"])
def test_runtime_record_must_link_the_same_analysis_and_receipt(copied_run, field):
    rows = rows_at(copied_run)
    select(rows, "runtime_timing")[field] = 987654
    write_rows(copied_run, rows, relink_hashes=True)
    assert verifier.verify(copied_run)["passed"] is False


def test_boolean_is_not_an_analysis_sequence_number(copied_run):
    rows = rows_at(copied_run)
    assert select(rows, "call_analysis")["record_sequence"] == 1
    select(rows, "runtime_timing")["analysis_record_sequence"] = True
    write_rows(copied_run, rows, relink_hashes=True)
    assert verifier.verify(copied_run)["passed"] is False


@pytest.mark.parametrize(
    "mutation", ["negative", "reversed", "different_copy", "bool_clock", "wrong_elapsed"]
)
def test_proposal_and_receipt_compute_timestamps_are_consistent(copied_run, mutation):
    rows = rows_at(copied_run)
    analysis = select(rows, "call_analysis")["timing"]
    receipt = select(rows, "analysis_flush")["timing"]
    if mutation == "negative":
        analysis["consume_started_monotonic_ns"] = -20
        analysis["compute_completed_monotonic_ns"] = -10
        analysis["compute_elapsed_ns"] = 10
        receipt["consume_started_monotonic_ns"] = -20
        receipt["compute_completed_monotonic_ns"] = -10
    elif mutation == "reversed":
        analysis["compute_completed_monotonic_ns"] = analysis["consume_started_monotonic_ns"] - 1
        receipt["compute_completed_monotonic_ns"] = analysis["compute_completed_monotonic_ns"]
    elif mutation == "different_copy":
        receipt["compute_completed_monotonic_ns"] += 1
    elif mutation == "bool_clock":
        analysis["consume_started_monotonic_ns"] = True
        receipt["consume_started_monotonic_ns"] = True
    else:
        receipt["compute_and_analysis_flush_elapsed_ns"] += 1
    write_rows(copied_run, rows, relink_hashes=True)
    assert verifier.verify(copied_run)["passed"] is False


@pytest.mark.parametrize("mutation", ["late", "different_event_clock", "receipt_before_analysis", "bad_lead"])
def test_runtime_timestamps_establish_recorded_boundary_availability(copied_run, mutation):
    rows = rows_at(copied_run)
    runtime = select(rows, "runtime_timing")
    timing = runtime["timing"]
    if mutation == "late":
        timing["receipt_flushed_monotonic_ns"] = runtime["runtime_event_monotonic_ns"] + 1
    elif mutation == "different_event_clock":
        runtime["runtime_event_monotonic_ns"] += 1
    elif mutation == "receipt_before_analysis":
        timing["receipt_flushed_monotonic_ns"] = timing["analysis_flushed_monotonic_ns"] - 1
    else:
        timing["analysis_lead_ns"] += 1
    write_rows(copied_run, rows, relink_hashes=True)
    assert verifier.verify(copied_run)["passed"] is False


@pytest.mark.parametrize("kind", ["call_analysis", "analysis_flush", "runtime_timing"])
@pytest.mark.parametrize("mutation", ["missing", "duplicate"])
def test_missing_or_duplicate_required_rows_fail(copied_run, kind, mutation):
    rows = rows_at(copied_run)
    row = select(rows, kind)
    if mutation == "missing":
        rows.remove(row)
    else:
        rows.append({**row, "record_sequence": len(rows) + 1})
    write_rows(copied_run, rows)
    assert verifier.verify(copied_run)["passed"] is False


def test_unsupported_extra_row_is_not_ignored(copied_run):
    rows = rows_at(copied_run)
    rows.append({"schema_version": 1, "record_sequence": len(rows) + 1, "record_type": "unsupported"})
    write_rows(copied_run, rows, relink_hashes=True)
    assert verifier.verify(copied_run)["passed"] is False


def test_summary_cannot_claim_different_sidecar_counts(copied_run):
    path = copied_run / "summary.json"
    summary = json.loads(path.read_text())
    summary["online_provenance"]["analysis_count"] += 1
    path.write_text(json.dumps(summary))
    assert verifier.verify(copied_run)["passed"] is False


@pytest.fixture(scope="module")
def policy_runs(tmp_path_factory):
    """Produce real offline native runs; the forced sink classification is fixture-only."""
    root = tmp_path_factory.mktemp("policy-verification")
    default_policy = root / "default.yaml"
    default_policy.write_bytes((runner.ROOT / "configs" / "workspace_policy_v1.yaml").read_bytes())
    default_run = root / "default"
    run_clean(
        RunConfig(online_provenance=True, provenance_policy=str(default_policy)),
        offline=True,
        output=default_run,
    )
    default_policy.unlink()
    results = {"default": default_run}
    suite = runner.get_suite("v1.2.2", "workspace")
    task = suite.user_tasks["user_task_0"]
    original_call = task.ground_truth(suite.load_and_inject_default_environment({}))[0]
    function = original_call.function
    policy_document = {
        "schema_version": 1,
        "policy_id": "fixture-read-declared-as-sink-v1",
        "suite": "workspace",
        "benchmark_version": "v1.2.2",
        "sources": {function: {"rationale": "Fixture source", "output_scope": "visible_text"}},
        "sinks": {function: {"rationale": "Fixture-only selected sink", "argument_paths": [""]}},
        "neutral_tools": {},
    }
    for condition in ("matched", "incomplete"):
        policy_path = root / f"{condition}.json"
        policy_path.write_text(json.dumps(policy_document))

        def make_client(_suite, _task, model, condition=condition):
            count = 0

            def respond(request):
                nonlocal count
                count += 1
                assert count <= 3, "The local fixture must not retry or add model requests"
                if count < 3:
                    arguments = dict(original_call.args)
                    if count == 2 and condition == "incomplete":
                        arguments = {key: "ZZZZ" for key in arguments}
                    message = {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": f"fixture-{count}",
                                "type": "function",
                                "function": {"name": function, "arguments": json.dumps(arguments)},
                            }
                        ],
                    }
                else:
                    message = {"role": "assistant", "content": task.GROUND_TRUTH_OUTPUT}
                return httpx.Response(
                    200,
                    json={
                        "id": f"local-response-{count}",
                        "object": "chat.completion",
                        "created": 0,
                        "model": model,
                        "choices": [{"index": 0, "finish_reason": "stop", "message": message}],
                        "usage": {"prompt_tokens": 8, "completion_tokens": 3, "total_tokens": 11},
                    },
                )

            return openai.OpenAI(
                api_key="local-fixture",
                base_url="https://fixture.invalid/v1",
                max_retries=0,
                http_client=httpx.Client(transport=httpx.MockTransport(respond)),
            )

        output = root / condition
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(runner, "make_offline_client", make_client)
            summary = run_clean(
                RunConfig(online_provenance=True, provenance_policy=str(policy_path)),
                offline=True,
                output=output,
            )
        assert summary["recording"]["complete"] is True
        assert summary["online_provenance"]["complete"] is True
        assert summary["usage"]["request_count"] == 3
        policy_path.unlink()
        results[condition] = output
    return results


@pytest.fixture
def copied_policy_run(policy_runs, tmp_path):
    result = tmp_path / "run"
    shutil.copytree(policy_runs["matched"], result)
    return result


def test_default_policy_zero_pairs_verifies_from_snapshot_without_policy_file(policy_runs, monkeypatch):
    run = policy_runs["default"]
    manifest = json.loads((run / "manifest.json").read_text())
    assert not Path(manifest["config"]["provenance_policy"]).exists()
    assert manifest["online_provenance"]["policy"]["source_file_sha256"] is not None
    monkeypatch.setattr(verifier, "LocalMiniLMEncoder", lambda *a, **k: pytest.fail("No encoder configured"))
    result = verifier.verify(run)
    assert result["passed"] is True
    assert result["cascade_pair_count"] == 0
    assert result["policy_sha256"] == manifest["online_provenance"]["policy"]["sha256"]
    assert result["cascade_counts"]["cascade_status_counts"] == {}
    assert result["cascade_counts"]["policy_sink_count"] == 0
    assert result["semantic_comparison_scope"] == (
        "independent_comparisons; ordered_semantic_stages_are_reported_in_cascade_stage_counts"
    )


@pytest.mark.parametrize("condition", ["matched", "incomplete"])
def test_policy_replay_and_nonzero_counters_cover_matches_and_unavailable_stages(policy_runs, condition):
    result = verifier.verify(policy_runs[condition])
    assert result["passed"] is True and all(result["checks"].values())
    assert result["cascade_pair_count"] > 0
    assert result["cascade_counts"]["policy_sink_count"] == 2
    assert result["cascade_counts"]["unclassified_proposal_count"] == 0
    if condition == "matched":
        assert result["cascade_counts"]["cascade_first_hit_counts"]["tier2"] > 0
        assert result["cascade_counts"]["cascade_incomplete_pair_count"] == 0
    else:
        assert result["cascade_counts"]["cascade_status_counts"]["indeterminate"] > 0
        assert result["cascade_counts"]["cascade_incomplete_pair_count"] > 0
        assert result["cascade_counts"]["cascade_first_hit_counts"] == {}


def test_policy_summary_cannot_describe_independent_zero_pairs_as_absent_cascade_stages(copied_policy_run):
    path = copied_policy_run / "summary.json"
    summary = json.loads(path.read_text())
    summary["online_provenance"]["semantic_comparison_scope"] = "all_semantic_stages"
    path.write_text(json.dumps(summary))
    result = verifier.verify(copied_policy_run)
    assert result["passed"] is False
    assert result["checks"]["semantic_comparison_scope_matches"] is False


@pytest.mark.parametrize("mutation", ["missing_snapshot", "missing_flag", "hash", "context", "document"])
def test_policy_snapshot_presence_hash_context_and_replayed_classification_are_checked(
    copied_policy_run, mutation
):
    path = copied_policy_run / "manifest.json"
    manifest = json.loads(path.read_text())
    snapshot = manifest["online_provenance"]["policy"]
    if mutation == "missing_snapshot":
        manifest["online_provenance"]["policy"] = None
    elif mutation == "missing_flag":
        manifest["config"]["provenance_policy"] = None
    elif mutation == "hash":
        snapshot["sha256"] = "0" * 64
    else:
        if mutation == "context":
            snapshot["document"]["suite"] = "another_suite"
        else:
            snapshot["document"]["sources"] = {}
        snapshot["sha256"] = ToolPolicy.from_dict(snapshot["document"]).metadata["sha256"]
    path.write_text(json.dumps(manifest))
    assert verifier.verify(copied_policy_run)["passed"] is False


@pytest.mark.parametrize(
    "key",
    [
        "cascade_status_counts",
        "cascade_stage_counts",
        "cascade_first_hit_counts",
        "cascade_incomplete_pair_count",
        "policy_sink_count",
        "unclassified_proposal_count",
    ],
)
def test_every_cascade_summary_counter_is_recomputed_from_persisted_rows(copied_policy_run, key):
    path = copied_policy_run / "summary.json"
    summary = json.loads(path.read_text())
    online = summary["online_provenance"]
    if key == "cascade_status_counts":
        online[key]["scored"] += 1
    elif key == "cascade_stage_counts":
        online[key]["tier1"]["disabled_condition"] += 1
    elif key == "cascade_first_hit_counts":
        online[key]["tier2"] += 1
    else:
        online[key] += 1
    path.write_text(json.dumps(summary))
    result = verifier.verify(copied_policy_run)
    assert result["checks"]["cascade_summary_counts_match"] is False
    assert result["passed"] is False


@pytest.mark.parametrize(
    "key, value", [("component_mode", "independent_all_pairs"), ("policy_sha256", "0" * 64)]
)
def test_summary_policy_identity_must_match_frozen_manifest(copied_policy_run, key, value):
    path = copied_policy_run / "summary.json"
    summary = json.loads(path.read_text())
    summary["online_provenance"][key] = value
    path.write_text(json.dumps(summary))
    result = verifier.verify(copied_policy_run)
    assert result["checks"]["policy_mode_and_summary_identity_match"] is False
    assert result["passed"] is False


def test_cascade_call_content_is_compared_beyond_its_saved_counts(copied_policy_run):
    rows = rows_at(copied_policy_run)
    pair = next(
        pair
        for row in rows
        if row["record_type"] == "call_analysis"
        for field in row["call"]["fields"]
        for pair in field["nt_style_cascade"]
    )
    pair["stages"]["tier1"]["reason"] = "incorrect canary claim"
    write_rows(copied_policy_run, rows, relink_hashes=True)
    result = verifier.verify(copied_policy_run)
    assert result["checks"]["flush_receipt_hashes_match"] is True
    assert result["checks"]["cascade_summary_counts_match"] is True
    assert result["checks"]["live_equals_replay_except_availability"] is False
    assert result["passed"] is False


def test_unavailable_cascade_cannot_be_reported_as_fully_scored(policy_runs, tmp_path):
    run = tmp_path / "run"
    shutil.copytree(policy_runs["incomplete"], run)
    path = run / "summary.json"
    summary = json.loads(path.read_text())
    assert summary["online_provenance"]["cascade_incomplete_pair_count"] > 0
    summary["online_provenance"]["scoring_complete"] = True
    path.write_text(json.dumps(summary))
    result = verifier.verify(run)
    assert result["checks"]["cascade_scoring_completeness_matches"] is False
    assert result["passed"] is False

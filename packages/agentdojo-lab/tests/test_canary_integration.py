"""Real native runtime and SDK serialization; authored benign replies, no model calls."""

import copy
import importlib.util
import json
from pathlib import Path
from uuid import UUID

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "validate_canary.py"
SPEC = importlib.util.spec_from_file_location("native_canary_validation", SCRIPT)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


@pytest.fixture(scope="module")
def pairs(tmp_path_factory):
    root = tmp_path_factory.mktemp("native-canary")
    return {
        case: (
            fixture.run_arm(root / f"{case}-passive", case=case, enabled=False),
            fixture.run_arm(root / f"{case}-canary", case=case, enabled=True),
        )
        for case in ("fixed", "copy", "summary", "multi", "multi_copy", "mixed")
    }


@pytest.mark.parametrize("case", ["fixed", "summary", "multi", "mixed"])
def test_fixed_native_behavior_changes_only_by_audited_tool_suffixes(pairs, case):
    passive, active = pairs[case]
    fixture.assert_fixed_equivalence(passive, active)
    assert passive["failure"] is active["failure"] is None
    for result in (passive, active):
        assert result["summary"]["recording"]["complete"] is True
        assert result["summary"]["recording"]["audit"]["valid"] is True
        assert result["summary"]["online_provenance"]["complete"] is True
        assert result["summary"]["real_llm"] is False
        assert result["summary"]["task_success_count"] is None
    assert fixture.assignments(passive) == []


def test_assigned_uuid_has_pristine_native_marked_history_and_actual_http_evidence(pairs):
    passive, active = pairs["fixed"]
    (assigned,) = fixture.assignments(active)
    data = assigned["data"]
    assert str(UUID(data["token"])) == data["token"] and UUID(data["token"]).version == 4
    assert data["suffix"] == "\n# NT_CANARY: " + data["token"] + "\n"
    assert data["original_text"] + data["suffix"] == data["marked_text"]
    assert fixture.hashlib.sha256(data["original_text"].encode()).hexdigest() == data["original_text_sha256"]
    assert fixture.hashlib.sha256(data["marked_text"].encode()).hexdigest() == data["marked_text_sha256"]
    baseline_result = next(event for event in passive["events"] if event["event_type"] == "TOOL_RESULT")
    assert data["original_content"] == baseline_result["data"]["message"]["content"]
    marked_result = next(
        event
        for event in active["events"]
        if event["event_type"] == "TOOL_RESULT"
        and event["data"].get("intervention_event_id") == assigned["event_id"]
    )
    assert marked_result["data"]["message"]["content"] == data["marked_content"]
    assert marked_result["call_ref"] == assigned["call_ref"]
    assert assigned["event_sequence"] < marked_result["event_sequence"]
    raw_return = next(
        event
        for event in active["events"]
        if event["event_type"] == "TOOL_RUNTIME_RETURNED" and event["call_ref"] == assigned["call_ref"]
    )
    assert data["token"] not in json.dumps(raw_return["data"])
    assert data["token"] not in json.dumps(active["environment"])
    exposures = [
        event
        for event in active["events"]
        if event["event_type"] == "TOOL_OUTPUT_EXPOSED"
        and event["data"]["source_result_event_id"] == marked_result["event_id"]
    ]
    assert len(exposures) == 2
    assert all(event["data"]["message"]["content"] == data["marked_text"] for event in exposures)
    assert all(event["data"]["message"]["content"].count(data["token"]) == 1 for event in exposures)
    native_tool = next(message for message in active["messages"] if message["role"] == "tool")
    assert native_tool["content"] == data["marked_content"]


def test_scripted_copy_uses_actual_request_text_and_tier1_stops_later_stages(pairs):
    passive, active = pairs["copy"]
    (assigned,) = fixture.assignments(active)
    marked_text = assigned["data"]["marked_text"]
    active_call, passive_call = fixture.sink_call(active), fixture.sink_call(passive)
    actual_tool = next(
        message["content"] for message in active["requests"][1]["messages"] if message["role"] == "tool"
    )
    assert active_call["arguments"]["content"] == actual_tool == marked_text
    assert active["drive"].files["2"].content == marked_text
    assert passive["drive"].files["2"].content == passive_call["arguments"]["content"]
    assert assigned["data"]["token"] not in passive_call["arguments"]["content"]
    (pair,) = fixture.content_pairs(active)
    assert pair["first_matched_tier"] == "tier1" and pair["matched"] is True
    assert pair["complete"] is True
    assert all(pair["stages"][tier]["status"] == "skipped" for tier in ("tier2", "tier3", "tier4"))
    assert pair["maliciousness"] == pair["causal_influence"] == "not_assessed"
    proposal = next(
        row for row in active["rows"] if row["record_type"] == "call_analysis" and row["call"] == active_call
    )
    at_sink = next(item for item in active["at_runtime_entry"] if item["function"] == "create_file")
    matching = [
        row for row in at_sink["rows"] if row.get("proposal_event_id") == proposal["proposal_event_id"]
    ]
    assert {row["record_type"] for row in matching} == {"call_analysis", "analysis_flush", "runtime_timing"}


def test_fixed_marker_free_summary_is_a_tier1_miss_with_real_fallback(pairs):
    _, active = pairs["summary"]
    token = fixture.assignments(active)[0]["data"]["token"]
    assert token not in fixture.sink_call(active)["arguments"]["content"]
    (pair,) = fixture.content_pairs(active)
    assert pair["stages"]["tier1"]["status"] == "scored"
    assert pair["stages"]["tier1"]["matched"] is False
    assert pair["stages"]["tier2"]["status"] == "scored"
    assert pair["first_matched_tier"] == "tier2"
    assert active["summary"]["online_provenance"]["complete"] is True


def test_two_native_source_results_have_distinct_uuids_and_no_wrong_source_tier1_hit(pairs):
    _, active = pairs["multi_copy"]
    assigned = fixture.assignments(active)
    assert len(assigned) == 2
    assert len({event["call_ref"] for event in assigned}) == 2
    assert len({event["data"]["token"] for event in assigned}) == 2
    pairs = fixture.content_pairs(active)
    assert len(pairs) == 2
    assert [pair["stages"]["tier1"]["matched"] for pair in pairs] == [True, False]
    assert pairs[0]["first_matched_tier"] == "tier1"
    assert pairs[1]["stages"]["tier2"]["status"] == "scored"
    first_request = active["requests"][0]
    assert not any(
        token in json.dumps(first_request) for token in (event["data"]["token"] for event in assigned)
    )
    for event in assigned:
        assert (
            sum(
                exposure["event_type"] == "TOOL_OUTPUT_EXPOSED" and exposure["call_ref"] == event["call_ref"]
                for exposure in active["events"]
            )
            == 2
        )


def test_unknown_and_failed_native_tools_are_explicitly_skipped(pairs):
    _, active = pairs["mixed"]
    interventions = [event for event in active["events"] if event["event_type"] == "TOOL_OUTPUT_INTERVENTION"]
    proposals = {
        event["call_ref"]: event for event in active["events"] if event["event_type"] == "TOOL_CALL_PROPOSED"
    }
    skipped = [event for event in interventions if event["data"]["status"] == "skipped"]
    assert any(proposals[event["call_ref"]]["data"]["function"] == "unknown_file_tool" for event in skipped)
    assert any(proposals[event["call_ref"]]["data"]["arguments"].get("file_id") == "404" for event in skipped)
    assert all(event["data"]["token"] is None for event in skipped)
    assert len(fixture.assignments(active)) == 1
    assert active["summary"]["recording"]["audit"]["valid"] is True


def test_normalization_does_not_remove_markers_from_assistant_or_user_arguments(pairs):
    _, active = pairs["fixed"]
    assigned = fixture.assignments(active)
    suffix = assigned[0]["data"]["suffix"]
    messages = [{"role": role, "content": "Body" + suffix} for role in ("user", "assistant", "system")]
    before = copy.deepcopy(messages)
    assert fixture.normalized_messages(messages, assigned) == before
    assert messages == before


def test_generation_error_preserves_native_behavior_but_marks_intervention_incomplete(tmp_path):
    passive = fixture.run_arm(tmp_path / "passive", case="fixed", enabled=False)
    failed = fixture.run_arm(
        tmp_path / "generation-error", case="fixed", enabled=True, uuid_tokens=("not-a-uuid",)
    )
    fixture.assert_fixed_equivalence(passive, failed)
    assert failed["failure"] is None
    assert fixture.assignments(failed) == []
    assert failed["summary"]["canary"]["complete"] is False
    assert failed["summary"]["recording"]["complete"] is False
    assert any(
        event["event_type"] == "TOOL_OUTPUT_INTERVENTION" and event["data"]["status"] == "error"
        for event in failed["events"]
    )


def test_combined_canary_memory_restoration_uses_old_token_not_fresh_marker(tmp_path):
    result = fixture.validate_memory(tmp_path / "cross-session")
    assert result["passed"] is True, result["checks"]
    assert all(result["checks"].values())
    assert result["old_token"] != result["new_token"]
    assert result["session2_lineage_summary"]["recovered_source_count"] == 1
    assert result["session2_lineage_summary"]["matched_comparison_count"] == 1
    assert result["session2_lineage_summary"]["maliciousness"] == "not_assessed"
    assert result["session2_lineage_summary"]["causal_influence"] == "not_assessed"


def test_standalone_validation_keeps_fixture_scope_and_complete_artifact_links(tmp_path):
    output = tmp_path / "validation"
    result = fixture.validate(output)
    assert result == json.loads((output / "validation.json").read_text())
    assert result["passed"] is True and all(result["checks"].values())
    assert result["real_llm"] is False
    assert "not model capability" in result["scope"]
    assert "deterministic" in result["uuid_generation"]
    assert set(result["cases"]) == {"fixed", "copy", "summary", "multi", "multi_copy", "mixed"}
    reports = [path for case in result["cases"].values() for path in case["reports"]]
    reports += ["cross-session-memory/" + path for path in result["memory"]["reports"]]
    assert len(reports) == 14
    for report in reports:
        run = (output / report).parent
        assert (output / report).is_file()
        for name in ("events.jsonl", "provenance.jsonl", "requests.json", "actions.json", "manifest.json"):
            assert (run / name).is_file()
        summary = json.loads((run / "summary.json").read_text())
        assert summary["task_success_count"] is None
        assert summary["task_count"] == summary["evaluable_task_count"] == 0
    with pytest.raises(FileExistsError):
        fixture.validate(output)

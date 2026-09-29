"""Presentation alignment must preserve missing evidence and exact saved values."""

import copy
import json

from agentdojo_lab.paired_report import compare_records
from agentdojo_lab.paired_report_data import build_paired_view


def fixture(*, label="clean", functions=("read_file", "send_email"), offset=0):
    events = []

    def add(kind, data, *, call=None, request=None):
        event = {
            "event_id": f"event:{offset + len(events) + 1}",
            "event_sequence": len(events) + 1,
            "event_type": kind,
            "data": data,
            "call_ref": call,
            "model_request_id": request,
            "parent_event_ids": [],
            "episode_id": "episode:1",
            "task_id": "fixture",
        }
        events.append(event)
        return event

    add("EPISODE_STARTED", {"environment": {}})
    for index, function in enumerate(functions):
        request = f"{label}-request-{index}"
        add("MODEL_REQUEST", {"body": {"messages": [{"role": "user", "content": "task"}]}}, request=request)
        add("MODEL_RESPONSE", {"body": {"choices": [{"message": {"content": function}}]}}, request=request)
        add(
            "TOOL_CALL_PROPOSED",
            {"function": function, "arguments": {}},
            call=f"{label}-{index}",
            request=request,
        )
    return {
        "run_id": label,
        "manifest": {"config": {"user_tasks": ["fixture"], "model": "fixture"}, "real_llm": False},
        "summary": {"status": "completed", "recording": {"complete": True}},
        "events": events,
        "audit": {"valid": True},
        "source_hashes": {},
    }


def view(clean, attacked):
    return build_paired_view(compare_records(clean, attacked), [clean, attacked])


def test_extra_tool_request_does_not_shift_later_pairing_and_ids_are_arm_local():
    clean = fixture()
    attacked = fixture(label="attacked", functions=("extra_tool", "read_file", "send_email"), offset=500)
    result = view(clean, attacked)
    seen_clean, seen_attacked = [], []
    for row in result["rows"]:
        left = clean["events"][row["clean_index"]] if row["clean_index"] is not None else None
        right = attacked["events"][row["attacked_index"]] if row["attacked_index"] is not None else None
        if left:
            seen_clean.append(left["event_id"])
        if right:
            seen_attacked.append(right["event_id"])
        if left and right:
            assert left["event_type"] == right["event_type"]
            assert left["data"] == right["data"]
            assert left["event_id"] != right["event_id"]
    assert seen_clean == [event["event_id"] for event in clean["events"]]
    assert seen_attacked == [event["event_id"] for event in attacked["events"]]
    proposals = [row for row in result["rows"] if row["event_type"] == "TOOL_CALL_PROPOSED"]
    assert [row["status"] for row in proposals] == ["attacked_only", "same", "same"]


def test_different_event_types_are_never_paired_in_a_replacement_span():
    clean, attacked = fixture(), fixture(label="attacked")
    attacked["events"][2]["event_type"] = "MODEL_PARSE_ERROR"
    result = view(clean, attacked)
    missing = [row for row in result["rows"] if row["status"].endswith("_only")]
    assert {row["event_type"] for row in missing} == {"MODEL_RESPONSE", "MODEL_PARSE_ERROR"}


def test_null_missing_boolean_and_integer_differences_stay_distinct():
    clean, attacked = fixture(), fixture(label="attacked")
    clean["events"][-1]["data"]["arguments"] = {"present": None, "typed": True, "a/b": {"~k": 1}}
    attacked["events"][-1]["data"]["arguments"] = {"typed": 1, "a/b": {"~k": 2}}
    result = view(clean, attacked)
    changes = result["rows"][-1]["changes"]
    removed = next(change for change in changes if change["path"] == "/arguments/present")
    assert removed == {
        "path": "/arguments/present",
        "before_present": True,
        "after_present": False,
        "before": None,
        "after": None,
        "kind": "removed",
    }
    assert {change["path"] for change in changes} == {
        "/arguments/present",
        "/arguments/typed",
        "/arguments/a~1b/~0k",
    }


def test_transport_fields_are_separate_but_business_ids_remain_content():
    clean, attacked = fixture(), fixture(label="attacked")
    for record, identifier, args in (
        (clean, "run-a", '{"id": "invoice-a"}'),
        (attacked, "run-b", '{"id": "invoice-b"}'),
    ):
        record["events"][2]["data"] = {
            "body_sha256": identifier,
            "body": {
                "id": identifier,
                "created": 10 if identifier == "run-a" else 20,
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {"id": identifier, "function": {"name": "read_file", "arguments": args}}
                            ]
                        }
                    }
                ],
            },
        }
    result = view(clean, attacked)
    row = next(row for row in result["rows"] if row["clean_index"] == 2)
    assert [change["path"] for change in row["changes"]] == [
        "/body/choices/0/message/tool_calls/0/function/arguments/id"
    ]
    assert any("body_sha256" in change["path"] for change in row["metadata_changes"])
    assert result["arms"][0]["events"][2]["data"] == clean["events"][2]["data"]


def test_equivalent_argument_serialization_is_metadata_only():
    clean, attacked = fixture(), fixture(label="attacked")
    for record, args in ((clean, '{"a": 1, "b": 2}'), (attacked, '{"b":2,"a":1}')):
        record["events"][2]["data"] = {
            "body": {
                "choices": [
                    {"message": {"tool_calls": [{"function": {"name": "read_file", "arguments": args}}]}}
                ]
            }
        }
    row = next(row for row in view(clean, attacked)["rows"] if row["clean_index"] == 2)
    assert row["changes"] == []
    assert any(change["path"].endswith("raw_arguments") for change in row["metadata_changes"])


def with_exposure(record, *, missing_source=False):
    source = {
        "event_id": "source:1",
        "event_sequence": 3,
        "event_type": "TOOL_RESULT",
        "call_ref": f"{record['run_id']}-0",
        "model_request_id": record["events"][1]["model_request_id"],
        "data": {"message": {"content": [{"type": "text", "content": "Original tool result"}]}},
    }
    exposure = {
        "event_id": "exposure:1",
        "event_sequence": 4,
        "event_type": "TOOL_OUTPUT_EXPOSED",
        "call_ref": source["call_ref"],
        "model_request_id": record["events"][-1]["model_request_id"],
        "data": {
            "source_result_event_id": "missing:source" if missing_source else "source:1",
            "message": {"content": "Actual outbound source content"},
        },
    }
    # The exposure follows its source and precedes the second response/proposal.
    record["events"][5:5] = [source, exposure]
    for index, event in enumerate(record["events"]):
        event["event_sequence"] = index + 1
    return source, exposure


def test_outbound_source_text_is_distinct_from_result_and_links_are_preserved():
    clean, attacked = fixture(), fixture(label="attacked")
    with_exposure(clean)
    with_exposure(attacked)
    result = view(clean, attacked)
    event = result["arms"][0]["events"][-1]
    assert len(event["sources"]) == 1
    source = event["sources"][0]
    assert source["source_result_event_id"] == "source:1"
    assert source["exposure_event_id"] == "exposure:1"
    assert source["content"] == "Actual outbound source content"
    assert source["source_content"] == "Original tool result"
    assert source["resolution_status"] == "resolved_earlier_tool_result"
    assert source["function"] == "read_file"


def test_unresolved_exposure_is_visible_and_no_exposure_stays_unknown():
    clean, attacked = fixture(), fixture(label="attacked")
    with_exposure(attacked, missing_source=True)
    result = view(clean, attacked)
    assert result["arms"][0]["events"][-1]["source_status"] == "unknown_no_linked_exposure_evidence"
    source = result["arms"][1]["events"][-1]["sources"][0]
    assert source["source_result_event_id"] == "missing:source"
    assert source["resolution_status"] == "unresolved_source_reference"
    assert source["source_index"] is None


def test_source_exposure_is_not_inferred_from_a_prior_tool_result():
    clean, attacked = fixture(), fixture(label="attacked")
    with_exposure(clean)
    clean["events"] = [event for event in clean["events"] if event["event_type"] != "TOOL_OUTPUT_EXPOSED"]
    result = view(clean, attacked)
    assert result["arms"][0]["events"][-1]["sources"] == []
    assert result["arms"][0]["sources"] == []


def test_result_later_exposure_is_marked_and_runtime_uses_recorded_call_binding():
    clean, attacked = fixture(), fixture(label="attacked")
    with_exposure(clean)
    proposal = clean["events"][-1]
    clean["events"].append(
        {
            "event_id": "runtime:1",
            "event_sequence": len(clean["events"]) + 1,
            "event_type": "TOOL_RUNTIME_STARTED",
            "data": {"function": "send_email", "runtime_input_args": {}},
            "call_ref": proposal["call_ref"],
            "model_request_id": None,
        }
    )
    result = view(clean, attacked)
    events = result["arms"][0]["events"]
    tool_result = next(event for event in events if event["event_id"] == "source:1")
    assert tool_result["sources"][0]["relation"] == "later_exposure_of_this_result"
    assert tool_result["sources"][0]["at_or_before_selected_event"] is False
    runtime = events[-1]
    assert runtime["resolved_request_id"] == proposal["model_request_id"]
    assert runtime["sources"][0]["exposure_event_id"] == "exposure:1"
    assert runtime["sources"][0]["at_or_before_selected_event"] is True


def test_display_builder_keeps_evidence_immutable_and_html_like_content_literal():
    clean, attacked = fixture(), fixture(label="attacked")
    literal = '</script><img src=x onerror="alert(1)"> & text'
    attacked["events"][-1]["data"]["arguments"] = {"body": literal}
    attacked["outcome"] = {"attack_success": False, "status": "evaluated"}
    before = copy.deepcopy([clean, attacked])
    result = view(clean, attacked)
    assert [clean, attacked] == before
    assert result["arms"][1]["outcome"]["attack_success"] is False
    assert json.loads(result["arms"][1]["events"][-1]["content"])["body"] == literal
    assert json.loads(json.dumps(result))["arms"][1]["events"][-1]["data"]["arguments"]["body"] == literal


def test_comparison_uncertainty_is_carried_through_without_promoting_candidate_rows():
    clean, attacked = fixture(), fixture(label="attacked")
    attacked["events"][-1]["data"]["arguments"] = {"recipients": ["changed@example.com"]}
    attacked["audit"]["valid"] = False
    comparison = compare_records(clean, attacked)
    result = build_paired_view(comparison, [clean, attacked])
    assert result["comparability"] == comparison["comparability"]
    assert result["sensitive_paths"] == comparison["sensitive_paths"]
    assert result["first_tool_proposal_divergence"] == comparison["first_tool_proposal_divergence"]
    assert result["first_tool_proposal_divergence"]["status"] == "unknown"
    assert result["first_tool_proposal_divergence"]["alignment_row"] is None
    assert result["first_tool_proposal_divergence"]["candidate_row_for_inspection"] is not None
    # A visible changed row is an inspection aid, not a stronger conclusion.
    assert result["first_security_row"] is not None
    result["comparability"]["reasons"].append("Display-only mutation")
    assert "Display-only mutation" not in comparison["comparability"]["reasons"]

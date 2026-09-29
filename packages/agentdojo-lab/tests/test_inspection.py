import copy
import json

import pytest

from agentdojo_lab.inspection import inspect_events


def event(event_type, *, request=None, call=None, data=None, **fields):
    return {
        "schema_version": 1,
        "run_id": "run",
        "event_id": "assigned-on-write",
        "event_sequence": 0,
        "monotonic_ns": 0,
        "time_utc": "2026-09-07T00:00:00Z",
        "event_type": event_type,
        "task_id": "task",
        "episode_id": "episode",
        "model_request_id": request,
        "tool_call_id": "provider-id" if call else None,
        "call_ref": call,
        "parent_event_ids": [],
        "data": data if data is not None else {},
        **fields,
    }


def clean_events():
    message = {"role": "tool", "tool_call_id": "provider-id", "content": "example"}
    return [
        event(
            "MODEL_REQUEST", request="r1", data={"body": {"messages": [{"role": "user", "content": "hi"}]}}
        ),
        event("MODEL_RESPONSE", request="r1"),
        event("MODEL_PARSED", request="r1"),
        event("TOOL_CALL_PROPOSED", request="r1", call="c1"),
        event("TOOL_RUNTIME_STARTED", request="r1", call="c1"),
        event("TOOL_RUNTIME_RETURNED", request="r1", call="c1"),
        event("TOOL_RESULT", request="r1", call="c1", data={"message": message}),
        event("MODEL_REQUEST", request="r2", data={"body": {"messages": [message]}}),
        event(
            "TOOL_OUTPUT_EXPOSED",
            request="r2",
            call="c1",
            data={
                "message_index": 0,
                "message": message,
                "source_result_event_id": "e7",
            },
            parent_event_ids=["e7", "e8"],
        ),
        event("MODEL_RESPONSE", request="r2"),
    ]


def write_events(tmp_path, events, *, mutate=None):
    events = copy.deepcopy(events)
    for number, item in enumerate(events, 1):
        item.update(event_id=f"e{number}", event_sequence=number, monotonic_ns=number)
    if mutate:
        mutate(events)
    path = tmp_path / "events.jsonl"
    path.write_text("".join(json.dumps(item) + "\n" for item in events))
    return path


def test_complete_log_counts_cross_request_exposure_and_is_read_only(tmp_path):
    path = write_events(tmp_path, clean_events())
    original = path.read_bytes()
    report = inspect_events(path)
    assert report["valid"], report["errors"]
    assert report["event_count"] == 10
    assert report["model_requests"] == 2
    assert report["tool_proposals"] == 1
    assert report["runtime_calls"] == 1
    assert report["tool_results"] == 1
    assert report["tool_output_exposures"] == 1
    assert report["episodes"] == 1
    assert report["event_counts"]["MODEL_RESPONSE"] == 2
    assert path.read_bytes() == original


@pytest.mark.parametrize("with_response", [False, True])
def test_model_error_with_or_without_http_response_is_a_valid_outcome(tmp_path, with_response):
    events = [event("MODEL_REQUEST", request="r1", data={"body": {"messages": []}})]
    if with_response:
        events.append(event("MODEL_RESPONSE", request="r1", data={"status_code": 400}))
    events.append(event("MODEL_ERROR", request="r1", data={"error_type": "BadRequestError"}))
    report = inspect_events(write_events(tmp_path, events))
    assert report["valid"], report["errors"]


def test_unknown_tool_result_does_not_need_runtime_entry(tmp_path):
    events = clean_events()
    events = [item for item in events if not item["event_type"].startswith("TOOL_RUNTIME_")]
    exposed = next(item for item in events if item["event_type"] == "TOOL_OUTPUT_EXPOSED")
    exposed["data"]["source_result_event_id"] = "e5"
    exposed["parent_event_ids"] = ["e5", "e6"]
    report = inspect_events(write_events(tmp_path, events))
    assert report["valid"], report["errors"]
    assert report["runtime_calls"] == 0
    assert report["tool_results"] == 1


def test_runtime_exception_return_can_omit_tool_result(tmp_path):
    events = clean_events()[:6]
    events[-1]["data"] = {"raised_exception_type": "RuntimeError"}
    report = inspect_events(write_events(tmp_path, events))
    assert report["valid"], report["errors"]


@pytest.mark.parametrize(
    ("index", "field", "value", "message"),
    [
        (1, "event_sequence", 8, "event_sequence is not consecutive"),
        (1, "event_id", "e1", "duplicate event_id"),
        (1, "run_id", "other", "run_id changed"),
        (0, "parent_event_ids", ["e2"], "parent_event_ids must reference earlier"),
        (0, "parent_event_ids", ["e1"], "parent_event_ids must reference earlier"),
        (1, "schema_version", 2, "schema_version"),
        (1, "monotonic_ns", 0, "monotonic_ns moved backwards"),
        (2, "model_request_id", "future", "model_request_id must reference an earlier"),
        (3, "model_request_id", "future", "model_request_id must reference an earlier"),
        (4, "model_request_id", "future", "model_request_id must reference an earlier"),
        (5, "call_ref", "missing", "call_ref must reference an earlier"),
        (6, "call_ref", "missing", "call_ref must reference an earlier"),
        (8, "call_ref", "missing", "TOOL_OUTPUT_EXPOSED lacks earlier TOOL_RESULT"),
        (8, "model_request_id", "future", "model_request_id must reference an earlier"),
    ],
)
def test_invalid_identifiers_order_and_schema_are_reported(tmp_path, index, field, value, message):
    path = write_events(tmp_path, clean_events(), mutate=lambda events: events[index].update({field: value}))
    report = inspect_events(path)
    assert not report["valid"]
    assert any(message in error for error in report["errors"]), report["errors"]


@pytest.mark.parametrize(
    ("event_type", "message"),
    [
        ("MODEL_RESPONSE", "duplicate MODEL_RESPONSE"),
        ("TOOL_CALL_PROPOSED", "duplicate TOOL_CALL_PROPOSED call_ref"),
        ("TOOL_RUNTIME_STARTED", "duplicate TOOL_RUNTIME_STARTED"),
        ("TOOL_RUNTIME_RETURNED", "duplicate TOOL_RUNTIME_RETURNED"),
        ("TOOL_RESULT", "duplicate TOOL_RESULT"),
        ("TOOL_OUTPUT_EXPOSED", "duplicate TOOL_OUTPUT_EXPOSED message_index"),
    ],
)
def test_duplicate_events_are_reported(tmp_path, event_type, message):
    events = clean_events()
    events.append(copy.deepcopy(next(item for item in events if item["event_type"] == event_type)))
    report = inspect_events(write_events(tmp_path, events))
    assert not report["valid"]
    assert any(message in error for error in report["errors"]), report["errors"]


def test_missing_exposure_is_detected_from_request_body(tmp_path):
    events = [item for item in clean_events() if item["event_type"] != "TOOL_OUTPUT_EXPOSED"]
    report = inspect_events(write_events(tmp_path, events))
    assert not report["valid"]
    assert any("tool message count differs" in error for error in report["errors"])


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("message_index", 100, "message_index is not a request tool message"),
        ("source_result_event_id", "e1", "source_result_event_id disagrees"),
        ("message", {"role": "tool", "content": "different"}, "message differs from request body"),
    ],
)
def test_exposure_consistency_is_checked(tmp_path, field, value, message):
    events = clean_events()
    events[8]["data"][field] = value
    report = inspect_events(write_events(tmp_path, events))
    assert not report["valid"]
    assert any(message in error for error in report["errors"])


def test_return_without_start_is_invalid(tmp_path):
    events = clean_events()[:4] + [clean_events()[5]]
    report = inspect_events(write_events(tmp_path, events))
    assert not report["valid"]
    assert any("lacks earlier TOOL_RUNTIME_STARTED" in error for error in report["errors"])


def test_unfinished_request_and_runtime_are_partial_logs(tmp_path):
    events = clean_events()[:5]
    events.append(event("MODEL_REQUEST", request="r2", data={"body": {"messages": []}}))
    report = inspect_events(write_events(tmp_path, events))
    assert not report["valid"]
    assert any("MODEL_REQUEST lacks MODEL_RESPONSE or MODEL_ERROR" in error for error in report["errors"])
    assert any("TOOL_RUNTIME_STARTED lacks TOOL_RUNTIME_RETURNED" in error for error in report["errors"])


def test_run_end_is_required_when_run_started_is_present(tmp_path):
    path = write_events(tmp_path, [event("RUN_STARTED"), event("CUSTOM_BOUNDARY", data={"extension": True})])
    assert not inspect_events(path)["valid"]
    path = write_events(tmp_path, [event("RUN_STARTED"), event("RUN_END")])
    assert inspect_events(path)["valid"]


def test_started_episode_needs_an_end(tmp_path):
    path = write_events(tmp_path, [event("EPISODE_STARTED")])
    assert not inspect_events(path)["valid"]
    path = write_events(tmp_path, [event("EPISODE_STARTED"), event("EPISODE_ENDED")])
    assert inspect_events(path)["valid"]


def test_unknown_events_and_extension_fields_are_allowed(tmp_path):
    path = write_events(tmp_path, [event("CUSTOM_BOUNDARY", future_field={"anything": True})])
    assert inspect_events(path)["valid"]


@pytest.mark.parametrize("raw", ["", "not-json-secret", "[]\n", '{"partial-secret":', "\n"])
def test_empty_or_malformed_log_is_invalid_without_exposing_payload(tmp_path, raw):
    path = tmp_path / "events.jsonl"
    path.write_text(raw)
    report = inspect_events(path)
    assert not report["valid"]
    assert "secret" not in str(report)


def test_missing_file_returns_invalid_report(tmp_path):
    report = inspect_events(tmp_path / "missing.jsonl")
    assert not report["valid"]
    assert report["event_count"] == 0
    assert "cannot open event log: FileNotFoundError" in report["errors"]

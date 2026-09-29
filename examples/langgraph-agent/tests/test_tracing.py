from datetime import datetime, timezone

import json
from pathlib import Path
from langchain_core.messages import AIMessage, ToolMessage

from boundary_agent.tracing import (
    TRACE_SCHEMA_VERSION,
    TraceRecorder,
    append_trace_event,
    create_trace_event,
    serialize_message,
)

def test_serialize_ai_message_with_tool_call() -> None:
    message = AIMessage(
        content="",
        id="message-1",
        tool_calls=[
            {
                "name": "mock_web_search",
                "args": {"query": "LangGraph"},
                "id": "call-1",
                "type": "tool_call",
            }
        ],
    )

    record = serialize_message(message)

    assert record["message_type"] == "ai"
    assert record["message_id"] == "message-1"
    assert record["tool_calls"][0]["name"] == "mock_web_search"
    assert record["tool_calls"][0]["args"] == {"query": "LangGraph"}
    assert json.loads(json.dumps(record)) == record


def test_serialize_tool_message() -> None:
    message = ToolMessage(
        content="Search result",
        name="mock_web_search",
        tool_call_id="call-1",
    )

    record = serialize_message(message)

    assert record["message_type"] == "tool"
    assert record["name"] == "mock_web_search"
    assert record["tool_call_id"] == "call-1"
    assert record["content"] == "Search result"
    assert json.loads(json.dumps(record)) == record

def test_create_trace_event() -> None:
    message = AIMessage(content="Final answer")

    event = create_trace_event(
        run_id="run-123",
        sequence=1,
        event_type="node_message",
        data={
            "node": "model",
            "message": serialize_message(message),
        },
    )

    assert event["schema_version"] == TRACE_SCHEMA_VERSION
    assert event["run_id"] == "run-123"
    assert event["sequence"] == 1
    assert event["event_type"] == "node_message"
    assert event["data"]["node"] == "model"
    assert event["data"]["message"]["content"] == "Final answer"
    assert datetime.fromisoformat(event["timestamp_utc"]).tzinfo == timezone.utc

    json.dumps(event)

def test_append_trace_event_writes_each_event_on_new_line(
        tmp_path: Path,
) -> None:
    trace_path = tmp_path / "run.jsonl"

    first_event = create_trace_event(
        run_id="run-123",
        sequence=1,
        event_type="run_started",
        data={"model": "test-model"},
    )
    second_event = create_trace_event(
        run_id="run-123",
        sequence=2,
        event_type="input_received",
        data={"messages": []},
    )

    append_trace_event(trace_path, first_event)
    append_trace_event(trace_path, second_event)

    stored_events = [
        json.loads(line)
        for line in trace_path.read_text(encoding="utf-8").splitlines()
    ]

    assert stored_events == [first_event, second_event]

def test_create_lifecycle_trace_events() -> None:
    completed_event = create_trace_event(
        run_id="run-123",
        sequence=6,
        event_type="run_completed",
        data={"duration_ms": 125.5},
    )
    failed_event = create_trace_event(
        run_id="run-456",
        sequence=4,
        event_type="run_failed",
        data={
            "error_type": "RuntimeError",
            "error_message": "Tool execution failed",
            "duration_ms": 40.2,
        },
    )

    assert completed_event["event_type"] == "run_completed"
    assert completed_event["data"]["duration_ms"] == 125.5

    assert failed_event["event_type"] == "run_failed"
    assert failed_event["data"]["error_type"] == "RuntimeError"

    json.dumps(completed_event)
    json.dumps(failed_event)

def test_trace_recorder_assigns_sequences_and_writes_jsonl(
        tmp_path: Path,
) -> None:
    trace_path = tmp_path / "run.jsonl"
    recorder = TraceRecorder(
        run_id="run-123",
        path=trace_path,
    )

    first_event = recorder.record(
        event_type="run_started",
        data={"model": "test-model"},
    )
    second_event = recorder.record(
        event_type="run_completed",
        data={"duration_ms": 10.0},
    )

    assert first_event["sequence"] == 1
    assert second_event["sequence"] == 2

    stored_events = [
        json.loads(line)
        for line in trace_path.read_text(encoding="utf-8").splitlines()
    ]

    assert stored_events == [first_event, second_event]
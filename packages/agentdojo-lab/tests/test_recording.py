import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

import pytest
from pydantic import BaseModel

from agentdojo_lab.recording import EventRecorder


def read_events(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_subscriber_sees_only_flushed_redacted_detached_events(tmp_path):
    path = tmp_path / "events.jsonl"
    seen = []

    def consume(event):
        assert read_events(path)[-1] == event
        seen.append(event)
        event["data"]["values"].append("subscriber modification")

    recorder = EventRecorder(path, "run", redactions=("fixture-secret",), on_event=consume)
    payload = {"values": ["fixture-secret"]}
    recorder.emit("RUN_STARTED", payload)
    recorder.close()
    assert payload == {"values": ["fixture-secret"]}
    assert read_events(path)[0]["data"] == {"values": ["[REDACTED]"]}
    assert seen[0]["data"]["values"] == ["[REDACTED]", "subscriber modification"]
    assert recorder.status()["complete"]
    assert recorder.subscriber_status()["complete"]


def test_subscriber_failure_disables_only_subscriber_and_hides_error_payload(tmp_path):
    seen = []

    def fail(event):
        seen.append(event)
        raise RuntimeError("fixture-sensitive-error-message")

    recorder = EventRecorder(tmp_path / "events.jsonl", "run", on_event=fail)
    assert recorder.emit("RUN_STARTED", {}) is not None
    assert recorder.emit("RUN_END", {}) is not None
    recorder.close()
    assert len(seen) == 1
    assert recorder.status()["complete"]
    assert recorder.status()["event_count"] == 2
    assert not recorder.subscriber_status()["complete"]
    assert "fixture-sensitive" not in json.dumps(recorder.subscriber_status())


def test_failed_event_is_never_sent_to_subscriber(tmp_path):
    seen = []
    recorder = EventRecorder(tmp_path / "events.jsonl", "run", on_event=seen.append)
    assert recorder.emit("RUN_STARTED", {"bad": object()}) is None
    assert seen == []
    recorder.close()


class ToolState(str, Enum):
    COMPLETE = "complete"


class Environment(BaseModel):
    values: list[str]
    location: Path


def test_events_are_immediate_snapshots_with_linked_ids_and_times(tmp_path):
    path = tmp_path / "events.jsonl"
    recorder = EventRecorder(path, "run-1")
    episode_id = recorder.new_id("episode")
    model_id = recorder.new_id("model")
    tool_id = recorder.new_id("tool")
    environment = Environment(values=["initial"], location=Path("example.txt"))
    payload = {
        "environment": environment,
        "state": ToolState.COMPLETE,
        "at": datetime(2026, 9, 7, tzinfo=timezone.utc),
        "set": {"z", "a", 2},
        "frozen": frozenset({3, 1}),
    }
    first_id = recorder.emit("task.started", payload, task_id="task", episode_id=episode_id)
    # Visibility before close verifies each successful emit is flushed.
    first = read_events(path)[0]
    assert first["data"]["environment"] == {"values": ["initial"], "location": "example.txt"}
    assert first["data"]["state"] == "complete"
    assert first["data"]["at"] == "2026-09-07T00:00:00+00:00"
    assert first["data"]["set"] == ["a", "z", 2]
    assert first["data"]["frozen"] == [1, 3]
    environment.values.append("mutated")
    payload["set"].add("later")
    parents = [first_id]
    second_id = recorder.emit(
        "tool.called",
        {"arguments": {"filename": "example.txt"}},
        task_id="task",
        episode_id=episode_id,
        model_request_id=model_id,
        tool_call_id=tool_id,
        call_ref="provider-call-1",
        parent_event_ids=parents,
    )
    parents.clear()
    recorder.close()
    events = read_events(path)
    assert events[0] == first
    assert [event["event_sequence"] for event in events] == [1, 2]
    assert len({episode_id, model_id, tool_id, first_id, second_id}) == 5
    assert all(event["schema_version"] == 1 and event["run_id"] == "run-1" for event in events)
    assert events[1]["parent_event_ids"] == [first_id]
    assert events[1]["model_request_id"] == model_id
    assert events[1]["tool_call_id"] == tool_id
    assert events[1]["call_ref"] == "provider-call-1"
    assert events[0]["model_request_id"] is None
    assert events[0]["monotonic_ns"] <= events[1]["monotonic_ns"]
    assert all(datetime.fromisoformat(event["time_utc"]).utcoffset().total_seconds() == 0 for event in events)
    assert recorder.status() == {
        "event_count": 2,
        "event_attempt_count": 2,
        "complete": True,
        "errors": [],
        "failed_event_sequences": [],
    }


def test_known_credentials_are_redacted_even_with_json_escaping(tmp_path):
    path = tmp_path / "events.jsonl"
    secret = 'credential-"quoted\\with\nnewline'
    recorder = EventRecorder(path, "run", redactions=("", secret, "abc", "abcdef"))
    recorder.emit(
        "example",
        {secret: [f"prefix {secret} suffix", "abcdef", "ab", "ordinary text"]},
    )
    recorder.close()
    payload = read_events(path)[0]["data"]
    assert payload == {"[REDACTED]": ["prefix [REDACTED] suffix", "[REDACTED]", "ab", "ordinary text"]}
    assert secret not in path.read_text()


def test_json_compatible_mixed_mapping_keys_are_supported(tmp_path):
    path = tmp_path / "events.jsonl"
    recorder = EventRecorder(path, "run")
    assert recorder.emit("mapping", {"nested": {2: "two", "one": 1}}) is not None
    recorder.close()
    assert read_events(path)[0]["data"] == {"nested": {"2": "two", "one": 1}}


@pytest.mark.parametrize("bad_value", [object(), float("nan"), float("inf")])
def test_serialization_failure_is_nonfatal_and_leaves_an_explicit_gap(tmp_path, bad_value):
    path = tmp_path / "events.jsonl"
    recorder = EventRecorder(path, "run")
    assert recorder.emit("first", {}) is not None
    assert recorder.emit("unserializable", {"value": bad_value}) is None
    assert recorder.emit("third", {}) is not None
    recorder.close()
    assert [event["event_sequence"] for event in read_events(path)] == [1, 3]
    status = recorder.status()
    assert status["event_count"] == 2
    assert status["event_attempt_count"] == 3
    assert status["complete"] is False
    assert status["failed_event_sequences"] == [2]
    assert status["errors"][0].startswith("emit.serialize:")
    status["errors"].clear()
    status["failed_event_sequences"].clear()
    assert recorder.status()["errors"]
    assert recorder.status()["failed_event_sequences"] == [2]


def test_cyclic_data_does_not_escape_into_agent(tmp_path):
    recorder = EventRecorder(tmp_path / "events.jsonl", "run")
    data = {}
    data["self"] = data
    assert recorder.emit("cyclic", data) is None
    assert recorder.emit("recovered", {}) is not None
    recorder.close()
    assert recorder.status()["complete"] is False


class FailingStream:
    def __init__(self, stream, failure):
        self.stream = stream
        self.failure = failure
        self.failed = False

    def __getattr__(self, name):
        return getattr(self.stream, name)

    def write(self, text):
        if self.failure == "write" and not self.failed:
            self.failed = True
            self.stream.write(text[:10])
            raise OSError("secret-payload-must-not-appear")
        return self.stream.write(text)

    def flush(self):
        if self.failure == "flush" and not self.failed:
            self.failed = True
            raise OSError("secret-payload-must-not-appear")
        return self.stream.flush()

    def close(self):
        self.stream.close()
        if self.failure == "close":
            raise OSError("secret-payload-must-not-appear")


@pytest.mark.parametrize("failure", ["write", "flush"])
def test_io_failure_preserves_valid_lines_and_allows_later_events(tmp_path, failure, capsys):
    path = tmp_path / "events.jsonl"
    recorder = EventRecorder(path, "run")
    recorder.emit("first", {})
    recorder._file = FailingStream(recorder._file, failure)
    assert recorder.emit("lost", {"payload": "secret-payload-must-not-appear"}) is None
    assert recorder.emit("third", {}) is not None
    recorder.close()
    assert [event["event_sequence"] for event in read_events(path)] == [1, 3]
    status = recorder.status()
    assert status["event_count"] == 2
    assert status["complete"] is False
    assert status["failed_event_sequences"] == [2]
    assert "secret-payload" not in str(status)
    assert "secret-payload" not in path.read_text()
    assert capsys.readouterr() == ("", "")


def test_close_failure_is_nonfatal_and_recorded(tmp_path):
    recorder = EventRecorder(tmp_path / "events.jsonl", "run")
    recorder._file = FailingStream(recorder._file, "close")
    recorder.emit("first", {})
    recorder.close()
    recorder.close()
    assert recorder.status()["errors"] == ["close: OSError"]
    assert recorder.status()["complete"] is False


def test_existing_event_file_is_never_overwritten(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text("existing evidence\n")
    with pytest.raises(FileExistsError):
        EventRecorder(path, "run")
    assert path.read_text() == "existing evidence\n"


def test_emit_after_close_reports_loss_without_raising(tmp_path):
    path = tmp_path / "events.jsonl"
    recorder = EventRecorder(path, "run")
    recorder.close()
    assert recorder.emit("late", {}) is None
    assert recorder.status()["complete"] is False
    assert recorder.status()["event_count"] == 0
    assert recorder.status()["failed_event_sequences"] == [1]
    assert read_events(path) == []

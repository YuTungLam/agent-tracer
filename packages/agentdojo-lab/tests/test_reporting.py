"""Saved synthetic observations exercise exports without model or network access."""

import csv
import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

from agentdojo_lab.inspection import inspect_events
from agentdojo_lab.reporting import export_report, trace_data, write_latex


def observed_events(episode_ids=("episode-1",)):
    events = []

    def emit(event_type, *, episode=None, request=None, call=None, data=None, parents=()):
        event_id = f"event-{len(events) + 1}"
        events.append(
            {
                "schema_version": 1,
                "run_id": "synthetic-run",
                "event_id": event_id,
                "event_sequence": len(events) + 1,
                "monotonic_ns": len(events) + 1,
                "time_utc": "2026-09-07T00:00:00Z",
                "event_type": event_type,
                "task_id": "user_task_0" if episode else None,
                "episode_id": episode,
                "model_request_id": request,
                "tool_call_id": "provider-call" if call else None,
                "call_ref": call,
                "parent_event_ids": list(parents),
                "data": deepcopy(data or {}),
            }
        )
        return event_id

    emit("RUN_STARTED")
    for episode in episode_ids:
        start = emit("EPISODE_STARTED", episode=episode)
        history = [{"role": "user", "content": "Look up the meeting location."}]
        outputs = []
        for index in range(1, 4):
            request = f"{episode}-request-{index}"
            requested = emit(
                "MODEL_REQUEST",
                episode=episode,
                request=request,
                data={"body": {"messages": history}},
                parents=[start],
            )
            for call, result_event, message_index in outputs:
                emit(
                    "TOOL_OUTPUT_EXPOSED",
                    episode=episode,
                    request=request,
                    call=call,
                    data={
                        "message_index": message_index,
                        "message": history[message_index],
                        "source_result_event_id": result_event,
                    },
                    parents=[requested, result_event],
                )
            response = emit("MODEL_RESPONSE", episode=episode, request=request, parents=[requested])
            emit(
                "MODEL_PARSED",
                episode=episode,
                request=request,
                data={"tool_call_count": int(index < 3)},
                parents=[response],
            )
            if index == 3:
                continue
            call = f"{episode}-call-{index}"
            args = {"query": "meeting" if index == 1 else "location"}
            proposal = emit(
                "TOOL_CALL_PROPOSED",
                episode=episode,
                request=request,
                call=call,
                data={"call_index": 0, "function": "search_calendar_events", "arguments": args},
                parents=[response],
            )
            runtime_start = emit(
                "TOOL_RUNTIME_STARTED", episode=episode, request=request, call=call, parents=[proposal]
            )
            runtime_end = emit(
                "TOOL_RUNTIME_RETURNED", episode=episode, request=request, call=call, parents=[runtime_start]
            )
            message = {"role": "tool", "tool_call_id": "provider-call", "content": "Room A"}
            result_event = emit(
                "TOOL_RESULT",
                episode=episode,
                request=request,
                call=call,
                data={"message": message, "runtime_entered": True},
                parents=[proposal, runtime_end],
            )
            history.append(
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "provider-call",
                            "type": "function",
                            "function": {"name": "search_calendar_events", "arguments": json.dumps(args)},
                        }
                    ],
                }
            )
            history.append(message)
            outputs.append((call, result_event, len(history) - 1))
        emit("EPISODE_ENDED", episode=episode, parents=[start])
    emit("RUN_END")
    return events


def make_run(root: Path, name="synthetic-run", *, recording=True, failed=False, model="model_a&b%"):
    directory = root / name
    directory.mkdir(parents=True)
    manifest = {
        "mode": "live-groq",
        "real_llm": True,
        "attack": None,
        "defense": None,
        "config": {
            "model": model,
            "benchmark_version": "v1.2.2",
            "suite": "workspace",
            "user_tasks": ["user_task_0"],
            "record_events": recording,
        },
    }
    summary = {
        "mode": "live-groq",
        "real_llm": True,
        "status": "failed" if failed else "completed",
    }
    if not failed:
        summary.update(
            tasks=[
                {
                    "task": "user_task_0",
                    "status": "evaluated",
                    "utility": True,
                    "proposed_tool_calls": 2,
                    "tool_errors": 0,
                }
            ],
            task_count=1,
            evaluable_task_count=1,
            task_success_count=1,
            usage={"request_count": 3, "prompt_tokens": 1234, "completion_tokens": 56},
            elapsed_seconds=1.234,
        )
    if recording:
        events_path = directory / "events.jsonl"
        events_path.write_text("".join(json.dumps(event) + "\n" for event in observed_events()))
        audit = inspect_events(events_path)
        assert audit["valid"], audit["errors"]
        summary["recording"] = {
            "enabled": True,
            "complete": True,
            "event_count": audit["event_count"],
            "audit": audit,
        }
    for filename, document in (("manifest.json", manifest), ("summary.json", summary)):
        (directory / filename).write_text(json.dumps(document))
    return directory


def test_repeated_exposure_is_not_counted_as_additional_tool_execution():
    data = trace_data(observed_events(), "episode-1")
    assert data["requests"] == 3
    assert data["results"] == 2
    assert len(data["nodes"]) == 5  # Three parsed responses and two tool results.
    assert sum(node["kind"] == "tool" for node in data["nodes"]) == 2
    matrix = {(cell["tool_result"], cell["request"]): cell["included"] for cell in data["matrix"]}
    assert matrix == {(1, 1): 0, (1, 2): 1, (1, 3): 1, (2, 1): 0, (2, 2): 0, (2, 3): 1}
    assert sum(matrix.values()) == 3


def test_episode_selection_isolated_even_with_reused_provider_call_ids():
    events = observed_events(("episode-1", "episode-2"))
    data = trace_data(events, "episode-2")
    selected_ids = {event["event_id"] for event in events if event["episode_id"] == "episode-2"}
    assert len(data["nodes"]) == 5
    assert all(node["event_id"] in selected_ids for node in data["nodes"])
    assert data["requests"] == 3 and data["results"] == 2
    assert {cell["call_ref"] for cell in data["matrix"]} == {"episode-2-call-1", "episode-2-call-2"}
    assert all(cell["model_request_id"].startswith("episode-2-") for cell in data["matrix"])
    assert data["nodes"][0]["title"].startswith("Request 1")
    assert trace_data(events, "missing") == {"nodes": [], "matrix": [], "requests": 0, "results": 0}


def test_parsed_response_without_proposals_does_not_claim_final_text():
    data = trace_data(observed_events(), "episode-1")
    final_node = data["nodes"][-1]
    assert "final" not in final_node["title"].lower()
    assert "final text" not in final_node["detail"].lower()


def test_latex_escapes_reserved_characters_and_unknown_measurements(tmp_path):
    row = {
        "model": r"a_b%&#${}~^\name",
        "successful_tasks": None,
        "evaluated_tasks": None,
        "model_requests": None,
        "proposed_tool_calls": None,
        "tool_errors": None,
        "input_tokens": None,
        "output_tokens": None,
        "elapsed_seconds": None,
        "recording_complete": None,
        "recording_enabled": None,
        "event_count": None,
    }
    path = tmp_path / "table.tex"
    write_latex([row], path, 0)
    content = path.read_text()
    for escaped in (
        r"\_",
        r"\%",
        r"\&",
        r"\#",
        r"\$",
        r"\{",
        r"\}",
        r"\textasciitilde{}",
        r"\textasciicircum{}",
        r"\textbackslash{}",
    ):
        assert escaped in content
    assert "None" not in content
    assert "--/--" in content
    assert "0 unique evaluated" in content
    row["model"] = None
    write_latex([row], path, 0)
    assert "None" not in path.read_text()


def test_export_report_creates_vector_raster_source_tables_and_audited_trace(tmp_path):
    runs = tmp_path / "runs"
    source = make_run(runs)
    before = {path.name: path.read_bytes() for path in source.iterdir()}
    report = export_report(runs, tmp_path / "report")
    output = Path(report["output_dir"])
    assert report["real_runs"] == 1
    assert report["unique_evaluated_tasks"] == 1
    assert report["trace"]["model_requests"] == 3
    assert report["trace"]["tool_results"] == 2
    assert report["trace"]["audit_valid"] is True
    for stem in ("table_runs", "figure_trace"):
        assert (output / f"{stem}.png").read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
        assert (output / f"{stem}.pdf").read_bytes().startswith(b"%PDF-")
        svg = (output / f"{stem}.svg").read_text()
        assert "<svg" in svg and "<text" in svg
    for filename in (
        "run_table.csv",
        "run_inventory.json",
        "table_runs.tex",
        "trace_nodes.csv",
        "trace_exposure.csv",
        "captions.md",
        "report.json",
    ):
        assert (output / filename).stat().st_size > 0
    with (output / "trace_exposure.csv").open(newline="") as stream:
        cells = list(csv.DictReader(stream))
    assert len(cells) == 6 and sum(int(cell["included"]) for cell in cells) == 3
    assert (
        report["source_hashes"]["synthetic-run/events.jsonl"]
        == hashlib.sha256(before["events.jsonl"]).hexdigest()
    )
    assert before == {path.name: path.read_bytes() for path in source.iterdir()}


def test_failed_run_with_unknown_model_and_no_recording_still_exports(tmp_path):
    runs = tmp_path / "runs"
    make_run(runs, failed=True, model=None, recording=False)
    report = export_report(runs, tmp_path / "report")
    assert report["real_runs"] == 1
    assert report["unique_evaluated_tasks"] == 0
    assert report["trace"] is None
    output = Path(report["output_dir"])
    assert (output / "table_runs.png").is_file()
    assert "None" not in (output / "table_runs.tex").read_text()
    with (output / "run_table.csv").open(newline="") as stream:
        row = next(csv.DictReader(stream))
    assert row["status"] == "failed"
    assert row["input_tokens"] == ""
    assert row["model_requests"] == ""


def test_export_refuses_to_overwrite_existing_report(tmp_path):
    runs = tmp_path / "runs"
    make_run(runs, recording=False)
    output = tmp_path / "report"
    output.mkdir()
    marker = output / "existing.txt"
    marker.write_text("keep")
    with pytest.raises(FileExistsError):
        export_report(runs, output)
    assert marker.read_text() == "keep"


def test_invalid_complete_recording_is_not_drawn(tmp_path):
    runs = tmp_path / "runs"
    source = make_run(runs)
    (source / "events.jsonl").write_text("invalid-json\n")
    report = export_report(runs, tmp_path / "report")
    assert report["trace"] is None
    assert report["trace_candidates"][0]["audit"]["valid"] is False
    assert not (Path(report["output_dir"]) / "figure_trace.png").exists()

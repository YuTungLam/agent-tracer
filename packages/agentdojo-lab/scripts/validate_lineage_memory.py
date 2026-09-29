"""Validate two-session memory lineage with native AgentDojo tools and mocked SDK replies.

This deterministic engineering control never calls a model endpoint. Native
memory and tracer state are persisted separately and restored into fresh objects.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import time
from contextlib import contextmanager
from datetime import date, datetime
from pathlib import Path
from types import SimpleNamespace

import httpx
import openai
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
from agentdojo.default_suites.v1.tools import cloud_drive_client
from agentdojo.default_suites.v1.tools.calendar_client import Calendar
from agentdojo.default_suites.v1.tools.cloud_drive_client import (
    CloudDrive,
    append_to_file,
    create_file,
    get_file_by_id,
)
from agentdojo.default_suites.v1.tools.email_client import Inbox
from agentdojo.default_suites.v1.tools.types import CloudDriveFile
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite
from pydantic import BaseModel

from agentdojo_lab.groq_adapter import GroqLLM
from agentdojo_lab.html_report import export_run_html
from agentdojo_lab.inspection import inspect_events
from agentdojo_lab.observation import ObservationSession, observe_pipeline
from agentdojo_lab.online import OnlineProvenance
from agentdojo_lab.policy import ToolPolicy
from agentdojo_lab.recording import EventRecorder

MODEL = "openai/gpt-oss-20b"
NAMESPACE = "native-fixture-drive-v1"
ACCOUNT = "fixture@example.com"
CONTENT = "Project reference: violet-copper-4821."
FIXED_TIME = datetime(2026, 1, 2, 12)


def write_json(path: Path, value) -> None:
    def encode(item):
        if isinstance(item, BaseModel):
            return item.model_dump(mode="json")
        raise TypeError("Unsupported fixture artifact value")

    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False, default=encode)
        stream.write("\n")


def read_lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def fixture_policy() -> ToolPolicy:
    return ToolPolicy.from_dict(
        {
            "schema_version": 1,
            "policy_id": "native-memory-fixture-v1",
            "suite": "workspace",
            "benchmark_version": "v1.2.2",
            "sources": {
                "get_file_by_id": {"rationale": "Native visible file content", "output_scope": "visible_text"}
            },
            "sinks": {
                name: {"rationale": "Native persistent content mutation", "argument_paths": ["/content"]}
                for name in ("create_file", "append_to_file")
            },
            "neutral_tools": {},
        }
    )


def initial_drive() -> CloudDrive:
    return CloudDrive(
        account_email=ACCOUNT,
        initial_files=[
            CloudDriveFile(
                id_="1",
                filename="external-reference.txt",
                content=CONTENT,
                owner=ACCOUNT,
                last_modified=FIXED_TIME,
            )
        ],
    )


def save_native_memory(path: Path, drive: CloudDrive, *, namespace: str = NAMESPACE) -> dict:
    """Save current native files; initial_files can be stale after native writes."""
    snapshot = {
        "schema_version": 1,
        "namespace": namespace,
        "account_email": str(drive.account_email),
        "files": [drive.files[key].model_dump(mode="json") for key in sorted(drive.files)],
    }
    write_json(path, snapshot)
    return snapshot


def load_native_memory(path: Path, *, namespace: str = NAMESPACE) -> CloudDrive:
    snapshot = json.loads(path.read_text(encoding="utf-8"))
    if snapshot["schema_version"] != 1 or snapshot["namespace"] != namespace:
        raise ValueError("Native memory snapshot namespace or schema mismatch")
    # CloudDrive's validator always rebuilds files from initial_files.
    restored = CloudDrive(
        account_email=snapshot["account_email"],
        initial_files=[CloudDriveFile.model_validate(value) for value in snapshot["files"]],
    )
    if [restored.files[key].model_dump(mode="json") for key in sorted(restored.files)] != snapshot["files"]:
        raise ValueError("Native memory restoration changed persisted file data")
    return restored


@contextmanager
def fixed_native_clock():
    """Only the offline native file clock is fixed, identically in both conditions."""
    original = cloud_drive_client.datetime

    class FixtureDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return FIXED_TIME if tz is None else FIXED_TIME.replace(tzinfo=tz)

    cloud_drive_client.datetime = SimpleNamespace(datetime=FixtureDateTime)
    try:
        yield
    finally:
        cloud_drive_client.datetime = original


def tool_reply(name: str, arguments: dict, identifier: str) -> dict:
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": identifier,
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(arguments)},
            }
        ],
    }


def session_script(*, source_id="1", failed_write=False) -> list[dict]:
    write = (
        tool_reply("append_to_file", {"file_id": "404", "content": CONTENT}, "store")
        if failed_write
        else tool_reply("create_file", {"filename": "session-memory.txt", "content": CONTENT}, "store")
    )
    return [
        tool_reply("get_file_by_id", {"file_id": source_id}, "read"),
        write,
        {"role": "assistant", "content": "Fixture complete."},
    ]


def run_session(
    output: Path,
    *,
    drive: CloudDrive,
    script: list[dict],
    lineage=None,
    policy: ToolPolicy | None = None,
    initial_state_path: Path | None = None,
) -> dict:
    """Create fresh native pipeline, runtime, SDK client, recorder, and empty history."""
    output.mkdir(parents=True, exist_ok=False)
    policy = policy or fixture_policy()
    requests, actions, at_runtime_entry = [], [], []
    runtime = FunctionsRuntime()
    for function in (get_file_by_id, create_file, append_to_file):
        runtime.register_function(function)
    provenance_path = output / "provenance.jsonl"
    sidecar = (
        OnlineProvenance(provenance_path, policy=policy, lineage=lineage) if lineage is not None else None
    )
    recorder = EventRecorder(
        output / "events.jsonl",
        output.name,
        on_event=sidecar.consume if sidecar is not None else None,
    )
    observer = ObservationSession(recorder)
    original_run = runtime.run_function

    def run_function(env, function, args, *rest, **kwargs):
        actions.append({"function": function, "arguments": copy.deepcopy(args)})
        if sidecar is not None:
            at_runtime_entry.append({"function": function, "rows": read_lines(provenance_path)})
        return original_run(env, function, args, *rest, **kwargs)

    runtime.run_function = run_function

    def respond(request):
        requests.append(json.loads(request.content))
        if len(requests) > len(script):
            raise AssertionError("Attribution added or retried a model request")
        return httpx.Response(
            200,
            json={
                "id": "native-memory-fixture",
                "object": "chat.completion",
                "created": 0,
                "model": MODEL,
                "choices": [
                    {"index": 0, "finish_reason": "stop", "message": copy.deepcopy(script[len(requests) - 1])}
                ],
                "usage": {"prompt_tokens": 8, "completion_tokens": 3, "total_tokens": 11},
            },
        )

    client = openai.OpenAI(
        api_key="synthetic-offline-key",
        base_url="https://native-memory.invalid/v1",
        max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(respond)),
    )
    observer.attach(client)
    llm = GroqLLM(client, MODEL, observer=observer)
    pipeline = observe_pipeline(
        AgentPipeline(
            [
                SystemMessage("Use the fixture file tools."),
                InitQuery(),
                llm,
                ToolsExecutionLoop([ToolsExecutor(), llm], max_iters=3),
            ]
        ),
        observer,
    )
    env = get_suite("v1.2.2", "workspace").environment_type(
        cloud_drive=drive,
        inbox=Inbox(account_email=ACCOUNT, initial_emails=[]),
        calendar=Calendar(account_email=ACCOUNT, current_day=date(2026, 1, 2), initial_events=[]),
    )
    manifest = {
        "schema_version": 1,
        "real_llm": False,
        "mode": "native-memory-fixture",
        "config": {
            "model": MODEL,
            "suite": "workspace",
            "benchmark_version": "v1.2.2",
            "user_tasks": [output.name],
            "online_provenance": sidecar is not None,
            "provenance_policy": str(output / "policy.json") if sidecar is not None else None,
            "semantic_model": None,
            "semantic_revision": None,
            "lineage_namespace": NAMESPACE if lineage is not None else None,
        },
        "online_provenance": {
            "enabled": sidecar is not None,
            "policy": policy.metadata if sidecar is not None else None,
            "mode": "synchronous_observation; ordered_cascade",
            "implementation_sha256": {
                name: hashlib.sha256(
                    Path(__file__).resolve().parents[1].joinpath("src", "agentdojo_lab", name).read_bytes()
                ).hexdigest()
                for name in (
                    "recording.py",
                    "observation.py",
                    "online.py",
                    "provenance.py",
                    "lexical.py",
                    "semantic.py",
                    "cascade.py",
                    "policy.py",
                    "lineage.py",
                )
            }
            if sidecar is not None
            else {},
        },
        "event_recording": {"enabled": True, "schema_version": 1},
        "endpoint": "in-process HTTPX MockTransport",
        "sdk_max_retries": 0,
        "attack": None,
        "defense": None,
        "fixture_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "notes": [
            "Deterministic native-tool engineering control; no real LLM or benchmark evaluator.",
            "Native file datetime.now is fixed to 2026-01-02T12:00:00 in all paired conditions.",
            "Native memory and tracer state are separate artifacts; neither implies the other was restored.",
        ],
    }
    write_json(output / "policy.json", policy.metadata["document"])
    if lineage is not None:
        manifest["online_provenance"]["lineage"] = copy.deepcopy(lineage.metadata)
        if initial_state_path is not None:
            raw = initial_state_path.read_bytes()
            with (output / "lineage-initial-state.json").open("xb") as stream:
                stream.write(raw)
            manifest["online_provenance"]["lineage"]["initial_state"] = {
                "path": "lineage-initial-state.json",
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
    write_json(output / "manifest.json", manifest)
    recorder.emit("RUN_STARTED", {"mode": manifest["mode"]})
    messages, failure = [], None
    history = []
    try:
        with fixed_native_clock(), client:
            returned = pipeline.query("Read the reference and store its content.", runtime, env, history, {})
            if returned[1] is not runtime or returned[2] is not env or history:
                raise AssertionError("Native pipeline object identity or initial history changed")
            messages = returned[3]
    except Exception as error:
        failure = type(error).__name__
    finally:
        recorder.emit("RUN_END", {"status": "completed" if failure is None else "failed"})
        recorder.close()
        if sidecar is not None:
            sidecar.close()
    audit = inspect_events(output / "events.jsonl")
    summary = {
        "mode": manifest["mode"],
        "real_llm": False,
        "status": "completed" if failure is None else "failed",
        "error_type": failure,
        "usage": dict(llm.stats),
        "tasks": [],
        "task_count": 0,
        "evaluable_task_count": 0,
        "task_success_count": None,
        "recording": {"enabled": True, **observer.status(), "audit": audit},
        "online_provenance": sidecar.status() if sidecar is not None else {"enabled": False},
    }
    if sidecar is not None:
        summary["lineage_state"] = sidecar.save_state(output / "lineage-state.json")
        summary["online_provenance"] = {
            **sidecar.status(),
            "enabled": True,
            "subscriber": recorder.subscriber_status(),
            "path": str(provenance_path),
        }
    write_json(output / "summary.json", summary)
    write_json(output / "events.audit.json", audit)
    write_json(output / "requests.json", requests)
    write_json(output / "actions.json", actions)
    write_json(output / "final-environment.json", env.model_dump(mode="json"))
    (output / "native").mkdir()
    write_json(output / "native" / "fixture.json", {"messages": messages, "error_type": failure})
    # Use the existing report exporter; this fixture does not create a separate viewer implementation.
    export_run_html(output)
    return {
        "requests": requests,
        "actions": actions,
        "messages": messages,
        "failure": failure,
        "environment": env.model_dump(mode="json"),
        "drive": env.cloud_drive,
        "events": read_lines(output / "events.jsonl"),
        "rows": read_lines(provenance_path) if sidecar is not None else [],
        "summary": summary,
        "at_runtime_entry": at_runtime_entry,
    }


def assert_native_equal(baseline: dict, traced: dict) -> None:
    for key in ("requests", "actions", "messages", "failure", "environment"):
        if baseline[key] != traced[key]:
            raise AssertionError(f"Native behavior differs: {key}")
    if baseline["summary"]["usage"] != traced["summary"]["usage"]:
        raise AssertionError("SDK usage differs")
    if not traced["summary"]["recording"]["audit"]["valid"]:
        raise AssertionError("Recorded events failed structural audit")


def file_sink(result: dict) -> dict:
    return next(
        row["call"]
        for row in result["rows"]
        if row["record_type"] == "call_analysis"
        and row["call"]["function"] in {"create_file", "append_to_file"}
    )


def validate(output: Path) -> dict:
    from agentdojo_lab.lineage import DCPG

    output.mkdir(parents=True, exist_ok=False)
    timing_ns = {}

    def timed(name, operation):
        started = time.perf_counter_ns()
        value = operation()
        timing_ns[name] = time.perf_counter_ns() - started
        return value

    policy = fixture_policy()
    first_core = DCPG(namespace=NAMESPACE, policy=policy)
    first_baseline = run_session(output / "session1-baseline", drive=initial_drive(), script=session_script())
    first = run_session(
        output / "session1-traced",
        drive=initial_drive(),
        script=session_script(),
        lineage=first_core,
        policy=policy,
    )
    assert_native_equal(first_baseline, first)
    memory_path, state_path = output / "native-memory.json", output / "lineage-state.json"
    timed("native_memory_save", lambda: save_native_memory(memory_path, first["drive"]))
    timed("lineage_checkpoint_save", lambda: first_core.save_state(state_path))
    before = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (memory_path, state_path)}
    restored = timed(
        "lineage_checkpoint_load", lambda: DCPG.load_state(state_path, namespace=NAMESPACE, policy=policy)
    )
    second_script = session_script(source_id="2")
    baseline_drive = timed("session2_baseline_native_memory_load", lambda: load_native_memory(memory_path))
    second_baseline = run_session(output / "session2-baseline", drive=baseline_drive, script=second_script)
    traced_drive = timed("session2_traced_native_memory_load", lambda: load_native_memory(memory_path))
    second = run_session(
        output / "session2-traced",
        drive=traced_drive,
        script=second_script,
        lineage=restored,
        policy=policy,
        initial_state_path=state_path,
    )
    assert_native_equal(second_baseline, second)
    after = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (memory_path, state_path)}
    call = file_sink(second)
    evidence = call["lineage"]
    original_sources = {
        source["source_id"] for source in file_sink(first)["visible_sources"] if source["kind"] == "tool"
    }
    proposal = next(
        row for row in second["rows"] if row["record_type"] == "call_analysis" and row["call"] == call
    )
    at_sink = next(item for item in second["at_runtime_entry"] if item["function"] == "create_file")
    available_records = {
        row["record_type"]
        for row in at_sink["rows"]
        if row.get("proposal_event_id") == proposal["proposal_event_id"]
    }
    checks = {
        "session1_native_behavior_equal": True,
        "session2_native_behavior_equal": True,
        "persisted_inputs_unchanged": before == after,
        "restored_memory_content_present": second["drive"].files["2"].content == CONTENT,
        "actual_outbound_tool_content_present": any(
            message.get("role") == "tool" and CONTENT in message.get("content", "")
            for message in second["requests"][1]["messages"]
        ),
        "session2_has_recovered_ancestry": evidence["summary"]["recovered_source_count"] > 0,
        "session2_recovers_session1_origin": any(
            item["origin_source_id"] in original_sources for item in evidence["recovered_sources"]
        ),
        "session2_has_matched_recovered_comparison": evidence["summary"]["matched_comparison_count"] > 0,
        "session2_has_lineage_paths": bool(evidence["paths"]),
        "session2_lineage_persisted_before_native_sink": {
            "call_analysis",
            "analysis_flush",
            "runtime_timing",
        }.issubset(available_records),
        "session2_initial_history_empty": all(
            message["role"] != "tool" for message in second["requests"][0]["messages"]
        ),
        "both_sidecars_complete": all(
            item["summary"]["online_provenance"]["complete"] is True for item in (first, second)
        ),
        "both_final_states_saved": all(
            item["summary"]["lineage_state"]["status"] == "saved" for item in (first, second)
        ),
        "checkpoint_copy_is_exact": (output / "session2-traced" / "lineage-initial-state.json").read_bytes()
        == state_path.read_bytes(),
    }
    write_json(output / "session1-graph.json", first_core.snapshot())
    write_json(output / "session2-graph.json", restored.snapshot())
    result = {
        "schema_version": 1,
        "passed": all(checks.values()),
        "checks": checks,
        "real_llm": False,
        "namespace": NAMESPACE,
        "policy_sha256": policy.metadata["sha256"],
        "input_sha256": before,
        "timing_ns": timing_ns,
        "timing_scope": (
            "One invocation of each named offline fixture operation measured with time.perf_counter_ns; "
            "save/load durations include serialization or parsing, validation and file I/O. "
            "The two native memory loads are the existing baseline/traced session initializations. "
            "Per-run sidecar checkpoint saves and callback compute/flush are separate operations. "
            "These single-operation descriptions are not live overhead estimates or model/accuracy evidence."
        ),
        "session2_lineage_summary": evidence["summary"],
        "scope": "Native two-session persistence and lineage engineering control; no provenance accuracy, maliciousness, causality, benchmark efficacy, or model capability claim.",
        "reports": [
            f"{name}/report.html"
            for name in ("session1-baseline", "session1-traced", "session2-baseline", "session2-traced")
        ],
    }
    write_json(output / "validation.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, required=True, help="New output directory; never overwrite a run"
    )
    args = parser.parse_args()
    result = validate(args.output.expanduser().resolve())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)

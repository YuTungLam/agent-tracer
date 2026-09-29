"""Native paired UUID-canary engineering controls using only an in-process SDK mock.

Fixtures use deterministic canonical UUIDv4 values. They test intervention
bookkeeping and a scripted copy rule, not model behavior or attack efficacy.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from uuid import UUID

import httpx
import openai
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
from agentdojo.default_suites.v1.tools.cloud_drive_client import append_to_file, create_file, get_file_by_id
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite

from agentdojo_lab.groq_adapter import GroqLLM
from agentdojo_lab.html_report import export_run_html
from agentdojo_lab.inspection import inspect_events
from agentdojo_lab.observation import ObservationSession, observe_pipeline
from agentdojo_lab.online import OnlineProvenance
from agentdojo_lab.recording import EventRecorder

MEMORY_SCRIPT = Path(__file__).with_name("validate_lineage_memory.py")
SPEC = importlib.util.spec_from_file_location("canary_native_memory_utilities", MEMORY_SCRIPT)
memory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(memory)

UUIDS = tuple(str(UUID(int=(4 << 76) | (2 << 62) | index)) for index in range(1, 17))
NAMESPACE = "native-canary-memory-fixture-v1"


def _read_reply(case: str, source_id: str) -> dict:
    calls = [memory.tool_reply("get_file_by_id", {"file_id": source_id}, "read-1")["tool_calls"][0]]
    if case in {"multi", "multi_copy"}:
        calls.append(memory.tool_reply("get_file_by_id", {"file_id": source_id}, "read-2")["tool_calls"][0])
    elif case == "mixed":
        calls = [
            memory.tool_reply("unknown_file_tool", {}, "unknown")["tool_calls"][0],
            memory.tool_reply("get_file_by_id", {"file_id": "404"}, "failed-read")["tool_calls"][0],
            *calls,
        ]
    return {"role": "assistant", "content": None, "tool_calls": calls}


def run_arm(
    output: Path,
    *,
    case: str,
    enabled: bool,
    drive=None,
    source_id="1",
    lineage=None,
    initial_state_path: Path | None = None,
    uuid_tokens=UUIDS,
) -> dict:
    """Fresh actual native runtime and empty history; only SDK replies are authored."""
    from agentdojo_lab.canary import CanaryInjector

    if case not in {"fixed", "copy", "summary", "multi", "multi_copy", "mixed", "copy_old_token"}:
        raise ValueError("Unknown canary fixture case")
    output.mkdir(parents=True, exist_ok=False)
    policy = memory.fixture_policy()
    values = iter(uuid_tokens)
    injector = CanaryInjector(policy, uuid_factory=lambda: UUID(next(values))) if enabled else None
    requests, actions, at_runtime_entry = [], [], []
    runtime = FunctionsRuntime()
    for function in (get_file_by_id, create_file, append_to_file):
        runtime.register_function(function)
    sidecar_path = output / "provenance.jsonl"
    sidecar = OnlineProvenance(sidecar_path, policy=policy, canary_enabled=enabled, lineage=lineage)
    recorder = EventRecorder(output / "events.jsonl", output.name, on_event=sidecar.consume)
    observer = ObservationSession(recorder, canary=injector)
    original_runtime = runtime.run_function

    def run_function(env, function, args, *rest, **kwargs):
        actions.append({"function": function, "arguments": copy.deepcopy(args)})
        at_runtime_entry.append({"function": function, "rows": memory.read_lines(sidecar_path)})
        return original_runtime(env, function, args, *rest, **kwargs)

    runtime.run_function = run_function

    def respond(request):
        body = json.loads(request.content)
        requests.append(body)
        if len(requests) == 1:
            reply = _read_reply(case, source_id)
        elif len(requests) == 2:
            # This rule reads the actual HTTP request. It never fabricates a marker
            # or reads an injector registry, pristine output, environment, or label.
            visible = next(
                message["content"]
                for message in body["messages"]
                if message["role"] == "tool" and message["tool_call_id"] == "read-1"
            )
            if case in {"copy", "multi_copy"}:
                content = visible
            elif case == "copy_old_token":
                import re

                candidates = re.findall(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", visible
                )
                if not candidates:
                    raise AssertionError(
                        "Scripted token copy requires a token actually visible in the request"
                    )
                content = candidates[0]
            elif case == "summary":
                content = memory.CONTENT
            else:
                content = "A fixed fixture summary."
            reply = memory.tool_reply(
                "create_file", {"filename": "fixture-copy.txt", "content": content}, "store"
            )
        elif len(requests) == 3:
            reply = {"role": "assistant", "content": "Fixture complete."}
        else:
            raise AssertionError("Intervention added or retried a model request")
        return httpx.Response(
            200,
            json={
                "id": "native-canary-fixture",
                "object": "chat.completion",
                "created": 0,
                "model": memory.MODEL,
                "choices": [{"index": 0, "finish_reason": "stop", "message": reply}],
                "usage": {"prompt_tokens": 8, "completion_tokens": 3, "total_tokens": 11},
            },
        )

    client = openai.OpenAI(
        api_key="synthetic-offline-canary-key",
        base_url="https://canary-fixture.invalid/v1",
        max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(respond)),
    )
    observer.attach(client)
    llm = GroqLLM(client, memory.MODEL, observer=observer)
    pipeline = observe_pipeline(
        AgentPipeline(
            [
                SystemMessage(
                    "Follow the benign fixture instruction; copy or summarize only visible tool text."
                ),
                InitQuery(),
                llm,
                ToolsExecutionLoop([ToolsExecutor(), llm], max_iters=3),
            ]
        ),
        observer,
    )
    env = get_suite("v1.2.2", "workspace").environment_type(
        cloud_drive=drive if drive is not None else memory.initial_drive(),
        inbox=memory.Inbox(account_email=memory.ACCOUNT, initial_emails=[]),
        calendar=memory.Calendar(
            account_email=memory.ACCOUNT, current_day=memory.date(2026, 1, 2), initial_events=[]
        ),
    )
    manifest = {
        "schema_version": 1,
        "mode": "native-canary-fixture",
        "real_llm": False,
        "input_condition": "canary_intervention" if enabled else "passive",
        "config": {
            "model": memory.MODEL,
            "suite": "workspace",
            "benchmark_version": "v1.2.2",
            "user_tasks": [output.name],
            "online_provenance": True,
            "canary_enabled": enabled,
            "provenance_policy": str(output / "policy.json"),
            "semantic_model": None,
            "semantic_revision": None,
            "lineage_namespace": NAMESPACE if lineage is not None else None,
        },
        "online_provenance": {
            "enabled": True,
            "mode": "synchronous_observation; ordered_cascade",
            "policy": policy.metadata,
        },
        "event_recording": {"enabled": True, "schema_version": 1},
        "endpoint": "in-process HTTPX MockTransport",
        "sdk_max_retries": 0,
        "attack": None,
        "defense": None,
        "canary_condition": {
            "enabled": enabled,
            "case": case,
            "uuid_generation": "deterministic canonical UUIDv4 fixture sequence; not production randomness",
            "rule": "copy case copies the entire actual tool HTTP message; summary and fixed cases use authored constants",
        },
        "fixture_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "fixture_utility_sha256": hashlib.sha256(MEMORY_SCRIPT.read_bytes()).hexdigest(),
        "notes": [
            "Offline engineering control with native AgentDojo tools, not a model or benchmark result.",
            "Canary is a separately enabled tool-output intervention. Passive output remains untouched.",
            "Scripted copying demonstrates transmission under that explicit rule, not maliciousness or model propensity.",
            "Native file datetime.now is fixed identically in paired conditions.",
        ],
    }
    if injector is not None:
        manifest["canary"] = injector.metadata
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
    memory.write_json(output / "policy.json", policy.metadata["document"])
    memory.write_json(output / "manifest.json", manifest)
    recorder.emit("RUN_STARTED", {"mode": manifest["mode"], "config": manifest["config"]})
    history, messages, failure = [], [], None
    try:
        with memory.fixed_native_clock(), client:
            returned = pipeline.query(
                "Copy or summarize the actual visible reference as specified by this fixture.",
                runtime,
                env,
                history,
                {},
            )
            if history or returned[1] is not runtime or returned[2] is not env:
                raise AssertionError("Native runtime/environment identity or empty initial history changed")
            messages = returned[3]
    except Exception as error:
        failure = type(error).__name__
    finally:
        recorder.emit("RUN_END", {"status": "completed" if failure is None else "failed"})
        recorder.close()
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
        "online_provenance": {
            **sidecar.status(),
            "enabled": True,
            "subscriber": recorder.subscriber_status(),
            "path": str(sidecar_path),
        },
        "canary": {**injector.status(), "input_condition": "canary_intervention"}
        if injector is not None
        else {"enabled": False, "input_condition": "passive"},
    }
    if lineage is not None:
        summary["lineage_state"] = (
            sidecar.save_state(output / "lineage-state.json")
            if summary["recording"]["complete"]
            and audit["valid"]
            and recorder.subscriber_status()["complete"]
            else {"status": "not_saved", "reason": "primary_recording_incomplete"}
        )
        summary["online_provenance"] = {
            **sidecar.status(),
            "enabled": True,
            "subscriber": recorder.subscriber_status(),
            "path": str(sidecar_path),
        }
    memory.write_json(output / "summary.json", summary)
    memory.write_json(output / "events.audit.json", audit)
    memory.write_json(output / "requests.json", requests)
    memory.write_json(output / "actions.json", actions)
    memory.write_json(output / "final-environment.json", env.model_dump(mode="json"))
    (output / "native").mkdir()
    memory.write_json(output / "native" / "fixture.json", {"messages": messages, "error_type": failure})
    export_run_html(output)
    return {
        "requests": requests,
        "actions": actions,
        "messages": messages,
        "failure": failure,
        "environment": env.model_dump(mode="json"),
        "drive": env.cloud_drive,
        "events": memory.read_lines(output / "events.jsonl"),
        "rows": memory.read_lines(sidecar_path),
        "summary": summary,
        "at_runtime_entry": at_runtime_entry,
    }


def assignments(result):
    return [
        event
        for event in result["events"]
        if event["event_type"] == "TOOL_OUTPUT_INTERVENTION" and event["data"]["status"] == "assigned"
    ]


def normalized_messages(messages, assigned):
    """Remove only complete recorded insertion suffixes from tool text, nowhere else."""
    copied = copy.deepcopy(messages)
    suffixes = [event["data"]["suffix"] for event in assigned]

    def strip(text):
        if isinstance(text, str):
            for suffix in suffixes:
                if text.endswith(suffix):
                    return text[: -len(suffix)]
        return text

    for message in copied:
        if message.get("role") != "tool":
            continue
        content = message.get("content")
        if isinstance(content, str):
            message["content"] = strip(content)
        elif isinstance(content, list):
            for part in content:
                if part.get("type") == "text":
                    for key in ("content", "text"):
                        if key in part:
                            part[key] = strip(part[key])
    return copied


def assert_fixed_equivalence(passive, active):
    assigned = assignments(active)
    requests = copy.deepcopy(active["requests"])
    for request in requests:
        request["messages"] = normalized_messages(request["messages"], assigned)
    assert requests == passive["requests"]
    assert normalized_messages(active["messages"], assigned) == passive["messages"]
    for key in ("actions", "environment", "failure"):
        assert active[key] == passive[key], key
    assert active["summary"]["usage"] == passive["summary"]["usage"]


def sink_call(result):
    return next(
        row["call"]
        for row in result["rows"]
        if row["record_type"] == "call_analysis" and row["call"]["function"] == "create_file"
    )


def content_pairs(result):
    return next(
        field["nt_style_cascade"]
        for field in sink_call(result)["fields"]
        if field["argument_path"] == "/content"
    )


def validate_memory(output: Path) -> dict:
    """Keep an old stored UUID distinct from the fresh UUID assigned on retrieval."""
    from agentdojo_lab.lineage import DCPG

    output.mkdir(parents=True, exist_ok=False)
    policy = memory.fixture_policy()
    first_core = DCPG(NAMESPACE, policy, canary_enabled=True)
    first = run_arm(output / "session1", case="copy", enabled=True, lineage=first_core)
    old_token = assignments(first)[0]["data"]["token"]
    memory_path = output / "native-memory.json"
    memory.save_native_memory(memory_path, first["drive"], namespace=NAMESPACE)
    checkpoint = output / "session1" / "lineage-state.json"
    source_hashes = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (memory_path, checkpoint)
    }
    restored = DCPG.load_state(checkpoint, NAMESPACE, policy, canary_enabled=True)
    second = run_arm(
        output / "session2",
        case="copy_old_token",
        enabled=True,
        drive=memory.load_native_memory(memory_path, namespace=NAMESPACE),
        source_id="2",
        lineage=restored,
        initial_state_path=checkpoint,
        uuid_tokens=UUIDS[8:],
    )
    new_token = assignments(second)[0]["data"]["token"]
    call = sink_call(second)
    comparisons = [pair for pair in call["lineage"]["comparisons"] if pair["argument_path"] == "/content"]
    carriers = call["lineage"]["recovered_sources"]
    checks = {
        "fresh_retrieval_marker_differs_from_stored_marker": new_token != old_token,
        "actual_memory_contains_original_marked_text": second["drive"].files["2"].content
        == first["drive"].files["2"].content,
        "old_marker_was_actually_retrieved_in_request": any(
            message["role"] == "tool" and old_token in message["content"]
            for message in second["requests"][1]["messages"]
        ),
        "sink_copied_old_visible_marker": call["arguments"]["content"] == old_token,
        "direct_fresh_marker_does_not_claim_old_marker_copy": all(
            pair["stages"]["tier1"]["matched"] is False for pair in content_pairs(second)
        ),
        "original_marker_reference_restored": any(
            carrier.get("original_canary", {}).get("token") == old_token for carrier in carriers
        ),
        "inherited_marker_hits_tier1": any(pair["first_matched_tier"] == "tier1" for pair in comparisons),
        "both_native_sessions_completed": first["failure"] is second["failure"] is None,
        "both_interventions_complete": all(item["summary"]["canary"]["complete"] for item in (first, second)),
        "both_recordings_and_sidecars_complete": all(
            item["summary"]["recording"]["complete"]
            and item["summary"]["recording"]["audit"]["valid"]
            and item["summary"]["online_provenance"]["complete"]
            for item in (first, second)
        ),
        "persisted_input_files_unchanged": source_hashes
        == {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (memory_path, checkpoint)},
    }
    result = {
        "schema_version": 1,
        "passed": all(checks.values()),
        "checks": checks,
        "real_llm": False,
        "old_token": old_token,
        "new_token": new_token,
        "session2_lineage_summary": call["lineage"]["summary"],
        "input_sha256": source_hashes,
        "reports": ["session1/report.html", "session2/report.html"],
        "scope": "Scripted native memory and observer-checkpoint restoration with distinct UUIDs; no model capability, maliciousness or causal evidence.",
    }
    memory.write_json(output / "validation.json", result)
    return result


def validate(output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    checks, cases = {}, {}
    for case in ("fixed", "copy", "summary", "multi", "multi_copy", "mixed"):
        passive = run_arm(output / f"{case}-passive", case=case, enabled=False)
        active = run_arm(output / f"{case}-canary", case=case, enabled=True)
        if case not in {"copy", "multi_copy"}:
            assert_fixed_equivalence(passive, active)
            checks[f"{case}_only_audited_tool_suffixes_change"] = True
        assigned = assignments(active)
        checks[f"{case}_native_execution_completed"] = (
            passive["failure"] is None and active["failure"] is None
        )
        checks[f"{case}_recording_complete"] = all(
            item["summary"]["recording"]["complete"] and item["summary"]["recording"]["audit"]["valid"]
            for item in (passive, active)
        )
        checks[f"{case}_sidecar_complete"] = all(
            item["summary"]["online_provenance"]["complete"] for item in (passive, active)
        )
        checks[f"{case}_passive_has_no_insertion"] = not assignments(passive)
        checks[f"{case}_expected_assignment_count"] = len(assigned) == (
            2 if case in {"multi", "multi_copy"} else 1
        )
        pairs = content_pairs(active)
        if case in {"copy", "multi_copy"}:
            checks[f"{case}_scripted_actual_copy_hits_tier1"] = any(
                pair["first_matched_tier"] == "tier1" for pair in pairs
            )
        if case == "summary":
            checks["marker_free_summary_falls_through_tier1"] = all(
                pair["stages"]["tier1"]["matched"] is False and pair["stages"]["tier2"]["status"] == "scored"
                for pair in pairs
            )
        cases[case] = {
            "assigned_count": len(assigned),
            "content_first_hit_tiers": [pair["first_matched_tier"] for pair in pairs],
            "reports": [f"{case}-passive/report.html", f"{case}-canary/report.html"],
        }
    result = {
        "schema_version": 1,
        "passed": all(checks.values()),
        "checks": checks,
        "cases": cases,
        "real_llm": False,
        "uuid_generation": "deterministic canonical UUIDv4 fixture values",
        "scope": "Paired native-runtime bookkeeping and explicitly scripted copying only; not model capability, provenance accuracy, malicious propagation, causality, or benchmark efficacy.",
    }
    result["memory"] = validate_memory(output / "cross-session-memory")
    result["checks"]["cross_session_memory_control_passed"] = result["memory"]["passed"]
    result["passed"] = all(result["checks"].values())
    memory.write_json(output / "validation.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New output directory; existing artifacts are never overwritten",
    )
    args = parser.parse_args()
    result = validate(args.output.expanduser().resolve())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)

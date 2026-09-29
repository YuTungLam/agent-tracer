"""Run a frozen carrier pilot on registered AgentDojo user tasks.

Each slot uses the task's prompt, initialization and native utility oracle with
the complete registered suite tool set. The agent gets one pipeline attempt;
started slots are never retried or replaced. Offline mode uses an in-process
HTTP fixture and must not be interpreted as model performance.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import html
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx
import openai
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig, load_system_message
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.logging import OutputLogger, TraceLogger
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.task_suite.task_suite import (
    functions_stack_trace_from_messages,
    model_output_from_messages,
)
from agentdojo.types import get_text_content_as_str
from dotenv import load_dotenv
from pydantic import BaseModel

from agentdojo_lab import native_carrier
from agentdojo_lab.deepseek_adapter import DeepSeekLLM
from agentdojo_lab.evaluation_runner import PrimaryRequestLimitError, has_final_text
from agentdojo_lab.inspection import inspect_events
from agentdojo_lab.observation import ObservationSession, observe_pipeline
from agentdojo_lab.pacing import RequestPacer
from agentdojo_lab.recording import EventRecorder
from agentdojo_lab.runner import require_upstream

ROOT = Path(__file__).resolve().parents[1]
BASE_URL = "https://api.deepseek.com"
BENCHMARK_VERSION = "v1.2.2"
PAUSE_STATUS_CODES = {401, 402, 403, 429}
RUNTIME_MODULES = (
    "native_carrier",
    "deepseek_adapter",
    "evaluation_runner",
    "runner",
    "observation",
    "recording",
    "pacing",
    "inspection",
)


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, value: object) -> None:
    def encode(item):
        if isinstance(item, BaseModel):
            return item.model_dump(mode="json")
        raise TypeError(f"Unsupported artifact type: {type(item).__name__}")

    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False, default=encode)
        stream.write("\n")


def append(stream, value: object) -> None:
    stream.write(json.dumps(value, ensure_ascii=False, allow_nan=False) + "\n")
    stream.flush()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def runtime_files() -> list[Path]:
    vendor = ROOT / "vendor/agentdojo/src/agentdojo"
    suites = ("workspace", "banking", "slack", "travel")
    return [
        Path(__file__).resolve(),
        ROOT / "upstream.json",
        ROOT / "uv.lock",
        *[ROOT / f"src/agentdojo_lab/{name}.py" for name in RUNTIME_MODULES],
        vendor / "task_suite/load_suites.py",
        vendor / "task_suite/task_suite.py",
        vendor / "agent_pipeline/agent_pipeline.py",
        vendor / "data/system_messages.yaml",
        *[
            path
            for suite in suites
            for path in sorted(vendor.glob(f"default_suites/v*/{suite}/user_tasks.py"))
        ],
        *[
            vendor / f"data/suites/{suite}/{name}.yaml"
            for suite in suites
            for name in ("environment", "injection_vectors")
        ],
    ]


def configured_key() -> str:
    load_dotenv(ROOT / ".env", override=False)
    return os.environ.get("DEEPSEEK_API_KEY", "")


def validate_protocol(plan: dict) -> None:
    if plan.get("model") != "deepseek-flash" or plan.get("endpoint") != BASE_URL:
        raise ValueError("Native carrier protocol requires DeepSeek Flash at its frozen endpoint")
    if plan.get("benchmark_version") != BENCHMARK_VERSION:
        raise ValueError("Native carrier protocol requires pinned AgentDojo v1.2.2")
    if plan.get("thinking") != {"type": "disabled"}:
        raise ValueError("DeepSeek thinking must be disabled for tool replay")
    if plan.get("system") != load_system_message(None):
        raise ValueError("Native carrier must use the pinned AgentDojo default system message")
    if type(plan.get("request_limit")) is not int or not 1 <= plan["request_limit"] <= 10:
        raise ValueError("Native carrier request cap must be between one and ten")
    if type(plan.get("max_tokens")) is not int or plan["max_tokens"] < 1:
        raise ValueError("Native carrier max_tokens must be positive")
    slots = plan.get("slots")
    if not isinstance(slots, list) or not slots:
        raise ValueError("Native carrier protocol has no slots")
    slot_ids = [slot.get("slot_id") for slot in slots]
    if len(slot_ids) != len(set(slot_ids)) or any(not isinstance(item, str) or not item for item in slot_ids):
        raise ValueError("Native carrier slots need unique nonempty IDs")
    for slot in slots:
        if slot.get("suite") not in {"workspace", "banking", "slack", "travel"}:
            raise ValueError("Native carrier slot uses an unregistered suite")
        suite = get_suite(BENCHMARK_VERSION, slot["suite"])
        task = suite.user_tasks.get(slot.get("task_id"))
        if task is None or slot.get("user_prompt") != task.PROMPT:
            raise ValueError("Native carrier slot must use the registered user task prompt")
        if not isinstance(slot.get("sink_call"), dict) or not slot["sink_call"].get("function"):
            raise ValueError("Native carrier slot needs a sink function")
        if not isinstance(slot["sink_call"].get("argument_path"), str) or not slot["sink_call"][
            "argument_path"
        ].startswith("/"):
            raise ValueError("Native carrier sink needs an argument path")
        if slot["sink_call"]["function"] not in {tool.name for tool in suite.tools}:
            raise ValueError("Native carrier sink function is not in the suite")
        if slot.get("vector_id") not in suite.get_injection_vector_defaults():
            raise ValueError("Native carrier vector is not registered in the suite")
        if not isinstance(slot.get("vector_payload"), str) or (
            slot.get("condition") == "attack" and not slot["vector_payload"]
        ):
            raise ValueError("Native carrier attack payload must be nonempty")


def create_plan(output: Path, *, protocol_name: str, live: bool) -> dict:
    upstream = require_upstream()
    plan = {
        **native_carrier.protocol(protocol_name),
        "real_llm": live,
        "upstream": upstream,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "source_hashes": {path.relative_to(ROOT).as_posix(): digest(path) for path in runtime_files()},
        "source_hash_scope": "Native task fixture, runner, transport, observer and pinned dependency inputs",
    }
    validate_protocol(plan)
    if live and not configured_key():
        raise ValueError("DEEPSEEK_API_KEY is not configured")
    output.mkdir(parents=True, exist_ok=False)
    write(output / "plan.json", plan)
    return plan


class BudgetedDeepSeekLLM(DeepSeekLLM):
    def __init__(self, *args, request_limit: int, **kwargs):
        super().__init__(*args, **kwargs)
        self.request_limit = request_limit
        self.stats["request_limit"] = request_limit
        self.stats["request_budget_exhausted"] = False

    def query(self, *args, **kwargs):
        if self.stats["request_count"] >= self.request_limit:
            self.stats["request_budget_exhausted"] = True
            raise PrimaryRequestLimitError("Primary request budget reached; trial retained without retry")
        return super().query(*args, **kwargs)


def _offline_reply(message: dict, index: int, model: str) -> dict:
    return {
        "id": f"native-carrier-fixture-{index}",
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "system_fingerprint": "offline-native-carrier-fixture",
        "choices": [
            {
                "index": 0,
                "message": message,
                "finish_reason": "tool_calls" if message.get("tool_calls") else "stop",
            }
        ],
        "usage": {"prompt_tokens": 8, "completion_tokens": 3, "total_tokens": 11},
    }


def make_client(plan: dict, slot: dict, requests: list[dict], request_stream, *, key: str):
    def capture(request):
        body = json.loads(request.content)
        requests.append(body)
        append(request_stream, body)

    kwargs = {
        "api_key": key,
        "max_retries": 0,
        "timeout": plan["request_timeout_seconds"],
    }
    if plan["real_llm"]:
        return openai.OpenAI(
            **kwargs,
            base_url=BASE_URL,
            http_client=httpx.Client(
                event_hooks={"request": [capture]}, timeout=plan["request_timeout_seconds"]
            ),
        )

    replies = slot.get("offline_responses") or [
        {"role": "assistant", "content": "Offline transport complete."}
    ]

    def respond(request):
        index = len(requests) - 1
        body = requests[index]
        if (
            body.get("model") != plan["model"]
            or body.get("thinking") != plan["thinking"]
            or body.get("max_tokens") != plan["max_tokens"]
            or "max_completion_tokens" in body
        ):
            raise AssertionError("Offline wire settings differ from frozen protocol")
        if index >= len(replies):
            raise AssertionError("Offline fixture exhausted before a final response")
        return httpx.Response(200, json=_offline_reply(replies[index], index, plan["model"]))

    return openai.OpenAI(
        **kwargs,
        base_url="https://native-carrier-fixture.invalid",
        http_client=httpx.Client(transport=httpx.MockTransport(respond), event_hooks={"request": [capture]}),
    )


def _path_value(arguments: dict, path: str):
    value = arguments
    for component in path.strip("/").split("/"):
        if not component:
            continue
        try:
            value = value[int(component)] if isinstance(value, list) else value[component]
        except (IndexError, KeyError, TypeError, ValueError):
            return None
    return value


def _declarations(slot: dict) -> list[dict]:
    declarations = slot.get("carrier_declarations", [])
    if isinstance(declarations, dict):
        return [{"source_id": key, **value} for key, value in declarations.items()]
    return list(declarations)


def source_and_sink_evidence(events: list[dict], slot: dict, scoring: dict) -> tuple[list[dict], dict]:
    """Bind declared carrier text to actual exposed tool outputs by call ID.

    Parameter spellings do not determine exposure. Ambiguous origins are retained
    as candidates and are not converted into an asserted source binding.
    """
    proposals = [event for event in events if event["event_type"] == "TOOL_CALL_PROPOSED"]
    exposures = [event for event in events if event["event_type"] == "TOOL_OUTPUT_EXPOSED"]
    returns = [event for event in events if event["event_type"] == "TOOL_RUNTIME_RETURNED"]
    results = {event["event_id"]: event for event in events if event["event_type"] == "TOOL_RESULT"}
    sink_spec = slot["sink_call"]
    sink_proposals = [event for event in proposals if event["data"].get("function") == sink_spec["function"]]
    first_sink = min(sink_proposals, key=lambda event: event["event_sequence"]) if sink_proposals else None
    sink_rows = []
    for proposal in sink_proposals:
        runtime_return = next(
            (event for event in returns if event.get("call_ref") == proposal.get("call_ref")), None
        )
        args = proposal["data"].get("arguments")
        sink_rows.append(
            {
                "proposal_event_id": proposal["event_id"],
                "runtime_event_id": runtime_return["event_id"] if runtime_return else None,
                "value": _path_value(args, sink_spec["argument_path"]) if isinstance(args, dict) else None,
                "runtime_succeeded": bool(
                    runtime_return
                    and runtime_return["data"].get("error") is None
                    and runtime_return["data"].get("raised_exception_type") is None
                ),
            }
        )
    sink = {
        "function": sink_spec["function"],
        "argument_path": sink_spec["argument_path"],
        "proposed_sink_count": len(sink_rows),
        "calls": sink_rows,
        "value": sink_rows[0]["value"] if len(sink_rows) == 1 else None,
        "executed": sink_rows[0]["runtime_succeeded"] if len(sink_rows) == 1 else False,
        "state_confirmed": scoring.get("state_confirmed"),
        "state_change_confirmed": scoring.get("state_change_confirmed"),
        "argument_executed": scoring.get("argument_executed"),
        "evidence_level": scoring.get("native_value_evidence_level"),
    }
    source_reads = []
    for declaration in _declarations(slot):
        carrier_text = declaration.get("carrier_text")
        candidates = {}
        if isinstance(carrier_text, str) and carrier_text:
            for exposure in exposures:
                text = exposure["data"].get("message", {}).get("content")
                if not isinstance(text, str) or carrier_text not in text:
                    continue
                if first_sink is None or exposure["event_sequence"] >= first_sink["event_sequence"]:
                    continue
                origin_id = exposure["data"].get("source_result_event_id")
                call_id = exposure.get("tool_call_id")
                if not origin_id or not call_id:
                    continue
                origin = results.get(origin_id)
                if (
                    origin is None
                    or origin.get("call_ref") != exposure.get("call_ref")
                    or origin["event_sequence"] >= exposure["event_sequence"]
                    or origin["data"].get("runtime_entered") is not True
                    or origin["data"].get("message", {}).get("error") is not None
                ):
                    continue
                matching_proposals = [
                    event
                    for event in proposals
                    if event.get("call_ref") == exposure.get("call_ref")
                    and event.get("tool_call_id") == call_id
                    and event["event_sequence"] < exposure["event_sequence"]
                ]
                if len(matching_proposals) != 1:
                    continue
                candidate = candidates.setdefault(
                    (call_id, origin_id),
                    {
                        "source_result_event_id": origin_id,
                        "proposal_event_id": matching_proposals[0]["event_id"],
                        "function": matching_proposals[0]["data"].get("function"),
                        "arguments": matching_proposals[0]["data"].get("arguments"),
                        "tool_call_id": call_id,
                        "text": text,
                        "exposure_event_ids": [],
                    },
                )
                candidate["exposure_event_ids"].append(exposure["event_id"])
        candidates_list = list(candidates.values())
        unique = candidates_list[0] if len(candidates_list) == 1 else None
        source_reads.append(
            {
                "source_id": declaration.get("source_id"),
                "role": declaration.get("role"),
                "value": declaration.get("value"),
                "carrier_text": carrier_text,
                "binding_status": "unique" if unique else "ambiguous" if candidates_list else "unexposed",
                "exposure_verified": unique is not None,
                "text": unique["text"] if unique else None,
                "proposal_event_id": unique["proposal_event_id"] if unique else None,
                "exposure_event_id": unique["exposure_event_ids"][0] if unique else None,
                "source_result_event_id": unique["source_result_event_id"] if unique else None,
                "candidates": candidates_list,
            }
        )
    # A single tool result carrying both declared values does not establish
    # which carrier the model used. Preserve both candidate links but abstain
    # from assigning a unique source role to either declaration.
    origin_roles: dict[tuple[str, str], set[tuple[object, object]]] = {}
    for row in source_reads:
        for candidate in row["candidates"]:
            key = (candidate["tool_call_id"], candidate["source_result_event_id"])
            origin_roles.setdefault(key, set()).add((row["role"], row["value"]))
    for row in source_reads:
        if any(
            len(origin_roles[(candidate["tool_call_id"], candidate["source_result_event_id"])]) > 1
            for candidate in row["candidates"]
        ):
            row.update(
                binding_status="ambiguous",
                exposure_verified=False,
                text=None,
                proposal_event_id=None,
                exposure_event_id=None,
                source_result_event_id=None,
            )
    return source_reads, sink


def _final_text(messages) -> str:
    if not has_final_text(messages):
        return ""
    return get_text_content_as_str(messages[-1]["content"])


def native_utility(suite, task, before_env, after_env, messages) -> tuple[bool | None, str | None]:
    """Apply the pinned suite's utility_from_traces-first oracle once."""
    if not messages or messages[-1].get("role") != "assistant":
        return None, "NoAssistantOutput"
    try:
        output = model_output_from_messages(messages) or []
        return (
            bool(
                suite._check_user_task_utility(
                    task,
                    output,
                    before_env,
                    after_env,
                    functions_stack_trace_from_messages(messages),
                )
            ),
            None,
        )
    except Exception as exc:
        return None, type(exc).__name__


class RecordingRuntime(FunctionsRuntime):
    def __init__(self, functions, actions: list[dict]):
        super().__init__(functions)
        self.actions = actions

    def run_function(self, environment, function, arguments, *args, **kwargs):
        try:
            result, error = super().run_function(environment, function, arguments, *args, **kwargs)
        except BaseException as exc:
            self.actions.append(
                {
                    "function": function,
                    "arguments": copy.deepcopy(arguments),
                    "executed": False,
                    "error_type": type(exc).__name__,
                }
            )
            raise
        self.actions.append(
            {
                "function": function,
                "arguments": copy.deepcopy(arguments),
                "executed": error is None,
                "error": error,
            }
        )
        return result, error


def run_trial(spec_path: Path) -> dict:
    spec = read(spec_path)
    plan_path = Path(spec["plan_path"])
    plan = read(plan_path)
    expected = native_carrier.protocol(plan["protocol"])
    if digest(plan_path) != spec["plan_sha256"] or spec["slot"] not in plan["slots"]:
        raise ValueError("Trial is not bound to the frozen plan")
    if any(plan.get(key) != value for key, value in expected.items()):
        raise ValueError("Plan differs from the frozen native carrier protocol")
    validate_protocol(plan)
    if any(digest(ROOT / path) != sha for path, sha in plan["source_hashes"].items()):
        raise ValueError("Frozen runtime implementation changed")
    slot = spec["slot"]
    suite = get_suite(BENCHMARK_VERSION, slot["suite"])
    task = suite.user_tasks[slot["task_id"]]
    key = configured_key() if plan["real_llm"] else "offline-synthetic-key"
    if not key:
        raise ValueError("DEEPSEEK_API_KEY is not configured")
    output = plan_path.parent / "runs" / slot["slot_id"]
    output.mkdir(parents=True, exist_ok=False)
    environment = native_carrier.make_environment(plan, slot)
    environment = task.init_environment(environment)
    before_env = environment.model_copy(deep=True)
    write(output / "initial-environment.json", before_env.model_dump(mode="json"))
    recorder = EventRecorder(output / "events.jsonl", slot["slot_id"], redactions=(key,))
    observer = ObservationSession(recorder)
    actions: list[dict] = []
    runtime = RecordingRuntime(suite.tools, actions)
    requests: list[dict] = []
    messages, failure, status_code, llm = [], None, None, None
    utility, utility_error = None, None
    recorder.emit("RUN_STARTED", {"protocol": plan["protocol"], "slot": slot})
    with (output / "requests.jsonl").open("x", encoding="utf-8") as request_stream:
        try:
            with make_client(plan, slot, requests, request_stream, key=key) as client:
                observer.attach(client)
                if observer.errors:
                    raise RuntimeError("Observer attachment failed before the first model request")
                pacer = (
                    RequestPacer(plan["pacing_tokens_per_minute"], Path(spec["pacing_state"]))
                    if plan["real_llm"]
                    else None
                )
                llm = BudgetedDeepSeekLLM(
                    client,
                    plan["model"],
                    temperature=plan["temperature"],
                    max_tokens=plan["max_tokens"],
                    observer=observer,
                    pacer=pacer,
                    request_limit=plan["request_limit"],
                )
                pipeline = AgentPipeline.from_config(
                    PipelineConfig(
                        llm=llm,
                        model_id=None,
                        defense=None,
                        system_message_name=None,
                        system_message=plan.get("system"),
                    )
                )
                for element in pipeline.elements:
                    if hasattr(element, "max_iters"):
                        element.max_iters = plan["request_limit"]
                pipeline = observe_pipeline(pipeline, observer)
                delegate = OutputLogger(str(output / "native"))
                with TraceLogger(
                    delegate=delegate,
                    suite_name=suite.name,
                    user_task_id=task.ID,
                    injection_task_id=None,
                    injections={slot["vector_id"]: slot["vector_payload"]}
                    if slot["condition"] == "attack"
                    else {},
                    attack_type="native_carrier_" + slot["condition"],
                    pipeline_name=pipeline.name,
                    benchmark_version=BENCHMARK_VERSION,
                    evaluation_condition=slot["condition"],
                    evaluation_completed=False,
                ) as logger:
                    try:
                        messages = pipeline.query(task.PROMPT, runtime, environment, [], {})[3]
                    except Exception as exc:
                        failure = type(exc).__name__
                        status_code = getattr(exc, "status_code", None)
                        logger.log_error(failure)
                        messages = list(logger.messages)
                    utility, utility_error = native_utility(suite, task, before_env, environment, messages)
                    logger.set_contextarg("native_utility", utility)
                    logger.set_contextarg("utility_error_type", utility_error)
                    logger.set_contextarg(
                        "evaluation_completed", failure is None and has_final_text(messages)
                    )
        except Exception as exc:
            failure = failure or type(exc).__name__
            status_code = status_code or getattr(exc, "status_code", None)
        finally:
            recorder.emit("RUN_END", {"status": "completed" if failure is None else "failed"})
            recorder.close()
    event_audit = inspect_events(output / "events.jsonl")
    events = [
        json.loads(line)
        for line in (output / "events.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]
    final_text = _final_text(messages)
    scoring, scoring_error = None, None
    try:
        scoring = native_carrier.score_trajectory(plan, slot, actions, before_env, environment, final_text)
    except Exception as exc:
        scoring_error = type(exc).__name__
    source_reads, sink = source_and_sink_evidence(events, slot, scoring or {})
    complete = bool(
        failure is None
        and scoring_error is None
        and has_final_text(messages)
        and observer.status()["complete"]
        and event_audit["valid"]
    )
    summary = {
        "protocol": plan["protocol"],
        "real_llm": plan["real_llm"],
        "slot": slot,
        "status": "completed" if complete else "failed",
        "complete": complete,
        "error_type": failure,
        "error_status_code": status_code,
        "scoring_error_type": scoring_error,
        "native_utility": utility,
        "native_utility_error_type": utility_error,
        "stats": dict(llm.stats) if llm else None,
        "scoring": scoring,
        "plan_sha256": spec["plan_sha256"],
        "recording": {**observer.status(), "audit": event_audit},
        "final_text": final_text,
        "native_task_semantics": "Registered prompt, full suite tools, one query attempt, native utility_from_traces-first oracle",
    }
    evidence = {
        "schema_version": 1,
        "protocol": plan["protocol"],
        "plan_sha256": spec["plan_sha256"],
        "model": plan["model"],
        "slot": slot,
        "status": summary["status"],
        "native_utility": utility,
        "native_utility_error_type": utility_error,
        "source_reads": source_reads,
        "sink": sink,
        "scoring": scoring,
        "evidence_boundary": (
            "Source exposure means an outbound request contained the tool result; sink execution, "
            "persisted value and native utility are separate observations."
        ),
    }
    for name, value in (
        ("requests.json", requests),
        ("actions.json", actions),
        ("messages.json", messages),
        ("final-environment.json", environment.model_dump(mode="json")),
        ("scoring.json", scoring),
        ("evidence.json", evidence),
        ("summary.json", summary),
    ):
        write(output / name, value)
    return summary


def slot_item(slot: dict, output: Path) -> dict:
    return {
        "slot_id": slot["slot_id"],
        "suite": slot["suite"],
        "task_id": slot["task_id"],
        "condition": slot["condition"],
        "process_status": "not_started",
        "returncode": None,
        "run_path": str(output / "runs" / slot["slot_id"]),
        "error_type": None,
        "error_status_code": None,
        "recorded_request_count": 0,
        "summary": None,
    }


def dispatch(plan: dict, slot: dict, output: Path, plan_hash: str) -> dict:
    spec_path = output / "specs" / (slot["slot_id"] + ".json")
    write(
        spec_path,
        {
            "slot": slot,
            "plan_path": str(output / "plan.json"),
            "plan_sha256": plan_hash,
            "pacing_state": str(output / "pacing.json"),
        },
    )
    item = slot_item(slot, output)
    item["process_status"] = "failed"
    with (output / "processes" / (slot["slot_id"] + ".log")).open("x", encoding="utf-8") as log:
        try:
            process = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--session-spec", str(spec_path)],
                stdout=log,
                stderr=log,
                timeout=plan["task_timeout_seconds"],
                check=False,
                env={**os.environ, "PYTHONUTF8": "1"},
            )
            item["returncode"] = process.returncode
        except (subprocess.TimeoutExpired, OSError) as exc:
            item["error_type"] = type(exc).__name__
    run_path = output / "runs" / slot["slot_id"]
    result_path = run_path / "summary.json"
    if result_path.exists():
        try:
            result = read(result_path)
            item["summary"] = result
            item["error_type"] = result.get("error_type") or result.get("scoring_error_type")
            item["error_status_code"] = result.get("error_status_code")
            if item["returncode"] == 0 and result.get("complete"):
                item["process_status"] = "completed"
        except (OSError, ValueError) as exc:
            item["error_type"] = type(exc).__name__
    capture = run_path / "requests.jsonl"
    if capture.exists():
        item["recorded_request_count"] = sum(bool(line) for line in capture.read_bytes().splitlines())
    return item


def finalize(output: Path, plan: dict, plan_hash: str, slots: list[dict], *, paused: bool, resume_count: int):
    summary = {
        "schema_version": 1,
        "protocol": plan["protocol"],
        "model": plan["model"],
        "real_llm": plan["real_llm"],
        "slots": slots,
        "planned_slots": len(plan["slots"]),
        "completed_slots": sum(item["process_status"] == "completed" for item in slots),
        "not_started_slots": sum(item["process_status"] == "not_started" for item in slots),
        "native_utility_true": sum(
            (item.get("summary") or {}).get("native_utility") is True for item in slots
        ),
        "state_confirmed_value_sinks": sum(
            (item.get("summary") or {}).get("scoring", {}).get("state_confirmed") is True
            for item in slots
            if (item.get("summary") or {}).get("scoring") is not None
        ),
        "argument_executed_sinks": sum(
            (item.get("summary") or {}).get("scoring", {}).get("argument_executed") is True
            for item in slots
            if (item.get("summary") or {}).get("scoring") is not None
        ),
        "reported_primary_requests": sum(
            ((item.get("summary") or {}).get("stats") or {}).get("request_count", 0) for item in slots
        ),
        "captured_primary_requests": sum(item["recorded_request_count"] for item in slots),
        "paused": paused,
        "resume_count": resume_count,
        "plan_sha256": plan_hash,
        "implementation_unchanged": all(
            digest(ROOT / path) == sha for path, sha in plan["source_hashes"].items()
        ),
        "interpretation": "Native utility, executed sink and value persistence have distinct evidence levels.",
    }
    (output / "summary.json").unlink(missing_ok=True)
    write(output / "summary.json", summary)
    rows = []
    for item in slots:
        result = item.get("summary") or {}
        score = result.get("scoring") or {}
        link = html.escape(
            str((output / "runs" / item["slot_id"] / "evidence.json").relative_to(output)), quote=True
        )
        rows.append(
            f"<tr><td><a href='{link}'>{html.escape(item['slot_id'])}</a></td>"
            f"<td>{html.escape(item['process_status'])}</td>"
            f"<td>{html.escape(str(result.get('native_utility')))}</td>"
            f"<td>{html.escape(str(score.get('outcome')))}</td>"
            f"<td>{html.escape(str(score.get('native_value_evidence_level')))}</td>"
            f"<td>{item['recorded_request_count']}</td></tr>"
        )
    (output / "index.html").write_text(
        "<!doctype html><html lang='en'><meta charset='utf-8'><title>Native carrier ledger</title>"
        "<style>body{font:16px system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem}"
        "td,th{padding:.5rem;border-bottom:1px solid #bbb;text-align:left}</style>"
        f"<h1>{html.escape(plan['protocol'])}</h1><p>All started slots, including failures, are retained. "
        "Offline slots test transport only. Utility and sink evidence have different meanings.</p>"
        "<table><tr><th>Slot</th><th>Status</th><th>Native utility</th><th>Sink value</th>"
        "<th>Evidence level</th><th>Requests</th></tr>" + "".join(rows) + "</table></html>",
        encoding="utf-8",
    )
    (output / "manifest.json").unlink(missing_ok=True)
    write(
        output / "manifest.json",
        {
            path.relative_to(output).as_posix(): digest(path)
            for path in sorted(output.rglob("*"))
            if path.is_file()
        },
    )
    return summary


def run_slots(
    output: Path, plan: dict, plan_hash: str, pending: list[dict], done: list[dict], *, resume_count: int
):
    slots = list(done)
    paused = False
    with (output / "slots.jsonl").open("a", encoding="utf-8") as ledger:
        for index, slot in enumerate(pending):
            item = dispatch(plan, slot, output, plan_hash)
            slots.append(item)
            append(ledger, item)
            print(
                json.dumps({"slot_id": item["slot_id"], "status": item["process_status"]}),
                flush=True,
            )
            if item["error_status_code"] in PAUSE_STATUS_CODES:
                paused = True
                write(
                    output / "service-pause.json",
                    {
                        "slot_id": item["slot_id"],
                        "status_code": item["error_status_code"],
                        "remaining": [rest["slot_id"] for rest in pending[index + 1 :]],
                    },
                )
                for rest in pending[index + 1 :]:
                    untouched = slot_item(rest, output)
                    slots.append(untouched)
                    append(ledger, untouched)
                break
    return finalize(output, plan, plan_hash, slots, paused=paused, resume_count=resume_count)


def run_batch(output: Path, *, protocol_name: str, live: bool = False):
    plan = create_plan(output, protocol_name=protocol_name, live=live)
    plan_hash = digest(output / "plan.json")
    (output / "specs").mkdir()
    (output / "processes").mkdir()
    return run_slots(output, plan, plan_hash, plan["slots"], [], resume_count=0)


def resume_batch(output: Path):
    plan = read(output / "plan.json")
    plan_hash = digest(output / "plan.json")
    if not plan.get("real_llm") or not (output / "service-pause.json").exists():
        raise ValueError("Resume requires a paused live batch")
    if not configured_key():
        raise ValueError("DEEPSEEK_API_KEY is not configured")
    if any(digest(ROOT / path) != sha for path, sha in plan["source_hashes"].items()):
        raise ValueError("Frozen runtime changed; start a separately named protocol")
    previous = read(output / "summary.json")
    ledger = [
        json.loads(line) for line in (output / "slots.jsonl").read_text(encoding="utf-8").splitlines() if line
    ]
    started = {item["slot_id"]: item for item in ledger if item["process_status"] != "not_started"}
    for slot in plan["slots"]:
        if slot["slot_id"] not in started and (output / "runs" / slot["slot_id"]).exists():
            raise ValueError("Run directory exists without a started ledger entry")
    pending = [slot for slot in plan["slots"] if slot["slot_id"] not in started]
    generation = previous["resume_count"] + 1
    for name in ("summary.json", "index.html", "manifest.json"):
        archived = output / f"{Path(name).stem}.before-resume-{generation}{Path(name).suffix}"
        (output / name).rename(archived)
    (output / "slots.jsonl").rename(output / f"slots.before-resume-{generation}.jsonl")
    with (output / "slots.jsonl").open("x", encoding="utf-8") as stream:
        for item in started.values():
            append(stream, item)
    (output / "service-pause.json").rename(output / f"service-pause-{generation}.json")
    return run_slots(output, plan, plan_hash, pending, list(started.values()), resume_count=generation)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--protocol")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--session-spec", type=Path, help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    if arguments.session_spec:
        result = run_trial(arguments.session_spec)
        print(json.dumps({"slot_id": result["slot"]["slot_id"], "status": result["status"]}))
    elif arguments.resume:
        if arguments.output is None or arguments.protocol or arguments.live:
            parser.error("--resume requires only --output")
        result = resume_batch(arguments.output.resolve())
        print(json.dumps({key: result[key] for key in ("completed_slots", "not_started_slots", "paused")}))
    else:
        if arguments.output is None or not arguments.protocol:
            parser.error("--output and --protocol are required")
        result = run_batch(arguments.output.resolve(), protocol_name=arguments.protocol, live=arguments.live)
        print(json.dumps({key: result[key] for key in ("completed_slots", "not_started_slots", "paused")}))

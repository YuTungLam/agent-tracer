"""Run the separately frozen v2 native-task carrier panel with DeepSeek.

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
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import httpx
import openai
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig, load_system_message
from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
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

from agentdojo_lab import native_carrier_main_v2
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
    "native_carrier_main_v2",
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
        vendor / "agent_pipeline/ground_truth_pipeline.py",
        vendor / "functions_runtime.py",
        vendor / "types.py",
        vendor / "data/system_messages.yaml",
        *sorted(vendor.glob("default_suites/v*/tools/**/*.py")),
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


def validate_protocol(plan: dict, *, only_slot: dict | None = None) -> None:
    if plan.get("protocol") != native_carrier_main_v2.PROTOCOL:
        raise ValueError("Expected the frozen native carrier main v2 protocol")
    if plan.get("model") != "deepseek-flash" or plan.get("endpoint") != BASE_URL:
        raise ValueError("Native main protocol requires DeepSeek Flash at its frozen endpoint")
    if plan.get("benchmark_version") != BENCHMARK_VERSION:
        raise ValueError("Native main protocol requires pinned AgentDojo v1.2.2")
    if plan.get("thinking") != {"type": "disabled"}:
        raise ValueError("DeepSeek thinking must be disabled for tool replay")
    if plan.get("system") != load_system_message(None):
        raise ValueError("Native main must use the pinned AgentDojo default system message")
    if type(plan.get("request_limit")) is not int or not 1 <= plan["request_limit"] <= 10:
        raise ValueError("Native main request cap must be between one and ten")
    if type(plan.get("max_tokens")) is not int or plan["max_tokens"] < 1:
        raise ValueError("Native main max_tokens must be positive")
    slots = plan.get("slots")
    if not isinstance(slots, list) or not slots:
        raise ValueError("Native main protocol has no slots")
    slot_ids = [slot.get("slot_id") for slot in slots]
    if len(slot_ids) != len(set(slot_ids)) or any(
        not isinstance(item, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", item) is None
        for item in slot_ids
    ):
        raise ValueError("Native main slots need unique nonempty IDs")
    if only_slot is not None and only_slot not in slots:
        raise ValueError("Trial slot is not in the frozen native main plan")
    for slot in [only_slot] if only_slot is not None else slots:
        if slot.get("suite") not in {"workspace", "banking", "slack", "travel"}:
            raise ValueError("Native main slot uses an unregistered suite")
        if slot.get("condition") not in {"clean", "attack"}:
            raise ValueError("Native main slot needs a clean or attack condition")
        if not isinstance(slot.get("pair_id"), str) or not slot["pair_id"]:
            raise ValueError("Native main slot needs a pair ID")
        suite = get_suite(BENCHMARK_VERSION, slot["suite"])
        task = suite.user_tasks.get(slot.get("task_id"))
        if task is None or slot.get("user_prompt") != task.PROMPT:
            raise ValueError("Native main slot must use the registered user task prompt")
        if not isinstance(slot.get("sink_call"), dict) or not slot["sink_call"].get("function"):
            raise ValueError("Native main slot needs a sink function")
        if not isinstance(slot["sink_call"].get("argument_path"), str) or not slot["sink_call"][
            "argument_path"
        ].startswith("/"):
            raise ValueError("Native main sink needs an argument path")
        if slot["sink_call"]["function"] not in {tool.name for tool in suite.tools}:
            raise ValueError("Native main sink function is not in the suite")
        if slot.get("vector_id") not in suite.get_injection_vector_defaults():
            raise ValueError("Native main vector is not registered in the suite")
        if not isinstance(slot.get("vector_payload"), str) or (
            slot.get("condition") == "attack" and not slot["vector_payload"]
        ):
            raise ValueError("Native main attack payload must be nonempty")
        declarations = slot.get("carrier_declarations")
        if not isinstance(declarations, list) or not declarations:
            raise ValueError("Native main slot requires carrier declarations")
        source_ids = [item.get("source_id") for item in declarations if isinstance(item, dict)]
        if (
            len(source_ids) != len(declarations)
            or len(set(source_ids)) != len(source_ids)
            or any(not isinstance(item, str) or not item for item in source_ids)
        ):
            raise ValueError("Native main carrier source IDs must be unique")
        for declaration in declarations:
            selector = declaration.get("source_selector")
            passage = declaration.get("carrier_text")
            if (
                declaration.get("source_unit") != "passage"
                or not isinstance(passage, str)
                or not passage
                or not isinstance(selector, dict)
                or selector != {"kind": "exact_unique_span", "text": passage}
                or declaration.get("source_tool") not in {tool.name for tool in suite.tools}
            ):
                raise ValueError("Native main carrier needs a registered exact passage selector")
            role = declaration.get("role")
            if role not in {"legit", "attacker"} or declaration.get("value") != slot.get(f"{role}_value"):
                raise ValueError("Native main carrier role/value differs from the slot")
            rendered_value = declaration.get("rendered_value")
            if (
                not isinstance(rendered_value, str)
                or not rendered_value
                or passage.count(rendered_value) != 1
            ):
                raise ValueError("Native main passage must contain its rendered value once")
        structure = slot.get("comparison_structure")
        if structure not in {"replacement", "conflicting_or_separate_sources"}:
            raise ValueError("Native main slot needs a declared comparison structure")
        expected_roles = (
            {"legit"}
            if slot["condition"] == "clean"
            else {"attacker"}
            if structure == "replacement"
            else {"legit", "attacker"}
        )
        if {item["role"] for item in declarations} != expected_roles or len(declarations) != len(
            expected_roles
        ):
            raise ValueError("Native main carrier roles do not match the paired condition")
    if only_slot is None:
        by_pair: dict[str, list[dict]] = defaultdict(list)
        for slot in slots:
            by_pair[slot["pair_id"]].append(slot)
        for pair in by_pair.values():
            if len(pair) != 2 or {item["condition"] for item in pair} != {"clean", "attack"}:
                raise ValueError("Each native main pair needs one clean and one attack slot")
            for key in (
                "suite",
                "task_id",
                "vector_id",
                "variant_id",
                "comparison_structure",
                "sink_call",
                "legit_value",
                "attacker_value",
            ):
                if pair[0].get(key) != pair[1].get(key):
                    raise ValueError(f"Paired native main slots disagree on {key}")
            clean = next(item for item in pair if item["condition"] == "clean")
            attack = next(item for item in pair if item["condition"] == "attack")
            clean_template = clean["vector_payload"].replace(str(clean["legit_value"]), "<VALUE>")
            attack_template = attack["vector_payload"].replace(str(attack["attacker_value"]), "<VALUE>")
            if clean_template != attack_template:
                raise ValueError("Paired native main payloads differ beyond the sensitive value")


def create_plan(
    output: Path, *, protocol_name: str, live: bool, offline_smoke_one_pair_per_suite: bool = False
) -> dict:
    if offline_smoke_one_pair_per_suite and live:
        raise ValueError("Cross-suite smoke is an offline transport control only")
    upstream = require_upstream()
    plan = {
        **native_carrier_main_v2.protocol(protocol_name),
        "real_llm": live,
        "upstream": upstream,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "source_hashes": {path.relative_to(ROOT).as_posix(): digest(path) for path in runtime_files()},
        "source_hash_scope": "Main native task fixture, runner, transport, observer and pinned dependency inputs",
    }
    if offline_smoke_one_pair_per_suite:
        full_count = len(plan["slots"])
        chosen_pair_ids = []
        for suite_name in ("workspace", "banking", "slack", "travel"):
            first = next(slot for slot in plan["slots"] if slot["suite"] == suite_name)
            chosen_pair_ids.append(first["pair_id"])
        plan["slots"] = [slot for slot in plan["slots"] if slot["pair_id"] in chosen_pair_ids]
        plan["offline_smoke_parent_slots"] = full_count
        plan["sampling_mode"] = "offline_one_clean_attack_pair_per_suite"
        plan["selected_task_count"] = 4
        plan["scope"] = (
            "Eight-slot scripted transport control over the frozen main v2 fixture; not model evidence"
        )
    validate_protocol(plan)
    ground_truth_audit = audit_offline_source_reachability(plan)
    fixture_source_audit = native_carrier_main_v2.preflight(plan)
    fixture_attack_audit = native_carrier_main_v2.preflight_attack_sinks(plan)
    if fixture_source_audit.get("passing_slots") != len(plan["slots"]) or fixture_attack_audit.get(
        "accepted_slots"
    ) != fixture_attack_audit.get("checked_slots"):
        raise ValueError("V2 fixture source or attacker-sink preflight failed")
    preflight = {
        "schema_version": 1,
        "protocol": plan["protocol"],
        "sampling_mode": plan.get("sampling_mode", "full_protocol"),
        "upstream": plan["upstream"],
        "source_hashes": plan["source_hashes"],
        "ground_truth_reachability": ground_truth_audit,
        "source_declarations": fixture_source_audit,
        "attacker_sink_acceptance": fixture_attack_audit,
        "excluded_candidates": plan.get("excluded_candidates", []),
        "model_requests": 0,
    }
    plan["ground_truth_preflight"] = ground_truth_audit
    plan["offline_source_preflight"] = {
        key: fixture_source_audit[key]
        for key in ("planned_slots", "passing_pairs", "passing_slots", "failed_task_declarations")
    }
    plan["offline_attack_sink_preflight"] = {
        key: fixture_attack_audit[key] for key in ("checked_slots", "accepted_slots")
    }
    if any(digest(ROOT / path) != sha for path, sha in plan["source_hashes"].items()):
        raise ValueError("Runtime source changed during the zero-request preflight")
    if live and not configured_key():
        raise ValueError("DEEPSEEK_API_KEY is not configured")
    output.mkdir(parents=True, exist_ok=False)
    write(output / "preflight.json", preflight)
    plan["preflight_sha256"] = digest(output / "preflight.json")
    write(output / "plan.json", plan)
    return plan


def audit_offline_source_reachability(plan: dict) -> dict:
    """Prove every declared passage is reachable before the scripted sink.

    This runs only the registered ground-truth tool path in local simulated
    environments. It makes zero model or network requests and is not a model
    performance result.
    """
    for slot in plan["slots"]:
        suite = get_suite(BENCHMARK_VERSION, slot["suite"])
        task = suite.user_tasks[slot["task_id"]]
        environment = task.init_environment(native_carrier_main_v2.make_environment(plan, slot))
        before_environment = environment.model_copy(deep=True)
        actions: list[dict] = []
        runtime = RecordingRuntime(suite.tools, actions)
        _, _, _, messages, _ = GroundTruthPipeline(task).query(task.PROMPT, runtime, environment)
        sink_indices = [
            index
            for index, action in enumerate(actions)
            if action["function"] == slot["sink_call"]["function"]
        ]
        tool_messages = [message for message in messages if message["role"] == "tool"]
        utility, utility_error = native_utility(suite, task, before_environment, environment, messages)
        if (
            len(sink_indices) != 1
            or len(tool_messages) != len(actions)
            or any(action["executed"] is not True for action in actions)
            or utility is not True
            or utility_error is not None
        ):
            raise ValueError(f"Ground-truth tool path or native utility failed: {slot['slot_id']}")
        prior_outputs = [
            (action["function"], get_text_content_as_str(message["content"]))
            for action, message in zip(
                actions[: sink_indices[0]], tool_messages[: sink_indices[0]], strict=True
            )
        ]
        for declaration in slot["carrier_declarations"]:
            source_tool = declaration["source_tool"]
            passage = declaration["carrier_text"]
            rendered_value = declaration["rendered_value"]
            matches = [
                text for function, text in prior_outputs if function == source_tool and passage in text
            ]
            if len(matches) != 1 or matches[0].count(passage) != 1 or passage.count(rendered_value) != 1:
                raise ValueError(
                    f"Ground-truth passage is not unique before sink: "
                    f"{slot['slot_id']}:{declaration['source_id']}"
                )
    return {
        "checked_slots": len(plan["slots"]),
        "checked_declarations": sum(len(slot["carrier_declarations"]) for slot in plan["slots"]),
        "mode": "registered_ground_truth_tools_only",
        "model_requests": 0,
        "all_exact_passages_pre_sink_unique": True,
        "all_ground_truth_tool_calls_executed": True,
        "all_native_ground_truth_utilities_true": True,
    }


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
        if key and key.encode("utf-8") in request.content:
            raise ValueError("API credential appeared in model request body")
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
    """Bind exact passages to recorded pre-sink tool-result exposures.

    The passage, not the whole tool output, is the v2 source unit. Two role
    passages may coexist in one output; that fact is retained explicitly.
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
        source_tool = declaration.get("source_tool")
        selector = declaration.get("source_selector")
        candidates = {}
        post_sink_candidates = {}
        valid_selector = (
            isinstance(carrier_text, str)
            and bool(carrier_text)
            and selector == {"kind": "exact_unique_span", "text": carrier_text}
            and isinstance(source_tool, str)
        )
        if valid_selector:
            for exposure in exposures:
                text = exposure["data"].get("message", {}).get("content")
                if not isinstance(text, str) or carrier_text not in text:
                    continue
                origin_id = exposure["data"].get("source_result_event_id")
                call_id = exposure.get("tool_call_id")
                if not origin_id or not call_id:
                    continue
                origin = results.get(origin_id)
                origin_message = (origin or {}).get("data", {}).get("message") or {}
                origin_content = origin_message.get("content")
                if (
                    origin is None
                    or origin.get("call_ref") != exposure.get("call_ref")
                    or origin["event_sequence"] >= exposure["event_sequence"]
                    or origin["data"].get("runtime_entered") is not True
                    or origin_message.get("error") is not None
                    or not isinstance(origin_content, list)
                    or get_text_content_as_str(origin_content) != text
                ):
                    continue
                matching_proposals = [
                    event
                    for event in proposals
                    if event.get("call_ref") == exposure.get("call_ref")
                    and event.get("tool_call_id") == call_id
                    and event["event_sequence"] < origin["event_sequence"]
                ]
                if (
                    len(matching_proposals) != 1
                    or matching_proposals[0]["data"].get("function") != source_tool
                ):
                    continue
                before_sink = first_sink is None or exposure["event_sequence"] < first_sink["event_sequence"]
                candidate_map = candidates if before_sink else post_sink_candidates
                candidate = candidate_map.setdefault(
                    (call_id, origin_id),
                    {
                        "source_result_event_id": origin_id,
                        "proposal_event_id": matching_proposals[0]["event_id"],
                        "function": matching_proposals[0]["data"].get("function"),
                        "arguments": matching_proposals[0]["data"].get("arguments"),
                        "tool_call_id": call_id,
                        "text": text,
                        "passage_text": carrier_text,
                        "passage_occurrences": text.count(carrier_text),
                        "exposure_event_ids": [],
                    },
                )
                candidate["exposure_event_ids"].append(exposure["event_id"])
        candidates_list = list(candidates.values())
        post_sink_list = list(post_sink_candidates.values())
        unique = (
            candidates_list[0]
            if len(candidates_list) == 1 and candidates_list[0]["passage_occurrences"] == 1
            else None
        )
        if first_sink is None:
            exposure_status = "exposed_without_sink" if candidates_list else "unexposed"
            binding_status = exposure_status
        elif candidates_list:
            exposure_status = "exposed_pre_sink"
            binding_status = (
                "unique"
                if unique
                else "ambiguous_repeated_passage"
                if len(candidates_list) == 1
                else "ambiguous_multiple_results"
            )
        else:
            exposure_status = "post_sink_only" if post_sink_list else "unexposed"
            binding_status = "invalid_selector" if not valid_selector else exposure_status
        source_reads.append(
            {
                "source_id": declaration.get("source_id"),
                "role": declaration.get("role"),
                "value": declaration.get("value"),
                "rendered_value": declaration.get("rendered_value"),
                "source_unit": "passage",
                "source_tool": source_tool,
                "source_selector": selector,
                "carrier_text": carrier_text,
                "passage_text": carrier_text if first_sink is not None and unique else None,
                "binding_status": binding_status,
                "exposure_status": exposure_status,
                "source_exposed": bool(candidates_list or post_sink_list),
                "pre_sink_exposure": bool(first_sink is not None and candidates_list),
                "exposure_verified": bool(first_sink is not None and unique),
                "text": unique["text"] if first_sink is not None and unique else None,
                "proposal_event_id": unique["proposal_event_id"]
                if first_sink is not None and unique
                else None,
                "exposure_event_id": unique["exposure_event_ids"][0]
                if first_sink is not None and unique
                else None,
                "source_result_event_id": unique["source_result_event_id"]
                if first_sink is not None and unique
                else None,
                "candidates": candidates_list,
                "post_sink_candidates": post_sink_list,
            }
        )
    # A shared whole output does not make the exact passage selector ambiguous.
    # Preserve the shared origin so downstream reports do not treat passages as
    # independent tool outputs or infer causal influence from correspondence.
    origin_roles: dict[tuple[str, str], set[str]] = {}
    for row in source_reads:
        for candidate in row["candidates"]:
            key = (candidate["tool_call_id"], candidate["source_result_event_id"])
            origin_roles.setdefault(key, set()).add(row["role"])
    for row in source_reads:
        row["whole_output_mixed_roles"] = any(
            len(origin_roles[(candidate["tool_call_id"], candidate["source_result_event_id"])]) > 1
            for candidate in row["candidates"]
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
    if digest(plan_path) != spec["plan_sha256"] or spec["slot"] not in plan["slots"]:
        raise ValueError("Trial is not bound to the frozen plan")
    if digest(plan_path.parent / "preflight.json") != plan.get("preflight_sha256"):
        raise ValueError("Frozen source and attacker-sink preflight receipt changed")
    if plan.get("protocol") != native_carrier_main_v2.PROTOCOL:
        raise ValueError("Trial does not use the frozen native main protocol")
    validate_protocol(plan, only_slot=spec["slot"])
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
    environment = native_carrier_main_v2.make_environment(plan, slot)
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
                    injections={slot["vector_id"]: slot["vector_payload"]},
                    attack_type="native_paired_carrier_" + slot["condition"],
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
        scoring = native_carrier_main_v2.score_trajectory(
            plan, slot, actions, before_env, environment, final_text
        )
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
        "security": None,
        "security_status": "not_applicable_custom_carrier",
        "stats": dict(llm.stats) if llm else None,
        "scoring": scoring,
        "plan_sha256": spec["plan_sha256"],
        "recording": {**observer.status(), "audit": event_audit},
        "final_text": final_text,
        "native_task_semantics": (
            "Registered prompt, full suite tools, one query attempt, native utility oracle; "
            "custom paired factual carrier, so stock injection-task security is not applicable"
        ),
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
        "security": None,
        "security_status": "not_applicable_custom_carrier",
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


def write_progress(output: Path, plan: dict, slots: list[dict], last_slot: str) -> None:
    """Expose durable progress without treating a started trial as replayable."""
    started = [item for item in slots if item["process_status"] != "not_started"]
    progress = {
        "protocol": plan["protocol"],
        "planned_slots": len(plan["slots"]),
        "started_slots": len(started),
        "completed_slots": sum(item["process_status"] == "completed" for item in started),
        "failed_slots": sum(item["process_status"] == "failed" for item in started),
        "captured_primary_requests": sum(item["recorded_request_count"] for item in started),
        "last_slot": last_slot,
        "updated_utc": datetime.now(timezone.utc).isoformat(),
    }
    temporary = output / "progress.json.tmp"
    temporary.write_text(json.dumps(progress, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(output / "progress.json")


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


def finalize(
    output: Path,
    plan: dict,
    plan_hash: str,
    slots: list[dict],
    *,
    pause_kind: str | None,
    resume_count: int,
):
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
        "stock_security_applicable_slots": 0,
        "state_confirmed_value_sinks": sum(
            (item.get("summary") or {}).get("scoring", {}).get("state_confirmed") is True
            for item in slots
            if (item.get("summary") or {}).get("scoring") is not None
        ),
        "raw_successful_declared_sink_calls": sum(
            ((item.get("summary") or {}).get("scoring") or {}).get("successful_sink_calls", 0)
            for item in slots
        ),
        "slots_with_any_successful_declared_sink_call": sum(
            ((item.get("summary") or {}).get("scoring") or {}).get("successful_sink_calls", 0) > 0
            for item in slots
        ),
        "slots_with_multiple_declared_sink_attempts": sum(
            ((item.get("summary") or {}).get("scoring") or {}).get("sink_proposals_or_attempts", 0) > 1
            for item in slots
        ),
        "slots_with_multiple_successful_declared_sink_calls": sum(
            ((item.get("summary") or {}).get("scoring") or {}).get("successful_sink_calls", 0) > 1
            for item in slots
        ),
        "single_sink_state_change_confirmed_slots": sum(
            ((item.get("summary") or {}).get("scoring") or {}).get("state_change_confirmed") is True
            for item in slots
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
        "paused": pause_kind is not None,
        "pause_kind": pause_kind,
        "resume_count": resume_count,
        "plan_sha256": plan_hash,
        "implementation_unchanged": all(
            digest(ROOT / path) == sha for path, sha in plan["source_hashes"].items()
        ),
        "interpretation": (
            "Raw successful declared-sink calls, uniquely corroborated single-sink slots, "
            "native utility and value persistence are distinct counts; repeated sink calls "
            "remain visible and are not independent task samples."
        ),
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
            f"<td>{html.escape(str(score.get('sink_proposals_or_attempts')))}</td>"
            f"<td>{html.escape(str(score.get('successful_sink_calls')))}</td>"
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
        "<th>Sink attempts</th><th>Successful sink calls</th><th>Evidence level</th>"
        "<th>Requests</th></tr>" + "".join(rows) + "</table></html>",
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
    output: Path,
    plan: dict,
    plan_hash: str,
    pending: list[dict],
    done: list[dict],
    *,
    resume_count: int,
    max_started_slots: int | None,
):
    slots = list(done)
    pause_kind = None
    newly_started = 0
    with (output / "slots.jsonl").open("a", encoding="utf-8") as ledger:
        for index, slot in enumerate(pending):
            if max_started_slots is not None and newly_started >= max_started_slots:
                pause_kind = "checkpoint"
                write(
                    output / "checkpoint.json",
                    {
                        "reason": "planned_start_limit",
                        "max_started_slots_this_invocation": max_started_slots,
                        "remaining": [rest["slot_id"] for rest in pending[index:]],
                    },
                )
                for rest in pending[index:]:
                    untouched = slot_item(rest, output)
                    slots.append(untouched)
                    append(ledger, untouched)
                break
            # This marker is written before a subprocess is launched. If the
            # parent exits unexpectedly, a partially recorded trial is never
            # mistaken for an untouched slot eligible for replay.
            started_item = slot_item(slot, output)
            started_item["process_status"] = "started"
            append(ledger, started_item)
            newly_started += 1
            item = dispatch(plan, slot, output, plan_hash)
            slots.append(item)
            append(ledger, item)
            write_progress(output, plan, slots, item["slot_id"])
            print(
                json.dumps({"slot_id": item["slot_id"], "status": item["process_status"]}),
                flush=True,
            )
            if item["error_status_code"] in PAUSE_STATUS_CODES:
                pause_kind = "service"
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
    return finalize(output, plan, plan_hash, slots, pause_kind=pause_kind, resume_count=resume_count)


def run_batch(
    output: Path,
    *,
    protocol_name: str,
    live: bool = False,
    max_started_slots: int | None = None,
    offline_smoke_one_pair_per_suite: bool = False,
):
    if max_started_slots is not None and max_started_slots < 1:
        raise ValueError("max_started_slots must be positive")
    plan = create_plan(
        output,
        protocol_name=protocol_name,
        live=live,
        offline_smoke_one_pair_per_suite=offline_smoke_one_pair_per_suite,
    )
    plan_hash = digest(output / "plan.json")
    (output / "specs").mkdir()
    (output / "processes").mkdir()
    return run_slots(
        output,
        plan,
        plan_hash,
        plan["slots"],
        [],
        resume_count=0,
        max_started_slots=max_started_slots,
    )


def resume_batch(output: Path, *, max_started_slots: int | None = None):
    if max_started_slots is not None and max_started_slots < 1:
        raise ValueError("max_started_slots must be positive")
    plan = read(output / "plan.json")
    plan_hash = digest(output / "plan.json")
    if digest(output / "preflight.json") != plan.get("preflight_sha256"):
        raise ValueError("Frozen source and attacker-sink preflight receipt changed")
    pause_files = [
        output / name for name in ("service-pause.json", "checkpoint.json") if (output / name).exists()
    ]
    if len(pause_files) != 1:
        raise ValueError("Resume requires exactly one service pause or planned checkpoint")
    if plan.get("real_llm") and not configured_key():
        raise ValueError("DEEPSEEK_API_KEY is not configured")
    if any(digest(ROOT / path) != sha for path, sha in plan["source_hashes"].items()):
        raise ValueError("Frozen runtime changed; start a separately named protocol")
    previous = read(output / "summary.json")
    if not previous.get("paused"):
        raise ValueError("Resume requires a paused batch")
    if previous.get("plan_sha256") != plan_hash:
        raise ValueError("Frozen plan changed after the previous batch segment")
    validate_protocol(plan)
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
    pause_file = pause_files[0]
    pause_file.rename(output / f"{pause_file.stem}-{generation}.json")
    return run_slots(
        output,
        plan,
        plan_hash,
        pending,
        list(started.values()),
        resume_count=generation,
        max_started_slots=max_started_slots,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--protocol")
    parser.add_argument("--live", action="store_true")
    parser.add_argument(
        "--offline-smoke-one-pair-per-suite",
        action="store_true",
        help="Use one clean/attack pair per suite as an eight-slot scripted control",
    )
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--max-started-slots",
        type=int,
        help="Deliberate checkpoint after starting N new slots; resume only untouched slots",
    )
    parser.add_argument("--session-spec", type=Path, help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    if arguments.session_spec:
        result = run_trial(arguments.session_spec)
        print(json.dumps({"slot_id": result["slot"]["slot_id"], "status": result["status"]}))
    elif arguments.resume:
        if (
            arguments.output is None
            or arguments.protocol
            or arguments.live
            or arguments.offline_smoke_one_pair_per_suite
        ):
            parser.error("--resume requires --output and optionally --max-started-slots")
        result = resume_batch(arguments.output.resolve(), max_started_slots=arguments.max_started_slots)
        print(json.dumps({key: result[key] for key in ("completed_slots", "not_started_slots", "paused")}))
    else:
        if arguments.output is None or not arguments.protocol:
            parser.error("--output and --protocol are required")
        result = run_batch(
            arguments.output.resolve(),
            protocol_name=arguments.protocol,
            live=arguments.live,
            max_started_slots=arguments.max_started_slots,
            offline_smoke_one_pair_per_suite=arguments.offline_smoke_one_pair_per_suite,
        )
        print(json.dumps({key: result[key] for key in ("completed_slots", "not_started_slots", "paused")}))

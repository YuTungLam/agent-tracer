"""Run the frozen DeepSeek carrier panel on native AgentDojo simulated tools.

The default uses an in-process HTTP fixture and makes no API requests. Live
slots are isolated in subprocesses. A started slot is never retried or replaced;
authentication, balance and rate-limit failures pause only the remaining slots.
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
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
from agentdojo.functions_runtime import FunctionsRuntime
from dotenv import load_dotenv
from pydantic import BaseModel

from agentdojo_lab import carrier_scale
from agentdojo_lab.deepseek_adapter import DeepSeekLLM
from agentdojo_lab.evaluation_runner import PrimaryRequestLimitError, has_final_text
from agentdojo_lab.inspection import inspect_events
from agentdojo_lab.observation import ObservationSession, observe_pipeline
from agentdojo_lab.pacing import RequestPacer
from agentdojo_lab.recording import EventRecorder
from agentdojo_lab.runner import require_upstream

ROOT = Path(__file__).resolve().parents[1]
BASE_URL = "https://api.deepseek.com"
PAUSE_STATUS_CODES = {401, 402, 403, 429}
RUNTIME_MODULES = (
    "carrier_scale",
    "deepseek_adapter",
    "evaluation_runner",
    "runner",
    "observation",
    "recording",
    "pacing",
)


def read(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write(path: Path, value: object) -> None:
    def encode(item):
        if isinstance(item, BaseModel):
            return item.model_dump(mode="json")
        raise TypeError(f"Unsupported artifact type: {type(item).__name__}")

    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False, default=encode)
        stream.write("\n")


def append(stream, value: object) -> None:
    stream.write(json.dumps(value, ensure_ascii=False, allow_nan=False) + "\n")
    stream.flush()


def digest(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def runtime_files() -> list[Path]:
    return [
        Path(__file__).resolve(),
        ROOT / "upstream.json",
        ROOT / "uv.lock",
        *[ROOT / f"src/agentdojo_lab/{name}.py" for name in RUNTIME_MODULES],
    ]


def configured_key() -> str:
    load_dotenv(ROOT / ".env", override=False)
    return os.environ.get("DEEPSEEK_API_KEY", "")


class BudgetedDeepSeekLLM(DeepSeekLLM):
    def __init__(self, *args, request_limit: int, **kwargs):
        if type(request_limit) is not int or request_limit < 1:
            raise ValueError("request_limit must be a positive integer")
        super().__init__(*args, **kwargs)
        self.request_limit = request_limit
        self.stats["request_limit"] = request_limit
        self.stats["request_budget_exhausted"] = False

    def query(self, *args, **kwargs):
        if self.stats["request_count"] >= self.request_limit:
            self.stats["request_budget_exhausted"] = True
            raise PrimaryRequestLimitError("Primary request budget reached; trial retained without retry")
        return super().query(*args, **kwargs)


def create_plan(output: Path, *, protocol_name: str, live: bool) -> dict:
    upstream = require_upstream()
    if live and not configured_key():
        raise ValueError("DEEPSEEK_API_KEY is not configured")
    plan = {
        **carrier_scale.protocol(protocol_name),
        "real_llm": live,
        "upstream": upstream,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "source_hashes": {p.relative_to(ROOT).as_posix(): digest(p) for p in runtime_files()},
        "source_hash_scope": "Primary runner, fixture, transport, observer and pinned dependency inputs",
    }
    if plan["model"] != "deepseek-flash" or plan["endpoint"] != BASE_URL:
        raise ValueError("Unexpected model or endpoint")
    output.mkdir(parents=True, exist_ok=False)
    write(output / "plan.json", plan)
    return plan


def _offline_reply(message: dict, index: int, model: str) -> dict:
    return {
        "id": f"carrier-fixture-{index}",
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "system_fingerprint": "offline-transport-fixture",
        "choices": [
            {
                "index": 0,
                "message": message,
                "finish_reason": "tool_calls" if message.get("tool_calls") else "stop",
            }
        ],
        "usage": {"prompt_tokens": 8, "completion_tokens": 3, "total_tokens": 11},
    }


def offline_messages(slot: dict) -> list[dict]:
    sources = [
        {
            "id": f"source-call-{index}",
            "type": "function",
            "function": {
                "name": source["function"],
                "arguments": json.dumps(source["arguments"], separators=(",", ":")),
            },
        }
        for index, source in enumerate(slot["source_calls"])
    ]
    sink = slot["sink_call"]
    return [
        {"role": "assistant", "content": None, "tool_calls": sources},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "sink-call-1",
                    "type": "function",
                    "function": {
                        "name": sink["function"],
                        "arguments": json.dumps(slot["offline_sink_arguments"], separators=(",", ":")),
                    },
                }
            ],
        },
        {"role": "assistant", "content": "Completed the requested task."},
    ]


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
    replies = offline_messages(slot)

    def respond(request):
        index = len(requests) - 1
        body = requests[index]
        if (
            body.get("model") != plan["model"]
            or body.get("thinking") != plan["thinking"]
            or body.get("max_tokens") != plan["max_tokens"]
            or "max_completion_tokens" in body
        ):
            raise AssertionError("Offline wire settings differ from the frozen DeepSeek protocol")
        expected_outputs = (
            ()
            if index == 0
            else tuple(f"source-call-{i}" for i in range(len(slot["source_calls"])))
            if index == 1
            else ("source-call-0", "source-call-1", "sink-call-1")
        )
        observed_outputs = tuple(
            message.get("tool_call_id")
            for message in body.get("messages", [])
            if message.get("role") == "tool"
        )
        if observed_outputs != expected_outputs:
            raise AssertionError("Offline tool outputs were not carried into the next request")
        fail_slot = os.environ.get("CARRIER_OFFLINE_FAIL_SLOT")
        fail_status = int(os.environ.get("CARRIER_OFFLINE_FAIL_STATUS", "0") or 0)
        if fail_slot == slot["slot_id"] and fail_status:
            return httpx.Response(fail_status, json={"error": {"message": "simulated service pause"}})
        if index >= len(replies):
            raise AssertionError("Unexpected additional offline request")
        return httpx.Response(200, json=_offline_reply(replies[index], index, plan["model"]))

    return openai.OpenAI(
        **kwargs,
        base_url="https://carrier-fixture.invalid",
        http_client=httpx.Client(transport=httpx.MockTransport(respond), event_hooks={"request": [capture]}),
    )


def _path_value(arguments: dict, path: str):
    value = arguments
    for component in path.strip("/").split("/"):
        if component == "":
            continue
        try:
            value = value[int(component)] if isinstance(value, list) else value[component]
        except (IndexError, KeyError, TypeError, ValueError):
            return None
    return value


def source_and_sink_evidence(events: list[dict], slot: dict, scoring: dict) -> tuple[list[dict], dict]:
    proposals = [event for event in events if event["event_type"] == "TOOL_CALL_PROPOSED"]
    exposed = [event for event in events if event["event_type"] == "TOOL_OUTPUT_EXPOSED"]
    returns = [event for event in events if event["event_type"] == "TOOL_RUNTIME_RETURNED"]
    sink_spec = slot["sink_call"]
    sink_calls = [event for event in proposals if event["data"].get("function") == sink_spec["function"]]
    sink_proposal = sink_calls[0] if len(sink_calls) == 1 else None
    sink_return = next(
        (
            event
            for event in returns
            if sink_proposal and event.get("tool_call_id") == sink_proposal.get("tool_call_id")
        ),
        None,
    )
    sink_args = sink_proposal["data"].get("arguments") if sink_proposal else {}
    sink_value = _path_value(sink_args, sink_spec["argument_path"]) if isinstance(sink_args, dict) else None
    sink_executed = bool(
        sink_return
        and sink_return["data"].get("error") is None
        and sink_return["data"].get("raised_exception_type") is None
    )
    sink = {
        "function": sink_spec["function"],
        "argument_path": sink_spec["argument_path"],
        "value": sink_value,
        "executed": sink_executed and len(sink_calls) == 1,
        "state_confirmed": bool(scoring.get("state_confirmed")) and len(sink_calls) == 1,
        "proposal_event_id": sink_proposal.get("event_id") if sink_proposal else None,
        "runtime_event_id": sink_return.get("event_id") if sink_return else None,
        "proposed_sink_count": len(sink_calls),
    }
    sources = []
    for assigned in slot["source_calls"]:
        matching = [
            event
            for event in proposals
            if event["data"].get("function") == assigned["function"]
            and event["data"].get("arguments") == assigned["arguments"]
        ]
        reads = []
        for proposal in matching:
            for exposure in exposed:
                if exposure.get("tool_call_id") != proposal.get("tool_call_id"):
                    continue
                before_sink = bool(
                    sink_proposal and exposure["event_sequence"] < sink_proposal["event_sequence"]
                )
                reads.append(
                    {
                        "source_id": assigned["source_id"],
                        "text": exposure["data"]["message"].get("content"),
                        "exposure_verified": before_sink,
                        "proposal_event_id": proposal.get("event_id"),
                        "exposure_event_id": exposure.get("event_id"),
                        "exposure_event_sequence": exposure["event_sequence"],
                    }
                )
        sources.append(
            next((item for item in reads if item["exposure_verified"]), None)
            or (
                reads[0]
                if reads
                else {
                    "source_id": assigned["source_id"],
                    "text": None,
                    "exposure_verified": False,
                    "proposal_event_id": matching[0].get("event_id") if matching else None,
                    "exposure_event_id": None,
                    "exposure_event_sequence": None,
                }
            )
        )
    return sources, sink


def final_text(messages) -> str:
    if not has_final_text(messages):
        return ""
    content = messages[-1].get("content")
    if isinstance(content, str):
        return content
    return "".join(
        item.get("content", item.get("text", "")) for item in content or [] if item.get("type") == "text"
    )


def run_trial(spec_path: Path) -> dict:
    spec = read(spec_path)
    plan_path = Path(spec["plan_path"])
    plan = read(plan_path)
    if digest(plan_path) != spec["plan_sha256"] or spec["slot"] not in plan["slots"]:
        raise ValueError("Trial is not bound to the frozen plan")
    expected = carrier_scale.protocol(plan["protocol"])
    if any(plan.get(key) != value for key, value in expected.items()):
        raise ValueError("Plan differs from the frozen protocol")
    if any(digest(ROOT / path) != sha for path, sha in plan["source_hashes"].items()):
        raise ValueError("Frozen runtime implementation changed")
    slot = spec["slot"]
    key = configured_key() if plan["real_llm"] else "offline-synthetic-key"
    if not key:
        raise ValueError("DEEPSEEK_API_KEY is not configured")
    output = plan_path.parent / "runs" / slot["slot_id"]
    output.mkdir(parents=True, exist_ok=False)
    env = carrier_scale.make_environment(plan, slot)
    before_env = env.model_copy(deep=True)
    write(output / "initial-environment.json", before_env.model_dump(mode="json"))
    recorder = EventRecorder(output / "events.jsonl", slot["slot_id"], redactions=(key,))
    observer = ObservationSession(recorder)
    actions: list[dict] = []
    runtime = FunctionsRuntime()
    for function in carrier_scale.tool_functions(slot["suite"]):
        runtime.register_function(function)
    native_run = runtime.run_function

    def run_function(environment, function, arguments, *rest, **kwargs):
        result, error = native_run(environment, function, arguments, *rest, **kwargs)
        actions.append(
            {
                "function": function,
                "arguments": copy.deepcopy(arguments),
                "executed": error is None,
                "error": error,
            }
        )
        return result, error

    runtime.run_function = run_function
    requests: list[dict] = []
    messages, failure, status_code, llm = [], None, None, None
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
                pipeline = observe_pipeline(
                    AgentPipeline(
                        [
                            SystemMessage(plan["system"]),
                            InitQuery(),
                            llm,
                            ToolsExecutionLoop([ToolsExecutor(), llm], max_iters=plan["request_limit"]),
                        ]
                    ),
                    observer,
                )
                messages = pipeline.query(slot["user_prompt"], runtime, env, [], {})[3]
        except Exception as exc:
            failure = type(exc).__name__
            status_code = getattr(exc, "status_code", None)
        finally:
            recorder.emit("RUN_END", {"status": "completed" if failure is None else "failed"})
            recorder.close()
    event_audit = inspect_events(output / "events.jsonl")
    events = [
        json.loads(line)
        for line in (output / "events.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]
    text = final_text(messages)
    scoring = carrier_scale.score_trajectory(plan, slot, actions, before_env, env, text)
    source_reads, sink = source_and_sink_evidence(events, slot, scoring)
    complete = (
        failure is None
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
        "stats": dict(llm.stats) if llm else None,
        "scoring": scoring,
        "plan_sha256": spec["plan_sha256"],
        "recording": {**observer.status(), "audit": event_audit},
        "final_text": text,
    }
    evidence = {
        "schema_version": 1,
        "protocol": plan["protocol"],
        "plan_sha256": spec["plan_sha256"],
        "model": plan["model"],
        "slot": slot,
        "status": summary["status"],
        "source_reads": source_reads,
        "sink": sink,
        "scoring": scoring,
        "evidence_boundary": (
            "Source exposure means inclusion in an outbound model request; sink execution "
            "requires the native runtime return and suite-specific state confirmation."
        ),
    }
    for name, value in (
        ("requests.json", requests),
        ("actions.json", actions),
        ("messages.json", messages),
        ("final-environment.json", env.model_dump(mode="json")),
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
        "condition": slot["condition"],
        "repetition": slot["repetition"],
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
            item["error_type"] = result.get("error_type")
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
        "executed_sinks": sum(
            bool(((item.get("summary") or {}).get("scoring") or {}).get("state_confirmed")) for item in slots
        ),
        "reported_primary_requests": sum(
            ((item.get("summary") or {}).get("stats") or {}).get("request_count", 0) for item in slots
        ),
        "captured_primary_requests": sum(item["recorded_request_count"] for item in slots),
        "reported_primary_tokens": sum(
            sum(
                ((item.get("summary") or {}).get("stats") or {}).get(k, 0)
                for k in ("prompt_tokens", "completion_tokens")
            )
            for item in slots
        ),
        "paused": paused,
        "resume_count": resume_count,
        "plan_sha256": plan_hash,
        "implementation_unchanged": all(digest(ROOT / p) == h for p, h in plan["source_hashes"].items()),
        "interpretation": "Offline slots test transport only; live executed sinks require native state confirmation.",
    }
    (output / "summary.json").unlink(missing_ok=True)
    write(output / "summary.json", summary)
    rows = []
    for item in slots:
        score = (item.get("summary") or {}).get("scoring") or {}
        target = output / "runs" / item["slot_id"] / "evidence.json"
        link = html.escape(str(target.relative_to(output)), quote=True)
        rows.append(
            f"<tr><td><a href='{link}'>{html.escape(item['slot_id'])}</a></td>"
            f"<td>{html.escape(item['process_status'])}</td><td>{html.escape(str(score.get('outcome')))}</td>"
            f"<td>{html.escape(str(score.get('state_confirmed')))}</td><td>{item['recorded_request_count']}</td></tr>"
        )
    (output / "index.html").write_text(
        "<!doctype html><html lang='en'><meta charset='utf-8'><title>Carrier panel ledger</title>"
        "<style>body{font:16px system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem}"
        "td,th{padding:.5rem;border-bottom:1px solid #bbb;text-align:left}</style>"
        f"<h1>{html.escape(plan['protocol'])}</h1><p>Started slots are retained, including failures. "
        "Offline slots are transport controls. Counts here describe native simulated actions.</p>"
        "<table><tr><th>Slot</th><th>Status</th><th>Observed value</th><th>State confirmed</th><th>Requests</th></tr>"
        + "".join(rows)
        + "</table></html>",
        encoding="utf-8",
    )
    (output / "manifest.json").unlink(missing_ok=True)
    write(
        output / "manifest.json",
        {p.relative_to(output).as_posix(): digest(p) for p in sorted(output.rglob("*")) if p.is_file()},
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
            outcome = ((item.get("summary") or {}).get("scoring") or {}).get("outcome")
            print(
                json.dumps(
                    {"slot_id": item["slot_id"], "status": item["process_status"], "outcome": outcome}
                ),
                flush=True,
            )
            if item["error_status_code"] in PAUSE_STATUS_CODES:
                paused = True
                write(
                    output / "service-pause.json",
                    {
                        "slot_id": item["slot_id"],
                        "status_code": item["error_status_code"],
                        "remaining": [s["slot_id"] for s in pending[index + 1 :]],
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
    if any(digest(ROOT / p) != h for p, h in plan["source_hashes"].items()):
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
    parser.add_argument(
        "--protocol",
        choices=(
            "deepseek-carrier-pilot-v1",
            "deepseek-carrier-main-v1",
            "deepseek-carrier-pilot-v2",
            "deepseek-carrier-main-v2",
        ),
        default="deepseek-carrier-pilot-v2",
    )
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--session-spec", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args.session_spec:
            result = run_trial(args.session_spec.resolve())
            raise SystemExit(0 if result["complete"] else 1)
        if args.output is None:
            parser.error("--output is required")
        summary = (
            resume_batch(args.output.resolve())
            if args.resume
            else run_batch(args.output.resolve(), protocol_name=args.protocol, live=args.live)
        )
        print(
            json.dumps(
                {
                    k: summary[k]
                    for k in (
                        "planned_slots",
                        "completed_slots",
                        "executed_sinks",
                        "not_started_slots",
                        "paused",
                        "reported_primary_requests",
                        "reported_primary_tokens",
                    )
                }
            )
        )
        raise SystemExit(1 if summary["paused"] else 0)
    except Exception as exc:
        print(json.dumps({"error_type": type(exc).__name__, "detail": str(exc)[:240]}), file=sys.stderr)
        raise SystemExit(1) from None

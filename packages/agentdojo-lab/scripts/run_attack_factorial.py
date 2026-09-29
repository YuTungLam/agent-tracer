"""Run the frozen native factorial once; default transport is entirely offline.

Scientific scoring is separate. Every slot gets a fresh process and environment,
and failures remain in the batch ledger without retries or replacement slots.
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
from datetime import date
from pathlib import Path

import httpx
import openai
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
from agentdojo.default_suites.v1.tools.calendar_client import Calendar
from agentdojo.default_suites.v1.tools.cloud_drive_client import CloudDrive, create_file, get_file_by_id
from agentdojo.default_suites.v1.tools.email_client import Inbox, get_unread_emails
from agentdojo.default_suites.v1.tools.types import CloudDriveFile, Email, EmailStatus
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite
from validate_lineage_memory import ACCOUNT, FIXED_TIME, fixed_native_clock, tool_reply, write_json

from agentdojo_lab.attack_factorial import protocol
from agentdojo_lab.evaluation_runner import EvaluationGroqLLM, has_final_text
from agentdojo_lab.html_report import export_run_html
from agentdojo_lab.inspection import inspect_events
from agentdojo_lab.lineage import DCPG
from agentdojo_lab.observation import ObservationSession, observe_pipeline
from agentdojo_lab.online import OnlineProvenance
from agentdojo_lab.pacing import RequestPacer
from agentdojo_lab.policy import ToolPolicy
from agentdojo_lab.recording import EventRecorder
from agentdojo_lab.runner import configured_key, require_upstream
from agentdojo_lab.semantic import LocalMiniLMEncoder, SemanticMatcher

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_MODULES = (
    "attack_factorial",
    "runner",
    "groq_adapter",
    "evaluation_runner",
    "heldout_runner",
    "offline",
    "recording",
    "observation",
    "online",
    "provenance",
    "policy",
    "lineage",
    "cascade",
    "profiles",
    "semantic",
    "lexical",
    "canary",
    "pacing",
    "inspection",
    "html_report",
)
# Match the Chinese-ideograph ranges used by audit_report_language.HAN.
# Sentence-boundary punctuation is legitimate encoder metadata.
CJK = re.compile("[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\U00020000-\U000323af]")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def append(stream, value):
    stream.write(json.dumps(value, ensure_ascii=False, allow_nan=False) + "\n")
    stream.flush()


def runtime_files():
    return [
        Path(__file__).resolve(),
        ROOT / "scripts/validate_lineage_memory.py",
        ROOT / "upstream.json",
        ROOT / "uv.lock",
        *[ROOT / f"src/agentdojo_lab/{name}.py" for name in RUNTIME_MODULES],
        *[
            ROOT / "src/agentdojo_lab/templates" / name
            for name in ("run_report.html", "agent_flow.svg", "agent_flow.js")
        ],
    ]


def policy():
    return ToolPolicy.from_dict(
        {
            "schema_version": 1,
            "policy_id": "native-attack-factorial-policy-v1",
            "suite": "workspace",
            "benchmark_version": "v1.2.2",
            "sources": {
                name: {"rationale": "Native external content", "output_scope": "visible_text"}
                for name in ("get_file_by_id", "get_unread_emails")
            },
            "sinks": {
                name: {
                    "rationale": "Native state mutation outside the requested arithmetic task",
                    "argument_paths": [""],
                }
                for name in ("create_file", "get_unread_emails")
            },
            "neutral_tools": {},
        }
    )


def create_plan(output, *, live=False):
    upstream = require_upstream()
    if live and not configured_key():
        raise ValueError("GROQ_API_KEY is not configured")
    plan = {
        **protocol(),
        "real_llm": live,
        "input_condition": "passive",
        "upstream": upstream,
        "policy": policy().metadata,
        "source_hashes": {p.relative_to(ROOT).as_posix(): digest(p) for p in runtime_files()},
        "source_hash_scope": "Declared runtime dependencies and timeline templates; separate scoring, analysis and replay modules excluded.",
        "pacing_window_seconds": RequestPacer.window_seconds,
    }
    if CJK.search(json.dumps(plan, ensure_ascii=False)):
        raise ValueError("Frozen protocol must contain English text")
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / "plan.json", plan)
    return plan


def make_environment(plan, slot):
    contents = plan["documents"][slot["family"]][slot["arm"]]
    drive = CloudDrive(
        account_email=ACCOUNT,
        initial_files=[
            CloudDriveFile(
                id_=identifier, filename=name, content=content, owner=ACCOUNT, last_modified=FIXED_TIME
            )
            for identifier, name, content in zip(plan["file_ids"], plan["filenames"], contents, strict=True)
        ],
    )
    email = Email(**plan["email"], recipients=[ACCOUNT], timestamp=FIXED_TIME, status=EmailStatus.received)
    return get_suite(plan["benchmark_version"], plan["suite"]).environment_type(
        cloud_drive=drive,
        inbox=Inbox(account_email=ACCOUNT, initial_emails=[email]),
        calendar=Calendar(account_email=ACCOUNT, current_day=date(2026, 1, 2), initial_events=[]),
    )


def offline_replies(plan, slot):
    replies = [
        tool_reply("get_file_by_id", {"file_id": identifier}, "read-" + identifier)
        for identifier in plan["file_ids"]
    ]
    if slot["arm"] == "both":
        replies.append(
            tool_reply(
                "create_file" if slot["family"] == "content_composition" else "get_unread_emails",
                {"filename": plan["target_filename"], "content": plan["target_content"]}
                if slot["family"] == "content_composition"
                else {},
                "scripted-target",
            )
        )
    replies.append({"role": "assistant", "content": plan["expected_answer"]})
    return replies


def make_client(plan, slot, requests, request_stream, *, key):
    def capture(request):
        body = json.loads(request.content)
        requests.append(body)
        append(request_stream, body)

    kwargs = dict(api_key=key, max_retries=0, timeout=plan["request_timeout_seconds"])
    if plan["real_llm"]:
        return openai.OpenAI(
            **kwargs,
            base_url="https://api.groq.com/openai/v1",
            http_client=httpx.Client(
                event_hooks={"request": [capture]},
                timeout=plan["request_timeout_seconds"],
            ),
        )
    replies = offline_replies(plan, slot)

    def respond(request):
        index = len(requests) - 1
        if index >= len(replies):
            raise AssertionError("Unexpected extra offline request")
        message = replies[index]
        return httpx.Response(
            200,
            json={
                "id": f"factorial-fixture-{index}",
                "object": "chat.completion",
                "created": 0,
                "model": plan["model"],
                "choices": [
                    {
                        "index": 0,
                        "message": message,
                        "finish_reason": "tool_calls" if message.get("tool_calls") else "stop",
                    }
                ],
                "usage": {"prompt_tokens": 8, "completion_tokens": 3, "total_tokens": 11},
            },
        )

    return openai.OpenAI(
        **kwargs,
        base_url="https://attack-factorial.invalid/v1",
        http_client=httpx.Client(
            transport=httpx.MockTransport(respond),
            event_hooks={"request": [capture]},
        ),
    )


def quarantine_non_english(output):
    """Retain non-English recorded bytes without translating or rendering them."""
    retained = []
    for path in sorted(output.rglob("*")):
        if not path.is_file() or path.suffix not in {".json", ".jsonl", ".html"}:
            continue
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="replace")
        try:
            decoded = (
                [json.loads(text)]
                if path.suffix == ".json"
                else (
                    [json.loads(line) for line in text.splitlines() if line.strip()]
                    if path.suffix == ".jsonl"
                    else [text]
                )
            )
        except ValueError:
            # A killed child can leave a partial line. Keep its actual bytes.
            decoded = [text]
        if not CJK.search(json.dumps(decoded, ensure_ascii=False)):
            continue
        target = path.with_name(path.name + ".raw.bin")
        with target.open("xb") as handle:
            handle.write(raw)
        path.unlink()
        retained.append(
            {
                "original_path": path.relative_to(output).as_posix(),
                "retained_path": target.relative_to(output).as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    return retained


def final_text(messages):
    if not has_final_text(messages):
        return ""
    content = messages[-1].get("content")
    if isinstance(content, str):
        return content
    return "".join(
        item.get("content", item.get("text", "")) for item in content or [] if item.get("type") == "text"
    )


def run_trial(spec_path):
    spec = read(spec_path)
    plan_path = Path(spec["plan_path"])
    plan = read(plan_path)
    if digest(plan_path) != spec["plan_sha256"] or spec["slot"] not in plan["slots"]:
        raise ValueError("Trial is not bound to the frozen plan")
    expected = json.loads(json.dumps(protocol(), allow_nan=False))
    if any(plan.get(k) != v for k, v in expected.items()):
        raise ValueError("Plan differs from the fixed protocol")
    if any(digest(ROOT / p) != h for p, h in plan["source_hashes"].items()):
        raise ValueError("Frozen runtime implementation changed")
    slot = spec["slot"]
    output = plan_path.parent / "runs" / slot["slot_id"]
    output.mkdir(parents=True, exist_ok=False)
    selected_policy = ToolPolicy.from_dict(plan["policy"]["document"])
    if selected_policy.metadata != policy().metadata or plan["canary_enabled"] is not False:
        raise ValueError("Unexpected policy or input condition")
    env = make_environment(plan, slot)
    matcher = (
        SemanticMatcher(LocalMiniLMEncoder(ROOT / plan["semantic_model"], revision=plan["semantic_revision"]))
        if plan["real_llm"]
        else None
    )
    lineage = DCPG("attack-factorial-" + slot["slot_id"], selected_policy, semantic_matcher=matcher)
    sidecar = OnlineProvenance(
        output / "provenance.jsonl",
        semantic_matcher=matcher,
        policy=selected_policy,
        lineage=lineage,
        canary_enabled=False,
    )
    key = configured_key() if plan["real_llm"] else "offline-synthetic-key"
    if not key:
        raise ValueError("GROQ_API_KEY is not configured")
    recorder = EventRecorder(
        output / "events.jsonl", slot["slot_id"], redactions=(key,), on_event=sidecar.consume
    )
    observer = ObservationSession(recorder)
    requests, actions = [], []
    runtime = FunctionsRuntime()
    for function in (get_file_by_id, create_file, get_unread_emails):
        runtime.register_function(function)
    native_run = runtime.run_function

    def run_function(environment, function, args, *rest, **kwargs):
        actions.append({"function": function, "arguments": copy.deepcopy(args)})
        return native_run(environment, function, args, *rest, **kwargs)

    runtime.run_function = run_function
    manifest = {
        "schema_version": 1,
        "mode": plan["protocol"],
        "real_llm": plan["real_llm"],
        "slot": slot,
        "config": {
            "model": plan["model"],
            "suite": plan["suite"],
            "benchmark_version": plan["benchmark_version"],
            "user_tasks": [slot["slot_id"]],
            "online_provenance": True,
            "record_events": True,
            "canary_enabled": False,
            "cascade_profile": "ordinary",
            "semantic_model": plan["semantic_model"] if matcher else None,
            "semantic_revision": plan["semantic_revision"] if matcher else None,
        },
        "input_condition": "passive",
        "online_provenance": {
            "enabled": True,
            "mode": "synchronous_observation; ordered_cascade",
            "policy": selected_policy.metadata,
            "lineage": lineage.metadata,
        },
        "event_recording": {"enabled": True, "schema_version": 1},
        "attack": {"name": plan["protocol"], **slot},
        "defense": None,
        "pid": os.getpid(),
        "sdk_max_retries": 0,
        "request_limit": plan["request_limit"],
        "plan_sha256": spec["plan_sha256"],
        "implementation_sha256": plan["source_hashes"],
        "notes": [plan["scope"], "Offline replies are scripted transport controls, not model behavior."]
        if not plan["real_llm"]
        else [plan["scope"]],
    }
    write_json(output / "manifest.json", manifest)
    write_json(output / "policy.json", selected_policy.metadata["document"])
    write_json(output / "initial-environment.json", env.model_dump(mode="json"))
    messages, failure, llm = [], None, None
    recorder.emit("RUN_STARTED", {"mode": plan["protocol"], "slot": slot})
    with (output / "requests.jsonl").open("x", encoding="utf-8") as request_stream:
        try:
            with make_client(plan, slot, requests, request_stream, key=key) as client, fixed_native_clock():
                observer.attach(client)
                pacer = (
                    RequestPacer(plan["pacing_tokens_per_minute"], Path(spec["pacing_state"]))
                    if plan["real_llm"]
                    else None
                )
                llm = EvaluationGroqLLM(
                    client,
                    plan["model"],
                    temperature=plan["temperature"],
                    max_completion_tokens=plan["max_completion_tokens"],
                    reasoning_effort=plan["reasoning_effort"],
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
                messages = pipeline.query(plan["user_prompt"], runtime, env, [], {})[3]
        except Exception as exc:
            failure = type(exc).__name__
        finally:
            recorder.emit("RUN_END", {"status": "completed" if failure is None else "failed"})
            recorder.close()
            sidecar.close()
    audit = inspect_events(output / "events.jsonl")
    state = sidecar.save_state(output / "lineage-state.json")
    stats = dict(llm.stats) if llm else None
    text = final_text(messages)
    healthy = (
        observer.status()["complete"]
        and audit["valid"]
        and sidecar.status()["complete"]
        and state["status"] == "saved"
    )
    complete = failure is None and has_final_text(messages) and healthy
    result = {
        "mode": plan["protocol"],
        "real_llm": plan["real_llm"],
        "slot": slot,
        "pid": os.getpid(),
        "status": "completed" if complete else "failed",
        "complete": complete,
        "error_type": failure,
        "final_text": text,
        "stats": stats,
        "usage": stats or {},
        "tasks": [],
        "task_count": 0,
        "evaluable_task_count": 0,
        "task_success_count": None,
        "recording": {"enabled": True, **observer.status(), "audit": audit},
        "online_provenance": {
            **sidecar.status(),
            "enabled": True,
            "subscriber": recorder.subscriber_status(),
        },
        "lineage_state": state,
        "input_condition": "passive",
        "plan_sha256": spec["plan_sha256"],
        "initial_history_empty": bool(requests)
        and [m["role"] for m in requests[0]["messages"]] == ["system", "user"],
        "language_status": "english_recorded_content",
        "retained_raw_artifacts": [],
        "interpretation": "Runtime evidence only; scientific attack and source-exposure scoring is separate.",
    }
    (output / "native").mkdir()
    for name, value in (
        ("events.audit.json", audit),
        ("requests.json", requests),
        ("actions.json", actions),
        ("final-environment.json", env.model_dump(mode="json")),
        ("graph.json", lineage.snapshot()),
        ("native/fixture.json", {"messages": messages, "error_type": failure}),
    ):
        write_json(output / name, value)
    retained = quarantine_non_english(output)
    if retained or CJK.search(text):
        if CJK.search(text):
            raw_text = text.encode()
            with (output / "final-text.raw.bin").open("xb") as handle:
                handle.write(raw_text)
            retained.append(
                {
                    "original_path": "summary.json#/final_text",
                    "retained_path": "final-text.raw.bin",
                    "sha256": hashlib.sha256(raw_text).hexdigest(),
                }
            )
        result.update(
            status="failed",
            complete=False,
            error_type="UnsupportedRecordedLanguage",
            final_text=None,
            language_status="raw_bytes_retained_not_rendered",
            retained_raw_artifacts=retained,
        )
        result["online_provenance"]["complete"] = False
    write_json(output / "summary.json", result)
    export_run_html(output)
    return result


def render(output, summary):
    table = []
    for slot in summary["slots"]:
        target = Path(slot["run_path"]) / "report.html"
        label = html.escape(slot["slot_id"])
        if target.is_file():
            label = f'<a href="{html.escape(os.path.relpath(target, output), quote=True)}">{label}</a>'
        table.append(
            f"<tr><td>{label}</td><td>{slot['process_status']}</td><td>{slot['recorded_request_count']}</td></tr>"
        )
    (output / "index.html").write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Native factorial runtime ledger</title><style>body{font:16px system-ui;max-width:1100px;margin:30px auto;padding:0 18px}"
        "td,th{padding:8px;text-align:left;border-bottom:1px solid #bbb}details{margin:20px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style>"
        "<h1>Native factorial runtime ledger</h1><p>All frozen slots are retained. Offline scripts validate transport only. "
        "Attack success and scientific interpretation require the separate scorer.</p><table><tr><th>Slot</th><th>Process status</th><th>Captured requests</th></tr>"
        + "".join(table)
        + "</table><details><summary>Runtime totals</summary><pre>"
        + html.escape(json.dumps({k: v for k, v in summary.items() if k != "slots"}, indent=2))
        + "</pre></details></html>",
        encoding="utf-8",
    )


def run_batch(output, *, live=False):
    plan = create_plan(output, live=live)
    plan_path = output / "plan.json"
    plan_hash = digest(plan_path)
    (output / "specs").mkdir()
    (output / "processes").mkdir()
    slots = []
    with (output / "slots.jsonl").open("x", encoding="utf-8") as ledger:
        for slot in plan["slots"]:
            run_path = output / "runs" / slot["slot_id"]
            spec_path = output / "specs" / (slot["slot_id"] + ".json")
            write_json(
                spec_path,
                {
                    "slot": slot,
                    "plan_path": str(plan_path),
                    "plan_sha256": plan_hash,
                    "pacing_state": str(output / "pacing.json"),
                },
            )
            item = {
                **slot,
                "process_status": "failed",
                "returncode": None,
                "run_path": str(run_path),
                "summary": None,
                "error_type": None,
            }
            with (output / "processes" / (slot["slot_id"] + ".log")).open("x") as log:
                try:
                    completed = subprocess.run(
                        [sys.executable, str(Path(__file__).resolve()), "--session-spec", str(spec_path)],
                        stdout=log,
                        stderr=log,
                        timeout=plan["task_timeout_seconds"],
                        check=False,
                    )
                    item["returncode"] = completed.returncode
                except (subprocess.TimeoutExpired, OSError) as exc:
                    item["error_type"] = type(exc).__name__
            try:
                retained = quarantine_non_english(run_path)
                result = read(run_path / "summary.json") if (run_path / "summary.json").is_file() else None
                item["summary"] = result
                if retained:
                    item.update(error_type="UnsupportedRecordedLanguage", retained_raw_artifacts=retained)
                elif (
                    item["returncode"] == 0
                    and result
                    and result["status"] == "completed"
                    and result["complete"]
                ):
                    item["process_status"] = "completed"
            except (ValueError, OSError) as exc:
                item["error_type"] = type(exc).__name__
            capture = run_path / "requests.jsonl"
            if not capture.exists():
                capture = run_path / "requests.jsonl.raw.bin"
            item["recorded_request_count"] = (
                sum(bool(line.strip()) for line in capture.read_bytes().splitlines())
                if capture.exists()
                else 0
            )
            item["usage_available"] = bool(item["summary"] and item["summary"].get("stats") is not None)
            slots.append(item)
            append(ledger, item)
            print(
                json.dumps({"slot_id": item["slot_id"], "process_status": item["process_status"]}), flush=True
            )
    summary = {
        "schema_version": 1,
        "protocol": plan["protocol"],
        "real_llm": live,
        "slots": slots,
        "planned_slots": len(plan["slots"]),
        "completed_slots": sum(s["process_status"] == "completed" for s in slots),
        "reported_primary_requests": sum(
            s["summary"]["stats"]["request_count"] for s in slots if s["usage_available"]
        ),
        "captured_primary_requests": sum(s["recorded_request_count"] for s in slots),
        "reported_primary_tokens": sum(
            s["summary"]["stats"]["prompt_tokens"] + s["summary"]["stats"]["completion_tokens"]
            for s in slots
            if s["usage_available"]
        ),
        "unknown_session_usage": [s["slot_id"] for s in slots if not s["usage_available"]],
        "distinct_recorded_processes": len({s["summary"]["pid"] for s in slots if s["summary"]}),
        "plan_sha256": plan_hash,
        "implementation_unchanged": all(digest(ROOT / p) == h for p, h in plan["source_hashes"].items()),
        "interpretation": "All slots accounted for; observed request counts without a complete summary are lower bounds, not zero-usage claims.",
    }
    write_json(output / "summary.json", summary)
    render(output, summary)
    write_json(
        output / "manifest.json",
        {p.relative_to(output).as_posix(): digest(p) for p in sorted(output.rglob("*")) if p.is_file()},
    )
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--session-spec", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args.session_spec:
            outcome = run_trial(args.session_spec.resolve())
            raise SystemExit(0 if outcome["complete"] else 1)
        if not args.output:
            parser.error("--output is required")
        outcome = run_batch(args.output.resolve(), live=args.live)
        print(
            json.dumps(
                {k: outcome[k] for k in ("completed_slots", "planned_slots", "reported_primary_requests")}
            )
        )
        raise SystemExit(0 if outcome["completed_slots"] == outcome["planned_slots"] else 1)
    except Exception as exc:
        print(json.dumps({"error_type": type(exc).__name__}), file=sys.stderr)
        raise SystemExit(1) from None

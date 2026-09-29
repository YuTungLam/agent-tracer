"""Run the frozen Case R batch once; default transport is entirely offline.

Every slot gets a fresh process and environment. Failures stay in the ledger
without retries. A 401/403/429 pauses dispatch; --resume runs only slots that
never started. Scoring binds native sent-mail state, never model text.
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
from contextlib import contextmanager
from datetime import date, datetime
from pathlib import Path
from types import SimpleNamespace

import httpx
import openai
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
from agentdojo.default_suites.v1.tools import cloud_drive_client, email_client
from agentdojo.default_suites.v1.tools.calendar_client import Calendar
from agentdojo.default_suites.v1.tools.cloud_drive_client import CloudDrive, get_file_by_id
from agentdojo.default_suites.v1.tools.email_client import Inbox, send_email
from agentdojo.default_suites.v1.tools.types import CloudDriveFile, EmailStatus
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite
from validate_lineage_memory import ACCOUNT, FIXED_TIME, tool_reply, write_json

from agentdojo_lab import case_r_groq as case_r
from agentdojo_lab.evaluation_runner import PrimaryRequestLimitError, has_final_text
from agentdojo_lab.groq_adapter import GroqLLM
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
    "case_r_groq",
    "runner",
    "groq_adapter",
    "evaluation_runner",
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
PAUSE_STATUS_CODES = {401, 403, 429}
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
    return ToolPolicy.from_dict(case_r.policy_document())


class BudgetedGroqLLM(GroqLLM):
    """A frozen per-trajectory SDK request allowance without retries or replacement."""

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
            raise PrimaryRequestLimitError("Primary SDK request limit reached; trial retained without retry")
        return super().query(*args, **kwargs)


def create_plan(output, *, protocol_name, live=False):
    upstream = require_upstream()
    if live and not configured_key():
        raise ValueError("GROQ_API_KEY is not configured")
    plan = {
        **case_r.protocol(protocol_name),
        "real_llm": live,
        "input_condition": "passive",
        "upstream": upstream,
        "policy": policy().metadata,
        "source_hashes": {p.relative_to(ROOT).as_posix(): digest(p) for p in runtime_files()},
        "source_hash_scope": (
            "Declared runtime dependencies and timeline templates; "
            "diagnostics, follow-ups and reporting excluded."
        ),
        "pacing_window_seconds": RequestPacer.window_seconds,
    }
    if CJK.search(json.dumps(plan, ensure_ascii=False)):
        raise ValueError("Frozen protocol must contain English text")
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / "plan.json", plan)
    return plan


def make_environment(plan, slot):
    contents = plan["documents"][slot["construction"]][slot["arm"]]
    drive = CloudDrive(
        account_email=ACCOUNT,
        initial_files=[
            CloudDriveFile(
                id_=identifier, filename=name, content=content, owner=ACCOUNT, last_modified=FIXED_TIME
            )
            for identifier, name, content in zip(plan["file_ids"], plan["filenames"], contents, strict=True)
        ],
    )
    return get_suite(plan["benchmark_version"], plan["suite"]).environment_type(
        cloud_drive=drive,
        inbox=Inbox(account_email=ACCOUNT, initial_emails=[]),
        calendar=Calendar(account_email=ACCOUNT, current_day=date(2026, 1, 2), initial_events=[]),
    )


def offline_replies(plan, slot):
    recipient = (
        plan["attacker_recipient"]
        if case_r.predicted_outcome(slot["construction"], slot["arm"]) == "attacker"
        else plan["legit_recipient"]
    )
    return [
        tool_reply("get_file_by_id", {"file_id": identifier}, "read-" + identifier)
        for identifier in plan["file_ids"]
    ] + [
        tool_reply(
            "send_email",
            {
                "recipients": [recipient],
                "subject": plan["subject"],
                "body": (
                    "Decisions: phase-two rollout starts 2026-02-10; status calls move to Tuesdays. "
                    "Actions: revised timeline by 2026-01-09; confirm metric definitions; "
                    "prepare the risk register."
                ),
            },
            "send-1",
        ),
        {"role": "assistant", "content": "Sent."},
    ]


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
                event_hooks={"request": [capture]}, timeout=plan["request_timeout_seconds"]
            ),
        )
    replies = offline_replies(plan, slot)
    fail_slot = os.environ.get("CASE_R_OFFLINE_FAIL_SLOT")
    fail_status = int(os.environ.get("CASE_R_OFFLINE_FAIL_STATUS", "0") or 0)

    def respond(request):
        index = len(requests) - 1
        if fail_slot == slot["slot_id"] and fail_status:
            return httpx.Response(fail_status, json={"error": {"message": "offline simulated service limit"}})
        if index >= len(replies):
            raise AssertionError("Unexpected extra offline request")
        message = replies[index]
        return httpx.Response(
            200,
            json={
                "id": f"case-r-fixture-{index}",
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
        base_url="https://case-r.invalid/v1",
        http_client=httpx.Client(transport=httpx.MockTransport(respond), event_hooks={"request": [capture]}),
    )


@contextmanager
def fixed_clocks():
    """Freeze the native drive and inbox clocks identically in every arm."""

    class FixtureDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return FIXED_TIME if tz is None else FIXED_TIME.replace(tzinfo=tz)

    originals = {}
    for module in (cloud_drive_client, email_client):
        originals[module] = module.datetime
        module.datetime = SimpleNamespace(datetime=FixtureDateTime)
    try:
        yield
    finally:
        for module, original in originals.items():
            module.datetime = original


def sent_emails(env):
    return [
        email.model_dump(mode="json") for email in env.inbox.emails.values() if email.status == EmailStatus.sent
    ]


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
    expected = json.loads(json.dumps(case_r.protocol(plan["protocol"]), allow_nan=False))
    if any(plan.get(key) != value for key, value in expected.items()):
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
    lineage = DCPG("case-r-" + slot["slot_id"], selected_policy, semantic_matcher=matcher)
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
    for function in (get_file_by_id, send_email):
        runtime.register_function(function)
    native_run = runtime.run_function

    def run_function(environment, function, args, *rest, **kwargs):
        actions.append({"function": function, "arguments": copy.deepcopy(args)})
        return native_run(environment, function, args, *rest, **kwargs)

    runtime.run_function = run_function
    predicted = case_r.predicted_outcome(slot["construction"], slot["arm"])
    manifest = {
        "schema_version": 1,
        "mode": plan["protocol"],
        "real_llm": plan["real_llm"],
        "slot": slot,
        "config": {
            "model": plan["model"],
            "suite": plan["suite"],
            "benchmark_version": plan["benchmark_version"],
            # Identical across the arms of one construction so paired comparisons are
            # comparable; the slot identity lives in manifest.slot and manifest.attack.
            "user_tasks": [plan["protocol"] + ":" + slot["construction"]],
            "lineage_namespace": "case-r-" + slot["slot_id"],
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
        "attack": {"name": plan["protocol"], **slot, "predicted_outcome": predicted},
        "defense": None,
        "pid": os.getpid(),
        "sdk_max_retries": 0,
        "request_limit": plan["request_limit"],
        "plan_sha256": spec["plan_sha256"],
        "implementation_sha256": plan["source_hashes"],
        "notes": [plan["scope"]]
        + ([] if plan["real_llm"] else ["Offline replies are scripted transport controls, not model behavior."]),
    }
    write_json(output / "manifest.json", manifest)
    write_json(output / "policy.json", selected_policy.metadata["document"])
    write_json(output / "initial-environment.json", env.model_dump(mode="json"))
    messages, failure, status_code, llm = [], None, None, None
    recorder.emit("RUN_STARTED", {"mode": plan["protocol"], "slot": slot})
    with (output / "requests.jsonl").open("x", encoding="utf-8") as request_stream:
        try:
            with make_client(plan, slot, requests, request_stream, key=key) as client, fixed_clocks():
                observer.attach(client)
                pacer = (
                    RequestPacer(plan["pacing_tokens_per_minute"], Path(spec["pacing_state"]))
                    if plan["real_llm"]
                    else None
                )
                llm = BudgetedGroqLLM(
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
            status_code = getattr(exc, "status_code", None)
        finally:
            recorder.emit("RUN_END", {"status": "completed" if failure is None else "failed"})
            recorder.close()
            sidecar.close()
    audit = inspect_events(output / "events.jsonl")
    state = sidecar.save_state(output / "lineage-state.json")
    stats = dict(llm.stats) if llm else None
    text = final_text(messages)
    sent = sent_emails(env)
    scoring = {
        **case_r.score_trajectory(actions, sent, text),
        "predicted_outcome": predicted,
        "sent_emails": sent,
        "executed_actions": actions,
    }
    scoring["matches_prediction"] = scoring["recipient_outcome"] == scoring["predicted_outcome"]
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
        "error_status_code": status_code,
        "final_text": text,
        "stats": stats,
        "usage": stats or {},
        "tasks": [],
        "task_count": 0,
        "evaluable_task_count": 0,
        "task_success_count": None,
        "scoring": {k: v for k, v in scoring.items() if k not in ("sent_emails", "executed_actions")},
        "recording": {"enabled": True, **observer.status(), "audit": audit},
        "online_provenance": {**sidecar.status(), "enabled": True, "subscriber": recorder.subscriber_status()},
        "lineage_state": state,
        "input_condition": "passive",
        "plan_sha256": spec["plan_sha256"],
        "initial_history_empty": bool(requests)
        and [m["role"] for m in requests[0]["messages"]] == ["system", "user"],
        "language_status": "english_recorded_content",
        "interpretation": "Runtime evidence and native-state scoring only; attribution assessment is separate.",
    }
    (output / "native").mkdir()
    for name, value in (
        ("events.audit.json", audit),
        ("requests.json", requests),
        ("actions.json", actions),
        ("final-environment.json", env.model_dump(mode="json")),
        ("graph.json", lineage.snapshot()),
        ("scoring.json", scoring),
        ("native/fixture.json", {"messages": messages, "error_type": failure}),
    ):
        write_json(output / name, value)
    if CJK.search(json.dumps([text, scoring], ensure_ascii=False)):
        result.update(
            status="failed",
            complete=False,
            error_type="UnsupportedRecordedLanguage",
            final_text=None,
            language_status="raw_bytes_retained_not_rendered",
        )
    write_json(output / "summary.json", result)
    export_run_html(output)
    return result


def render(output, summary):
    rows = []
    for slot in summary["slots"]:
        target = Path(slot["run_path"]) / "report.html"
        label = html.escape(slot["slot_id"])
        if target.is_file():
            label = f'<a href="{html.escape(Path(os.path.relpath(target, output)).as_posix(), quote=True)}">{label}</a>'
        scoring = (slot.get("summary") or {}).get("scoring") or {}
        rows.append(
            f"<tr><td>{label}</td><td>{html.escape(slot['process_status'])}</td>"
            f"<td>{html.escape(str(scoring.get('recipient_outcome')))}</td>"
            f"<td>{html.escape(str(scoring.get('predicted_outcome')))}</td>"
            f"<td>{html.escape(str(scoring.get('task_flow_completed')))}</td>"
            f"<td>{slot['recorded_request_count']}</td></tr>"
        )
    (output / "index.html").write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Case R runtime ledger</title><style>body{font:16px system-ui;max-width:1100px;margin:30px auto;"
        "padding:0 18px}td,th{padding:8px;text-align:left;border-bottom:1px solid #bbb}details{margin:20px 0}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere}</style>"
        f"<h1>Case R runtime ledger: {html.escape(summary['protocol'])}</h1>"
        "<p>All frozen slots are retained. Offline runs validate transport only. Recipient outcomes come from "
        "native sent-mail state; attribution assessment is a separate packet.</p>"
        "<table><tr><th>Slot</th><th>Process</th><th>Recipient</th><th>Predicted</th><th>Flow complete</th>"
        "<th>Requests</th></tr>"
        + "".join(rows)
        + "</table><details><summary>Runtime totals</summary><pre>"
        + html.escape(json.dumps({k: v for k, v in summary.items() if k != "slots"}, indent=2))
        + "</pre></details></html>",
        encoding="utf-8",
    )


def _slot_item(slot, output):
    return {
        **slot,
        "process_status": "not_started",
        "returncode": None,
        "run_path": str(output / "runs" / slot["slot_id"]),
        "summary": None,
        "error_type": None,
        "error_status_code": None,
        "recorded_request_count": 0,
        "usage_available": False,
    }


def _dispatch(plan, slot, output, plan_hash, log_dir):
    run_path = output / "runs" / slot["slot_id"]
    spec_path = output / "specs" / (slot["slot_id"] + ".json")
    write_json(
        spec_path,
        {
            "slot": slot,
            "plan_path": str(output / "plan.json"),
            "plan_sha256": plan_hash,
            "pacing_state": str(output / "pacing.json"),
        },
    )
    item = _slot_item(slot, output)
    item["process_status"] = "failed"
    with (log_dir / (slot["slot_id"] + ".log")).open("x", encoding="utf-8") as log:
        try:
            completed = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--session-spec", str(spec_path)],
                stdout=log,
                stderr=log,
                timeout=plan["task_timeout_seconds"],
                check=False,
                env={**os.environ, "PYTHONUTF8": "1"},
            )
            item["returncode"] = completed.returncode
        except (subprocess.TimeoutExpired, OSError) as exc:
            item["error_type"] = type(exc).__name__
    try:
        result = read(run_path / "summary.json") if (run_path / "summary.json").is_file() else None
        item["summary"] = result
        if result:
            item["error_type"] = result.get("error_type")
            item["error_status_code"] = result.get("error_status_code")
        if item["returncode"] == 0 and result and result["status"] == "completed" and result["complete"]:
            item["process_status"] = "completed"
    except (ValueError, OSError) as exc:
        item["error_type"] = type(exc).__name__
    capture = run_path / "requests.jsonl"
    item["recorded_request_count"] = (
        sum(bool(line.strip()) for line in capture.read_bytes().splitlines()) if capture.exists() else 0
    )
    item["usage_available"] = bool(item["summary"] and item["summary"].get("stats") is not None)
    return item


def _finalize(output, plan, plan_hash, slots, *, paused, resume_count):
    summary = {
        "schema_version": 1,
        "protocol": plan["protocol"],
        "real_llm": plan["real_llm"],
        "slots": slots,
        "planned_slots": len(plan["slots"]),
        "completed_slots": sum(s["process_status"] == "completed" for s in slots),
        "not_started_slots": sum(s["process_status"] == "not_started" for s in slots),
        "paused": paused,
        "resume_count": resume_count,
        "reported_primary_requests": sum(
            s["summary"]["stats"]["request_count"] for s in slots if s["usage_available"]
        ),
        "captured_primary_requests": sum(s["recorded_request_count"] for s in slots),
        "reported_primary_tokens": sum(
            s["summary"]["stats"]["prompt_tokens"] + s["summary"]["stats"]["completion_tokens"]
            for s in slots
            if s["usage_available"]
        ),
        "unknown_session_usage": [
            s["slot_id"] for s in slots if s["process_status"] != "not_started" and not s["usage_available"]
        ],
        "distinct_recorded_processes": len({s["summary"]["pid"] for s in slots if s["summary"]}),
        "plan_sha256": plan_hash,
        "implementation_unchanged": all(digest(ROOT / p) == h for p, h in plan["source_hashes"].items()),
        "interpretation": (
            "All slots accounted for; not_started slots made no request; "
            "failed slots are retained, never replaced."
        ),
    }
    for name in ("summary.json", "index.html", "manifest.json"):
        (output / name).unlink(missing_ok=True)
    write_json(output / "summary.json", summary)
    render(output, summary)
    write_json(
        output / "manifest.json",
        {p.relative_to(output).as_posix(): digest(p) for p in sorted(output.rglob("*")) if p.is_file()},
    )
    return summary


def _run_slots(output, plan, plan_hash, pending, done, *, resume_count):
    slots = list(done)
    paused = False
    with (output / "slots.jsonl").open("a", encoding="utf-8") as ledger:
        for index, slot in enumerate(pending):
            item = _dispatch(plan, slot, output, plan_hash, output / "processes")
            slots.append(item)
            append(ledger, item)
            print(
                json.dumps(
                    {
                        "slot_id": item["slot_id"],
                        "process_status": item["process_status"],
                        "recipient_outcome": ((item.get("summary") or {}).get("scoring") or {}).get(
                            "recipient_outcome"
                        ),
                    }
                ),
                flush=True,
            )
            if item["error_status_code"] in PAUSE_STATUS_CODES:
                paused = True
                write_json(
                    output / "service-pause.json",
                    {
                        "slot_id": item["slot_id"],
                        "status_code": item["error_status_code"],
                        "error_type": item["error_type"],
                        "remaining": [s["slot_id"] for s in pending[index + 1 :]],
                    },
                )
                for remaining in pending[index + 1 :]:
                    rest = _slot_item(remaining, output)
                    slots.append(rest)
                    append(ledger, rest)
                break
    return _finalize(output, plan, plan_hash, slots, paused=paused, resume_count=resume_count)


def run_batch(output, *, protocol_name, live=False):
    plan = create_plan(output, protocol_name=protocol_name, live=live)
    plan_hash = digest(output / "plan.json")
    (output / "specs").mkdir()
    (output / "processes").mkdir()
    return _run_slots(output, plan, plan_hash, plan["slots"], [], resume_count=0)


def resume_batch(output):
    plan = read(output / "plan.json")
    plan_hash = digest(output / "plan.json")
    if not (output / "service-pause.json").is_file():
        raise ValueError("Resume requires a paused batch")
    if any(digest(ROOT / p) != h for p, h in plan["source_hashes"].items()):
        raise ValueError("Frozen runtime implementation changed; start a new named batch instead")
    previous = read(output / "summary.json")
    recorded = [
        json.loads(line)
        for line in (output / "slots.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    started = {s["slot_id"]: s for s in recorded if s["process_status"] != "not_started"}
    for slot in plan["slots"]:
        if slot["slot_id"] not in started and (output / "runs" / slot["slot_id"]).exists():
            raise ValueError(f"Slot {slot['slot_id']} has a run directory but no ledger entry; refusing to guess")
    pending = [slot for slot in plan["slots"] if slot["slot_id"] not in started]
    generation = previous["resume_count"] + 1
    (output / "slots.jsonl").rename(output / f"slots.before-resume-{generation}.jsonl")
    with (output / "slots.jsonl").open("x", encoding="utf-8") as ledger:
        for item in started.values():
            append(ledger, item)
    (output / "service-pause.json").rename(output / f"service-pause-{generation}.json")
    return _run_slots(output, plan, plan_hash, pending, list(started.values()), resume_count=generation)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--protocol", choices=sorted(case_r.PROTOCOLS), default=case_r.PILOT_PROTOCOL)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--session-spec", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args.session_spec:
            outcome = run_trial(args.session_spec.resolve())
            raise SystemExit(0 if outcome["complete"] else 1)
        if not args.output:
            parser.error("--output is required")
        outcome = (
            resume_batch(args.output.resolve())
            if args.resume
            else run_batch(args.output.resolve(), protocol_name=args.protocol, live=args.live)
        )
        print(
            json.dumps(
                {
                    k: outcome[k]
                    for k in (
                        "completed_slots",
                        "planned_slots",
                        "not_started_slots",
                        "paused",
                        "reported_primary_requests",
                        "reported_primary_tokens",
                    )
                }
            )
        )
        raise SystemExit(1 if outcome["paused"] else 0)
    except Exception as exc:
        print(json.dumps({"error_type": type(exc).__name__, "detail": str(exc)[:300]}), file=sys.stderr)
        raise SystemExit(1) from None

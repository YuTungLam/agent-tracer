#!/usr/bin/env python
"""H2 matched-framing runner on DeepSeek, through the shared budget guard.

Runs each (case, arm, repeat) of an H2 case file against the lab DeepSeek
pipeline and scores the declared authority argument with the typed outcome
oracle (``agentdojo_lab.h2_cases.classify_outcome``). It follows the no-defense
harness adapter pattern (``../harness/run_harness.py``): same vendored-AgentDojo
pin checks, same wire contract hook, same per-episode request ceiling, same
guard contract. It is launched only through ``../common/deepseek_route.py
run-stage`` with the lab venv python, and never reads a ``.env`` or a key.

Per planted arm it injects that arm's vector text (not an AgentDojo
injection-task attack), runs the user task once, extracts the executed calls and
the native post-state, and records a typed outcome
(attacker / other / legitimate / no_call / task_failure) plus AgentDojo utility.

Every episode writes one transcript, ``transcripts/<seq>-<arm>-r<repeat>-<hash>.json``
(a Windows-safe name; the episode id itself holds ``:`` and ``|``), recorded as the
record's ``transcript_path``. It keeps every attempt of the stock 3-attempt query loop
as ``attempts: [{index, ended, messages}]`` with the full AgentDojo message list
(assistant text, call ids, untruncated tool errors), plus the flat
``executed_calls`` / ``tool_outputs`` of all attempts. The task environment carries
over between attempts, so calls from every attempt count for the oracle. If an
attempt raises (an upstream 5xx or timeout, the request ceiling), the pipeline's
message list and environment as last output by the ToolsExecutor are salvaged, so
calls that already executed are still scored and saved. A transcript that cannot be
written stops the stage. Utility is read from the last attempt, as in stock AgentDojo.

``--plan-only`` expands the stage without any model call. ``--summarize-only``
rebuilds ``summary.json``. Saved benchmark text and model output are untrusted
data; this script never interprets them as instructions.

ADI-derived case files (ADI amendment, stages in ``stages.adi.json`` / ``config.adi.json``): the
case file's top-level ``tool_output_format`` is honoured (absent = yaml, the stock formatter, so SS runs
are unchanged; json = the ADI fork's formatter on the pipeline's ToolsExecutor), and
``--expect-content-sha256`` pins the file by its LF SHA-256. See ``README.md``.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(COMMON))

import h2_core as hc  # noqa: E402
from h2_core import SCHEMA_EPISODE, SCHEMA_PLAN, H2RunError  # noqa: E402

adi = hc.adi  # common/adi_compat.py: ADI-derived case files (ADI amendment)

ADAPTER_VERSION = "h2-deepseek-adapter/2"
TRANSCRIPT_SCHEMA = "h2-transcript/v2"
EXIT_OK, EXIT_CONFIG, EXIT_GUARD_HALT, EXIT_ERRORS, EXIT_OTHER = 0, 2, 3, 6, 1
MAX_CONSECUTIVE_ERRORS = 5
VENDOR_FILES = (
    "benchmark.py", "models.py", "functions_runtime.py", "types.py",
    "task_suite/task_suite.py", "task_suite/load_suites.py",
    "agent_pipeline/agent_pipeline.py", "agent_pipeline/tool_execution.py",
    "agent_pipeline/llms/openai_llm.py", "data/system_messages.yaml",
)


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def _append_jsonl(path: Path, value: Any) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, sort_keys=True, ensure_ascii=False) + "\n")


def _redact(text: str, token: str) -> str:
    return text.replace(token, "[REDACTED]") if token else text


# ---------------------------------------------------------------------------
# Lab / vendor pin checks (no network) -- same contract as the harness adapter
# ---------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=60, check=True).stdout.strip()


def lab_status(lab_root: Path) -> dict[str, Any]:
    from importlib.metadata import version

    import agentdojo
    import agentdojo_lab

    upstream = json.loads((lab_root / "upstream.json").read_text(encoding="utf-8"))
    vendor = lab_root / "vendor" / "agentdojo"
    vendor_src = (vendor / "src" / "agentdojo").resolve()
    actual = _git(vendor, "rev-parse", "HEAD")
    dirty = _git(vendor, "status", "--porcelain")
    imported = Path(agentdojo.__file__).resolve().parent
    lab_pkg = Path(agentdojo_lab.__file__).resolve().parent
    return {
        "upstream_expected": upstream,
        "vendor_commit": actual,
        "vendor_dirty": bool(dirty),
        "pin_matches": actual == upstream.get("commit") and not dirty,
        "agentdojo_is_vendored": imported == vendor_src,
        "agentdojo_version": version("agentdojo"),
        "agentdojo_lab_is_lab": lab_pkg == (lab_root / "src" / "agentdojo_lab").resolve(),
        "vendor_file_sha256": {name: hc.sha256_file(vendor_src / name) for name in VENDOR_FILES},
    }


def require_lab(status: dict[str, Any], expected_version: str) -> None:
    problems = []
    if not status["pin_matches"]:
        problems.append("vendored AgentDojo differs from upstream.json or has local changes")
    if not status["agentdojo_is_vendored"]:
        problems.append("agentdojo is not imported from the lab's vendored checkout")
    if not status["agentdojo_lab_is_lab"]:
        problems.append("agentdojo_lab is not imported from the given --lab-root")
    if status["agentdojo_version"] != expected_version:
        problems.append(f"agentdojo package version {status['agentdojo_version']} != {expected_version}")
    if problems:
        raise H2RunError("; ".join(problems))


# ---------------------------------------------------------------------------
# Runtime (pipeline + wire hook + per-episode request ceiling)
# ---------------------------------------------------------------------------


class WireAssertionError(RuntimeError):
    """An outbound request differed from the frozen lab DeepSeek wire contract (it was not sent)."""


class EpisodeRequestCeiling(RuntimeError):
    """The per-episode request ceiling was reached.

    Not an ``AbortAgentError`` on purpose: the stock 3-attempt loop would catch that, append an
    assistant message and treat the episode as finished (no run_error). Like any other failure of
    an attempt, the runner then salvages the calls that already executed from the ToolsExecutor
    record (``H2DeepSeekLLM.salvage_messages``). The model input at the refused call is attached
    for information only."""

    def __init__(self, message: str, messages: list[Any] | None = None, task_environment: Any = None) -> None:
        super().__init__(message)
        self.messages = list(messages or [])
        self.task_environment = task_environment


class _Context:
    def __init__(self) -> None:
        self.episode_id: str | None = None
        self.request_index = 0


def build_runtime(config: dict[str, Any], stage: dict[str, Any], *, base_url: str, token: str,
                  out_dir: Path, ctx: _Context, tool_output_format: str = "yaml") -> dict[str, Any]:
    """The undefended pipeline. ``tool_output_format`` is the case file's (``h2_core.tool_output_format``):
    ``"yaml"`` keeps AgentDojo's stock formatter untouched; ``"json"`` installs the ADI fork's formatter
    (``common/adi_compat.py``) on the pipeline's ToolsExecutor, so every tool output the agent sees -- and
    that a gate reusing this runtime (MELON) reads from the tool messages -- is rendered the same way."""
    import httpx
    import openai
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
    from agentdojo.functions_runtime import EmptyEnv
    from agentdojo_lab.deepseek_adapter import DeepSeekLLM
    from agentdojo_lab.pacing import RequestPacer

    llm_cfg = config["agent"]["llm"]
    # Per-stage temperature (protocol OPEN-1: 0.7 default, a T=0 sensitivity stage).
    # The wire assertion is pinned to the effective temperature so a request that
    # does not carry it is never sent.
    temperature = float(stage.get("temperature", llm_cfg["temperature"]))
    wire = json.loads(json.dumps(config["wire_request_assertion"]))
    wire["required_equals"]["temperature"] = temperature
    request_log = out_dir / "requests.jsonl"

    def hook(request: httpx.Request) -> None:
        if request.method != "POST" or not request.url.path.endswith("/chat/completions"):
            raise WireAssertionError(f"unexpected endpoint {request.method} {request.url.path}")
        content = request.content
        if token and token.encode("utf-8") in content:
            raise WireAssertionError("guard token appeared in a request body")
        body = json.loads(content)
        problems = [f"{k}={body.get(k)!r}" for k, v in wire["required_equals"].items() if body.get(k) != v]
        problems += [f"missing {k}" for k in wire["required_presence"] if k not in body]
        problems += [f"forbidden {k}" for k in wire["forbidden_fields"] if k in body]
        if problems:
            raise WireAssertionError("wire contract violated: " + ", ".join(problems))
        ctx.request_index += 1
        _append_jsonl(request_log, {"episode_id": ctx.episode_id, "n": ctx.request_index,
                                    "body_sha256": hc.sha256_bytes(content), "body_bytes": len(content),
                                    "messages": len(body.get("messages") or []), "tools": len(body.get("tools") or [])})

    timeout = float(stage.get("request_timeout_seconds", llm_cfg["request_timeout_seconds"]))
    http_client = httpx.Client(event_hooks={"request": [hook]}, timeout=timeout, trust_env=False)
    client = openai.OpenAI(api_key=token, base_url=base_url, max_retries=int(llm_cfg["sdk_max_retries"]),
                           timeout=timeout, http_client=http_client)

    class H2DeepSeekLLM(DeepSeekLLM):
        """The lab DeepSeekLLM plus the per-episode request ceiling and the salvage record.

        Salvage (B2): ``salvage_messages`` / ``salvage_env`` hold the pipeline's real message list and
        environment as last seen in the current attempt -- the output of the ToolsExecutor (every tool
        result appended so far, recorded by ``_RecordingExecutor``), or, before any tool ran, the first
        model input (system + user). The model's own inputs and outputs are not used after that, because
        a gate that reuses this runtime (MELON) also sends masked or copied conversations through it."""

        def __init__(self, *a: Any, ceiling: int, **k: Any) -> None:
            super().__init__(*a, **k)
            self.ceiling = ceiling
            self.episode_requests = 0
            self.begin_attempt()

        def begin_episode(self) -> None:
            self.episode_requests = 0
            self.begin_attempt()

        def begin_attempt(self) -> None:
            self.salvage_messages: list[Any] = []
            self.salvage_env: Any = None
            self.salvage_source: str | None = None

        def note_trajectory(self, messages: Any, env: Any) -> None:
            self.salvage_messages, self.salvage_env, self.salvage_source = list(messages), env, "tools-executor-output"

        def query(self, query: str, runtime: Any, env: Any = EmptyEnv(), messages: Any = (),  # type: ignore[override]
                  extra_args: dict | None = None):
            if not self.salvage_messages:
                self.salvage_messages, self.salvage_env, self.salvage_source = list(messages), env, "first-model-input"
            if self.episode_requests >= self.ceiling:
                raise EpisodeRequestCeiling(f"episode request ceiling {self.ceiling} reached", list(messages), env)
            self.episode_requests += 1
            return super().query(query, runtime, env, messages, extra_args)

    class _RecordingExecutor(BasePipelineElement):
        """AgentDojo's ToolsExecutor, unchanged, plus a record of its output for the salvage path."""

        def __init__(self, inner: Any, sink: Any) -> None:
            self.inner, self.sink = inner, sink
            self.name = getattr(inner, "name", None)

        def query(self, query: str, runtime: Any, env: Any = EmptyEnv(), messages: Any = (),
                  extra_args: dict | None = None):
            out = self.inner.query(query, runtime, env, messages, {} if extra_args is None else extra_args)
            self.sink.note_trajectory(out[3], out[2])
            return out

    tpm = config["agent"].get("pacing_tokens_per_minute")
    pacer = RequestPacer(int(tpm), out_dir / "pacing.json") if tpm else None
    llm = H2DeepSeekLLM(client, llm_cfg["model"], temperature=temperature,
                        max_tokens=int(llm_cfg["max_tokens"]), pacer=pacer,
                        ceiling=int(stage.get("episode_request_ceiling", 48)))
    pipeline = AgentPipeline.from_config(
        PipelineConfig(llm=llm, model_id=None, defense=None, system_message_name=None, system_message=None))
    loops = [e for e in pipeline.elements if isinstance(e, ToolsExecutionLoop)]
    if len(loops) != 1 or loops[0].max_iters != config["agent"]["tools_execution_loop_max_iters"]:
        raise H2RunError("pipeline does not have exactly one ToolsExecutionLoop with the configured max_iters")
    loop = loops[0]
    if sum(1 for e in loop.elements if isinstance(e, ToolsExecutor)) != 1:
        raise H2RunError("the ToolsExecutionLoop does not hold exactly one ToolsExecutor")
    formatter = adi.tool_output_formatter(tool_output_format)
    if formatter is not None:  # json only; yaml leaves the stock formatter in place
        for element in loop.elements:
            if isinstance(element, ToolsExecutor):
                element.output_formatter = formatter
    loop.elements = [_RecordingExecutor(e, llm) if isinstance(e, ToolsExecutor) else e for e in loop.elements]
    return {"client": client, "llm": llm, "pipeline": pipeline, "http_client": http_client,
            "tool_output_format": tool_output_format}


def _executed_calls_from_messages(messages: list[Any]) -> list[dict[str, Any]]:
    """Every executed tool call of one message list (one attempt), with its success flag.

    Read from the tool-result messages (which carry the FunctionCall and the tool
    error), so a call the tool rejected is recorded with success=False -- an attacker
    *attempt*, not an execution. ``_executed_calls_from_attempts`` joins the attempts.
    """
    out: list[dict[str, Any]] = []
    for m in messages:
        if m.get("role") != "tool":
            continue
        fc = m.get("tool_call")
        if fc is None:
            continue
        out.append({"function": fc.function, "args": dict(fc.args), "success": m.get("error") is None,
                    "error": (str(m.get("error"))[:200] if m.get("error") else None)})
    return out


def _executed_calls_from_attempts(attempts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Executed calls of every attempt, in order, each tagged with its attempt index. The task
    environment carries over between attempts, so an earlier attempt's call has a real effect."""
    out: list[dict[str, Any]] = []
    for a in attempts:
        for call in _executed_calls_from_messages(a["messages"]):
            out.append(dict(call, attempt=a["index"]))
    return out


def _tool_output_texts(messages: list[Any]) -> list[str]:
    texts = []
    for m in messages:
        if m.get("role") != "tool":
            continue
        texts.append("".join(b.get("content") or "" for b in (m.get("content") or []) if isinstance(b, dict)))
    return texts


def _jsonable(value: Any) -> Any:
    """AgentDojo messages (TypedDicts holding pydantic FunctionCalls) as plain JSON values."""
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def transcript_name(ep: dict[str, Any]) -> str:
    """Windows-safe, collision-free transcript file name.

    The episode id (``<case_id>|<ARM>|r<k>``) holds ``:`` and ``|``, which Windows refuses in a
    file name. The name keeps the plan position, the arm and the repeat for humans and a hash of
    the full episode id for uniqueness; it stays short so deep result paths stay under MAX_PATH.
    Readers find a transcript by its ``transcript_path`` or its internal ``episode_id`` field."""
    arm = re.sub(r"[^A-Za-z0-9_-]+", "_", str(ep.get("arm") or "x"))[:16]
    digest = hc.sha256_bytes(ep["episode_id"].encode("utf-8"))[:12]
    return f"{int(ep['seq']):05d}-{arm}-r{int(ep.get('repeat') or 0)}-{digest}.json"


def _write_transcript(transcripts_dir: Path, ep: dict[str, Any], attempts: list[dict[str, Any]],
                      executed: list[dict[str, Any]], salvaged: bool) -> tuple[str, str]:
    """Write the episode transcript atomically; returns (file name, sha256). Raises OSError."""
    tool_outputs = [t for a in attempts for t in _tool_output_texts(a["messages"])]
    doc = {
        "schema": TRANSCRIPT_SCHEMA, "episode_id": ep["episode_id"], "seq": ep["seq"],
        "attempts": [{"index": a["index"], "ended": a["ended"], "error_type": a.get("error_type"),
                      "salvaged": bool(a.get("salvaged")), "salvage_source": a.get("salvage_source"),
                      "messages": _jsonable(a["messages"])} for a in attempts],
        "salvaged_after_error": salvaged,
        # Flat views over all attempts, aligned one to one (each AgentDojo tool message has its call).
        "executed_calls": _jsonable(executed),
        "tool_outputs": tool_outputs,
    }
    name = transcript_name(ep)
    path = transcripts_dir / name
    data = json.dumps(doc, ensure_ascii=False, indent=1) + "\n"
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(data, encoding="utf-8")
    os.replace(tmp, path)
    return name, hc.sha256_file(path)


def run_one(ep: dict[str, Any], *, suites: dict[str, Any], authority_args: dict[str, Any],
            rt: dict[str, Any], token: str, transcripts_dir: Path | None) -> dict[str, Any]:
    from agentdojo.agent_pipeline.errors import AbortAgentError
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.task_suite.task_suite import (
        functions_stack_trace_from_messages,
        model_output_from_messages,
    )
    from agentdojo_lab.h2_cases import classify_outcome, normalize_value

    suite = suites[ep["suite"]]
    llm, pipeline = rt["llm"], rt["pipeline"]
    llm.begin_episode()
    user_task = suite.get_user_task_by_id(ep["user_task_id"])
    legit_set = ep.get("legitimate_set") or ([ep["legitimate_value"]] if ep.get("legitimate_value") else [])
    record: dict[str, Any] = {
        "schema": SCHEMA_EPISODE, "episode_id": ep["episode_id"], "seq": ep["seq"],
        "case_id": ep["case_id"], "arm": ep["arm"], "repeat": ep["repeat"],
        "suite": ep["suite"], "user_task": ep["user_task_id"], "target": ep["target"],
        "attacker_value_kind": ep.get("attacker_value_kind"),
        "attacker_executable": ep.get("attacker_executable"),
        "injection_payload_sha256": ep.get("injection_payload_sha256"),
        "started_at": _utc(), "scored": False, "run_error": False,
        "outcome": None, "subtype": None, "utility": None, "injection_exposed": None,
    }
    before = dict(llm.stats)
    t0 = time.monotonic()
    error: BaseException | None = None
    utility: bool | None = None
    run_error = False
    post_adds_x: bool | None = None
    attempts: list[dict[str, Any]] = []     # every attempt of the 3-attempt loop, salvaged ones included
    task_env: Any = None
    pre_json: str | None = None
    try:
        env = suite.load_and_inject_default_environment(ep["injections"])
        task_env = user_task.init_environment(env)
        pre_env = task_env.model_copy(deep=True)
        pre_json = pre_env.model_dump_json()
        runtime = FunctionsRuntime(suite.tools)
        model_output = None
        for index in range(3):
            llm.begin_attempt()
            try:
                _, _, task_env, messages, _ = pipeline.query(user_task.PROMPT, runtime, task_env)
                ended = "completed"
            except AbortAgentError as exc:
                task_env, messages, ended = exc.task_environment, exc.messages, "abort"
            except BaseException as exc:
                # Salvage what this attempt had already done (B2): the ToolsExecutor's last output holds
                # every tool result appended before the failure (see H2DeepSeekLLM).
                if llm.salvage_env is not None:
                    task_env = llm.salvage_env
                attempts.append({"index": index, "ended": "error", "error_type": type(exc).__name__,
                                 "salvaged": True, "salvage_source": llm.salvage_source,
                                 "messages": list(llm.salvage_messages or [])})
                raise
            attempts.append({"index": index, "ended": ended, "messages": list(messages)})
            model_output = model_output_from_messages(messages) if messages else None
            if model_output is not None:
                break
            attempts[-1]["ended"] = "no_output"
        last = attempts[-1]["messages"] if attempts else []
        stack = functions_stack_trace_from_messages(last)
        utility = bool(suite._check_user_task_utility(user_task, model_output or [], pre_env, task_env, stack))
    except BaseException as exc:  # noqa: BLE001 - recorded; the caller decides whether to stop
        if isinstance(exc, KeyboardInterrupt):
            raise
        error = exc
        run_error = True
        record.update({"run_error": True, "error_type": type(exc).__name__,
                       "error_status_code": getattr(exc, "status_code", None),
                       "error_message": _redact(str(exc), token)[:500],
                       "error_trace_tail": _redact("".join(traceback.format_exception(exc)[-3:]), token)[-800:]})

    # Calls, post-state and exposure come from every attempt, including one salvaged after an
    # error, so a call that executed before a 5xx, a timeout or the ceiling is still scored.
    executed = _executed_calls_from_attempts(attempts)
    if pre_json is not None and task_env is not None:
        try:
            # X as it appears inside a JSON dump (equal to X for every value without a quote, a backslash or a
            # control character, i.e. every SS value; an ADI value with such characters only exists escaped)
            needle = adi.state_needle(ep["attacker_value"])
            post_adds_x = task_env.model_dump_json().count(needle) > pre_json.count(needle)
        except Exception:  # noqa: BLE001 - an unreadable post-state stays None (unconfirmed)
            post_adds_x = None
    if "exposure_needles" in ep and attempts:
        # ADI episode (M2): exposure is the payload as the environment holds it, raw or JSON-escaped, per output
        # (X may be native, so an X test would almost always pass); the X test is kept as its own field
        from agentdojo_lab.h2_cases import collapse_ws, contains_value

        fmt = rt.get("tool_output_format", "yaml")
        outputs = [t for a in attempts for t in _tool_output_texts(a["messages"])]
        record["injection_exposed"] = adi.needle_seen(ep["exposure_needles"], outputs, fmt, collapse_ws)
        record["attacker_value_in_tool_output"] = adi.value_in_outputs(contains_value, outputs, ep["attacker_value"], fmt)
    elif ep["carries_attacker_value"] and attempts:
        seen = normalize_value("\n".join(t for a in attempts for t in _tool_output_texts(a["messages"])))
        # under the JSON formatter X may appear escaped; under YAML the needle list is [X] (unchanged)
        variants = adi.rendered_variants(ep["attacker_value"], rt.get("tool_output_format", "yaml"))
        record["injection_exposed"] = any(normalize_value(v) in seen for v in variants)

    # Score every episode, errored or not, so none drops out of the denominator. An
    # attacker call that executed before the error still counts (ranked above run_error).
    verdict = classify_outcome(
        ep["target"], legit_set, ep["attacker_value"], ep.get("decoy_value"), executed, utility,
        authority_args=authority_args, run_error=run_error,
        attacker_state_observable=bool(ep.get("attacker_state_observable")), post_state_adds_attacker=post_adds_x)
    salvaged = any(a.get("salvaged") for a in attempts)
    # Declared-sink calls carrying X (protocol 6.2 F1 in this undefended runner; gate SS-0 reads it).
    x_sink = hc.x_sink_calls(executed, ep["target"], ep["attacker_value"], authority_args, normalize_value)
    record.update({"scored": True, "outcome": verdict["outcome"], "subtype": verdict["subtype"],
                   "utility": utility, "oracle_details": verdict["details"],
                   "x_sink_called": x_sink["called"] > 0, "x_sink_calls": x_sink["called"],
                   "x_sink_calls_succeeded": x_sink["succeeded"],
                   "executed_sink_calls": verdict["details"]["sink_calls"],
                   "attempts_run": len(attempts), "attempt_endings": [a["ended"] for a in attempts],
                   "salvaged_after_error": salvaged})
    if transcripts_dir is not None:
        try:
            name, digest = _write_transcript(transcripts_dir, ep, attempts, executed, salvaged)
            record["transcript_path"] = name
            record["transcript_sha256"] = digest
        except OSError as exc:
            # Never silent: the caller stops the stage, because a paid episode without its
            # transcript cannot be re-scored or audited.
            record["transcript_error"] = f"{type(exc).__name__}: {_redact(str(exc), token)[:300]}"
    record["duration_seconds"] = round(time.monotonic() - t0, 2)
    record["finished_at"] = _utc()
    record["requests"] = llm.stats["request_count"] - before["request_count"]
    record["prompt_tokens"] = llm.stats["prompt_tokens"] - before["prompt_tokens"]
    record["completion_tokens"] = llm.stats["completion_tokens"] - before["completion_tokens"]
    record["_exception"] = error
    return record


def _load_prior(resume_dirs: list[Path], digest: str) -> list[dict[str, Any]]:
    prior: list[dict[str, Any]] = []
    for folder in resume_dirs:
        plan_path = folder / "episode_plan.json"
        if not plan_path.exists():
            raise H2RunError(f"--resume-from {folder} has no episode_plan.json")
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        if plan.get("plan_digest") != digest:
            raise H2RunError(f"--resume-from {folder} was planned from a different case file or stage")
        prior.extend(hc.read_jsonl(folder / "episodes.jsonl"))
    return prior


def _latest(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for record in records:
        seen.setdefault(record["episode_id"], record)
    return list(seen.values())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="H2 matched-framing runner on DeepSeek (guarded).")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--cases", type=Path, required=True, help="H2 case file from generate_h2_cases.py")
    parser.add_argument("--stage", required=True)
    parser.add_argument("--lab-root", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--resume-from", type=Path, action="append", default=[])
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--summarize-only", action="store_true")
    parser.add_argument("--expect-content-sha256", action="append", default=[],
                        help="refuse unless the case file's LF-normalised SHA-256 equals this (the ADI stages pass "
                             "{cases_sha256}); repeatable, every value must match")
    args = parser.parse_args(argv)

    config = json.loads(args.config.read_text(encoding="utf-8"))
    if args.stage not in config["stages"]:
        print(f"unknown stage {args.stage}", file=sys.stderr)
        return EXIT_CONFIG
    stage = config["stages"][args.stage]
    try:
        case_file = hc.load_case_file(args.cases)
        case_lf = adi.check_pin(args.cases, args.expect_content_sha256) if args.expect_content_sha256 else None
        fmt, declared = hc.tool_output_format(case_file), hc.declared_tool_output_format(case_file)
        fixed = (config.get("agent") or {}).get("tool_output_format")
        if fixed in adi.TOOL_OUTPUT_FORMATS and fixed != fmt:
            raise H2RunError(f"runner config {config.get('config_id')} fixes tool_output_format {fixed!r}, the case "
                             f"file's is {fmt!r} (use the config that honours the case file, e.g. config.adi.json)")
    except (H2RunError, adi.CaseFormatError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    mode = os.environ.get("AUDITOR_MODE") or ("plan-only" if args.plan_only else "unknown")
    price = config.get("price_snapshot")

    if args.summarize_only:
        plan = json.loads((out_dir / "episode_plan.json").read_text(encoding="utf-8"))
        records = _latest(_load_prior(args.resume_from, plan["plan_digest"]) + hc.read_jsonl(out_dir / "episodes.jsonl"))
        summary = hc.summarize(case_file, args.stage, plan["episodes"], records, mode=plan.get("mode", mode), price=price)
        _write_json(out_dir / "summary.json", summary)
        print(json.dumps({"summary": str(out_dir / "summary.json"), "complete": summary["complete"]}))
        return EXIT_OK

    try:
        planned = hc.expand_stage(case_file, stage)
    except H2RunError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    digest = hc.plan_digest(planned)
    plan_doc = {
        "schema": SCHEMA_PLAN, "adapter": ADAPTER_VERSION, "stage": args.stage, "mode": mode,
        "planned_at": _utc(), "plan_digest": digest,
        "case_file": {"path": str(args.cases), "config_sha256": case_file.get("config_sha256"),
                      "cases_digest": case_file.get("cases_digest"), "sha256": hc.sha256_file(args.cases)},
        "counts": hc.count_arms(planned), "episodes": planned,
    }
    # Recorded only when declared or pinned, so an SS plan (no format key, no pin) is unchanged.
    if case_lf is not None or declared is not None:
        plan_doc["case_file"]["sha256_lf"] = case_lf or hc.sha256_text_lf(args.cases)
    if declared is not None:
        plan_doc["tool_output_format"] = adi.formatter_record(fmt, declared)
    _write_json(out_dir / "episode_plan.json", plan_doc)
    if args.plan_only:
        print(json.dumps({"stage": args.stage, "counts": plan_doc["counts"], "plan_digest": digest}))
        return EXIT_OK

    lab_root = args.lab_root.resolve()
    from agentdojo.task_suite.load_suites import get_suite
    version = config["benchmark"]["benchmark_version"]
    suites = {name: get_suite(version, name) for name in ("workspace", "travel", "banking", "slack")}
    # Every planned episode's vectors exist in its suite before the first request (as MELON checks): a case on a
    # vector the stock suite lacks (e.g. ADI's fork-only injection_restaurant_msg) is refused here, not run as errors.
    vectors = {name: set(s.get_injection_vector_defaults()) for name, s in suites.items()}
    unknown = sorted({f"{ep['case_id']}: {v}" for ep in planned for v in ep["injections"] if v not in vectors[ep["suite"]]})
    if unknown:
        print(f"refused: injection vector(s) not in the {version} suites: {unknown[:5]}", file=sys.stderr)
        return EXIT_CONFIG
    authority_args = {k: list(v) for k, v in (case_file.get("authority_arg_map") or {}).items()}
    if not authority_args:
        print("refused: case file has no authority_arg_map (regenerate with the v2 generator)", file=sys.stderr)
        return EXIT_CONFIG
    transcripts_dir = out_dir / "transcripts"
    transcripts_dir.mkdir(parents=True, exist_ok=True)

    try:
        require_lab(lab_status(lab_root), config["benchmark"]["package_version"])
        from deepseek_route import RouteError, require_guard
        try:
            base_url, token = require_guard()
        except RouteError as exc:
            raise H2RunError(str(exc)) from None
        prior = _load_prior(args.resume_from, digest)
    except H2RunError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    import openai
    ctx = _Context()
    rt = build_runtime(config, stage, base_url=base_url, token=token, out_dir=out_dir, ctx=ctx, tool_output_format=fmt)
    receipt = {
        "schema": "h2-receipt/v1", "adapter": ADAPTER_VERSION, "stage": args.stage, "mode": mode,
        "backbone": os.environ.get("AUDITOR_BACKBONE"), "plan_digest": digest, "started_at": _utc(),
        "lab": lab_status(lab_root), "case_file": plan_doc["case_file"],
        "files_sha256": {"run_h2.py": hc.sha256_file(Path(__file__)), "h2_core.py": hc.sha256_file(HERE / "h2_core.py"),
                         "deepseek_route.py": hc.sha256_file(COMMON / "deepseek_route.py")},
        "python": {"executable": sys.executable, "version": platform.python_version(), "platform": platform.platform()},
        "resumed_from": [str(p) for p in args.resume_from], "skipped_as_started_before": 0,
        "deviations": config.get("deviations", []),
    }
    if declared is not None:  # declared (ADI) files only, so an SS receipt keeps its frozen keys (m3)
        receipt["tool_output_format"] = adi.formatter_record(fmt, declared)
        receipt["files_sha256"]["adi_compat.py"] = hc.sha256_file(COMMON / "adi_compat.py")
    started_before = {r["episode_id"] for r in prior}
    episodes_path = out_dir / "episodes.jsonl"
    exit_code, stop_reason, consecutive = EXIT_OK, "all planned episodes started", 0
    try:
        for ep in planned:
            if ep["episode_id"] in started_before:
                receipt["skipped_as_started_before"] += 1
                continue
            ctx.episode_id = ep["episode_id"]
            ctx.request_index = 0
            record = run_one(ep, suites=suites, authority_args=authority_args, rt=rt, token=token,
                             transcripts_dir=transcripts_dir)
            exc = record.pop("_exception")
            _append_jsonl(episodes_path, record)
            if record.get("transcript_error"):
                exit_code, stop_reason = EXIT_ERRORS, f"transcript not written for {ep['episode_id']}: {record['transcript_error']}"
                break
            if exc is None:
                consecutive = 0
                continue
            consecutive += 1
            if isinstance(exc, WireAssertionError) or isinstance(getattr(exc, "__cause__", None), WireAssertionError):
                exit_code, stop_reason = EXIT_CONFIG, "wire assertion failed (request not sent)"
                break
            if isinstance(exc, openai.APIStatusError) and exc.status_code in (401, 402, 403):
                exit_code, stop_reason = EXIT_GUARD_HALT, f"guard or provider refused with HTTP {exc.status_code}"
                break
            if consecutive >= MAX_CONSECUTIVE_ERRORS:
                exit_code, stop_reason = EXIT_ERRORS, f"{consecutive} consecutive episode errors"
                break
    except BaseException as exc:  # noqa: BLE001
        exit_code, stop_reason = EXIT_OTHER, f"{type(exc).__name__}: {_redact(str(exc), token)[:300]}"
    finally:
        records = _latest(prior + hc.read_jsonl(episodes_path))
        summary = hc.summarize(case_file, args.stage, planned, records, mode=mode, price=price)
        _write_json(out_dir / "summary.json", summary)
        mine = hc.read_jsonl(episodes_path)
        receipt.update({"finished_at": _utc(), "exit_code": exit_code, "stop_reason": stop_reason,
                        "episodes_jsonl_sha256": hc.sha256_file(episodes_path) if episodes_path.exists() else None,
                        "transcripts": {"schema": TRANSCRIPT_SCHEMA,
                                        "written": sum(1 for r in mine if r.get("transcript_path")),
                                        "failed": sum(1 for r in mine if r.get("transcript_error")),
                                        "episodes_this_run": len(mine),
                                        "salvaged_after_error": sum(1 for r in mine if r.get("salvaged_after_error")),
                                        "multi_attempt": sum(1 for r in mine if (r.get("attempts_run") or 0) > 1)},
                        "llm_stats": dict(rt["llm"].stats)})
        _write_json(out_dir / "h2_receipt.json", receipt)
        rt["http_client"].close()
    print(json.dumps({"stage": args.stage, "exit_code": exit_code, "stop_reason": stop_reason,
                      "started": summary["started_episodes"], "planned": summary["planned_episodes"],
                      "ss_contrast": summary.get("ss_contrast"), "usage": summary["usage"]}))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

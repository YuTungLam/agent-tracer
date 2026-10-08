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

``--plan-only`` expands the stage without any model call. ``--summarize-only``
rebuilds ``summary.json``. Saved benchmark text and model output are untrusted
data; this script never interprets them as instructions.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
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

ADAPTER_VERSION = "h2-deepseek-adapter/1"
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
    """The per-episode request ceiling was reached."""


class _Context:
    def __init__(self) -> None:
        self.episode_id: str | None = None
        self.request_index = 0


def build_runtime(config: dict[str, Any], stage: dict[str, Any], *, base_url: str, token: str,
                  out_dir: Path, ctx: _Context) -> dict[str, Any]:
    import httpx
    import openai
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop
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
        def __init__(self, *a: Any, ceiling: int, **k: Any) -> None:
            super().__init__(*a, **k)
            self.ceiling = ceiling
            self.episode_requests = 0

        def begin_episode(self) -> None:
            self.episode_requests = 0

        def query(self, *a: Any, **k: Any):  # type: ignore[override]
            if self.episode_requests >= self.ceiling:
                raise EpisodeRequestCeiling(f"episode request ceiling {self.ceiling} reached")
            self.episode_requests += 1
            return super().query(*a, **k)

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
    return {"client": client, "llm": llm, "pipeline": pipeline, "http_client": http_client}


def _executed_calls_from_messages(messages: list[Any]) -> list[dict[str, Any]]:
    """Every executed tool call, across all attempts, with its success flag.

    Read from the tool-result messages (which carry the FunctionCall and the tool
    error), so a call the tool rejected is recorded with success=False -- an attacker
    *attempt*, not an execution. Calls from earlier attempts of the 3-attempt loop
    are kept.
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


def _tool_output_texts(messages: list[Any]) -> list[str]:
    texts = []
    for m in messages:
        if m.get("role") != "tool":
            continue
        texts.append("".join(b.get("content") or "" for b in (m.get("content") or []) if isinstance(b, dict)))
    return texts


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
    executed: list[dict[str, Any]] = []
    messages: list[Any] = []
    utility: bool | None = None
    run_error = False
    post_adds_x: bool | None = None
    try:
        env = suite.load_and_inject_default_environment(ep["injections"])
        task_env = user_task.init_environment(env)
        pre_env = task_env.model_copy(deep=True)
        pre_json = pre_env.model_dump_json()
        runtime = FunctionsRuntime(suite.tools)
        model_output = None
        for _ in range(3):
            try:
                _, _, task_env, messages, _ = pipeline.query(user_task.PROMPT, runtime, task_env)
            except AbortAgentError as exc:
                task_env, messages = exc.task_environment, exc.messages
            model_output = model_output_from_messages(messages) if messages else None
            if model_output is not None:
                break
        executed = _executed_calls_from_messages(messages)
        stack = functions_stack_trace_from_messages(messages)
        utility = bool(suite._check_user_task_utility(user_task, model_output or [], pre_env, task_env, stack))
        post_json = task_env.model_dump_json()
        post_adds_x = post_json.count(ep["attacker_value"]) > pre_json.count(ep["attacker_value"])
        if ep["carries_attacker_value"]:
            seen = "\n".join(_tool_output_texts(messages))
            record["injection_exposed"] = normalize_value(ep["attacker_value"]) in normalize_value(seen)
    except BaseException as exc:  # noqa: BLE001 - recorded; the caller decides whether to stop
        if isinstance(exc, KeyboardInterrupt):
            raise
        error = exc
        run_error = True
        record.update({"run_error": True, "error_type": type(exc).__name__,
                       "error_status_code": getattr(exc, "status_code", None),
                       "error_message": _redact(str(exc), token)[:500],
                       "error_trace_tail": _redact("".join(traceback.format_exception(exc)[-3:]), token)[-800:]})

    # Score every episode, errored or not, so none drops out of the denominator. An
    # attacker call that executed before the error still counts (ranked above run_error).
    verdict = classify_outcome(
        ep["target"], legit_set, ep["attacker_value"], ep.get("decoy_value"), executed, utility,
        authority_args=authority_args, run_error=run_error,
        attacker_state_observable=bool(ep.get("attacker_state_observable")), post_state_adds_attacker=post_adds_x)
    record.update({"scored": True, "outcome": verdict["outcome"], "subtype": verdict["subtype"],
                   "utility": utility, "oracle_details": verdict["details"],
                   "executed_sink_calls": verdict["details"]["sink_calls"]})
    if transcripts_dir is not None:
        try:
            tpath = transcripts_dir / (ep["episode_id"].replace("/", "_").replace("|", "__") + ".json")
            tpath.write_text(json.dumps({"episode_id": ep["episode_id"], "executed_calls": executed,
                                         "tool_outputs": _tool_output_texts(messages)},
                                        ensure_ascii=False, indent=2), encoding="utf-8")
            record["transcript_path"] = tpath.name
        except OSError:
            pass
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
    args = parser.parse_args(argv)

    config = json.loads(args.config.read_text(encoding="utf-8"))
    if args.stage not in config["stages"]:
        print(f"unknown stage {args.stage}", file=sys.stderr)
        return EXIT_CONFIG
    stage = config["stages"][args.stage]
    case_file = hc.load_case_file(args.cases)
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
    _write_json(out_dir / "episode_plan.json", plan_doc)
    if args.plan_only:
        print(json.dumps({"stage": args.stage, "counts": plan_doc["counts"], "plan_digest": digest}))
        return EXIT_OK

    lab_root = args.lab_root.resolve()
    from agentdojo.task_suite.load_suites import get_suite
    version = config["benchmark"]["benchmark_version"]
    suites = {name: get_suite(version, name) for name in ("workspace", "travel", "banking", "slack")}
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
    rt = build_runtime(config, stage, base_url=base_url, token=token, out_dir=out_dir, ctx=ctx)
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
        receipt.update({"finished_at": _utc(), "exit_code": exit_code, "stop_reason": stop_reason,
                        "episodes_jsonl_sha256": hc.sha256_file(episodes_path) if episodes_path.exists() else None,
                        "llm_stats": dict(rt["llm"].stats)})
        _write_json(out_dir / "h2_receipt.json", receipt)
        rt["http_client"].close()
    print(json.dumps({"stage": args.stage, "exit_code": exit_code, "stop_reason": stop_reason,
                      "started": summary["started_episodes"], "planned": summary["planned_episodes"],
                      "ss_contrast": summary.get("ss_contrast"), "usage": summary["usage"]}))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python
"""No-defense AgentDojo v1.2.2 important_instructions harness check on DeepSeek, through the budget guard.

Launch only through the shared stage runner, with the LAB venv python:

    python ../common/deepseek_route.py run-stage --artifact harness --stage S1 \
        --artifact-root <agent-tracer>/packages/agentdojo-lab --cap-usd 0.10 --cap-tokens 400000 ...

The runner starts the guard, gives this process only the guard URL and a
per-run token, and runs it from a scratch cwd with no ``.env`` on its path.
This script never reads a ``.env`` file or a provider key.

What it does, per planned episode (one attempt, never retried):

* builds the stock AgentDojo tool-calling pipeline (default system message,
  ``ToolsExecutionLoop`` max_iters 15) around the lab's ``DeepSeekLLM``
  (``agentdojo_lab/deepseek_adapter.py``: thinking disabled, ``max_tokens``,
  temperature 0, no SDK retries), on an openai client pointed at the guard;
* registers ``MODEL_NAMES["deepseek-flash"] = "DeepSeek"`` at runtime so the
  stock ``important_instructions`` payload addresses "DeepSeek" (SIEVE v3
  App. B prints the same wording); no vendored file is edited;
* calls AgentDojo's own ``run_task_with_injection_tasks`` (attacked) or
  ``run_task_without_injection_tasks`` (benign, injection-as-user) for that
  one episode, so utility and security come from the stock oracles and the
  stock per-episode JSON log is written;
* checks every outbound request body against the lab DeepSeek wire contract
  before it is sent, and appends one ``episodes.jsonl`` line with ids,
  outcomes, attempts and usage (no prompt text).

``--plan-only`` expands and writes the episode plan without any model call.
``--summarize-only`` rebuilds ``summary.json`` from ``episodes.jsonl`` files.
Benchmark text and model output are untrusted data; this script never
interprets them.
"""

from __future__ import annotations

import argparse
import hashlib
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

from harness_core import (  # noqa: E402
    FROZEN_AGENT,
    SCHEMA_EPISODE,
    SCHEMA_PLAN,
    HarnessConfigError,
    count_kinds,
    expand_stage,
    load_config,
    plan_digest,
    read_jsonl,
    sha256_bytes,
    sha256_file,
    summarize,
)

ADAPTER_VERSION = "harness-deepseek-adapter/1"
EXIT_OK, EXIT_CONFIG, EXIT_GUARD_HALT, EXIT_ERRORS, EXIT_OTHER = 0, 2, 3, 6, 1
MAX_CONSECUTIVE_ERRORS = 5
VENDOR_FILES = (
    "benchmark.py",
    "models.py",
    "functions_runtime.py",
    "types.py",
    "logging.py",
    "task_suite/task_suite.py",
    "task_suite/load_suites.py",
    "attacks/base_attacks.py",
    "attacks/important_instructions_attacks.py",
    "agent_pipeline/agent_pipeline.py",
    "agent_pipeline/tool_execution.py",
    "agent_pipeline/llms/openai_llm.py",
    "agent_pipeline/basic_elements.py",
    "data/system_messages.yaml",
)
LAB_FILES = (
    "upstream.json",
    "src/agentdojo_lab/deepseek_adapter.py",
    "src/agentdojo_lab/pacing.py",
)


class WireAssertionError(RuntimeError):
    """An outbound request differed from the frozen lab DeepSeek wire contract (it was not sent)."""


class EpisodeRequestCeiling(RuntimeError):
    """The per-episode request ceiling was reached (the stock bound is 48 = 3 attempts x 16 calls)."""


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def _append_jsonl(path: Path, value: Any) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, sort_keys=True, ensure_ascii=False) + "\n")


def _redact(text: str, secrets_: list[str]) -> str:
    for secret in secrets_:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return text


# ---------------------------------------------------------------------------
# Lab and vendor checks (no network)
# ---------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=60, check=True
    ).stdout.strip()


def lab_status(lab_root: Path, suites: list[str]) -> dict[str, Any]:
    """Pin and identity checks for the lab checkout and its vendored AgentDojo."""
    import agentdojo
    import agentdojo_lab

    upstream = json.loads((lab_root / "upstream.json").read_text(encoding="utf-8"))
    vendor = lab_root / "vendor" / "agentdojo"
    vendor_src = (vendor / "src" / "agentdojo").resolve()
    actual = _git(vendor, "rev-parse", "HEAD")
    dirty = _git(vendor, "status", "--porcelain")
    imported = Path(agentdojo.__file__).resolve().parent
    lab_pkg = Path(agentdojo_lab.__file__).resolve().parent
    from importlib.metadata import version

    suite_files = sorted(
        p for p in (vendor_src / "default_suites").rglob("*.py")
    ) + sorted(
        p for s in suites for p in (vendor_src / "data" / "suites" / s).rglob("*.yaml")
    )
    digest = hashlib.sha256()
    for path in suite_files:
        digest.update(str(path.relative_to(vendor_src)).replace("\\", "/").encode())
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).hexdigest().encode())
        digest.update(b"\n")
    status = {
        "upstream_expected": upstream,
        "vendor_commit": actual,
        "vendor_dirty": bool(dirty),
        "pin_matches": actual == upstream.get("commit") and not dirty,
        "agentdojo_imported_from": str(imported),
        "agentdojo_is_vendored": imported == vendor_src,
        "agentdojo_version": version("agentdojo"),
        "agentdojo_lab_imported_from": str(lab_pkg),
        "agentdojo_lab_is_lab": lab_pkg == (lab_root / "src" / "agentdojo_lab").resolve(),
        "openai_version": version("openai"),
        "httpx_version": version("httpx"),
        "vendor_file_sha256": {name: sha256_file(vendor_src / name) for name in VENDOR_FILES},
        "lab_file_sha256": {name: sha256_file(lab_root / name) for name in LAB_FILES},
        "suite_code_and_data": {"files": len(suite_files), "digest_sha256": digest.hexdigest()},
    }
    return status


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
        raise HarnessConfigError("; ".join(problems))


# ---------------------------------------------------------------------------
# Episode machinery (imports AgentDojo lazily so --summarize-only needs nothing)
# ---------------------------------------------------------------------------


class _Context:
    """Mutable per-episode context shared with the request hook."""

    def __init__(self) -> None:
        self.episode_id: str | None = None
        self.request_index = 0
        self.records: list[dict[str, Any]] = []


def build_runtime(config: dict[str, Any], stage: dict[str, Any], *, base_url: str, token: str,
                  out_dir: Path, ctx: _Context) -> dict[str, Any]:
    import httpx
    import openai
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop
    from agentdojo.functions_runtime import EmptyEnv
    from agentdojo.models import MODEL_NAMES
    from agentdojo_lab.deepseek_adapter import DeepSeekLLM
    from agentdojo_lab.pacing import RequestPacer

    agent = config["agent"]
    llm_cfg = agent["llm"]
    wire = config["wire_request_assertion"]
    capture = bool(stage.get("capture_request_bodies"))
    body_dir = out_dir / "request_bodies"
    request_log = out_dir / "requests.jsonl"

    def hook(request: httpx.Request) -> None:
        if request.method != "POST" or not request.url.path.endswith("/chat/completions"):
            raise WireAssertionError(f"unexpected endpoint {request.method} {request.url.path}")
        content = request.content
        if token and token.encode("utf-8") in content:
            raise WireAssertionError("guard token appeared in a request body")
        body = json.loads(content)
        problems = [
            f"{key}={body.get(key)!r}" for key, value in wire["required_equals"].items() if body.get(key) != value
        ]
        problems += [f"missing {key}" for key in wire["required_presence"] if key not in body]
        problems += [f"forbidden {key}" for key in wire["forbidden_fields"] if key in body]
        if problems:
            raise WireAssertionError("wire contract violated: " + ", ".join(problems))
        ctx.request_index += 1
        record = {
            "episode_id": ctx.episode_id,
            "n": ctx.request_index,
            "body_sha256": sha256_bytes(content),
            "body_bytes": len(content),
            "messages": len(body.get("messages") or []),
            "tools": len(body.get("tools") or []),
        }
        _append_jsonl(request_log, record)
        if capture:
            body_dir.mkdir(parents=True, exist_ok=True)
            name = (ctx.episode_id or "unknown").replace(":", "__")
            _append_jsonl(body_dir / f"{name}.jsonl", {**record, "body": body})

    # A stage may raise the client timeout (the DRY stage does, for a slow local GPU); paid stages use the frozen value.
    timeout = float(stage.get("request_timeout_seconds", llm_cfg["request_timeout_seconds"]))
    http_client = httpx.Client(event_hooks={"request": [hook]}, timeout=timeout, trust_env=False)
    client = openai.OpenAI(
        api_key=token,
        base_url=base_url,
        max_retries=int(llm_cfg["sdk_max_retries"]),
        timeout=timeout,
        http_client=http_client,
    )

    class HarnessDeepSeekLLM(DeepSeekLLM):
        def __init__(self, *args: Any, ceiling: int, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self.ceiling = ceiling
            self.episode_requests = 0

        def begin_episode(self) -> None:
            self.episode_requests = 0

        def query(self, *args: Any, **kwargs: Any):  # type: ignore[override]
            if self.episode_requests >= self.ceiling:
                raise EpisodeRequestCeiling(f"episode request ceiling {self.ceiling} reached")
            self.episode_requests += 1
            return super().query(*args, **kwargs)

    tpm = agent.get("pacing_tokens_per_minute")
    pacer = RequestPacer(int(tpm), out_dir / "pacing.json") if tpm else None
    llm = HarnessDeepSeekLLM(
        client,
        llm_cfg["model"],
        temperature=float(llm_cfg["temperature"]),
        max_tokens=int(llm_cfg["max_tokens"]),
        pacer=pacer,
        ceiling=int(stage.get("episode_request_ceiling", 48)),
    )
    pipeline = AgentPipeline.from_config(
        PipelineConfig(llm=llm, model_id=None, defense=None, system_message_name=None, system_message=None)
    )
    loops = [e for e in pipeline.elements if isinstance(e, ToolsExecutionLoop)]
    if len(loops) != 1 or loops[0].max_iters != agent["tools_execution_loop_max_iters"]:
        raise HarnessConfigError("pipeline does not have exactly one ToolsExecutionLoop with max_iters 15")
    if pipeline.name != config["attack"]["pipeline_name"]:
        raise HarnessConfigError(f"pipeline name {pipeline.name!r} != config {config['attack']['pipeline_name']!r}")

    attack_cfg = config["attack"]
    if attack_cfg["model_name_key"] not in pipeline.name:
        raise HarnessConfigError("model_name_key must occur in the pipeline name")
    existing = MODEL_NAMES.get(attack_cfg["model_name_key"])
    if existing not in (None, attack_cfg["model_name"]):
        raise HarnessConfigError("MODEL_NAMES already maps the key to a different name")
    MODEL_NAMES[attack_cfg["model_name_key"]] = attack_cfg["model_name"]

    class AttemptCounter(BasePipelineElement):
        """Counts stock pipeline.query attempts (TaskSuite retries up to 3 on empty output)."""

        def __init__(self, inner: Any) -> None:
            self.inner = inner
            self.name = inner.name
            self.attempts = 0

        def query(self, query, runtime, env=None, messages=(), extra_args=None):  # type: ignore[override]
            self.attempts += 1
            return self.inner.query(
                query, runtime, EmptyEnv() if env is None else env, messages,
                extra_args if extra_args is not None else {},
            )

    return {"client": client, "llm": llm, "pipeline": AttemptCounter(pipeline), "http_client": http_client}


def run_one(ep: dict[str, Any], *, suites: dict[str, Any], attacks: dict[str, Any], rt: dict[str, Any],
            config: dict[str, Any], log_root: Path, ctx: _Context, token: str) -> dict[str, Any]:
    from agentdojo.benchmark import run_task_with_injection_tasks, run_task_without_injection_tasks
    from agentdojo.logging import OutputLogger

    class QuietLogger(OutputLogger):
        """OutputLogger that keeps the logdir for TraceLogger but echoes nothing to the console."""

        def log(self, messages, **kwargs):  # noqa: D401
            self.messages = list(messages)

    version = config["benchmark"]["benchmark_version"]
    suite = suites[ep["suite"]]
    llm, pipeline = rt["llm"], rt["pipeline"]
    llm.begin_episode()
    pipeline.attempts = 0
    ctx.episode_id = ep["episode_id"]
    ctx.request_index = 0
    before = dict(llm.stats)
    record: dict[str, Any] = {
        "schema": SCHEMA_EPISODE,
        "episode_id": ep["episode_id"],
        "seq": ep["seq"],
        "kind": ep["kind"],
        "suite": ep["suite"],
        "user_task": ep["user_task"],
        "injection_task": ep["injection_task"],
        "attack": ep["attack"],
        "started_at": _utc(),
        "scored": False,
        "utility": None,
        "security": None,
    }
    t0 = time.monotonic()
    error: BaseException | None = None
    with QuietLogger(str(log_root)):
        try:
            if ep["kind"] == "attacked":
                user_task = suite.get_user_task_by_id(ep["user_task"])
                injection_task = suite.get_injection_task_by_id(ep["injection_task"])
                injections = attacks[ep["suite"]].attack(user_task, injection_task)
                record["injection_vectors"] = sorted(injections)
                record["injection_payload_sha256"] = sha256_bytes(
                    json.dumps(injections, sort_keys=True, ensure_ascii=False).encode("utf-8")
                )
                utility, security = run_task_with_injection_tasks(
                    suite, pipeline, user_task, attacks[ep["suite"]], None, True, [injection_task.ID], version
                )
                key = (user_task.ID, injection_task.ID)
                record["utility"], record["security"] = bool(utility[key]), bool(security[key])
                log_path = Path(pipeline.name.replace("/", "_")) / suite.name / user_task.ID / "important_instructions" / f"{injection_task.ID}.json"
            else:
                task = (
                    suite.get_user_task_by_id(ep["user_task"]) if ep["kind"] == "benign"
                    else suite.get_injection_task_by_id(ep["injection_task"])
                )
                utility, security = run_task_without_injection_tasks(suite, pipeline, task, None, True, version)
                record["utility"], record["security"] = bool(utility), bool(security)
                log_path = Path(pipeline.name.replace("/", "_")) / suite.name / task.ID / "none" / "none.json"
            record["scored"] = True
            record["log_path"] = str(log_path).replace("\\", "/")
            try:
                logged = json.loads((log_root / log_path).read_text(encoding="utf-8"))
                stock_error = logged.get("error")
            except (OSError, ValueError):
                stock_error = None
            record["stock_logged_error"] = _redact(str(stock_error), [token])[:300] if stock_error else None
        except BaseException as exc:  # noqa: BLE001 - recorded; the caller decides whether to stop
            if isinstance(exc, KeyboardInterrupt):
                raise
            error = exc
            record["error_type"] = type(exc).__name__
            record["error_status_code"] = getattr(exc, "status_code", None)
            record["error_message"] = _redact(str(exc), [token])[:500]
            record["error_trace_tail"] = _redact("".join(traceback.format_exception(exc)[-3:]), [token])[-800:]
    record["duration_seconds"] = round(time.monotonic() - t0, 2)
    record["finished_at"] = _utc()
    record["pipeline_attempts"] = pipeline.attempts
    record["requests"] = llm.stats["request_count"] - before["request_count"]
    record["prompt_tokens"] = llm.stats["prompt_tokens"] - before["prompt_tokens"]
    record["completion_tokens"] = llm.stats["completion_tokens"] - before["completion_tokens"]
    record["request_bodies_checked"] = ctx.request_index
    record["_exception"] = error
    return record


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _load_prior(resume_dirs: list[Path], digest: str) -> list[dict[str, Any]]:
    prior: list[dict[str, Any]] = []
    for folder in resume_dirs:
        plan_path = folder / "episode_plan.json"
        if not plan_path.exists():
            raise HarnessConfigError(f"--resume-from {folder} has no episode_plan.json")
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        if plan.get("plan_digest") != digest:
            raise HarnessConfigError(f"--resume-from {folder} was planned from a different config or stage")
        for row in read_jsonl(folder / "episodes.jsonl"):
            row["from_run"] = str(folder)
            prior.append(row)
    return prior


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="No-defense AgentDojo harness check on DeepSeek (guarded).")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--stage", required=True)
    parser.add_argument("--lab-root", type=Path, required=True, help="packages/agentdojo-lab checkout (venv + vendor)")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--resume-from", type=Path, action="append", default=[],
                        help="earlier out-dir of the same stage; its started episodes are skipped, never retried")
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--summarize-only", action="store_true")
    args = parser.parse_args(argv)

    config_path = args.config.resolve()
    config = load_config(config_path)
    if args.stage not in config["stages"]:
        print(f"unknown stage {args.stage}", file=sys.stderr)
        return EXIT_CONFIG
    stage = config["stages"][args.stage]
    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    mode = os.environ.get("AUDITOR_MODE") or ("plan-only" if args.plan_only else "unknown")

    if args.summarize_only:
        plan = json.loads((out_dir / "episode_plan.json").read_text(encoding="utf-8"))
        records = _load_prior(args.resume_from, plan["plan_digest"]) + read_jsonl(out_dir / "episodes.jsonl")
        summary = summarize(config, args.stage, plan["episodes"], _latest(records), mode=plan.get("mode", mode))
        _write_json(out_dir / "summary.json", summary)
        print(json.dumps({"summary": str(out_dir / "summary.json"), "complete": summary["complete"]}))
        return EXIT_OK

    lab_root = args.lab_root.resolve()
    from agentdojo.task_suite.load_suites import get_suite

    version = config["benchmark"]["benchmark_version"]
    suites = {name: get_suite(version, name) for name in ("workspace", "travel", "banking", "slack")}
    index = {n: {"user_tasks": list(s.user_tasks), "injection_tasks": list(s.injection_tasks)} for n, s in suites.items()}
    try:
        planned = expand_stage(config, args.stage, index)
    except HarnessConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    stage_suites = sorted({e["suite"] for e in planned})
    status = lab_status(lab_root, stage_suites)
    digest = plan_digest(planned)
    plan_doc = {
        "schema": SCHEMA_PLAN,
        "adapter": ADAPTER_VERSION,
        "config_id": config["config_id"],
        "config_sha256": sha256_file(config_path),
        "stage": args.stage,
        "mode": mode,
        "planned_at": _utc(),
        "plan_digest": digest,
        "counts": count_kinds(planned),
        "episodes": planned,
    }
    _write_json(out_dir / "episode_plan.json", plan_doc)
    if args.plan_only:
        print(json.dumps({"stage": args.stage, "counts": plan_doc["counts"], "plan_digest": digest,
                          "lab_pin_matches": status["pin_matches"]}))
        return EXIT_OK

    try:
        require_lab(status, config["benchmark"]["package_version"])
        from deepseek_route import RouteError, require_guard

        try:
            base_url, token = require_guard()
        except RouteError as exc:
            raise HarnessConfigError(str(exc)) from None
        prior = _load_prior(args.resume_from, digest)
    except HarnessConfigError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    import openai
    from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack

    ctx = _Context()
    rt = build_runtime(config, stage, base_url=base_url, token=token, out_dir=out_dir, ctx=ctx)
    attacks = {}
    for name in stage_suites:
        attack = ImportantInstructionsAttack(suites[name], rt["pipeline"])
        if attack.model_name != config["attack"]["model_name"] or attack.user_name != config["attack"]["user_name"]:
            print("refused: attack names differ from the frozen config", file=sys.stderr)
            return EXIT_CONFIG
        attacks[name] = attack

    receipt = {
        "schema": "harness-receipt/v1",
        "adapter": ADAPTER_VERSION,
        "config_id": config["config_id"],
        "config_sha256": plan_doc["config_sha256"],
        "stage": args.stage,
        "mode": mode,
        "backbone": os.environ.get("AUDITOR_BACKBONE"),
        "guard_stage": os.environ.get("AUDITOR_STAGE"),
        "plan_digest": digest,
        "started_at": _utc(),
        "lab": status,
        "agent_frozen": FROZEN_AGENT,
        "attack": {"name": "important_instructions", "model_name": attacks[stage_suites[0]].model_name,
                   "user_name": attacks[stage_suites[0]].user_name},
        "files_sha256": {
            "run_harness.py": sha256_file(Path(__file__)),
            "harness_core.py": sha256_file(HERE / "harness_core.py"),
            "deepseek_route.py": sha256_file(COMMON / "deepseek_route.py"),
        },
        "python": {"executable": sys.executable, "version": platform.python_version(), "platform": platform.platform()},
        "resumed_from": [str(p) for p in args.resume_from],
        "skipped_as_started_before": 0,
        "deviations": config.get("deviations", []),
    }
    started_before = {r["episode_id"] for r in prior}
    log_root = out_dir / "agentdojo_logs"
    episodes_path = out_dir / "episodes.jsonl"
    exit_code, stop_reason = EXIT_OK, "all planned episodes started"
    consecutive = 0
    try:
        for ep in planned:
            if ep["episode_id"] in started_before:
                receipt["skipped_as_started_before"] += 1
                continue
            record = run_one(ep, suites=suites, attacks=attacks, rt=rt, config=config,
                             log_root=log_root, ctx=ctx, token=token)
            exc = record.pop("_exception")
            _append_jsonl(episodes_path, record)
            _write_json(out_dir / "progress.json", {"last_seq": ep["seq"], "last_episode": ep["episode_id"],
                                                    "planned": len(planned), "at": _utc()})
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
        exit_code, stop_reason = EXIT_OTHER, f"{type(exc).__name__}: {_redact(str(exc), [token])[:300]}"
    finally:
        records = _latest(prior + read_jsonl(episodes_path))
        summary = summarize(config, args.stage, planned, records, mode=mode)
        _write_json(out_dir / "summary.json", summary)
        receipt.update({"finished_at": _utc(), "exit_code": exit_code, "stop_reason": stop_reason,
                        "episodes_jsonl_sha256": sha256_file(episodes_path) if episodes_path.exists() else None,
                        "llm_stats": dict(rt["llm"].stats)})
        _write_json(out_dir / "harness_receipt.json", receipt)
        rt["http_client"].close()
    print(json.dumps({"stage": args.stage, "exit_code": exit_code, "stop_reason": stop_reason,
                      "started": summary["started_episodes"], "planned": summary["planned_episodes"],
                      "usage": summary["usage"]}))
    return exit_code


def _latest(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One record per episode id: the first started attempt wins (episodes are never retried)."""
    seen: dict[str, dict[str, Any]] = {}
    for record in records:
        seen.setdefault(record["episode_id"], record)
    return list(seen.values())


if __name__ == "__main__":
    raise SystemExit(main())

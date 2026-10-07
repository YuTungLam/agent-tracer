#!/usr/bin/env python
"""Run the released AttriGuard gate with DeepSeek (deepseek-flash) through the local budget guard.

Run with the ARTIFACT's own venv python, from a scratch cwd that holds no .env:

    <attriguard .venv python> run_attriguard.py --artifact-src <usenix-artifacts/main/pipeline> \
        --config config.template.json --stage S1 --out <run dir>

Paths can also come from the environment: ATTRIGUARD_SRC (artifact pipeline dir) and AUDITOR_OUT (run dir).

Model traffic: every request (target agent, shadow, attenuation, judge) goes through one openai client whose
base URL is AUDITOR_GUARD_URL or OPENAI_BASE_URL, and that URL MUST be loopback (the budget guard). The adapter
reads OPENAI_API_KEY from the environment only to hand it to the client (the guard may hold the real key);
it never reads .env files, never prints the key, and redacts it from any error it records.

Nothing in the artifact is edited. The adapter (1) passes the artifact's own OpenAILLM as PipelineConfig.llm,
(2) replaces my_agent_pipeline._get_attriguard_aux_llms at runtime with the same OpenAILLM settings as the
released "openai" backend (temperature 0.2, top_p 0.9) but on the routed client, and (3) swaps in a subclass of
AttriGuardExecutionLoop whose _fuzzy_survive only records which code path decided each call.
Deviations are listed in README.md and written to the run receipt.

Use --plan-only to expand and write the episode plan without importing the artifact or calling any model.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import platform
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from attriguard_deepseek import (  # noqa: E402
    DEEPSEEK_MODEL,
    AdapterRefusal,
    JudgeProbe,
    RoutedClient,
    RunContext,
    UsageMeter,
    classify_route,
    expand_stage,
    redact,
    require_loopback_base_url,
    summarize_episodes,
)

ADAPTER_VERSION = "attriguard-deepseek-adapter/1"
ARTIFACT_FILES = (
    "AttriGuard.py",
    "my_agent_pipeline.py",
    "openai_llm_compat.py",
    "my_benchmark.py",
    "runtime_patches.py",
    "pydantic_fix.py",
    "combine_attack.py",
)


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _append_jsonl(path: Path, record: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--artifact-src", default=os.environ.get("ATTRIGUARD_SRC"),
                   help="directory src/usenix-artifacts/main/pipeline of the unpacked artifact (env ATTRIGUARD_SRC)")
    p.add_argument("--config", default=str(HERE / "config.template.json"))
    p.add_argument("--stage", required=True)
    p.add_argument("--out", default=os.environ.get("AUDITOR_OUT"), help="run directory (env AUDITOR_OUT)")
    p.add_argument("--guard-url", default=None,
                   help="loopback guard base URL; default AUDITOR_GUARD_URL, then OPENAI_BASE_URL")
    p.add_argument("--max-episodes", type=int, default=None, help="stop after this many NEW episodes")
    p.add_argument("--logprobs", choices=("auto", "off"), default=None,
                   help="judge logprobs handling (default from config backbone.judge_logprobs)")
    p.add_argument("--plan-only", action="store_true", help="write the expanded plan and exit; no model calls")
    p.add_argument("--timeout", type=float, default=None, help="per-request client timeout in seconds")
    p.add_argument("--resume-from", action="append", default=[], metavar="ADAPTER_DIR",
                   help="earlier adapter run dir of the SAME stage, config and mode; its done episodes are carried over")
    return p.parse_args(argv)


def _load_config(path: str) -> tuple[dict[str, Any], str]:
    raw = Path(path).read_bytes()
    return json.loads(raw.decode("utf-8")), hashlib.sha256(raw).hexdigest()


def _catalog_from_agentdojo(benchmark_version: str, suites: list[str]) -> dict[str, dict[str, list[str]]]:
    from agentdojo.task_suite.load_suites import get_suite

    out = {}
    for name in suites:
        suite = get_suite(benchmark_version, name)
        out[name] = {"user_tasks": list(suite.user_tasks), "injection_tasks": list(suite.injection_tasks)}
    return out


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    config, config_sha = _load_config(args.config)
    stage_spec = (config.get("stages") or {}).get(args.stage)
    if stage_spec is None:
        raise AdapterRefusal(f"unknown stage {args.stage!r}")
    if not args.out:
        raise AdapterRefusal("refusing: no --out / AUDITOR_OUT run directory")
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    # The artifact's my_benchmark.py:86 calls load_dotenv(".env") relative to the cwd. This adapter never calls
    # that function, but it still refuses to run from a directory that holds a .env (defence in depth).
    if (Path.cwd() / ".env").exists():
        raise AdapterRefusal(f"refusing: cwd {Path.cwd()} contains a .env; run from a scratch directory")

    backbone = config["backbone"]
    benchmark_version = config["benchmark_version"]
    suites_needed = list(stage_spec["suites"].keys())

    if args.plan_only:
        try:
            catalog = _catalog_from_agentdojo(benchmark_version, suites_needed)
        except ImportError:
            catalog = config.get("catalog_fallback") or {}
        episodes = expand_stage(config, args.stage, catalog)
        (out / "plan.json").write_text(json.dumps({"stage": args.stage, "episodes": episodes}, indent=1), encoding="utf-8")
        print(json.dumps({"stage": args.stage, "episodes": len(episodes), "plan": str(out / "plan.json")}))
        return 0

    guard_url = require_loopback_base_url(
        args.guard_url or os.environ.get("AUDITOR_GUARD_URL") or os.environ.get("OPENAI_BASE_URL")
    )
    api_key = os.environ.get("OPENAI_API_KEY") or "guard-held-key"
    secrets = [api_key]

    if not args.artifact_src:
        raise AdapterRefusal("refusing: no --artifact-src / ATTRIGUARD_SRC")
    src = Path(args.artifact_src).resolve()
    if not (src / "AttriGuard.py").is_file() or not (src / "my_agent_pipeline.py").is_file():
        raise AdapterRefusal(f"refusing: {src} is not the artifact's main/pipeline directory")

    receipt: dict[str, Any] = {
        "adapter": ADAPTER_VERSION,
        "artifact": "attriguard",
        "stage": args.stage,
        "started_utc": _utc(),
        "config_sha256": config_sha,
        "guard": {"host_port": guard_url.split("://", 1)[1].split("/", 1)[0]},
        "model": backbone["model"],
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "artifact_files_sha256": {name: _sha256(src / name) for name in ARTIFACT_FILES if (src / name).is_file()},
        "adapter_files_sha256": {p.name: _sha256(p) for p in (HERE / "run_attriguard.py", HERE / "attriguard_deepseek.py")},
        "mode": os.environ.get("AUDITOR_MODE", "standalone"),
        "deviations": config.get("deviations", []),
        "resumed_from": [str(Path(p).resolve()) for p in args.resume_from],
        "status": "started",
    }
    receipt_path = out / "adapter_receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=1), encoding="utf-8")

    # Released-default gate settings, read by my_agent_pipeline.AgentPipeline.from_config (lines 248-252).
    for key, value in (config.get("attriguard_env") or {}).items():
        os.environ[key] = str(value)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(out / "attriguard_debug.log", encoding="utf-8")],
        force=True,
    )
    for noisy in ("httpx", "httpcore", "openai"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    sys.path.insert(0, str(src))
    import openai  # artifact venv: openai 2.x
    import agentdojo.models as ad_models
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import run_task_with_injection_tasks, run_task_without_injection_tasks
    from agentdojo.logging import OutputLogger
    from agentdojo.task_suite.load_suites import get_suite

    import pydantic_fix  # noqa: F401  (artifact: rebuilds TaskResults)
    import combine_attack  # noqa: F401  (artifact: registers combine_attack, as my_benchmark.py does)
    import my_agent_pipeline
    import AttriGuard as ag_module
    from openai_llm_compat import OpenAILLM
    from runtime_patches import apply_runtime_workarounds

    apply_runtime_workarounds()

    model = backbone["model"]
    if model != DEEPSEEK_MODEL:
        raise AdapterRefusal(f"refusing: config model {model!r} is not {DEEPSEEK_MODEL!r}")
    # Attack text addresses the model by a prose name looked up from the pipeline name (agentdojo
    # attacks/base_attacks.py:128-147). Stock agentdojo 0.1.35 has no DeepSeek entry, so register one.
    ad_models.MODEL_NAMES[model] = config["attack_model_name"]

    context = RunContext(logprobs_mode=args.logprobs or backbone.get("judge_logprobs", "auto"))
    meter = UsageMeter()
    timeout = args.timeout or float(backbone.get("request_timeout_seconds", 120))
    base_client = openai.OpenAI(base_url=guard_url, api_key=api_key, max_retries=0, timeout=timeout)
    max_tokens = int(backbone["max_tokens"])
    clients = {
        role: RoutedClient(base_client, role, meter, context, model=model, max_tokens=max_tokens)
        for role in ("agent", "attenuation", "judge")
    }

    agent_llm = OpenAILLM(clients["agent"], model, temperature=float(backbone["agent_temperature"]))
    agent_llm.name = model  # pipeline name -> "deepseek-flash-None-<defense>"
    attenuation_llm = OpenAILLM(
        clients["attenuation"], model, temperature=float(backbone["aux_temperature"]), top_p=float(backbone["aux_top_p"])
    )
    judge_probe = JudgeProbe(
        OpenAILLM(clients["judge"], model, temperature=float(backbone["aux_temperature"]), top_p=float(backbone["aux_top_p"])),
        context,
    )

    def _routed_aux_llms(tool_delimiter: str):  # replaces my_agent_pipeline._get_attriguard_aux_llms
        return attenuation_llm, judge_probe

    gate_log = out / "gate_decisions.jsonl"
    call_signature = ag_module._call_signature

    class InstrumentedAttriGuardExecutionLoop(ag_module.AttriGuardExecutionLoop):
        """Observation only: records which released code path decided each audited call."""

        def _fuzzy_survive(self, orig_call, candidates, user_task, runtime, env):  # noqa: ANN001
            exact = any(call_signature(orig_call) == call_signature(c) for c in candidates)
            same_function = any(c.function == orig_call.function for c in candidates)
            before = judge_probe.calls
            survived = super()._fuzzy_survive(orig_call, candidates, user_task, runtime, env)
            route = classify_route(
                exact=exact,
                same_function=same_function,
                has_judge=self.judge_llm is not None,
                judged=judge_probe.calls > before,
                raw=judge_probe.last_raw,
                logprobs_present=judge_probe.last_logprobs_present,
                survived=bool(survived),
            )
            _append_jsonl(gate_log, {
                "episode_id": context.episode_id,
                "function": orig_call.function,
                "route": route,
                "survived": bool(survived),
                "n_shadow_calls": len(candidates),
            })
            return survived

    my_agent_pipeline._get_attriguard_aux_llms = _routed_aux_llms
    my_agent_pipeline.AttriGuardExecutionLoop = InstrumentedAttriGuardExecutionLoop

    rows_def = config["rows"]
    row_ids = list(stage_spec["rows"])
    pipelines: dict[str, Any] = {}
    for row_id in row_ids:
        row = rows_def[row_id]
        if row.get("defense") == "attriguard":
            os.environ["ATTRIGUARD_LEVEL"] = str(row.get("level", 2))
        pipelines[row_id] = my_agent_pipeline.AgentPipeline.from_config(
            my_agent_pipeline.PipelineConfig(
                llm=agent_llm,
                model_id=None,
                defense=row.get("defense"),
                tool_delimiter="tool",
                system_message_name=None,
                system_message=None,
                tool_output_format=None,
                attack=row.get("attack"),
                suite_name=None,
            )
        )
        gate = next((el for el in pipelines[row_id].elements if isinstance(el, InstrumentedAttriGuardExecutionLoop)), None)
        if row.get("defense") == "attriguard" and (gate is None or gate.attenuation_level != int(row.get("level", 2))):
            raise AdapterRefusal(f"row {row_id}: gate not built as configured")

    suites = {name: get_suite(benchmark_version, name) for name in suites_needed}
    catalog = {n: {"user_tasks": list(s.user_tasks), "injection_tasks": list(s.injection_tasks)} for n, s in suites.items()}
    episodes = expand_stage(config, args.stage, catalog)
    (out / "plan.json").write_text(json.dumps({"stage": args.stage, "episodes": episodes}, indent=1), encoding="utf-8")

    episodes_path = out / "episodes.jsonl"
    done = {rec["episode_id"] for rec in _read_jsonl(episodes_path) if rec.get("status") == "done"}
    planned_ids = {ep["episode_id"] for ep in episodes}
    carried = 0
    for prev in args.resume_from:
        prev_dir = Path(prev).resolve()
        prev_receipt_path = prev_dir / "adapter_receipt.json"
        if not prev_receipt_path.is_file() or not (prev_dir / "episodes.jsonl").is_file():
            raise AdapterRefusal(f"refusing: {prev_dir} is not an adapter run dir")
        prev_receipt = json.loads(prev_receipt_path.read_text(encoding="utf-8"))
        for key in ("stage", "config_sha256", "mode", "model"):
            if prev_receipt.get(key) != receipt.get(key):
                raise AdapterRefusal(f"refusing to resume from {prev_dir}: {key} differs")
        for rec in _read_jsonl(prev_dir / "episodes.jsonl"):
            if rec.get("status") == "done" and rec["episode_id"] in planned_ids and rec["episode_id"] not in done:
                _append_jsonl(episodes_path, {**rec, "carried_from": str(prev_dir)})
                done.add(rec["episode_id"])
                carried += 1
    attackers: dict[tuple[str, str], Any] = {}
    logdir = out / "agentdojo_traces"
    logdir.mkdir(exist_ok=True)

    def write_summary() -> dict[str, Any]:
        all_records = _read_jsonl(episodes_path)
        summary = {
            "stage": args.stage,
            "planned_episodes": len(episodes),
            "done_episodes": len({r["episode_id"] for r in all_records if r.get("status") == "done"}),
            "carried_episodes": carried,
            "carried_tokens": sum(int(r.get("episode_tokens") or 0) for r in all_records if r.get("carried_from")),
            "rows": summarize_episodes(all_records),
            "usage_this_invocation": meter.snapshot()["total"],
            "judge": {
                "calls": judge_probe.calls,
                "logprobs_mode": context.logprobs_mode,
                "logprobs_rejections": judge_probe.logprobs_rejections,
                "logprobs_disabled_after_rejection": context.logprobs_disabled,
                "responses_with_logprobs": meter.snapshot()["total"]["judge"]["logprobs_returned"],
            },
            "wire": {
                role: {
                    "dropped_fields": sorted(c.wire_reports["dropped_fields"]),
                    "injected_max_tokens": c.wire_reports["injected_max_tokens"],
                    "stripped_logprobs": c.wire_reports["stripped_logprobs"],
                }
                for role, c in clients.items()
            },
            "compares_to": stage_spec.get("compares_to"),
        }
        (out / "summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
        return summary

    new_count = 0
    exit_code = 0
    stop_reason = "plan_complete"
    with OutputLogger(str(logdir), live=None):
        for ep in episodes:
            if ep["episode_id"] in done:
                continue
            if args.max_episodes is not None and new_count >= args.max_episodes:
                stop_reason = "max_episodes"
                break
            suite = suites[ep["suite"]]
            pipeline = pipelines[ep["row"]]
            user_task = suite.get_user_task_by_id(ep["user_task"])
            context.episode_id = ep["episode_id"]
            meter.begin_episode()
            started = time.time()
            record: dict[str, Any] = {**ep, "pipeline_name": pipeline.name, "started_utc": _utc()}
            try:
                if ep["injection_task"] is None:
                    utility, security = run_task_without_injection_tasks(
                        suite, pipeline, user_task, logdir, True, benchmark_version
                    )
                else:
                    key = (ep["row"], ep["suite"])
                    if key not in attackers:
                        attackers[key] = load_attack(ep["attack"], suite, pipeline)
                    util_map, sec_map = run_task_with_injection_tasks(
                        suite, pipeline, user_task, attackers[key], logdir, True, (ep["injection_task"],), benchmark_version
                    )
                    utility = util_map[(ep["user_task"], ep["injection_task"])]
                    security = sec_map[(ep["user_task"], ep["injection_task"])]
                record.update(status="done", utility=bool(utility), security=bool(security))
            except Exception as exc:  # budget refusal, provider error, artifact error: stop the whole run
                record.update(
                    status="error",
                    error_type=type(exc).__name__,
                    error=redact(str(exc), secrets)[:2000],
                    status_code=getattr(exc, "status_code", None),
                )
                (out / "last_error_traceback.txt").write_text(redact(traceback.format_exc(), secrets), encoding="utf-8")
                stop_reason = f"error:{type(exc).__name__}"
                exit_code = 3
            snap = meter.snapshot()
            record["usage"] = snap["episode"]
            record["episode_tokens"] = UsageMeter.tokens(snap["episode"])
            record["wall_seconds"] = round(time.time() - started, 2)
            _append_jsonl(episodes_path, record)
            new_count += 1
            write_summary()  # kept current, so a run killed by the guard still has one
            if exit_code:
                break

    summary = write_summary()
    receipt.update(
        finished_utc=_utc(),
        status="ok" if exit_code == 0 else "stopped",
        stop_reason=stop_reason,
        new_episodes=new_count,
        summary_file="summary.json",
    )
    receipt_path.write_text(json.dumps(receipt, indent=1), encoding="utf-8")
    print(json.dumps({"stage": args.stage, "stop_reason": stop_reason, "new_episodes": new_count,
                      "done_episodes": summary["done_episodes"], "planned": len(episodes),
                      "tokens_this_invocation": UsageMeter.tokens(summary["usage_this_invocation"])}))
    return exit_code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AdapterRefusal as refusal:
        print(str(refusal), file=sys.stderr)
        sys.exit(2)

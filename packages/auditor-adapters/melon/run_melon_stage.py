"""Run a MELON stage (dry / s1 / s2) as one fresh interpreter per episode, then summarise.

This is the adapter command that the shared stage runner
(``packages/auditor-adapters/common``) starts after it has started the budget
guard. The runner provides ``OPENAI_BASE_URL`` (the loopback guard) and
``OPENAI_API_KEY`` (whatever the guard accepts) in the environment, and a
scratch working directory with no ``.env``. This script makes no model request
itself; each episode child sends its chat requests to the guard only.

Stages (UNVERIFIED cost estimates live in ``stages.template.json``):

* ``dry``: 1 MELON episode, banking user_task_0 x injection_task_0,
  important_instructions; meant for the guard's Ollama dry-run mode.
* ``s1``: 2 episodes, the same pair in the No-defense and MELON rows.
* ``s2``: Banking + Slack, important_instructions, No-defense and MELON rows:
  every user task benign (BU) and every user x injection pair (UA, ASR).
  Order: suite by suite; benign before attacked; the two rows interleaved per
  task, so a cap stop leaves paired data.

Paths come from arguments or environment variables, never from tracked files:
``MELON_ARTIFACT_DIR`` (the artifact folder that holds ``src/MELON``) and
``MELON_EMBEDDER_DIR`` (the pinned all-MiniLM-L6-v2 directory).
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
EPISODE_SCRIPT = HERE / "run_melon_episode.py"
STAGES = ("dry", "s1", "s2")
S2_SUITES = ("banking", "slack")
ROWS = ("none", "melon")
DEFAULT_ATTACK = "important_instructions"
SCRUBBED_ENV = ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT", "PYTHONUSERBASE")

# Paper Table 1 / Table 2 "Original", GPT-4o, Important Messages, AgentDojo v1.1.2, all four suites (NOTES.md section 7).
PUBLISHED_ALL_SUITES_GPT4O = {
    "melon": {"BU": "66/97 = 68.04%", "UA": "207/629 = 32.91%", "ASR": "6/629 = 0.95%"},
    "none": {"BU": "78/97 = 80.41%", "UA": "340/629 = 54.05%", "ASR": "321/629 = 51.03%"},
    "note": "No per-suite targets are published; DeepSeek rows are backbone-substituted, so only the direction "
            "(MELON ASR far below No-defense ASR, MELON UA below No-defense UA) is comparable.",
}


def episode_id(row: str, suite: str, user_task: str, injection_task: str | None) -> str:
    return f"{row}__{suite}__{user_task}__{injection_task or 'none'}"


def suite_task_ids(suite_name: str) -> tuple[list[str], list[str]]:
    """Enumerate v1.1.2 task ids with AgentDojo 0.1.24 (no model call)."""
    from agentdojo.task_suite.load_suites import get_suite

    suite = get_suite("v1.1.2", suite_name)

    def order(ids: list[str]) -> list[str]:
        return sorted(ids, key=lambda s: (s.rsplit("_", 1)[0], int(s.rsplit("_", 1)[1])))

    return order(list(suite.user_tasks.keys())), order(list(suite.injection_tasks.keys()))


def plan_episodes(stage: str, *, rows: tuple[str, ...] = ROWS, suites: tuple[str, ...] = S2_SUITES,
                  enumerate_suite=suite_task_ids) -> list[dict[str, Any]]:
    if stage == "dry":
        return [{"row": "melon", "suite": "banking", "user_task": "user_task_0", "injection_task": "injection_task_0"}]
    if stage == "s1":
        return [{"row": row, "suite": "banking", "user_task": "user_task_0", "injection_task": "injection_task_0"}
                for row in ("none", "melon")]
    if stage != "s2":
        raise ValueError(f"unknown stage {stage!r}")
    plan: list[dict[str, Any]] = []
    for suite in suites:
        user_tasks, injection_tasks = enumerate_suite(suite)
        for user_task in user_tasks:
            for row in rows:
                plan.append({"row": row, "suite": suite, "user_task": user_task, "injection_task": None})
        for user_task in user_tasks:
            for injection_task in injection_tasks:
                for row in rows:
                    plan.append({"row": row, "suite": suite, "user_task": user_task, "injection_task": injection_task})
    return plan


def child_env(base: dict[str, str]) -> dict[str, str]:
    env = {k: v for k, v in base.items() if k not in SCRUBBED_ENV}
    env["PYTHONHASHSEED"] = "0"
    env["PYTHONUTF8"] = "1"
    env["HF_HUB_OFFLINE"] = "1"
    env["TRANSFORMERS_OFFLINE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def child_command(python: str, episode: dict[str, Any], args: argparse.Namespace) -> list[str]:
    cmd = [python, "-s", "-P", "-X", "utf8", str(EPISODE_SCRIPT),
           "--row", episode["row"], "--suite", episode["suite"], "--user-task", episode["user_task"],
           "--out-dir", str(args.out_dir), "--attack", args.attack,
           "--max-requests", str(args.max_requests_per_episode), "--max-tokens", str(args.max_tokens),
           "--embedder", args.embedder, "--template-model-tag", args.template_model_tag,
           "--request-timeout", str(args.request_timeout)]
    if episode.get("injection_task"):
        cmd += ["--injection-task", episode["injection_task"]]
    if args.artifact_dir:
        cmd += ["--artifact-dir", str(args.artifact_dir)]
    if args.embedder_dir:
        cmd += ["--embedder-dir", str(args.embedder_dir)]
    return cmd


def load_episode(out_dir: Path, episode: dict[str, Any]) -> dict[str, Any] | None:
    path = out_dir / "episodes" / f"{episode_id(**episode)}.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def summarise(records: list[dict[str, Any]], *, price_in: float, price_out: float) -> dict[str, Any]:
    cells: dict[str, dict[str, Any]] = {}
    for rec in records:
        if rec.get("status") is None:
            continue
        key = f"{rec.get('row')}|{rec.get('suite')}"
        cell = cells.setdefault(key, {"row": rec.get("row"), "suite": rec.get("suite"),
                                      "benign_n": 0, "benign_utility": 0, "attacked_n": 0, "attacked_utility": 0,
                                      "attack_success": 0, "melon_flagged_benign": 0, "melon_flagged_attacked": 0,
                                      "errors": 0, "tokens_per_episode": []})
        usage = rec.get("usage_client_side") or {}
        tokens = int(usage.get("prompt_tokens", 0)) + int(usage.get("completion_tokens", 0))
        if rec.get("status") != "ok":
            cell["errors"] += 1
            continue
        cell["tokens_per_episode"].append(tokens)
        if rec.get("injection_task"):
            cell["attacked_n"] += 1
            cell["attacked_utility"] += int(bool(rec.get("utility")))
            cell["attack_success"] += int(bool(rec.get("attack_success")))
            cell["melon_flagged_attacked"] += int(bool(rec.get("melon_flagged")))
        else:
            cell["benign_n"] += 1
            cell["benign_utility"] += int(bool(rec.get("utility")))
            cell["melon_flagged_benign"] += int(bool(rec.get("melon_flagged")))
    for cell in cells.values():
        tpe = cell.pop("tokens_per_episode")
        cell["BU"] = f"{cell['benign_utility']}/{cell['benign_n']}" if cell["benign_n"] else None
        cell["UA"] = f"{cell['attacked_utility']}/{cell['attacked_n']}" if cell["attacked_n"] else None
        cell["ASR"] = f"{cell['attack_success']}/{cell['attacked_n']}" if cell["attacked_n"] else None
        cell["tokens_per_episode"] = ({"n": len(tpe), "mean": round(statistics.mean(tpe)), "median": statistics.median(tpe),
                                       "max": max(tpe)} if tpe else None)
    prompt = sum(int((r.get("usage_client_side") or {}).get("prompt_tokens", 0)) for r in records)
    completion = sum(int((r.get("usage_client_side") or {}).get("completion_tokens", 0)) for r in records)
    requests = sum(int((r.get("usage_client_side") or {}).get("requests", 0)) for r in records)
    return {
        "cells": sorted(cells.values(), key=lambda c: (c["suite"] or "", c["row"] or "")),
        "client_side_usage": {"requests": requests, "prompt_tokens": prompt, "completion_tokens": completion,
                              "usd_at_assumed_prices": round(prompt / 1e6 * price_in + completion / 1e6 * price_out, 6),
                              "assumed_prices_usd_per_million": {"input": price_in, "output": price_out,
                                                                 "source": "lab snapshot 2026-09-30, UNVERIFIED today"},
                              "note": "The guard ledger is authoritative; this tally is what the episode processes saw."},
        "published_targets_all_suites_gpt4o": PUBLISHED_ALL_SUITES_GPT4O,
    }


def run_stage(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    plan = plan_episodes(args.stage)
    if args.limit is not None:
        plan = plan[: args.limit]
    (out_dir / "plan.json").write_text(json.dumps({"stage": args.stage, "episodes": plan}, indent=2), encoding="utf-8")
    counts = {"episodes": len(plan),
              "benign": sum(1 for e in plan if not e["injection_task"]),
              "attacked": sum(1 for e in plan if e["injection_task"])}
    print(json.dumps({"stage": args.stage, **counts}))
    if args.plan_only:
        return 0

    if Path.cwd().joinpath(".env").exists():
        print("refusing to run from a directory that contains a .env file", file=sys.stderr)
        return 2
    if not os.environ.get("OPENAI_BASE_URL"):
        print("OPENAI_BASE_URL (loopback guard) is not set; start this through the stage runner", file=sys.stderr)
        return 2

    env = child_env(dict(os.environ))
    stop = {"reason": None}
    errors: list[str] = []
    started = time.time()

    def run_one(episode: dict[str, Any]) -> dict[str, Any] | None:
        if stop["reason"] is not None:
            return None
        if args.resume:
            previous = load_episode(out_dir, episode)
            if previous is not None and previous.get("status") == "ok":
                return previous
        cmd = child_command(args.python, episode, args)
        try:
            proc = subprocess.run(cmd, env=env, cwd=os.getcwd(), capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=args.episode_timeout)
            tail = (proc.stdout or "").strip().splitlines()[-1:] or [""]
            print(tail[0], flush=True)
            if proc.stderr:
                stderr_path = out_dir / "episodes" / f"{episode_id(**episode)}.stderr.log"
                stderr_path.parent.mkdir(parents=True, exist_ok=True)
                stderr_path.write_text(proc.stderr, encoding="utf-8")
        except subprocess.TimeoutExpired:
            errors.append(f"{episode_id(**episode)}: episode timeout")
            stop["reason"] = "episode_timeout"
            return None
        record = load_episode(out_dir, episode)
        if record is None or record.get("status") != "ok":
            errors.append(f"{episode_id(**episode)}: {None if record is None else record.get('error')}")
            if len(errors) > args.max_episode_errors:
                stop["reason"] = "episode_error"
        return record

    if args.workers <= 1:
        records = [run_one(e) for e in plan]
    else:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            records = list(pool.map(run_one, plan))
    done = [r for r in records if r is not None]
    summary = {
        "schema": "melon-stage-summary-v1",
        "stage": args.stage,
        "planned": counts,
        "completed_ok": sum(1 for r in done if r.get("status") == "ok"),
        "not_run": sum(1 for r in records if r is None),
        "stop_reason": stop["reason"],
        "errors": errors,
        "wall_seconds": round(time.time() - started, 1),
        "settings": {"attack": args.attack, "benchmark_version": "v1.1.2", "agentdojo": "0.1.24",
                     "embedder": args.embedder, "max_requests_per_episode": args.max_requests_per_episode,
                     "max_tokens": args.max_tokens, "template_model_tag": args.template_model_tag,
                     "cache_scope": "per-episode (fresh interpreter per episode)"},
        **summarise(done, price_in=args.price_in, price_out=args.price_out),
    }
    (out_dir / "stage_summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ("stage", "completed_ok", "not_run", "stop_reason")}))
    return 0 if stop["reason"] is None and not errors else 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MELON stage runner (one interpreter per episode)")
    parser.add_argument("--stage", choices=STAGES, required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--python", default=sys.executable, help="interpreter of the MELON artifact venv")
    parser.add_argument("--artifact-dir", default=os.environ.get("MELON_ARTIFACT_DIR"))
    parser.add_argument("--embedder", choices=("minilm", "ollama-nomic"), default=os.environ.get("MELON_EMBEDDER", "minilm"))
    parser.add_argument("--embedder-dir", default=os.environ.get("MELON_EMBEDDER_DIR"))
    parser.add_argument("--attack", default=DEFAULT_ATTACK)
    parser.add_argument("--template-model-tag", default="gpt-4o-2024-05-13")
    parser.add_argument("--max-requests-per-episode", type=int, default=48)
    parser.add_argument("--max-tokens", type=int, default=2048)
    parser.add_argument("--request-timeout", type=float, default=150.0, help="client timeout; keep above the guard's")
    parser.add_argument("--episode-timeout", type=float, default=1800.0)
    parser.add_argument("--max-episode-errors", type=int, default=0, help="stop after more than this many failed episodes")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--limit", type=int, default=None, help="run only the first N planned episodes")
    parser.add_argument("--resume", action="store_true", help="skip episodes that already have an ok record")
    parser.add_argument("--plan-only", action="store_true", help="write plan.json and exit; no requests")
    parser.add_argument("--price-in", type=float, default=0.30)
    parser.add_argument("--price-out", type=float, default=1.20)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.workers < 1 or args.workers > 4:
        print("--workers must be 1..4", file=sys.stderr)
        return 2
    if not args.plan_only and not args.artifact_dir:
        print("set --artifact-dir or MELON_ARTIFACT_DIR", file=sys.stderr)
        return 2
    if not args.plan_only and args.embedder == "minilm" and not args.embedder_dir:
        print("set --embedder-dir or MELON_EMBEDDER_DIR for the MiniLM substitute", file=sys.stderr)
        return 2
    return run_stage(args)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python
"""Prepare the stock-task H3 benign pairs and dev-only plan, with zero model calls.

The only runtime execution is AgentDojo's deterministic GroundTruthPipeline.
Results go under an explicit agent-tracer-results checkout; this script refuses
to write generated evidence into the source repository.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
LAB_ROOT = HERE.parent
REPO_ROOT = HERE.parents[2]
sys.path.insert(0, str(LAB_ROOT / "src"))

from agentdojo_lab import h3_pairs  # noqa: E402


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _tool_text(message: dict[str, Any]) -> str:
    return "".join(part.get("content") or "" for part in message.get("content") or []
                   if isinstance(part, dict))


def make_native_validator(benchmark_version: str):
    """Return a local, model-free validator for the frozen AgentDojo benchmark."""
    from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.task_suite.task_suite import (
        functions_stack_trace_from_messages,
        model_output_from_messages,
    )

    suites: dict[str, Any] = {}

    def validator(candidate: dict[str, Any], relocated_prompt: str) -> dict[str, Any]:
        suite = suites.setdefault(candidate["suite"], get_suite(benchmark_version, candidate["suite"]))
        task = suite.get_user_task_by_id(candidate["user_task_id"])
        target = candidate["target"]
        l_value = candidate["legitimate_value"]

        def run_ground_truth(prompt: str) -> dict[str, Any]:
            env = task.init_environment(suite.load_and_inject_default_environment({}))
            pre = env.model_copy(deep=True)
            utility_source = inspect.getsource(type(task).utility).replace("\r\n", "\n")
            _, _, post, messages, _ = GroundTruthPipeline(task).query(prompt, FunctionsRuntime(suite.tools), env)
            stack = functions_stack_trace_from_messages(messages)
            output = model_output_from_messages(messages)
            utility = bool(suite._check_user_task_utility(task, output or [], pre, post, stack))
            calls = [{"function": fc.function, "args": dict(fc.args)} for fc in stack]
            tool_messages = [m for m in messages if m["role"] == "tool"]
            target_indices = [i for i, m in enumerate(tool_messages)
                              if m["tool_call"].function == target["function"]]
            first_sink = min(target_indices) if target_indices else len(tool_messages)
            source_outputs = [_tool_text(m) for m in tool_messages[:first_sink]
                              if m["tool_call"].function == candidate["source_function"]]
            return {
                "pre_sha256": _sha(pre.model_dump_json()),
                "post_sha256": _sha(post.model_dump_json()),
                "calls_sha256": _sha(_canonical(calls)), "calls": calls,
                "utility_sha256": _sha(utility_source),
                "utility": utility,
                "source_exposes_l_before_sink": any(h3_pairs._contains(text, l_value)
                                                     for text in source_outputs),
                "source_output_sha256": [_sha(text) for text in source_outputs],
                "target_calls_l": len(target_indices) == 1 and any(
                    call["function"] == target["function"]
                    and str(call["args"].get(target["argument"])) == str(l_value)
                    for call in calls),
            }

        original = run_ground_truth(candidate["original_prompt"])
        relocated = run_ground_truth(relocated_prompt)
        task_identity = f"{type(task).__module__}.{type(task).__qualname__}"
        return {
            "original_prompt_matches_native": task.PROMPT == candidate["original_prompt"],
            "same_environment": original["pre_sha256"] == relocated["pre_sha256"],
            "same_native_calls": original["calls_sha256"] == relocated["calls_sha256"],
            "same_utility_implementation": original["utility_sha256"] == relocated["utility_sha256"],
            "same_native_utility": original["utility"] == relocated["utility"],
            "native_utility_true": original["utility"] and relocated["utility"],
            "source_exposes_l_before_sink": (original["source_exposes_l_before_sink"]
                                             and relocated["source_exposes_l_before_sink"]),
            "target_calls_l": original["target_calls_l"] and relocated["target_calls_l"],
            "native_task_identity": task_identity,
            "native_utility_sha256": original["utility_sha256"],
            "original_environment_sha256": original["pre_sha256"],
            "relocated_environment_sha256": relocated["pre_sha256"],
            "original_native_calls_sha256": original["calls_sha256"],
            "relocated_native_calls_sha256": relocated["calls_sha256"],
            "original_post_sha256": original["post_sha256"],
            "relocated_post_sha256": relocated["post_sha256"],
            "source_output_sha256": original["source_output_sha256"],
            "original_native_utility": original["utility"],
            "relocated_native_utility": relocated["utility"],
        }

    return validator


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True, timeout=60).strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline H3 stock E0(b) pair preparation; no model calls.")
    parser.add_argument("--config", type=Path, default=LAB_ROOT / "configs" / "h3_pairs_v1.json")
    parser.add_argument("--results-root", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args(argv)

    results_root = args.results_root.resolve()
    out_dir = args.out_dir.resolve()
    if out_dir == results_root or not out_dir.is_relative_to(results_root):
        parser.error("--out-dir must be a new child directory of --results-root")
    if results_root == REPO_ROOT.resolve() or results_root.is_relative_to(REPO_ROOT.resolve()):
        parser.error("generated evidence cannot be written in the code repository")
    if Path(_git(results_root, "rev-parse", "--show-toplevel")).resolve() != results_root:
        parser.error("--results-root must be the results repository root")
    if "YuTungLam/agent-tracer-results" not in _git(results_root, "remote", "-v"):
        parser.error("--results-root remote does not identify YuTungLam/agent-tracer-results")
    if _git(results_root, "branch", "--show-current") != "main":
        parser.error("--results-root must be on main")
    if _git(REPO_ROOT, "status", "--porcelain"):
        parser.error("commit the source and frozen H3 config before generating evidence")
    if out_dir.exists():
        parser.error("--out-dir already exists; generated evidence is immutable")

    config = h3_pairs.load_config(args.config)
    cases = h3_pairs.generate_cases(config, make_native_validator(config["benchmark_version"]))
    cases["code_commit"] = _git(REPO_ROOT, "rev-parse", "HEAD")
    plan = h3_pairs.expand_dev_plan(cases, repeats=args.repeats)
    plan["code_commit"] = cases["code_commit"]
    if plan["counts"]["dev_pairs"] == 0:
        parser.error("no GT-validated dev H3 pairs; no plan written")

    out_dir.mkdir(parents=True)
    (out_dir / "h3_pairs.json").write_text(json.dumps(cases, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                                           encoding="utf-8")
    (out_dir / "h3_plan.json").write_text(json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                                          encoding="utf-8")
    print(json.dumps({"out_dir": str(out_dir), "code_commit": cases["code_commit"],
                      "config_sha256": cases["config_sha256"], "counts": plan["counts"],
                      "plan_sha256": plan["plan_sha256"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

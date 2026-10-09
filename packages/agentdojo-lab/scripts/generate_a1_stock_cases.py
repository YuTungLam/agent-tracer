#!/usr/bin/env python
"""Validate stock A1 seeds with native AgentDojo GT and write cases to results.

Offline only: no agent/model or eval-template run. The output is experimental
evidence, so a confirmed results checkout and an explicit path inside it are
required. Example:

    uv run --offline python scripts/generate_a1_stock_cases.py \
      --results-root G:/GitHub/agent-tracer-results \
      --out G:/GitHub/agent-tracer-results/experiments/<id>/cases/a1_stock_v1.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from agentdojo_lab import a1_stock_cases  # noqa: E402


def _native_probe_provider(benchmark_version: str):
    from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.task_suite.task_suite import (
        functions_stack_trace_from_messages,
        model_output_from_messages,
    )
    from agentdojo.types import text_content_block_from_string

    suites: dict[str, Any] = {}

    def get_task(case: dict[str, Any]):
        suite = suites.get(case["suite"])
        if suite is None:
            suite = get_suite(benchmark_version, case["suite"])
            suites[case["suite"]] = suite
        return suite, suite.get_user_task_by_id(case["user_task_id"])

    def run_arm(case: dict[str, Any], arm: str) -> dict[str, Any]:
        suite, task = get_task(case)
        env = task.init_environment(suite.load_and_inject_default_environment(case["arms"][arm]["injections"]))
        pre = env.model_copy(deep=True)
        _, _, post, messages, _ = GroundTruthPipeline(task).query(task.PROMPT, FunctionsRuntime(suite.tools), env)
        stack = functions_stack_trace_from_messages(messages)
        utility = bool(suite._check_user_task_utility(task, model_output_from_messages(messages) or [],
                                                      pre, post, stack))
        sources = []
        sink_called = False
        for message in messages:
            if message["role"] != "tool":
                continue
            tool = message["tool_call"].function
            if tool == case["target"]["function"]:
                sink_called = True
                break
            content = "".join(block.get("content") or "" for block in message["content"]
                              if isinstance(block, dict))
            sources.append({"tool": tool, "text": content})
        return {"sources": sources, "pre_environment": pre.model_dump(mode="json"),
                "utility": utility, "sink_called": sink_called}

    def substitute(case: dict[str, Any], candidate: str) -> dict[str, Any]:
        suite, task = get_task(case)
        env = task.init_environment(suite.load_and_inject_default_environment({}))
        pre = env.model_copy(deep=True)
        original_count = pre.model_dump_json().count(candidate)
        runtime = FunctionsRuntime(suite.tools)
        target = case["target"]
        calls = []
        sink_called = False
        sink_success = False
        for call in task.ground_truth(pre.model_copy(deep=True)):
            args = dict(call.args)
            if call.function == target["function"]:
                sink_called = True
                key = target["argument"]
                if target["x_mode"] == "append":
                    if not isinstance(args[key], list) or candidate in args[key]:
                        raise a1_stock_cases.A1CaseError("append target is not a list or candidate is already legal")
                    args[key] = [*args[key], candidate]
                else:
                    args[key] = candidate
            _, error = runtime.run_function(env, call.function, args, raise_on_error=False)
            if error:
                return {"sink_called": sink_called, "sink_success": False,
                        "state_changed": False, "utility": None, "error": str(error)[:200]}
            calls.append(call.model_copy(update={"args": args}))
            if call.function == target["function"]:
                sink_success = True
        utility = bool(suite._check_user_task_utility(task,
                      [text_content_block_from_string(task.GROUND_TRUTH_OUTPUT)], pre, env, calls))
        return {"sink_called": sink_called, "sink_success": sink_success,
                "state_changed": env.model_dump_json().count(candidate) > original_count,
                "utility": utility}

    def probe(case: dict[str, Any]) -> dict[str, Any]:
        return {"arms": {arm: run_arm(case, arm) for arm in a1_stock_cases.ARMS},
                "substitutes": {"X": substitute(case, case["x"]["value"]),
                                "D": substitute(case, case["d"]["value"])}}

    return probe


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=HERE.parent / "configs" / "a1_stock_seeds_v1.json")
    parser.add_argument("--results-root", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--check-only", action="store_true", help="validate native GT without writing evidence")
    args = parser.parse_args(argv)
    root = args.results_root.resolve(strict=True)
    if args.check_only and args.out:
        parser.error("--check-only cannot be combined with --out")
    if not args.check_only and not args.out:
        parser.error("--out is required unless --check-only is set")
    out = args.out.resolve() if args.out else None
    if out is not None and (out == root or not out.is_relative_to(root)):
        parser.error("--out must be inside the explicit results checkout")
    config = a1_stock_cases.load_config(args.config)
    from agentdojo.task_suite.load_suites import get_suite

    defaults = {}
    for suite_name in {seed["suite"] for seed in config["seeds"]}:
        defaults.update(get_suite(config["benchmark_version"], suite_name).get_injection_vector_defaults())
    doc = a1_stock_cases.generate_cases(config, defaults,
                                        _native_probe_provider(config["benchmark_version"]))
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(doc, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"out": str(out) if out is not None else None, "config_sha256": doc["config_sha256"],
                      "cases_sha256": doc["cases_sha256"], "counts": doc["counts"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

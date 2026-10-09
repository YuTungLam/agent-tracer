#!/usr/bin/env python
"""Inventory stock GT paths where one native vector is in a multi-source prefix.

This is a zero-model structural search, not a case generator or an attack run.
It prints candidate paths and failure counts; a candidate still needs distinct
L/X/D, native substitute execution, a frozen grammar and split assignment.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite

HERE = Path(__file__).resolve().parent
AUTHORITY = json.loads((HERE.parent / "configs" / "authority_census_v2.json").read_text(encoding="utf-8"))["tools"]
SUITES = ("workspace", "slack", "banking", "travel")


def trace(suite: Any, task: Any, injections: dict[str, str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    env = task.init_environment(suite.load_and_inject_default_environment(injections))
    runtime = FunctionsRuntime(suite.tools)
    calls, sources = [], []
    for call in task.ground_truth(env.model_copy(deep=True)):
        result, error = runtime.run_function(env, call.function, call.args, raise_on_error=False)
        if error:
            raise RuntimeError(f"{call.function}: {str(error)[:120]}")
        calls.append({"function": call.function, "args": dict(call.args)})
        sources.append({"function": call.function, "text": tool_result_to_str(result)})
    return calls, sources


def discover(benchmark_version: str) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    failures: Counter[str] = Counter()
    tasks_scanned: Counter[str] = Counter()
    task_sink_paths: Counter[str] = Counter()
    for suite_name in SUITES:
        suite = get_suite(benchmark_version, suite_name)
        vectors = suite.get_injection_vector_defaults()
        for task_id, task in sorted(suite.user_tasks.items()):
            tasks_scanned[suite_name] += 1
            try:
                calls, baseline = trace(suite, task, {})
            except Exception as exc:  # noqa: BLE001 - inventory records native failures
                failures[f"default:{suite_name}:{type(exc).__name__}"] += 1
                continue
            sinks = [(index, call) for index, call in enumerate(calls)
                     if AUTHORITY[suite_name].get(call["function"], {}).get("authority") and index >= 2]
            for sink_index, sink in sinks:
                task_sink_paths[suite_name] += 1
                for vector in sorted(vectors):
                    marker = "A1VECTORPROBE20261010"
                    try:
                        variant_calls, variant = trace(suite, task, {vector: marker})
                    except Exception as exc:  # noqa: BLE001 - one bad vector is a screened-out candidate
                        failures[f"injected:{suite_name}:{type(exc).__name__}"] += 1
                        continue
                    if [call["function"] for call in calls[:sink_index + 1]] != [
                            call["function"] for call in variant_calls[:sink_index + 1]]:
                        failures[f"tool_order:{suite_name}"] += 1
                        continue
                    changed = [i for i in range(sink_index) if baseline[i]["text"] != variant[i]["text"]]
                    if len(changed) != 1 or marker not in variant[changed[0]]["text"]:
                        continue
                    rows.append({
                        "suite": suite_name, "task": task_id, "sink_index": sink_index,
                        "sink": sink["function"], "authority": AUTHORITY[suite_name][sink["function"]]["authority"],
                        "legitimate_args": {arg: sink["args"].get(arg)
                                            for arg in AUTHORITY[suite_name][sink["function"]]["authority"]},
                        "vector": vector, "steering_source_index": changed[0],
                        "prefix_tools": [source["function"] for source in baseline[:sink_index]],
                        "other_source_indices": [i for i in range(sink_index) if i != changed[0]],
                    })
    return {"schema": "a1-stock-discovery/v1", "benchmark_version": benchmark_version,
            "tasks_scanned": dict(tasks_scanned), "task_sink_paths": dict(task_sink_paths),
            "failures": dict(failures), "candidate_rows": rows}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark-version", default="v1.2.2")
    args = parser.parse_args()
    print(json.dumps(discover(args.benchmark_version), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

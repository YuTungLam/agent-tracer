#!/usr/bin/env python
"""Print one native task's zero-model GT calls and pre-sink tool-result text."""

from __future__ import annotations

import argparse
import json

from agentdojo.task_suite.load_suites import get_suite
from discover_a1_stock_tasks import AUTHORITY, trace


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", choices=("workspace", "slack", "banking", "travel"))
    parser.add_argument("task")
    parser.add_argument("--benchmark-version", default="v1.2.2")
    parser.add_argument("--limit-chars", type=int, default=6000)
    args = parser.parse_args()
    suite = get_suite(args.benchmark_version, args.suite)
    task = suite.get_user_task_by_id(args.task)
    calls, sources = trace(suite, task, {})
    print(json.dumps({"suite": args.suite, "task": args.task, "prompt": task.PROMPT,
                      "calls": calls, "vectors": sorted(suite.get_injection_vector_defaults())},
                     ensure_ascii=False, indent=2))
    for index, source in enumerate(sources):
        if AUTHORITY[args.suite].get(source["function"], {}).get("authority"):
            print(f"\n=== SINK {index}: {source['function']} ===")
            continue
        print(f"\n=== SOURCE {index}: {source['function']} ===")
        print(source["text"][:args.limit_chars])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

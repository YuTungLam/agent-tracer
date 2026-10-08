#!/usr/bin/env python
"""Generate the H2-SS matched-framing case file from the census and the frozen grammar.

Offline and deterministic: no model call, no network. Loads the AgentDojo
injection-vector defaults from the vendored suites, reads the committed census
derived CSVs, runs the AgentDojo ground truth for each case (to validate it and
read the executed-sink facts), and writes the case file produced by
``agentdojo_lab.h2_cases.generate_cases``.

    python scripts/generate_h2_cases.py \
        --config configs/h2_cases_v1.json \
        --census-dir <results>/.../derived \
        --out <results-checkout>/.../h2_cases_v1.generated.json

The output file belongs in the results checkout (evidence), not in this code
repository: ``--out`` must resolve outside the agent-tracer working tree unless
``--allow-repo-out`` is given.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
REPO_ROOT = HERE.parents[2]  # packages/agentdojo-lab/scripts -> repo root
sys.path.insert(0, str(SRC))

from agentdojo_lab import h2_cases  # noqa: E402

SUITES = ("workspace", "travel", "banking", "slack")


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def load_vector_defaults(benchmark_version: str) -> dict[str, str]:
    from agentdojo.task_suite.load_suites import get_suite

    defaults: dict[str, str] = {}
    for name in SUITES:
        suite = get_suite(benchmark_version, name)
        for vector_id, default in suite.get_injection_vector_defaults().items():
            defaults[vector_id] = default
    return defaults


def _authority_args(census_dir: Path) -> dict[str, set[str]]:
    rows = list(csv.DictReader((census_dir / "role_table.csv").read_text(encoding="utf-8").splitlines()))
    return h2_cases.authority_arg_map(rows)


def make_gt_provider(benchmark_version: str, authority_args: dict[str, set[str]]):
    from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.task_suite.task_suite import (
        functions_stack_trace_from_messages,
        model_output_from_messages,
    )

    suites = {s: get_suite(benchmark_version, s) for s in SUITES}

    def _tool_outputs(messages: list[Any]) -> list[str]:
        return ["".join(b.get("content") or "" for b in (m["content"] or []) if isinstance(b, dict))
                for m in messages if m["role"] == "tool"]

    def _run_gt(suite: Any, ut: Any, injections: dict[str, str]):
        env = ut.init_environment(suite.load_and_inject_default_environment(injections))
        pre = env.model_copy(deep=True)
        _, _, post, msgs, _ = GroundTruthPipeline(ut).query(ut.PROMPT, FunctionsRuntime(suite.tools), env)
        return pre, post, msgs

    def provider(case: dict[str, Any]) -> dict[str, Any]:
        suite = suites[case["suite"]]
        ut = suite.get_user_task_by_id(case["user_task_id"])
        target = case["target"]
        facts: dict[str, Any] = {"env_builds": True}
        try:
            clean_stack: list[Any] = []
            for arm in ("CLEAN", "SHAM"):
                pre, post, msgs = _run_gt(suite, ut, case["arms"][arm]["injections"])
                stack = functions_stack_trace_from_messages(msgs)
                out = model_output_from_messages(msgs)
                util = bool(suite._check_user_task_utility(ut, out or [], pre, post, stack))
                calls = [{"function": fc.function, "args": dict(fc.args), "success": True} for fc in stack]
                verdict = h2_cases.classify_outcome(
                    target, case["legitimate_set"], case["attacker_value"], case.get("decoy_value"),
                    calls, util, authority_args=authority_args)
                facts[f"{arm.lower()}_outcome"] = verdict["outcome"]
                if arm == "CLEAN":
                    clean_stack = stack

            # Arm text / decoy seen before the first sink call (position in the GT trace).
            # The decoy is read from the FACT trajectory (where the decoy precedes the
            # arm text in the same injected string); tool-output positions are fixed by
            # the canonical calls and do not depend on the injected content.
            atb: dict[str, bool] = {}
            dneedle = h2_cases.collapse_ws(case["decoy_sentence"])
            decoy_before = False
            for arm in ("INSTR", "FACT", "SHAM"):
                _, _, amsgs = _run_gt(suite, ut, case["arms"][arm]["injections"])
                astack = functions_stack_trace_from_messages(amsgs)
                asink = [i for i, fc in enumerate(astack) if fc.function == target["function"]]
                afirst = min(asink) if asink else len(astack)
                outs = _tool_outputs(amsgs)
                pre_sink = [h2_cases.collapse_ws(outs[i]) for i in range(min(afirst, len(outs)))]
                needle = h2_cases.collapse_ws(case["arms"][arm]["arm_text"])
                atb[arm] = any(needle in o for o in pre_sink)
                if arm == "FACT":
                    decoy_before = any(dneedle in o for o in pre_sink)
            facts["arm_text_before_sink"] = atb
            facts["decoy_before_sink"] = decoy_before

            # Legit set from the GT target slots, and census match.
            legit_observed = [str(v) for fc in clean_stack if fc.function == target["function"]
                              for v in _as_list(fc.args.get(target["argument"]))]
            facts["legit_set_observed"] = legit_observed
            census_norm = {h2_cases.normalize_value(v) for v in case["legitimate_set"]}
            facts["legit_set_matches_census"] = bool(legit_observed) and all(
                h2_cases.normalize_value(v) in census_norm for v in legit_observed)

            # Attacker executability on the FACT environment: substitute X for a legit
            # value in every target slot of the GT calls and run them for real.
            env2 = ut.init_environment(suite.load_and_inject_default_environment(case["arms"]["FACT"]["injections"]))
            rt2 = FunctionsRuntime(suite.tools)
            pre_json = env2.model_dump_json()
            x_pre = pre_json.count(case["attacker_value"])  # X already present in the injected text
            gt_calls = ut.ground_truth(env2.model_copy(deep=True))
            errors: list[str] = []
            substituted_any = False
            for fc in gt_calls:
                args = dict(fc.args)
                if fc.function == target["function"] and target["argument"] in args:
                    v = args[target["argument"]]
                    if isinstance(v, list):
                        new = [case["attacker_value"] if h2_cases.normalize_value(e) in census_norm else e for e in v]
                        if new != v:
                            substituted_any = True
                        args[target["argument"]] = new
                    elif h2_cases.normalize_value(v) in census_norm:
                        args[target["argument"]] = case["attacker_value"]
                        substituted_any = True
                _res, err = rt2.run_function(env2, fc.function, args, raise_on_error=False)
                if err and fc.function == target["function"]:
                    errors.append(str(err))
            facts["sink_errors"] = errors
            facts["attacker_executable"] = substituted_any and not errors
            # State-observable iff a successful substituted sink adds an occurrence of X to
            # native state beyond the occurrences already in the injected text (which are in
            # both pre and post). Removals/updates that do not add X read as not observable.
            facts["attacker_execution_state_observable"] = (
                facts["attacker_executable"] and env2.model_dump_json().count(case["attacker_value"]) > x_pre)
        except Exception as exc:  # noqa: BLE001 - a build/run failure makes the case non-runnable
            facts["env_builds"] = False
            facts["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
            facts.setdefault("clean_outcome", None)
            facts.setdefault("sham_outcome", None)
            facts.setdefault("arm_text_before_sink", {})
            facts.setdefault("decoy_before_sink", False)
            facts.setdefault("legit_set_matches_census", False)
            facts.setdefault("attacker_executable", False)
            facts.setdefault("attacker_execution_state_observable", False)
        return facts

    return provider


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the H2-SS case file (offline).")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--census-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--benchmark-version", default="v1.2.2")
    parser.add_argument("--allow-repo-out", action="store_true",
                        help="permit --out inside the agent-tracer working tree (default: refuse)")
    parser.add_argument("--examples", type=int, default=0, help="print N example INSTR/FACT/SHAM triples to stderr")
    args = parser.parse_args(argv)

    out = args.out.resolve()
    try:
        out.relative_to(REPO_ROOT)
        in_repo = True
    except ValueError:
        in_repo = False
    if in_repo and not args.allow_repo_out:
        print(f"refusing to write the case file inside the repo ({out}); pass --allow-repo-out to override",
              file=sys.stderr)
        return 2

    config = h2_cases.load_config(args.config)
    defaults = load_vector_defaults(args.benchmark_version)
    provider = make_gt_provider(args.benchmark_version, _authority_args(args.census_dir))
    doc = h2_cases.generate_cases(args.census_dir, config, defaults, gt_provider=provider)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps({"out": str(out), "config_sha256": doc["config_sha256"],
                      "counts": doc["counts"], "cases_digest": doc["cases_digest"]}, indent=2))
    if args.examples:
        shown = 0
        for c in doc["cases"]:
            if not c["invariants"]["all"]:
                continue
            print(f"\n=== {c['case_id']} (split={c['split']}, kind={c['attacker_value_kind']}, "
                  f"executable={(c.get('gt') or {}).get('attacker_executable')}) ===", file=sys.stderr)
            for arm in ("INSTR", "FACT", "SHAM"):
                print(f"  {arm}: {c['arms'][arm]['arm_text']!r}", file=sys.stderr)
            shown += 1
            if shown >= args.examples:
                break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

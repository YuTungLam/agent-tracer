#!/usr/bin/env python
"""Zero-cost conformance and integration checks on AgentDojo ground truth (lab venv).

Part A (protocol roster conformance, origin_rule O1): run every v1.2.2 user task's
ground truth in its default environment (no injection) and evaluate O1 under its
native table. O1 must deny at least one authority value in exactly the census v2 E0
tasks with ``non_prompt_values > 0`` (36/97 in the committed census). The
conservative join, PACT and SIEVE readings are tabulated on the same traces
(descriptive).

Part B (integration, optional ``--case-file``): for every runnable H2 case and arm,
execute the ground truth (legitimate trajectory) and, for value-carrying arms, the
ground truth with X substituted into the target slots (the generator's
executability rule), then run all three offline auditors through
``run_reference.py`` machinery and check the structural expectations:
O1 never admits X under its native table or carrier_untrusted when X is not in the
prompt; the native join blocks every authority call that follows a tool output; and
the generator's ground-truth invariant holds: the CLEAN and SHAM ground-truth
trajectories score ``legitimate`` (AgentDojo utility computed on the fixture).

These are scripted fixtures, not agent behaviour. No model, no network.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from ref_common import CONFIG_PATH, LAB, code_hashes, lab_code_hashes, load_config, sha256_bytes, write_json  # noqa: E402
import conservative_join  # noqa: E402
import native_replay as nr  # noqa: E402
import origin_rule  # noqa: E402
import ref_trace as rt  # noqa: E402
import run_reference  # noqa: E402

REPO = LAB.parents[1]
SENTINEL = "\u0000no-attacker-value"


def bare_spec(suite: str, task: str) -> dict[str, Any]:
    return rt.validate_spec({
        "schema": rt.SCHEMA_CASE_ARM, "case_id": None, "arm": None, "suite": suite, "user_task_id": task,
        "injections": {}, "oracle": {"target": {"function": "none", "argument": "none"}, "legitimate_set": [],
                                     "attacker_value": SENTINEL, "authority_arg_map": {}},
        "design": {}})


def part_a(config: dict[str, Any], census_e0: Path, authority_args, kinds) -> dict[str, Any]:
    expected = {}
    with census_e0.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            expected[(row["suite"], row["user_task_id"])] = int(row["non_prompt_values"] or 0) > 0
    denied: dict[str, set[tuple[str, str]]] = {}
    tasks_seen = 0
    readings = list(config["origin_rule"]["readings"])
    for suite in ("workspace", "travel", "banking", "slack"):
        s = nr.get_suite(suite)
        for task_id in sorted(s.user_tasks, key=lambda t: int(t.rsplit("_", 1)[1])):
            spec = bare_spec(suite, task_id)
            trace, _ = nr.scripted_trace(spec, nr.ground_truth_calls(spec), trace_id=f"gt:{suite}/{task_id}")
            tasks_seen += 1
            for reading in readings:
                ds = origin_rule.evaluate_trace(trace, config=config, reading_name=reading, labelling="native",
                                                authority_args=authority_args, kinds=kinds)
                if any(d["verdict"] == "block" for d in ds):
                    denied.setdefault(f"origin_rule/{reading}", set()).add((suite, task_id))
            ds = conservative_join.evaluate_trace(trace, authority_args=authority_args, kinds=kinds)
            if any(d["verdict"] == "block" for d in ds):
                denied.setdefault("conservative_join", set()).add((suite, task_id))
    want = {k for k, v in expected.items() if v}
    o1 = denied.get("origin_rule/O1", set())
    return {
        "user_tasks": tasks_seen, "census_tasks": len(expected),
        "census_tasks_with_non_prompt_values": len(want),
        "O1_denied_tasks": len(o1),
        "O1_exact_match": o1 == want,
        "O1_denied_not_in_census": sorted(f"{s}/{t}" for s, t in o1 - want),
        "census_not_denied_by_O1": sorted(f"{s}/{t}" for s, t in want - o1),
        "denied_task_counts": {k: len(v) for k, v in sorted(denied.items())},
        "join_superset_of_census_non_prompt": want <= denied.get("conservative_join", set()),
    }


def part_b(config: dict[str, Any], case_file: Path, out: Path, semantic_model: Path | None) -> dict[str, Any]:
    doc = rt.load_case_file(case_file)
    traces, binds, skipped = [], {}, []
    for spec in rt.iter_case_arm_specs(doc, runnable_only=True):
        calls = nr.ground_truth_calls(spec)
        tid = f"gtfix:{spec['case_id']}|{spec['arm']}|legit"
        trace, _ = nr.scripted_trace(spec, calls, trace_id=tid)
        traces.append(trace)
        binds[tid] = {"case_id": spec["case_id"], "arm": spec["arm"]}
        if spec["design"]["carries_attacker_value"]:
            sub, changed = nr.substitute_attacker(spec, calls)
            if not changed:
                skipped.append(tid)
                continue
            tid = f"gtfix:{spec['case_id']}|{spec['arm']}|attacker"
            trace, _ = nr.scripted_trace(spec, sub, trace_id=tid)
            traces.append(trace)
            binds[tid] = {"case_id": spec["case_id"], "arm": spec["arm"]}
    tdir = out / "fixtures"
    tdir.mkdir(parents=True, exist_ok=True)
    for t in traces:
        (tdir / (sha256_bytes(t["trace_id"].encode())[:16] + ".json")).write_text(json.dumps(t, ensure_ascii=False), encoding="utf-8")
    (out / "bind.json").write_text(json.dumps(binds, indent=1), encoding="utf-8")
    argv = ["--case-file", str(case_file), "--trace-dir", str(tdir), "--bind", str(out / "bind.json"),
            "--out-dir", str(out / "run"), "--auditors", "origin,join,neurotaint"]
    if semantic_model:
        argv += ["--semantic-model", str(semantic_model)]
    rc = run_reference.main(argv)
    calls = [json.loads(line) for line in (out / "run" / "calls.jsonl").read_text(encoding="utf-8").splitlines()]
    episodes = [json.loads(line) for line in (out / "run" / "episodes.jsonl").read_text(encoding="utf-8").splitlines()]
    violations = []
    for d in calls:
        if d["auditor"] == "origin_rule" and d["reading"] == "O1" and d["labelling"] in ("native", "carrier_untrusted"):
            for e in d["elements"]:
                if e["value_role"] == "attacker" and e["admitted"]:
                    violations.append({"rule": f"O1 ({d['labelling']}) admits X", "trace": d["trace_id"]})
        if d["auditor"] == "conservative_join" and d["labelling"] == "native":
            if d["visible_tool_sources"] > 0 and d["elements"] and d["verdict"] != "block":
                violations.append({"rule": "join passes a call after a tool output", "trace": d["trace_id"]})
    gt_outcomes: Counter = Counter()
    for e in episodes:
        if not e["trace_id"].endswith("|legit") or not e.get("undefended"):
            continue
        gt_outcomes[f"{e['arm']}:{e['undefended']['outcome']}/{e['undefended']['subtype']}"] += 1
        if e["arm"] in ("CLEAN", "SHAM") and e["undefended"]["outcome"] != "legitimate":
            violations.append({"rule": "CLEAN/SHAM ground truth does not score legitimate (generator invariant)",
                               "trace": e["trace_id"], "outcome": e["undefended"]["outcome"],
                               "subtype": e["undefended"]["subtype"]})
    summary = json.loads((out / "run" / "summary.json").read_text(encoding="utf-8"))
    return {"fixture_traces": len(traces), "substitution_noop_skipped": skipped, "run_exit": rc,
            "violations": violations, "ground_truth_outcomes": dict(sorted(gt_outcomes.items())),
            "decisions": Counter(f"{d['auditor']}/{d['reading']}/{d['labelling']}:{d['verdict']}"
                                 + (" (trivial_on_SS)" if d.get("trivial_on_SS") else "") for d in calls),
            "neurotaint_probe_plans": (summary.get("neurotaint") or {}).get("probe_plans"),
            "neurotaint_probes_planned": (summary.get("neurotaint") or {}).get("probes_planned")}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--census-e0-tasks", type=Path, required=True,
                        help="<results>/experiments/20261008-authority-origin-census-v2/derived/e0_tasks.csv")
    parser.add_argument("--case-file", type=Path, default=None)
    parser.add_argument("--semantic-model", type=Path, default=None)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    out = args.out_dir.resolve()
    try:
        out.relative_to(REPO.resolve())
        print("refused: --out-dir is inside the code repository", file=sys.stderr)
        return 2
    except ValueError:
        pass
    config = load_config(CONFIG_PATH)
    kinds = rt.value_kinds_from_census_config(REPO / "packages/agentdojo-lab/configs/authority_census_v2.json")
    authority_args = {fn: sorted(a) for fn, a in kinds.items()}
    result: dict[str, Any] = {"schema": "reference-conformance/v1", "model_requests": 0,
                              "census_e0_tasks_sha256_lf": sha256_bytes(args.census_e0_tasks.read_bytes().replace(b"\r\n", b"\n")),
                              "code_sha256_lf": code_hashes([HERE / f for f in run_reference.CODE_FILES] + [Path(__file__)]),
                              "lab_code_sha256_lf": lab_code_hashes()}
    result["part_a"] = part_a(config, args.census_e0_tasks, authority_args, kinds)
    if args.case_file:
        result["part_b"] = part_b(config, args.case_file, out / "part_b", args.semantic_model)
    write_json(out / "conformance.json", result)
    print(json.dumps({"O1_exact_match": result["part_a"]["O1_exact_match"],
                      "O1_denied": result["part_a"]["O1_denied_tasks"],
                      "census": result["part_a"]["census_tasks_with_non_prompt_values"],
                      "part_b_violations": len((result.get("part_b") or {}).get("violations") or [])}))
    ok = result["part_a"]["O1_exact_match"] and not (result.get("part_b") or {}).get("violations")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

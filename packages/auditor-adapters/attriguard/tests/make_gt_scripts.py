"""Precompute AgentDojo ground-truth call scripts per (case, arm) for ``fake_gt_upstream.py``.

Run with a python that has agentdojo 0.1.35 (the AttriGuard artifact venv) in UTF-8 mode; no model and
no network:

    python -X utf8 make_gt_scripts.py <case file> <out json> [split ...]

For each runnable case of the given splits (default: dev) and each arm, ``legit`` is the ground-truth
call list on the arm's injected environment. For an X-carrying arm, ``x`` is the same list with every
target-slot value that is in the legitimate set replaced by X (the substitution
``scripts/generate_h2_cases.py`` uses to test executability); otherwise ``x`` equals ``legit``.
"""

from __future__ import annotations

import json
import re
import sys
import unicodedata
from pathlib import Path

from agentdojo.task_suite.load_suites import get_suite


def _norm(text: object) -> str:
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", str(text)).casefold()).strip()


def main(argv: list[str]) -> int:
    cases_path, out_path = Path(argv[0]), Path(argv[1])
    splits = set(argv[2:]) or {"dev"}
    doc = json.loads(cases_path.read_text(encoding="utf-8"))
    suites: dict[str, object] = {}
    out: dict[str, dict[str, object]] = {}
    for case in doc["cases"]:
        if not (case.get("invariants") or {}).get("all") or case.get("split") not in splits:
            continue
        suite = suites.setdefault(case["suite"], get_suite("v1.2.2", case["suite"]))
        task = suite.get_user_task_by_id(case["user_task_id"])
        legit_values = {_norm(v) for v in case["legitimate_set"]}
        target = case["target"]
        for arm, spec in case["arms"].items():
            env = task.init_environment(suite.load_and_inject_default_environment(spec["injections"]))
            calls = task.ground_truth(env.model_copy(deep=True))
            legit = [{"function": c.function, "args": json.loads(json.dumps(dict(c.args), default=str))} for c in calls]
            x_calls = []
            for c in legit:
                args = dict(c["args"])
                if c["function"] == target["function"] and target["argument"] in args:
                    value = args[target["argument"]]
                    if isinstance(value, list):
                        args[target["argument"]] = [case["attacker_value"] if _norm(v) in legit_values else v for v in value]
                    elif _norm(value) in legit_values:
                        args[target["argument"]] = case["attacker_value"]
                x_calls.append({"function": c["function"], "args": args})
            out[f"{case['case_id']}|{arm}"] = {
                "legit": legit, "x": x_calls if spec.get("carries_attacker_value") else legit,
                "final": getattr(task, "GROUND_TRUTH_OUTPUT", "") or "Done.",
            }
    out_path.write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print(len(out), "scripts")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

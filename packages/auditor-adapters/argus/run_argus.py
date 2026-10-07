"""ARGUS / AgentLure on DeepSeek: command line. Run with the artifact's own venv python.

    run_argus.py designs [--seed 0]
    run_argus.py plan --agentlure-estimates FILE [--agentdojo-estimates FILE]
    run_argus.py agentlure --design s1|s2|full --rows none warrant --out DIR
    run_argus.py agentdojo --design s3 --rows none warrant --out DIR
    run_argus.py summarize --benchmark agentlure --out DIR

``agentlure`` and ``agentdojo`` make model calls, so they only run under the shared
budget guard (``common/deepseek_route.py run-stage``, see stages.json): it sets
OPENAI_BASE_URL and AUDITOR_GUARD_URL to the same loopback URL. Anything else is
refused. An Ollama dry run uses the same path (``run-stage --dry-run-ollama``).

Exit codes: 0 finished; 3 stopped by a budget refusal (partial, resumable with
``--resume-from``); 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from argus_adapter import (  # noqa: E402
    CostModel,
    _versions,
    agentdojo_design,
    agentlure_designs,
    estimate,
    load_estimator_rows,
    run_agentdojo,
    run_agentlure,
    summarize,
)
from argus_wire import DEEPSEEK_MODEL, WirePolicy, WireSession, require_loopback_base_url  # noqa: E402

AGENTDOJO_CONFIG = {"version": "v1.2.1", "attack": "important_instructions",
                    "target_model": "gpt-4o-mini-2024-07-18",
                    "artifact_draw": "80 attacked + 15 clean per suite, seed 0"}


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="run_argus", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("designs", help="print the S1 and S2 sample ids (no model calls)")
    d.add_argument("--seed", type=int, default=0)

    pl = sub.add_parser("plan", help="token and USD estimate per stage (no model calls)")
    pl.add_argument("--agentlure-estimates", type=Path, required=True,
                    help="estimate_calls_agentlure.json from the artifact smoke folder")
    pl.add_argument("--agentdojo-estimates", type=Path, help="estimate_calls_agentdojo_v1.2.1.json")
    pl.add_argument("--seed", type=int, default=0)

    for name, designs in (("agentlure", ["s1", "s2", "full"]), ("agentdojo", ["s3"])):
        r = sub.add_parser(name, help=f"run the {name} rows under the guard")
        r.add_argument("--design", choices=designs, required=True)
        r.add_argument("--rows", nargs="+", choices=["none", "warrant"], default=["none", "warrant"])
        r.add_argument("--out", type=Path, required=True, help="output folder (the runner passes {out_dir}/adapter)")
        r.add_argument("--resume-from", type=Path, action="append", default=[],
                       help="earlier output folder; its valid records of the same configuration are reused")
        r.add_argument("--stage", default=os.environ.get("AUDITOR_STAGE", ""))
        r.add_argument("--seed", type=int, default=0)
        r.add_argument("--limit", type=int, help="only the first N samples of the design")
        r.add_argument("--workers", type=int, default=8)
        r.add_argument("--max-requests", type=int, help="adapter-side request cap, under the guard's cap")
        r.add_argument("--max-total-tokens", type=int, help="adapter-side token cap, under the guard's cap")
        r.add_argument("--agent-temperature", choices=["artifact", "0"], default="artifact",
                       help="artifact: keep agentdojo 0.1.35's dropped temperature (provider default); "
                            "0: declared variant")

    s = sub.add_parser("summarize", help="metrics, CIs against the published rows, tokens and USD")
    s.add_argument("--benchmark", choices=["agentlure", "agentdojo"], required=True)
    s.add_argument("--out", type=Path, required=True)
    s.add_argument("--price-in", type=float, default=CostModel.price_in_per_m)
    s.add_argument("--price-out", type=float, default=CostModel.price_out_per_m)
    return p


def _plan(args) -> dict:
    cost = CostModel()
    designs = agentlure_designs(args.seed)
    rows = load_estimator_rows(args.agentlure_estimates, "agentlure")
    both = ("none", "warrant")
    plan = {"cost_model": cost.__dict__, "stages": {
        "DRY": estimate(rows, designs["s1"][:1], ("warrant",), cost),
        "S1": estimate(rows, designs["s1"], both, cost),
        "S2": estimate(rows, designs["s2"], both, cost),
        "S2-full (not planned)": estimate(rows, designs["full"], both, cost),
    }}
    if args.agentdojo_estimates:
        from agentlure.external import load

        bench = load("agentdojo", version=AGENTDOJO_CONFIG["version"], attack=AGENTDOJO_CONFIG["attack"])
        ad_rows = load_estimator_rows(args.agentdojo_estimates, "agentdojo")
        ids = [f"{s.subset}/{s.id}" for s in agentdojo_design(bench, args.seed)]
        plan["stages"]["S3"] = estimate(ad_rows, ids, both, cost)
    return plan


def guard_url(environ) -> str:
    """The loopback guard URL; refuses unless OPENAI_BASE_URL is the guard the runner started."""
    url = require_loopback_base_url(environ)
    if environ.get("AUDITOR_GUARD_URL") != url:
        raise SystemExit("Not running under the auditor guard: launch through "
                         "common/deepseek_route.py run-stage (AUDITOR_GUARD_URL must equal OPENAI_BASE_URL).")
    if not environ.get("OPENAI_API_KEY"):
        raise SystemExit("OPENAI_API_KEY (the guard token) is not set.")
    return url


def _run(args) -> int:
    if not sys.flags.utf8_mode:
        raise SystemExit("Set PYTHONUTF8=1: agentlure reads its corpus with the locale encoding (schema.py:21).")
    if (Path.cwd() / ".env").exists():
        raise SystemExit("Refusing to run from a folder that holds a .env file; use a scratch working folder.")
    url = guard_url(os.environ)
    out = args.out.resolve()
    policy = WirePolicy(model=DEEPSEEK_MODEL, agent_temperature=None if args.agent_temperature == "artifact" else 0.0,
                        max_requests=args.max_requests, max_total_tokens=args.max_total_tokens, stage=args.stage)
    session = WireSession(policy, out / "requests.jsonl")
    started = datetime.now(timezone.utc)
    if args.command == "agentlure":
        ids = agentlure_designs(args.seed)[args.design]
        ids = ids[: args.limit] if args.limit else ids
        counts = run_agentlure(ids, args.rows, out, session, policy.model, args.workers, args.resume_from)
        n = len(ids)
    else:
        from agentlure.external import load

        bench = load("agentdojo", version=AGENTDOJO_CONFIG["version"], attack=AGENTDOJO_CONFIG["attack"])
        samples = agentdojo_design(bench, args.seed)
        samples = samples[: args.limit] if args.limit else samples
        counts = run_agentdojo(samples, bench, args.rows, out, session, policy.model, args.workers,
                               AGENTDOJO_CONFIG, args.resume_from)
        n = len(samples)
    totals = session.totals()
    receipt = {
        "adapter": "argus", "benchmark": args.command, "design": args.design, "seed": args.seed,
        "samples_in_design": n, "rows": args.rows, "stage": policy.stage, "argv": sys.argv[1:],
        "mode": os.environ.get("AUDITOR_MODE"), "backbone": os.environ.get("AUDITOR_BACKBONE"),
        "endpoint": url, "policy": {**policy.identity(), "max_requests": policy.max_requests,
                                    "max_total_tokens": policy.max_total_tokens},
        "versions": _versions(), "counts": counts, "wire_totals": totals,
        "started_utc": started.isoformat(), "ended_utc": datetime.now(timezone.utc).isoformat(),
        "stopped_by_budget": totals["latch_reason"] is not None,
    }
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    (out / f"adapter-receipt-{stamp}.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    print(json.dumps({"counts": counts, "wire_totals": totals}, indent=2))
    return 3 if receipt["stopped_by_budget"] else 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "designs":
        print(json.dumps({k: v for k, v in agentlure_designs(args.seed).items() if k != "full"}, indent=1))
        return 0
    if args.command == "plan":
        print(json.dumps(_plan(args), indent=2))
        return 0
    if args.command == "summarize":
        print(json.dumps(summarize(args.out, args.benchmark, args.price_in, args.price_out), indent=2))
        return 0
    return _run(args)


if __name__ == "__main__":
    sys.exit(main())

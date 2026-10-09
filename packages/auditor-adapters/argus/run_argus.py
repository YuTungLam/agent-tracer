"""ARGUS / AgentLure on DeepSeek: command line. Run with the artifact's own venv python.

    run_argus.py designs [--seed 0]
    run_argus.py plan --agentlure-estimates FILE [--agentdojo-estimates FILE]
    run_argus.py agentlure --design s1|s2|full --rows none warrant --out DIR
    run_argus.py agentdojo --design s3 --rows none warrant --out DIR
    run_argus.py summarize --benchmark agentlure --out DIR
    run_argus.py cases-plan --cases FILE [selection] [--estimates FILE]
    run_argus.py cases --cases FILE [selection] --rows none warrant --out DIR
    run_argus.py cases-summarize --out DIR

``agentlure``, ``agentdojo`` and ``cases`` make model calls, so they only run under the
shared budget guard (``common/deepseek_route.py run-stage``, see stages.json): it sets
OPENAI_BASE_URL and AUDITOR_GUARD_URL to the same loopback URL. Anything else is
refused. An Ollama dry run uses the same path (``run-stage --dry-run-ollama``).
``cases-plan`` and ``cases-summarize`` make no model calls.

``cases`` runs Warrant as an online gate on a common authority case file (H2 SS, A1,
ADI authority cases; ``argus_cases.py`` documents the contract) through AgentLure's
AgentDojo integration on AgentDojo v1.2.2, scored with the typed authority oracle
(``agentdojo_lab.h2_cases.classify_outcome``).

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

    for name, help_text in (("cases-plan", "load, validate and select a case file; estimate tokens (no model calls)"),
                            ("cases", "run the rows as an online gate on a common case file, under the guard")):
        c = sub.add_parser(name, help=help_text)
        _case_selection_args(c)
        c.add_argument("--rows", nargs="+", choices=["none", "warrant"], default=["none", "warrant"])
        if name == "cases-plan":
            c.add_argument("--estimates", type=Path,
                           help="estimate_calls_agentdojo_v1.2.2.json from the artifact smoke folder")
            c.add_argument("--no-validate", action="store_true", help="skip the AgentDojo v1.2.2 vector check")
            continue
        c.add_argument("--out", type=Path, required=True, help="output folder (the runner passes {out_dir}/adapter)")
        c.add_argument("--resume-from", type=Path, action="append", default=[],
                       help="earlier output folder; its valid records of the same configuration are reused")
        c.add_argument("--rerun-errors", action="store_true", help="re-run episodes recorded with a run error")
        c.add_argument("--stage", default=os.environ.get("AUDITOR_STAGE", ""))
        c.add_argument("--workers", type=int, default=8)
        c.add_argument("--max-requests", type=int, help="adapter-side request cap, under the guard's cap")
        c.add_argument("--max-total-tokens", type=int, help="adapter-side token cap, under the guard's cap")
        c.add_argument("--agent-temperature", choices=["artifact", "0"], default="artifact")

    cs = sub.add_parser("cases-summarize", help="typed outcomes, gate funnel, verdicts, blame, false blocks, tokens")
    cs.add_argument("--out", type=Path, required=True)
    cs.add_argument("--price-in", type=float, default=CostModel.price_in_per_m)
    cs.add_argument("--price-out", type=float, default=CostModel.price_out_per_m)
    return p


def _case_selection_args(c: argparse.ArgumentParser) -> None:
    c.add_argument("--cases", type=Path, required=True, help="common case file (nested h2-cases or flat units)")
    c.add_argument("--oracle-module", type=Path, default=None,
                   help="agentdojo_lab/h2_cases.py (default: the lab checkout beside this adapter)")
    c.add_argument("--splits", nargs="+", default=["dev"],
                   help="case splits to run; 'any' keeps every split, including cases without one")
    c.add_argument("--families", nargs="+", default=None)
    c.add_argument("--value-kinds", nargs="+", default=None)
    c.add_argument("--arms", nargs="+", default=None,
                   help="default: the file's arms_emitted in order (else every arm of each case)")
    c.add_argument("--case-ids", nargs="+", default=None)
    c.add_argument("--max-cases", type=int, default=None)
    c.add_argument("--repeats", type=int, default=1)
    c.add_argument("--executable-only", action="store_true")
    c.add_argument("--no-require-runnable", action="store_true",
                   help="also run cases whose invariants.all is false")
    c.add_argument("--allow-unvalidated", action="store_true",
                   help="run stimuli that are not ground-truth validated (gt_validated not true and not every "
                        "selected unit runnable true); recorded in the plan and receipt")
    c.add_argument("--expect-content-sha256", action="append", default=[],
                   help="refuse unless the case file's LF-normalised SHA-256 equals this (pins a frozen file); "
                        "repeatable, every value must match, so a later flag cannot loosen a stage's pin")
    c.add_argument("--expect-cases-digest", action="append", default=[],
                   help="refuse unless the case file's declared cases_digest equals this; repeatable")
    c.add_argument("--limit", type=int, help="only the first N episodes of the selection")


def _load_selection(args):
    """(case file, oracle module, oracle info, episodes), or SystemExit with a reason (no calls made).

    ``case_file["validation"]`` records why the stimuli may run (``check_validated``) and the
    expected hashes that were checked."""
    from argus_cases import CaseContractError, check_validated, load_case_file, load_oracle, select_episodes

    try:
        oracle, oracle_info = load_oracle(args.oracle_module)
        case_file = load_case_file(args.cases, oracle)
        meta = case_file["meta"]
        for flag, key in (("expect_content_sha256", "content_sha256"), ("expect_cases_digest", "cases_digest")):
            for want in getattr(args, flag) or []:
                if str(meta.get(key)).lower() != str(want).strip().lower():
                    raise CaseContractError(f"case file {key} is {meta.get(key)}, the stage expects {want} "
                                            "(this stage is pinned to another file)")
        splits = None if any(s.lower() == "any" for s in args.splits) else args.splits
        episodes = select_episodes(case_file["units"], splits=splits, families=args.families,
                                   value_kinds=args.value_kinds, arms=args.arms, case_ids=args.case_ids,
                                   require_runnable=not args.no_require_runnable,
                                   executable_only=args.executable_only, max_cases=args.max_cases,
                                   repeats=args.repeats, arms_emitted=meta.get("arms_emitted"))
        episodes = episodes[: args.limit] if args.limit else episodes
        if not episodes:
            raise SystemExit("the selection is empty: nothing to run (check --splits/--value-kinds/--arms)")
        validation = check_validated(meta, episodes, args.allow_unvalidated)
    except CaseContractError as exc:
        raise SystemExit(f"case contract: {exc}") from None
    case_file["validation"] = {**validation, "expect_content_sha256": args.expect_content_sha256,
                               "expect_cases_digest": args.expect_cases_digest}
    return case_file, oracle, oracle_info, episodes


def _cases_plan(args) -> dict:
    from argus_cases import count_episodes, estimate_episodes, load_estimator_rows, plan_digest

    case_file, _, oracle_info, episodes = _load_selection(args)
    plan = {"case_file": case_file["meta"], "validation": case_file["validation"], "oracle": oracle_info,
            "counts": count_episodes(episodes), "plan_digest": plan_digest(episodes), "rows": args.rows}
    if not args.no_validate:
        from argus_gate import CaseAgentDojo, validate_units

        plan["validation_problems"] = validate_units(episodes, CaseAgentDojo(episodes))
    if args.estimates:
        plan["estimate"] = estimate_episodes(episodes, load_estimator_rows(args.estimates), args.rows, CostModel())
    return plan


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
    selection = _load_selection(args) if args.command == "cases" else None  # contract errors stop here, call-free
    out = args.out.resolve()
    policy = WirePolicy(model=DEEPSEEK_MODEL, agent_temperature=None if args.agent_temperature == "artifact" else 0.0,
                        max_requests=args.max_requests, max_total_tokens=args.max_total_tokens, stage=args.stage)
    session = WireSession(policy, out / "requests.jsonl")
    started = datetime.now(timezone.utc)
    if selection is not None:
        return _run_cases(args, selection, out, session, policy, url, started)
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


def _run_cases(args, selection, out: Path, session, policy, url: str, started) -> int:
    import argus_cases as ac
    import argus_gate as ag

    case_file, oracle, oracle_info, episodes = selection
    # The case file's tool-output format for this process (ADI amendment; yaml replaces nothing).
    ag.use_tool_output_format(case_file["meta"].get("tool_output_format") or "yaml")
    out.mkdir(parents=True, exist_ok=True)
    digest = ac.plan_digest(episodes)
    plan_doc = {"schema": ac.SCHEMA_PLAN, "adapter": ag.GATE_VERSION, "stage": policy.stage, "plan_digest": digest,
                "case_file": case_file["meta"], "validation": case_file["validation"], "oracle": oracle_info,
                "rows": args.rows, "counts": ac.count_episodes(episodes), "episodes": ac.episode_plan(episodes)}
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    (out / f"episode-plan-{stamp}.json").write_text(json.dumps(plan_doc, indent=1, default=str), encoding="utf-8")
    counts = ag.run_cases(episodes, args.rows, out, session, policy.model, args.workers, oracle=oracle,
                          oracle_info=oracle_info, case_meta=case_file["meta"], resume_from=args.resume_from,
                          rerun_errors=args.rerun_errors)
    totals = session.totals()
    code = {name: ac.sha256_text_lf(HERE / name)
            for name in ("run_argus.py", "argus_gate.py", "argus_cases.py", "argus_wire.py", "argus_adapter.py")}
    receipt = {
        "adapter": "argus", "benchmark": "cases", "gate": ag.GATE_VERSION, "suite_version": ag.AGENTDOJO_SUITE_VERSION,
        "stage": policy.stage, "argv": sys.argv[1:], "mode": os.environ.get("AUDITOR_MODE"),
        "backbone": os.environ.get("AUDITOR_BACKBONE"), "endpoint": url,
        "policy": {**policy.identity(), "max_requests": policy.max_requests, "max_total_tokens": policy.max_total_tokens},
        "case_file": case_file["meta"], "validation": case_file["validation"], "oracle": oracle_info,
        "plan_digest": digest,
        "selection": {k: getattr(args, k) for k in ("splits", "families", "value_kinds", "arms", "case_ids", "max_cases",
                                                     "repeats", "executable_only", "no_require_runnable",
                                                     "allow_unvalidated", "limit")},
        "episodes_planned": len(episodes), "rows": args.rows, "code_sha256_lf": code, "versions": _versions(),
        "counts": counts, "wire_totals": totals, "started_utc": started.isoformat(),
        "ended_utc": datetime.now(timezone.utc).isoformat(), "stopped_by_budget": totals["latch_reason"] is not None,
    }
    (out / f"adapter-receipt-{stamp}.json").write_text(json.dumps(receipt, indent=2, default=str), encoding="utf-8")
    try:  # the receipt is already on disk; a summary problem must not change the exit code
        summary = ac.summarize(out, CostModel.price_in_per_m, CostModel.price_out_per_m)
        (out / "cases-summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        print(f"warning: cases-summary.json not written ({type(exc).__name__}: {exc}); "
              "run `run_argus.py cases-summarize --out <dir>`", file=sys.stderr)
    print(json.dumps({"counts": counts, "wire_totals": totals}, indent=2, default=str))
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
    if args.command == "cases-plan":
        print(json.dumps(_cases_plan(args), indent=2, default=str))
        return 0
    if args.command == "cases-summarize":
        from argus_cases import summarize as summarize_cases

        print(json.dumps(summarize_cases(args.out, args.price_in, args.price_out), indent=1))
        return 0
    return _run(args)


if __name__ == "__main__":
    sys.exit(main())

"""Small entry point for installing and running the clean AgentDojo baseline."""

import argparse
import hashlib
import json
import sys
import tomllib
from pathlib import Path

from agentdojo.task_suite.load_suites import get_suites

from agentdojo_lab.inspection import inspect_events
from agentdojo_lab.runner import ROOT, RunConfig, RunExecutionError, doctor, load_config, run_clean


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("doctor", help="Check installation and credentials without network requests")
    check.add_argument("--config", type=Path, help="Check the endpoints selected by this run config")
    tasks = commands.add_parser("tasks", help="List native clean user tasks")
    tasks.add_argument("--suite", default="workspace")
    tasks.add_argument("--benchmark-version", default="v1.2.2")
    smoke = commands.add_parser("smoke", help="Verify the native pipeline with a fixed offline fixture")
    smoke.add_argument("--offline", action="store_true", required=True)
    smoke.add_argument("--output", type=Path)
    smoke.add_argument("--no-record", action="store_true", help="Disable event recording for a control run")
    inspect = commands.add_parser("inspect", help="Check event links and completeness without model calls")
    inspect.add_argument("--events", type=Path, required=True)
    report = commands.add_parser("report", help="Export paper-style tables and a trace from saved clean runs")
    report.add_argument("--runs", type=Path, default=ROOT / "runs")
    report.add_argument("--output", type=Path, help="New directory for CSV, LaTeX, PNG, SVG and PDF exports")
    html = commands.add_parser("html", help="Rebuild a self-contained interactive HTML record from one run")
    html.add_argument("--run", type=Path, required=True)
    html.add_argument("--output", type=Path, help="HTML path; defaults to RUN/report.html")
    pilot = commands.add_parser("pilot", help="Run a frozen clean pilot, one task per independent run")
    pilot.add_argument("--config", type=Path)
    pilot.add_argument("--output", type=Path)
    pilot.add_argument("--resume", type=Path, help="Continue only never-started trials in this frozen batch")
    pilot.add_argument("--through-repeat", type=int, default=1, choices=(1, 2, 3))
    pilot.add_argument(
        "--plan-only", action="store_true", help="Freeze the plan and export its index without model calls"
    )
    pilot_report = commands.add_parser(
        "pilot-report", help="Rebuild a pilot index and CSV files without model calls"
    )
    pilot_report.add_argument("--batch", type=Path, required=True)
    provenance = commands.add_parser(
        "provenance", help="Replay recorded prefixes into source candidates and blank review items"
    )
    inputs = provenance.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--run", type=Path, action="append", help="Source run; repeat for multiple runs")
    inputs.add_argument("--batch", type=Path, help="Frozen batch; analyzes recorded trials only")
    provenance.add_argument(
        "--output", type=Path, required=True, help="New analysis directory outside source runs"
    )
    provenance.add_argument(
        "--semantic-model", type=Path, help="Enable Tier 3/4 using a local pinned MiniLM snapshot"
    )
    provenance.add_argument(
        "--semantic-revision", help="Full model commit SHA; required with --semantic-model"
    )
    provenance.add_argument("--policy", type=Path, help="Select ordered cascade with a frozen tool policy")
    provenance.add_argument("--lineage-namespace", help="Build a DCPG independently for each recorded run")
    causal = commands.add_parser(
        "counterfactual", help="Audit saved proposal prefixes with an isolated, no-tools A/B judge"
    )
    causal.add_argument("--run", type=Path, required=True)
    causal.add_argument("--output", type=Path, required=True, help="New directory outside the source run")
    causal.add_argument(
        "--live", action="store_true", help="Call the selected judge; default is plan-only with no API calls"
    )
    causal.add_argument(
        "--judge-config", type=Path,
        help="Explicit provider/model/base_url/api_key_env TOML; required for live local-trace audits",
    )
    causal.add_argument("--max-probes", type=int, default=8)
    causal.add_argument("--pacing-state", type=Path, help="Shared sequential auditor quota state")
    evaluation = commands.add_parser("evaluate", help="Freeze or execute the native clean/injected pilot")
    evaluation_location = evaluation.add_mutually_exclusive_group(required=True)
    evaluation_location.add_argument("--output", type=Path, help="New immutable batch directory")
    evaluation_location.add_argument("--resume", type=Path, help="Run only never-started frozen slots")
    evaluation.add_argument("--config", type=Path)
    evaluation.add_argument("--plan-only", action="store_true", help="Freeze inputs without model calls")
    neurotaint = commands.add_parser(
        "neurotaint-eval", help="Freeze or execute the 120-slot NT-AgentDojo evaluation"
    )
    neurotaint_location = neurotaint.add_mutually_exclusive_group(required=True)
    neurotaint_location.add_argument("--output", type=Path, help="New immutable batch directory")
    neurotaint_location.add_argument("--resume", type=Path, help="Run only never-started frozen slots")
    neurotaint.add_argument("--config", type=Path)
    neurotaint.add_argument(
        "--conformance-dir",
        type=Path,
        help="Completed current-code M1-M7 receipt to copy into a new frozen batch",
    )
    neurotaint.add_argument(
        "--reference-dir",
        type=Path,
        help="Completed 24-pair known-origin evidence to copy into a new frozen batch",
    )
    neurotaint.add_argument("--plan-only", action="store_true", help="Freeze inputs without model calls")
    neurotaint_report = commands.add_parser(
        "neurotaint-eval-report",
        help="Render the normalized English NT-AgentDojo evaluation dashboard",
    )
    neurotaint_report.add_argument("--analysis", type=Path, required=True)
    neurotaint_report.add_argument("--plan", type=Path, required=True)
    neurotaint_report.add_argument("--reference-summary", type=Path)
    neurotaint_report.add_argument("--m7-aggregates", type=Path)
    neurotaint_report.add_argument(
        "--controlled-causal-panel",
        "--controlled-causal-panel-dir",
        dest="controlled_causal_panel",
        type=Path,
        help="Completed controlled causal-panel output directory",
    )
    neurotaint_report.add_argument(
        "--native-exact-prefix-replay",
        "--native-replay-dir",
        dest="native_exact_prefix_replay",
        type=Path,
        help="Completed native exact-prefix replay output directory",
    )
    neurotaint_report.add_argument("--output", type=Path, required=True)
    evaluation_report = commands.add_parser(
        "evaluation-report", help="Summarize saved evaluation with explicit unknowns"
    )
    evaluation_report.add_argument("--batch", type=Path, required=True)
    evaluation_report.add_argument("--output", type=Path, required=True)
    comparison = commands.add_parser("input-comparison", help="Freeze or run native passive/Canary controls")
    comparison_location = comparison.add_mutually_exclusive_group(required=True)
    comparison_location.add_argument("--output", type=Path)
    comparison_location.add_argument("--resume", type=Path)
    comparison.add_argument("--config", type=Path)
    comparison.add_argument("--plan-only", action="store_true")
    comparison_report = commands.add_parser("input-comparison-report", help="Analyze saved input controls")
    comparison_report.add_argument("--batch", type=Path, required=True)
    comparison_report.add_argument("--output", type=Path, required=True)
    assisted_score = commands.add_parser("assisted-score", help="Score exploratory AI-assisted agreement")
    assisted_score.add_argument("--packet", type=Path, required=True)
    assisted_score.add_argument("--labels", type=Path, required=True)
    assisted_score.add_argument("--output", type=Path, required=True)
    spans = commands.add_parser("span-diagnostic", help="Inspect decoded source regions in saved prefixes")
    spans.add_argument("--run", type=Path, required=True, action="append")
    spans.add_argument("--output", type=Path, required=True)
    heldout = commands.add_parser("heldout", help="Freeze or run the new passive clean/injected case")
    heldout_location = heldout.add_mutually_exclusive_group(required=True)
    heldout_location.add_argument("--output", type=Path)
    heldout_location.add_argument("--resume", type=Path)
    heldout.add_argument("--config", type=Path)
    heldout.add_argument("--plan-only", action="store_true")
    heldout_report = commands.add_parser("heldout-report", help="Summarize every slot in the held-out case")
    heldout_report.add_argument("--batch", type=Path, required=True)
    heldout_report.add_argument("--output", type=Path, required=True)
    heldout_report.add_argument("--span-report", type=Path, help="Link an existing optional span report")
    review = commands.add_parser("review-packet", help="Export a blinded human source-correspondence review")
    review.add_argument("--batch", type=Path, required=True)
    review.add_argument("--output", type=Path, required=True)
    labels = commands.add_parser("review-labels", help="Validate user-authored independent review labels")
    labels.add_argument("--packet", type=Path, required=True)
    labels.add_argument("--labels", type=Path, required=True)
    assisted = commands.add_parser(
        "assisted-review", help="Save disclosed Codex annotations as a separate report"
    )
    assisted.add_argument("--packet", type=Path, required=True)
    assisted.add_argument("--answers", type=Path, required=True)
    assisted.add_argument("--owner", required=True, help="Project owner; annotation authorship remains Codex")
    assisted.add_argument(
        "--output", type=Path, required=True, help="New directory outside the frozen packet"
    )
    live = commands.add_parser("run", help="Run selected clean tasks against the configured provider")
    live.add_argument("--config", type=Path, default=ROOT / "configs" / "groq.toml")
    live.add_argument("--model", help="Override the configured served model ID")
    live.add_argument("--task", action="append", help="Replace configured tasks; repeat to select more")
    live.add_argument("--no-record", action="store_true", help="Disable event recording for a control run")
    live.add_argument("--pacing-state", type=Path, help="Shared quota state for one sequential paced batch")
    live.add_argument(
        "--output", type=Path, help="New output directory; existing paths are never overwritten"
    )
    for command in (smoke, live):
        command.add_argument(
            "--canary",
            action="store_true",
            help="Enable the separate UUID source-text intervention condition",
        )
        command.add_argument(
            "--lineage-namespace", help="Observe DCPG in one native task and save a state sidecar"
        )
        command.add_argument("--policy", type=Path, help="Frozen tool policy for ordered online cascade")
        command.add_argument(
            "--online-provenance",
            action="store_true",
            help="Persist source candidates before tool runtime entry",
        )
        command.add_argument(
            "--online-causal-audit",
            action="store_true",
            help="Run bounded isolated causal judgments before native tool runtime",
        )
        command.add_argument("--causal-max-requests", type=int)
        command.add_argument("--causal-max-sources", type=int)
        command.add_argument("--causal-max-pairs", type=int)
        command.add_argument("--causal-model")
        command.add_argument("--causal-request-timeout-seconds", type=float)
        command.add_argument(
            "--semantic-model", type=Path, help="Local pinned MiniLM snapshot for online Tier 3/4"
        )
        command.add_argument("--semantic-revision", help="Full model commit SHA; use with --semantic-model")
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            result = doctor(load_config(args.config)) if args.config is not None else doctor()
        elif args.command == "evaluate":
            from agentdojo_lab.evaluation_batch import (
                create_evaluation_plan,
                execute_evaluation_batch,
                read_evaluation_plan,
            )

            if args.resume is not None and args.config is not None:
                raise ValueError("A resumed batch uses its frozen configuration")
            batch = args.resume or create_evaluation_plan(args.output, args.config)
            if args.plan_only:
                plan = read_evaluation_plan(batch)
                result = {
                    "batch_dir": str(batch.resolve()),
                    "planned": len(plan["schedule"]),
                    "model_calls": 0,
                }
            else:
                result = execute_evaluation_batch(batch)
        elif args.command == "evaluation-report":
            from agentdojo_lab.evaluation_analysis import analyze_batch
            from agentdojo_lab.evaluation_batch import read_evaluation_plan

            read_evaluation_plan(args.batch, check_implementation=False)
            result = analyze_batch(args.batch, args.output)
        elif args.command == "neurotaint-eval":
            from agentdojo_lab.neurotaint_eval import (
                create_neurotaint_eval_plan,
                execute_neurotaint_eval_batch,
                read_neurotaint_eval_plan,
            )

            if args.resume is not None and any(
                value is not None
                for value in (args.config, args.conformance_dir, args.reference_dir)
            ):
                raise ValueError("A resumed NT-AgentDojo batch uses all frozen inputs")
            if (
                args.resume is None
                and not args.plan_only
                and (args.conformance_dir is None or args.reference_dir is None)
            ):
                raise ValueError(
                    "A new live NT-AgentDojo batch requires both --conformance-dir and "
                    "--reference-dir before its immutable plan is created"
                )
            batch = args.resume or create_neurotaint_eval_plan(
                args.output,
                args.config,
                conformance_dir=args.conformance_dir,
                reference_dir=args.reference_dir,
            )
            if args.plan_only:
                plan = read_neurotaint_eval_plan(batch)
                result = {
                    "batch_dir": str(batch.resolve()),
                    "planned": len(plan["schedule"]),
                    "model_calls": 0,
                }
            else:
                result = execute_neurotaint_eval_batch(batch)
        elif args.command == "neurotaint-eval-report":
            from agentdojo_lab.neurotaint_eval import read_neurotaint_eval_plan
            from agentdojo_lab.neurotaint_eval_analysis import (
                adapt_native_matrix_summary,
                frozen_plan_identity,
            )
            from agentdojo_lab.neurotaint_eval_report import export_neurotaint_eval_report
            from agentdojo_lab.neurotaint_native_analysis import analyze_native_matrix

            if args.plan.name != "plan.json":
                raise ValueError("NeuroTaint reports require the frozen batch plan.json path")
            report_output = args.output.expanduser().resolve()
            protected_inputs = [
                args.plan.parent.expanduser().resolve(),
                args.analysis.expanduser().resolve(),
            ]
            if args.reference_summary is not None:
                protected_inputs.append(args.reference_summary.expanduser().resolve())
            for optional in (
                args.controlled_causal_panel,
                args.native_exact_prefix_replay,
            ):
                if optional is not None:
                    protected_inputs.append(optional.expanduser().resolve())
            if args.m7_aggregates is not None:
                protected_inputs.append(args.m7_aggregates.expanduser().resolve().parent)
            if any(
                report_output == source
                or report_output.is_relative_to(source)
                or source.is_relative_to(report_output)
                for source in protected_inputs
            ):
                raise ValueError(
                    "Report output must be separate from the frozen batch and optional "
                    "experiment evidence directories"
                )
            read_neurotaint_eval_plan(
                args.plan.parent,
                check_implementation=True,
                require_evidence=True,
            )
            try:
                supplied_analysis = json.loads(args.analysis.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, ValueError) as exc:
                raise ValueError("Cannot read the supplied native analysis summary") from exc
            if not isinstance(supplied_analysis, dict):
                raise ValueError("Native analysis summary must be one JSON object")
            recomputed_analysis = analyze_native_matrix(args.plan.parent)
            supplied_core = dict(supplied_analysis)
            recomputed_core = dict(recomputed_analysis)
            supplied_core.pop("normalized_adapter", None)
            recomputed_core.pop("normalized_adapter", None)
            if supplied_core != recomputed_core:
                raise ValueError(
                    "Supplied native analysis differs from a fresh read-only analysis of the "
                    "frozen batch"
                )
            attribution = None
            if args.reference_summary is not None:
                plan = json.loads(args.plan.read_text(encoding="utf-8"))
                reference = json.loads(args.reference_summary.read_text(encoding="utf-8"))
                if not isinstance(reference, dict) or not isinstance(
                    reference.get("attribution_metrics"), dict
                ):
                    raise ValueError(
                        "Reference summary must contain an attribution_metrics object"
                    )
                binding = plan.get("reference_panel") if isinstance(plan, dict) else None
                reference_files = binding.get("files") if isinstance(binding, dict) else None
                summary_digest = hashlib.sha256(args.reference_summary.read_bytes()).hexdigest()
                if (
                    not isinstance(binding, dict)
                    or binding.get("status") != "completed"
                    or not isinstance(reference_files, dict)
                    or reference_files.get("summary.json") != summary_digest
                    or reference.get("protocol") != binding.get("protocol")
                    or reference.get("panel_id") != binding.get("panel_id")
                ):
                    raise ValueError(
                        "Reference summary is not the completed evidence bound by the frozen plan"
                    )
                attribution = {
                    "status": reference.get("status", "available"),
                    "scope": reference.get("scope"),
                    "batch_identity": frozen_plan_identity(args.plan),
                    **reference["attribution_metrics"],
                }
            normalized = adapt_native_matrix_summary(
                recomputed_analysis,
                args.plan,
                attribution_summary=attribution,
                m7_aggregates=args.m7_aggregates,
                controlled_causal_panel=args.controlled_causal_panel,
                native_exact_prefix_replay=args.native_exact_prefix_replay,
                report_output=args.output,
            )
            result = export_neurotaint_eval_report(normalized, args.output)
        elif args.command == "input-comparison":
            from agentdojo_lab.input_comparison import (
                create_input_comparison_plan,
                execute_input_comparison_batch,
                read_input_comparison_plan,
            )

            if args.resume is not None and args.config is not None:
                raise ValueError("A resumed batch uses its frozen configuration")
            batch = args.resume or create_input_comparison_plan(args.output, args.config)
            if args.plan_only:
                plan = read_input_comparison_plan(batch)
                result = {
                    "batch_dir": str(batch.resolve()),
                    "planned": len(plan["schedule"]),
                    "model_calls": 0,
                }
            else:
                result = execute_input_comparison_batch(batch)
        elif args.command == "input-comparison-report":
            from agentdojo_lab.input_comparison_analysis import analyze_input_comparison

            result = analyze_input_comparison(args.batch, args.output)
        elif args.command == "heldout":
            from agentdojo_lab.heldout import create_heldout_plan, execute_heldout_batch, read_heldout_plan

            if args.resume is not None and args.config is not None:
                raise ValueError("A resumed held-out batch uses its frozen configuration")
            batch = args.resume or create_heldout_plan(args.output, args.config)
            if args.plan_only:
                plan = read_heldout_plan(batch)
                result = {"batch_dir": str(batch), "planned": len(plan["schedule"]), "model_calls": 0}
            else:
                result = execute_heldout_batch(batch)
        elif args.command == "heldout-report":
            from agentdojo_lab.heldout_analysis import analyze_heldout

            result = analyze_heldout(args.batch, args.output, span_report=args.span_report)
        elif args.command == "span-diagnostic":
            from agentdojo_lab.span_report import export_span_diagnostic

            result = export_span_diagnostic(args.run, args.output)
        elif args.command == "assisted-score":
            from agentdojo_lab.assisted_scoring import score_assisted_review

            result = score_assisted_review(args.packet, args.labels, args.output)
        elif args.command == "review-packet":
            from agentdojo_lab.evaluation_batch import read_evaluation_plan
            from agentdojo_lab.evaluation_review import export_review_packet

            plan = read_evaluation_plan(args.batch, check_implementation=False)
            runs = [
                args.batch / "runs" / item["trial_id"]
                for item in plan["schedule"]
                if (args.batch / "runs" / item["trial_id"] / "provenance.jsonl").is_file()
            ]
            result = export_review_packet(runs, args.output)
        elif args.command == "review-labels":
            from agentdojo_lab.evaluation_review import validate_review_labels

            result = validate_review_labels(args.packet, args.labels)
        elif args.command == "assisted-review":
            from agentdojo_lab.assisted_review import export_assisted_review

            result = export_assisted_review(args.packet, args.answers, args.owner, args.output)
        elif args.command == "counterfactual":
            from agentdojo_lab.counterfactual_audit import (
                ConfiguredCounterfactualJudge,
                GroqCounterfactualJudge,
                audit_run,
            )
            from agentdojo_lab.pacing import RequestPacer
            from agentdojo_lab.providers import EndpointSettings, reject_implicit_groq_audit

            if args.judge_config is not None and not args.live:
                raise ValueError("--judge-config requires --live; plan-only performs no provider selection")
            judge = None
            if args.live:
                if args.judge_config is None:
                    reject_implicit_groq_audit(args.run)
                    judge = GroqCounterfactualJudge(pacer=RequestPacer(7000, args.pacing_state))
                else:
                    endpoint = EndpointSettings.model_validate(tomllib.loads(args.judge_config.read_text()))
                    pacer = RequestPacer(7000, args.pacing_state) if endpoint.provider == "groq" else None
                    judge = ConfiguredCounterfactualJudge(endpoint, pacer=pacer)
            try:
                result = audit_run(args.run, args.output, judge=judge, max_probes=args.max_probes)
            finally:
                if judge is not None:
                    judge.close()
        elif args.command == "inspect":
            result = inspect_events(args.events)
        elif args.command == "report":
            from agentdojo_lab.reporting import export_report

            result = export_report(args.runs, args.output)
        elif args.command == "html":
            from agentdojo_lab.html_report import export_run_html

            result = export_run_html(args.run, output=args.output)
        elif args.command == "pilot":
            from agentdojo_lab.pilot import run_pilot

            result = run_pilot(
                config_path=args.config,
                output=args.output,
                resume=args.resume,
                through_repeat=args.through_repeat,
                plan_only=args.plan_only,
            )
        elif args.command == "pilot-report":
            from agentdojo_lab.pilot_report import export_pilot_report

            report_data = export_pilot_report(args.batch)
            result = {"batch_dir": str(args.batch.resolve()), **report_data["totals"]}
        elif args.command == "provenance":
            from agentdojo_lab.provenance_report import export_provenance

            if bool(args.semantic_model) != bool(args.semantic_revision):
                raise ValueError("Use --semantic-model and --semantic-revision together")
            matcher = None
            if args.semantic_model:
                from agentdojo_lab.semantic import LocalMiniLMEncoder, SemanticMatcher

                matcher = SemanticMatcher(
                    LocalMiniLMEncoder(args.semantic_model, revision=args.semantic_revision)
                )
            policy = None
            if args.policy:
                from agentdojo_lab.policy import load_policy

                policy = load_policy(args.policy)
            result = export_provenance(
                run_dirs=args.run,
                batch=args.batch,
                output=args.output,
                semantic_matcher=matcher,
                policy=policy,
                **(
                    {"lineage_namespace": args.lineage_namespace}
                    if args.lineage_namespace is not None
                    else {}
                ),
            )
        elif args.command == "tasks":
            suites = get_suites(args.benchmark_version)
            if args.suite not in suites:
                raise ValueError(f"Unknown suite/version: {args.suite}/{args.benchmark_version}")
            result = {
                "suite": args.suite,
                "benchmark_version": args.benchmark_version,
                "tasks": [{"id": t.ID, "prompt": t.PROMPT} for t in suites[args.suite].user_tasks.values()],
            }
        elif args.command == "smoke":
            result = run_clean(
                RunConfig(
                    record_events=not args.no_record,
                    online_provenance=args.online_provenance,
                    online_causal_audit=args.online_causal_audit,
                    provenance_policy=str(args.policy) if args.policy else None,
                    lineage_namespace=args.lineage_namespace,
                    canary_enabled=args.canary,
                    semantic_model=str(args.semantic_model) if args.semantic_model else None,
                    semantic_revision=args.semantic_revision,
                    **(
                        {"causal_max_requests": args.causal_max_requests}
                        if args.causal_max_requests is not None
                        else {}
                    ),
                    **(
                        {"causal_max_sources": args.causal_max_sources}
                        if args.causal_max_sources is not None
                        else {}
                    ),
                    **(
                        {"causal_max_pairs": args.causal_max_pairs}
                        if args.causal_max_pairs is not None
                        else {}
                    ),
                    **({"causal_model": args.causal_model} if args.causal_model is not None else {}),
                    **(
                        {"causal_request_timeout_seconds": args.causal_request_timeout_seconds}
                        if args.causal_request_timeout_seconds is not None
                        else {}
                    ),
                ),
                offline=True,
                output=args.output,
            )
        else:
            config = load_config(args.config)
            data = config.model_dump()
            if args.lineage_namespace is not None:
                data["lineage_namespace"] = args.lineage_namespace
            if args.canary:
                data["canary_enabled"] = True
            if args.model:
                data["model"] = args.model
                if not args.model.startswith("openai/gpt-oss"):
                    data["reasoning_effort"] = None
            if args.task:
                data["user_tasks"] = args.task
            if args.no_record:
                data["record_events"] = False
            if args.online_provenance:
                data["online_provenance"] = True
            if args.online_causal_audit:
                data["online_causal_audit"] = True
            if args.policy is not None:
                data["provenance_policy"] = str(args.policy)
            if args.semantic_model is not None:
                data["semantic_model"] = str(args.semantic_model)
            if args.semantic_revision is not None:
                data["semantic_revision"] = args.semantic_revision
            for option in (
                "causal_max_requests",
                "causal_max_sources",
                "causal_max_pairs",
                "causal_model",
                "causal_request_timeout_seconds",
            ):
                if getattr(args, option) is not None:
                    data[option] = getattr(args, option)
            result = run_clean(
                RunConfig.model_validate(data), output=args.output, pacing_state=args.pacing_state
            )
        if args.command in {"run", "smoke"} and result.get("run_dir"):
            report_status = Path(result["run_dir"]) / "html-report-status.json"
            try:
                if report_status.is_file():
                    status_data = json.loads(report_status.read_text(encoding="utf-8"))
                    if not isinstance(status_data, dict):
                        raise ValueError("Invalid report status")
                else:
                    status_data = {"status": "unavailable"}
            except (OSError, ValueError) as exc:
                status_data = {"status": "unavailable", "error_type": type(exc).__name__}
            result = {**result, "html_report": status_data}
    except Exception as exc:
        # Don't echo SDK request bodies or credentials to the terminal.
        if isinstance(exc, (ValueError, FileNotFoundError, FileExistsError, RunExecutionError)):
            print(f"Error: {exc}", file=sys.stderr)
        else:
            print(
                f"Run failed ({type(exc).__name__}). Inspect the latest runs/*/summary.json.", file=sys.stderr
            )
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.command == "doctor" and not result["offline_ready"]:
        return 2
    if args.command == "inspect" and not result["valid"]:
        return 2
    if args.command == "pilot" and not args.plan_only:
        if result["unscorable_trials"] or result["complete_recordings"] != result["started_trials"]:
            return 2
        if result["failed_trials"]:
            return 1
    if args.command in {"run", "smoke"} and result.get("recording", {}).get("complete") is False:
        return 2
    if args.command in {"run", "smoke"} and result.get("online_provenance", {}).get("complete") is False:
        return 2
    if args.command in {"run", "smoke"} and result.get("online_causal_audit", {}).get("complete") is False:
        return 2
    if args.command in {"run", "smoke"} and result.get("status") == "completed_with_issues":
        return 2
    if args.command in {"run", "smoke"} and result["task_success_count"] != result["task_count"]:
        return 1
    return 0

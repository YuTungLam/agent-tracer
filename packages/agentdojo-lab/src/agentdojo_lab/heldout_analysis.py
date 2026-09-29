"""Read-only accounting for one frozen held-out native task, with passive tracing."""

from __future__ import annotations

import csv
import html
import io
import os
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

from agentdojo_lab import evaluation_analysis as base
from agentdojo_lab.evaluation_review import _local
from agentdojo_lab.evaluation_runner import payload_exposure_audit
from agentdojo_lab.input_comparison_analysis import TIERS, _stages
from agentdojo_lab.inspection import inspect_events
from agentdojo_lab.runner import RunConfig

PROTOCOL = "native-heldout-passive-v1"
METHOD = "heldout_passive_analysis_v1"
ARMS = ("clean", "injected")
NATIVE_UTILITY_LIMITATION = (
    "The pinned task8 utility requires the diff category to be exactly iterable_item_added "
    "and checks the two added addresses, but does not explicitly bind those additions to event24. "
    "Extra file deletion can make native utility false even when the participants were added."
)


def _same(left, right):
    """JSON equality must distinguish booleans from numeric identities."""
    return base._canonical(left) == base._canonical(right)


def _plan(batch):
    from agentdojo_lab.heldout import read_heldout_plan

    plan = read_heldout_plan(batch, check_implementation=False)
    slots = plan.get("schedule")
    config = base._map(plan.get("config"))
    if (
        plan.get("protocol") != PROTOCOL
        or not isinstance(slots, list)
        or len(slots) != 10
        or Counter(slot.get("condition") for slot in slots) != {"clean": 5, "injected": 5}
        or any(slot.get("input_condition") != "passive" for slot in slots)
        or RunConfig.model_validate(config.get("run")).canary_enabled is not False
    ):
        raise ValueError("A frozen ten-slot passive held-out plan is required")
    return plan


def _usage(events, summary, recording_complete):
    reported = base._map(summary.get("usage"))
    requests = [event for event in events or [] if event.get("event_type") == "MODEL_REQUEST"]
    responses = [event for event in events or [] if event.get("event_type") == "MODEL_RESPONSE"]
    sums = {}
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        values = [
            base._number(
                base._map(base._map(event.get("data")).get("body")).get("usage", {}).get(key), integer=True
            )
            if isinstance(base._map(base._map(event.get("data")).get("body")).get("usage"), dict)
            else None
            for event in responses
        ]
        sums[key] = base._sum_known(values)
    request_count = base._number(reported.get("request_count"), integer=True)
    complete = events is not None and recording_complete is True
    request_consistent = complete and request_count == len(requests)
    token_consistent = all(
        reported.get(key) is None
        or base._number(reported.get(key), integer=True) is not None
        and sums[key]["unknown_count"] == 0
        and sums[key]["known_sum"] == reported[key]
        for key in ("prompt_tokens", "completion_tokens", "total_tokens")
    )
    for response in responses:
        usage = base._map(base._map(base._map(response.get("data")).get("body")).get("usage"))
        values = [
            base._number(usage.get(key), integer=True)
            for key in ("prompt_tokens", "completion_tokens", "total_tokens")
        ]
        if all(value is not None for value in values) and values[2] != values[0] + values[1]:
            token_consistent = False
    return {
        "available": events is not None,
        "request_count_consistent": request_consistent,
        "reported_token_totals_consistent": token_consistent if complete else None,
        "observed_requests": len(requests) if events is not None else None,
        "observed_responses": len(responses) if events is not None else None,
        "response_token_totals": sums,
        "scope": "recorded_API_fields_only; missing_response_usage_and_provider_billing_are_not_estimated",
    }


def _auditor(batch, slot, errors):
    root = batch / "audits" / slot["trial_id"]
    summary = base._object(root / "summary.json", errors)
    manifest = base._object(root / "manifest.json", errors)
    counts = base._map(summary.get("counts"))
    available = (
        type(summary.get("schema_version")) is int
        and summary["schema_version"] == 1
        and summary.get("execution_mode") == "deferred_prefix_audit"
        and manifest.get("source_run") == str(batch / "runs" / slot["trial_id"])
        and summary.get("unchanged_original_hashes") is True
        and isinstance(summary.get("counts"), dict)
        and all(
            isinstance(key, str) and base._number(value, integer=True) is not None
            for key, value in counts.items()
        )
    )
    return {
        "available": available,
        "request_count": counts.get("request", 0) if available else None,
        "status_counts": counts if available else {},
        "elapsed_seconds": base._number(summary.get("elapsed_seconds")) if available else None,
        "gate7_condition_eligibility": "ineligible_tier1_disabled",
        "judgment": None,
        "scope": "passive_Tier1_is_disabled; no_eligible_probe_is_not_a_negative_judgment",
    }


def _trial(batch, slot, plan):
    row = base._trial(batch, slot)
    run = Path(row["run_path"])
    errors = row["artifact_errors"]
    manifest = base._object(run / "manifest.json", [])
    summary = base._object(run / "summary.json", [])
    events = base._jsonl(run / "events.jsonl", [])
    provenance = base._jsonl(run / "provenance.jsonl", [])
    process = base._object(batch / "jobs" / slot["trial_id"] / "result.json", [])
    expected_config = RunConfig.model_validate(plan["config"]["run"]).model_dump()
    evaluation = base._map(summary.get("evaluation"))
    declaration_valid = (
        type(manifest.get("schema_version")) is int
        and manifest["schema_version"] == 1
        and _same(manifest.get("evaluation"), slot)
        and _same(manifest.get("config"), expected_config)
        and manifest.get("input_condition") == "passive"
        and base._map(manifest.get("config")).get("canary_enabled") is False
        and all(
            _same(evaluation.get(key), slot[key])
            for key in (
                "protocol",
                "input_condition",
                "case_id",
                "condition",
                "injection_task_id",
                "request_limit",
            )
        )
        and all(
            key not in evaluation or _same(evaluation[key], slot[key])
            for key in ("trial_id", "repeat", "user_task_id", "payload", "vector_id")
        )
        and (slot["condition"] == "injected" or evaluation.get("attack_goal_success") is None)
    )
    interventions = sum(event.get("event_type") == "TOOL_OUTPUT_INTERVENTION" for event in events or [])
    passive_valid = events is not None and not interventions and not summary.get("canary")
    inspection = inspect_events(run / "events.jsonl") if events is not None else None
    recording_valid = bool(row["recording_complete"] is True and inspection and inspection["valid"] is True)
    row["input_condition"] = "passive"
    row["declared_input_condition"] = manifest.get("input_condition")
    row["declaration_valid"] = declaration_valid and passive_valid
    row["passive_input_verified"] = passive_valid and recording_valid
    row["observed_intervention_count"] = interventions if events is not None else None
    row["recording_inspection"] = inspection
    row["recording_valid"] = recording_valid
    row["usage_validation"] = _usage(events, summary, recording_valid)
    row["native_query_attempts"] = base._number(evaluation.get("native_query_attempts"), integer=True)
    row["lineage_restart_limitation"] = evaluation.get("lineage_restart_limitation")
    row["auditor"] = _auditor(batch, slot, errors)
    row["budget_violation"] = (
        row["primary_usage"]["request_count"] is not None
        and row["primary_usage"]["request_count"] > slot["request_limit"]
        or row["usage_validation"]["observed_requests"] is not None
        and row["usage_validation"]["observed_requests"] > slot["request_limit"]
        or row["auditor"]["request_count"] is not None
        and row["auditor"]["request_count"] > 0
    )
    row["primary_protocol_valid"] = (
        row["declaration_valid"]
        and recording_valid
        and row["usage_validation"]["request_count_consistent"]
        and type(evaluation.get("request_limit")) is int
        and row["request_limit"] == slot["request_limit"]
        and row["primary_usage"]["request_count"] <= slot["request_limit"]
        and row["native_query_attempts"] is not None
        and row["native_query_attempts"] >= 1
        and base._map(inspection.get("event_counts")).get("EPISODE_STARTED") == row["native_query_attempts"]
    )
    # A later auditor/worker failure cannot erase an already persisted valid primary outcome.
    row["evaluation_valid"] = row["evaluation_valid"] and row["primary_protocol_valid"]
    if not row["evaluation_valid"]:
        row["utility"] = row["attack_goal_success"] = None
    if row["started"] and not row["declaration_valid"]:
        errors.append({"file": "manifest_or_summary.json", "error_type": "HeldoutDeclarationMismatch"})
    if row["started"] and not recording_valid:
        errors.append({"file": "events.jsonl", "error_type": "IncompleteOrInvalidRecording"})
    audit = (
        payload_exposure_audit(run / "events.jsonl", SimpleNamespace(**slot)) if events is not None else None
    )
    saved_audit = base._object(run / "payload-exposure.json", errors)
    source_ids = (
        list(dict.fromkeys(item["source_result_event_id"] for item in audit["occurrences"])) if audit else []
    )
    audit_bound = bool(
        audit
        and _same(audit, saved_audit)
        and row["declaration_valid"]
        and recording_valid
        and evaluation.get("payload_exposure_complete") is audit["complete"]
        and _same(evaluation.get("exposed_source_event_ids"), source_ids)
        and evaluation.get("payload_exposed")
        is (True if audit["occurrences"] else False if audit["complete"] else None)
    )
    row["exposure_audit_bound"] = audit_bound
    row["payload_exposed"] = (
        evaluation.get("payload_exposed") if slot["condition"] == "injected" and audit_bound else None
    )
    row["clean_raw_goal_scope"] = "technical_native_evaluator_output_only; not_an_assigned_attack_outcome"
    row["routing"]["stages"] = _stages(provenance, row["sidecar_complete"])
    row["routing"]["bound_to_declared_trial"] = row["declaration_valid"] and recording_valid
    row["timing"]["primary_run_elapsed_seconds"] = row["timing"].pop("run_elapsed_seconds")
    row["timing"]["whole_worker_elapsed_seconds"] = base._number(process.get("elapsed_seconds"))
    if row["usage_validation"]["reported_token_totals_consistent"] is False:
        for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
            row["primary_usage"][key] = None
        row["primary_usage"]["total_tokens_source"] = "inconsistent_recorded_totals"
        errors.append({"file": "summary_or_events.json", "error_type": "ReportedUsageMismatch"})
    return row


def _aggregate(rows):
    started = [row for row in rows if row["started"]]
    injected = [row for row in rows if row["condition"] == "injected"]
    bound = [row for row in started if row["routing"]["bound_to_declared_trial"]]
    first_hits, stages = Counter(), {tier: Counter() for tier in TIERS}
    for row in bound:
        first_hits.update(row["routing"]["first_hit_counts"])
        for tier in TIERS:
            stages[tier].update(row["routing"]["stages"]["observed_status_counts"][tier])
    return {
        "counts": {
            "planned": len(rows),
            "started": len(started),
            "unstarted": len(rows) - len(started),
            "completed_primary": sum(row["completed"] for row in rows),
            "evaluation_valid": sum(row["evaluation_valid"] for row in rows),
            "unknown_evaluation": sum(not row["evaluation_valid"] for row in rows),
            "process_failed": sum(row["process_failed"] for row in rows),
            "request_budget_exhausted": sum(row["request_budget_exhausted"] is True for row in started),
            "unknown_request_budget_status": sum(row["request_budget_exhausted"] is None for row in started),
            "budget_violation": sum(row["budget_violation"] for row in rows),
            "recording_valid": sum(row["recording_valid"] for row in started),
            "sidecar_complete": sum(row["sidecar_complete"] is True for row in started),
            "declaration_mismatch": sum(not row["declaration_valid"] for row in started),
            "artifact_error_trials": sum(bool(row["artifact_errors"]) for row in rows),
            "multi_query_attempts": sum((row["native_query_attempts"] or 0) > 1 for row in rows),
        },
        "metrics": {
            **base._outcomes(rows),
            "payload_exposed": base._ratio([row["payload_exposed"] for row in injected]),
            "attack_scope": "injected_assignment_only; clean_is_not_applicable",
        },
        "primary_usage": {
            key: base._sum_known(
                [row["primary_usage"][key] if row["declaration_valid"] else None for row in started]
            )
            for key in ("request_count", "prompt_tokens", "completion_tokens", "total_tokens")
        },
        "auditor_requests": base._sum_known(
            [row["auditor"]["request_count"] if row["declaration_valid"] else None for row in started]
        ),
        "timing": {
            key: base._sum_known(
                [
                    row["timing"][key]
                    if row["declaration_valid"] or key == "whole_worker_elapsed_seconds"
                    else None
                    for row in started
                ]
            )
            for key in (
                "primary_run_elapsed_seconds",
                "whole_worker_elapsed_seconds",
                "pacing_wait_seconds",
                "recorder_seconds",
                "sidecar_consume_ns",
                "sidecar_tracker_compute_ns",
                "sidecar_write_flush_ns",
            )
        },
        "routing": {
            "first_hit_counts": dict(first_hits),
            "stage_status_counts": {tier: dict(values) for tier, values in stages.items()},
            "comparison_count": base._sum_known(
                [
                    row["routing"]["comparison_count"] if row["routing"]["bound_to_declared_trial"] else None
                    for row in started
                ]
            ),
            "complete_stage_trials": sum(row["routing"]["stages"]["complete"] for row in bound),
            "scope": "descriptive_routing_only; no_attribution_accuracy_or_malicious_propagation_claim",
        },
    }


def _ratio_text(value):
    return f"{value['numerator']} / {value['denominator']} ({value['unknown_count']} unknown)"


def _display(value):
    return (
        "Unknown"
        if value is None
        else "Yes"
        if value is True
        else "No"
        if value is False
        else html.escape(str(value), quote=True)
    )


def _report(summary, output):
    arm_rows, trials = [], []
    for arm in summary["conditions"]:
        metrics = arm["metrics"]
        arm_rows.append(
            "<tr>"
            + "".join(
                f"<td>{value}</td>"
                for value in (
                    arm["condition"],
                    _ratio_text(metrics["utility"]),
                    _ratio_text(metrics["attack_goal_success"])
                    if arm["condition"] == "injected"
                    else "Not applicable",
                    _ratio_text(metrics["payload_exposed"])
                    if arm["condition"] == "injected"
                    else "Not applicable",
                    str(arm["counts"]["process_failed"]),
                    _display(arm["primary_usage"]["total_tokens"]["known_sum"]),
                )
            )
            + "</tr>"
        )
    for row in summary["trials"]:
        link = Path(row["run_path"]) / "report.html"
        report_link = (
            f'<a href="{quote(os.path.relpath(link, output), safe="/")}">Open agent timeline and diagram</a>'
            if link.is_file()
            else "Run report unavailable"
        )
        goal = _display(row["attack_goal_success"]) if row["condition"] == "injected" else "Not applicable"
        trials.append(
            f"<details><summary>{html.escape(row['trial_id'])} · {row['condition']} · utility {_display(row['utility'])} · attack goal {goal}</summary>"
            f"<p>{report_link}</p><dl>"
            + "".join(
                f"<dt>{name}</dt><dd>{_display(value)}</dd>"
                for name, value in (
                    ("Valid primary evaluation", row["evaluation_valid"]),
                    ("Verified complete recording", row["recording_valid"]),
                    (
                        "Payload exposed to an outbound request",
                        row["payload_exposed"] if row["condition"] == "injected" else "Not applicable",
                    ),
                    ("Primary requests", row["primary_usage"]["request_count"]),
                    ("Known primary tokens", row["primary_usage"]["total_tokens"]),
                    ("Request limit reached", row["request_budget_exhausted"]),
                    ("Worker failed", row["process_failed"]),
                    ("Primary execution seconds", row["timing"]["primary_run_elapsed_seconds"]),
                    ("Whole worker seconds", row["timing"]["whole_worker_elapsed_seconds"]),
                    ("Auditor requests", row["auditor"]["request_count"]),
                )
            )
            + f"</dl><details><summary>Technical evidence and unavailable fields</summary><pre>{html.escape(base._canonical({'artifact_errors': row['artifact_errors'], 'routing': row['routing'], 'usage_validation': row['usage_validation'], 'native_query_attempts': row['native_query_attempts'], 'lineage_restart_limitation': row['lineage_restart_limitation'], 'clean_raw_native_goal': row['raw_native_security'] if row['condition'] == 'clean' else None, 'clean_raw_goal_scope': row['clean_raw_goal_scope']}).decode())}</pre></details></details>"
        )
    span = summary.get("span_report")
    span_link = (
        f'<p><a href="{quote(os.path.relpath(span["path"], output), safe="/")}">Open the decoded-scalar span diagnostic</a> — offline lexical evidence, not attribution ground truth.</p>'
        if span
        else ""
    )
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Held-out passive task evaluation</title><style>body{font:16px/1.5 system-ui;max-width:1100px;margin:32px auto;padding:0 20px;color:#17202a}table{border-collapse:collapse;width:100%;font-size:14px}th,td{padding:9px;border:1px solid #cbd5e1;text-align:left}th{background:#edf2f7}details{margin:14px 0;padding:12px;border:1px solid #cbd5e1;border-radius:8px}summary{cursor:pointer;font-weight:600}.note{background:#fff4d6;padding:14px}a{color:#1257a5}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}dl{display:grid;grid-template-columns:1fr 1fr}dt,dd{margin:4px}section{overflow:auto}</style>"
        '<h1>Held-out passive task evaluation</h1><p class="note">One held-out native operation; five clean and five injected repeats. The source object, carrier and injection pattern may recur from development. This is a descriptive held-out task check, not benchmark-wide attribution accuracy.</p>'
        '<p><a href="heldout-summary.json">Full JSON</a> · <a href="outcomes.csv">CSV table</a> · <a href="outcomes.tex">LaTeX table</a></p>'
        + span_link
        + "<section><table><thead><tr><th>Condition</th><th>Utility</th><th>Attack goal</th><th>Payload exposed</th><th>Worker failures</th><th>Known primary tokens</th></tr></thead><tbody>"
        + "".join(arm_rows)
        + "</tbody></table></section><p>Ratios use observed eligible outcomes. Every planned slot is retained; missing results remain unknown. Clean attack and exposure rates are not applicable.</p><h2>Inspect one trial at a time</h2>"
        + "".join(trials)
        + "<details><summary>How to interpret these measurements</summary>"
        + f"<p>{html.escape(NATIVE_UTILITY_LIMITATION)}</p>"
        + "<p>The source run links open the original interactive event timeline and agent diagram. Source exposure means the fixed payload appeared in a recorded outbound tool message. It does not establish model influence, propagation or correct attribution. Five repetitions share one task and attack; they are not five independent scenarios.</p><p>Passive tracing disables Tier 1. The unchanged all-four-stages-negative auditor gate is therefore ineligible. Zero auditor requests is not a negative judgment. A missing audit artifact remains unknown. Independent label precision, recall and F1 remain unavailable.</p><p>The primary execution interval starts after manifest creation and ends on entry into finalization. It includes requests, pacing, native tools and synchronous tracing; it excludes earlier model setup, final artifact export and deferred auditing. Whole worker time includes these other phases. These overlapping measurements are not additive tracer overhead and do not provide a cross-condition overhead estimate.</p><p>Tokens are recorded provider-reported fields; failed or missing response usage and total billing are not estimated. Completed valid primary outcomes remain available after a later worker or auditor failure. No previous pilot is pooled.</p></details></html>"
    )


def _exports(summary):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(
        [
            "condition",
            "utility_positive",
            "utility_observed",
            "utility_unknown",
            "attack_goal_positive",
            "attack_goal_observed",
            "attack_goal_unknown",
            "payload_exposed_positive",
            "payload_exposed_observed",
            "payload_exposed_unknown",
        ]
    )
    latex = [
        r"\begin{tabular}{lrrr}",
        r"\hline",
        r"Condition & Utility & Attack goal & Payload exposed \\",
        r"\hline",
    ]
    for arm in summary["conditions"]:
        values, cells = [arm["condition"]], []
        for key in ("utility", "attack_goal_success", "payload_exposed"):
            metric = arm["metrics"][key]
            applicable = arm["condition"] == "injected" or key == "utility"
            values.extend(
                [metric["numerator"], metric["denominator"], metric["unknown_count"]]
                if applicable
                else ["", "", ""]
            )
            cells.append(
                f"{metric['numerator']}/{metric['denominator']} ({metric['unknown_count']} unknown)"
                if applicable
                else "N/A"
            )
        writer.writerow(values)
        latex.append(" & ".join([arm["condition"], *cells]) + r" \\")
    latex.extend(
        [
            r"\hline",
            r"\end{tabular}",
            "% Ratios use observed eligible outcomes. Missing slots remain unknown; clean attack outcomes are not applicable.",
        ]
    )
    return stream.getvalue(), "\n".join(latex) + "\n"


def analyze_heldout(batch: Path, output: Path, *, span_report: Path | None = None) -> dict:
    """Validate frozen declarations and export all slots without modifying source artifacts."""
    batch, output = _local(Path(batch)), _local(Path(output))
    if output.exists():
        raise FileExistsError(output)
    if output.is_relative_to(batch) or batch.is_relative_to(output):
        raise ValueError("Analysis output must be outside the source batch")
    span = None
    if span_report is not None:
        span_path = _local(Path(span_report))
        if not span_path.is_file() or span_path.suffix.lower() != ".html":
            raise ValueError("The optional span report must be an existing local HTML file")
        span = {"path": str(span_path), "sha256": base._sha(base._read_bytes(span_path))}
    before = base._tree(batch)
    plan = _plan(batch)
    trials = [_trial(batch, slot, plan) for slot in plan["schedule"]]
    summary = {
        "schema_version": 1,
        "protocol": PROTOCOL,
        "method": METHOD,
        "batch_path": str(batch),
        "plan_sha256": base._sha(base._read_bytes(batch / "plan.json")),
        **_aggregate(trials),
        "conditions": [
            {"condition": arm, **_aggregate([row for row in trials if row["condition"] == arm])}
            for arm in ARMS
        ],
        "trials": trials,
        "historical_runs_included": False,
        "span_report": span,
        "heldout_scope": "new_native_legitimate_operation; source_object_carrier_and_injection_pattern_may_recur; one_case_only",
        "gate8_status": "independent_attribution_evaluation_pending",
        "attribution_accuracy": {
            "status": "independent_labels_not_scored",
            "precision": None,
            "recall": None,
            "f1": None,
        },
        "source_hashes_before": before,
        "source_hashes_after": base._tree(batch),
        "limitations": [
            NATIVE_UTILITY_LIMITATION,
            "A native goal outcome, payload exposure and attribution correctness have separate denominators and meanings.",
            "Clean raw native security is a technical evaluator output; clean attack success is not applicable.",
            "All scheduled slots remain represented, including failures, timeouts, partial recordings and unstarted slots.",
            "Passive Tier 1 is disabled; auditor ineligibility supplies no negative judgment.",
            "No independent labels, significance claim, causal interpretation or benchmark-wide result is created.",
        ],
    }
    summary["source_files_unchanged"] = before == summary["source_hashes_after"]
    if not summary["source_files_unchanged"]:
        raise ValueError("Source batch changed during analysis; no output was written")
    if span and base._sha(base._read_bytes(Path(span["path"]))) != span["sha256"]:
        raise ValueError("Linked span report changed during analysis; no output was written")
    report = _report(summary, output)
    csv_text, latex = _exports(summary)
    output.mkdir(parents=True, exist_ok=False)
    (output / "heldout-summary.json").write_bytes(base._canonical(summary) + b"\n")
    (output / "index.html").write_text(report, encoding="utf-8")
    (output / "outcomes.csv").write_text(csv_text, encoding="utf-8")
    (output / "outcomes.tex").write_text(latex, encoding="utf-8")
    return summary

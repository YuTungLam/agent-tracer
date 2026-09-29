"""Verify and aggregate saved M7 evidence from a frozen native matrix.

This module does not score attribution truth, maliciousness, or causal
correctness.  It accepts only internally verified saved run evidence and keeps
missing or malformed slots explicit as unknown.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import os
import re
from collections import Counter, defaultdict
from pathlib import Path
from tempfile import TemporaryDirectory
from types import ModuleType

METHOD = "nt_agentdojo_m7_saved_aggregate_v1"
PROTOCOL = "NT-AgentDojo-Eval-v1"
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_TREE_FILES = 200_000
MAX_JSONL_ROWS = 200_000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_FUNCTION = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_REQUIRED_RUN_FILES = {
    "manifest.json",
    "summary.json",
    "events.jsonl",
    "provenance.jsonl",
    "causal-online.jsonl",
    "causal-online-graph.json",
    "lineage-state.json",
}
_PLAN_STATUSES = {"eligible", "partial", "not_eligible", "unknown"}
_JUDGMENT_STATUSES = {"valid", "invalid", "error", "not_run"}
_PREDICTION_STATUSES = {"complete_predictions", "partial_predictions", "unknown"}
_DECISION_STATUSES = {
    "not_selected",
    "explicit_positive",
    "predicted_control_positive",
    "negative_under_tested_interventions",
    "negative_no_policy_source",
    "unknown",
}
_TIMING_FIELDS = (
    "proposal_total_ns",
    "planning_total_ns",
    "judge_total_ns",
    "composition_total_ns",
    "serialization_total_ns",
    "write_flush_total_ns",
)
_SNAPSHOT_SCOPE = "all_regular_noncredential_files_in_frozen_batch"


def _unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate JSON key")
        value[key] = item
    return value


def _read(path: Path, *, limit: int = MAX_FILE_BYTES) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Analysis inputs must be regular non-symlink files")
    if path.stat().st_size > limit:
        raise ValueError("Analysis input exceeds its byte budget")
    return path.read_bytes()


def _json(path: Path) -> dict:
    try:
        value = json.loads(
            _read(path),
            object_pairs_hook=_unique_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise ValueError(f"Cannot parse {path.name}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain one JSON object")
    return value


def _jsonl(path: Path) -> list[dict]:
    raw = _read(path)
    lines = raw.splitlines()
    if len(lines) > MAX_JSONL_ROWS:
        raise ValueError("JSONL input exceeds its row budget")
    rows = []
    try:
        for line in lines:
            if not line.strip():
                continue
            row = json.loads(
                line,
                object_pairs_hook=_unique_pairs,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
            )
            if not isinstance(row, dict):
                raise ValueError("JSONL rows must be objects")
            rows.append(row)
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise ValueError(f"Cannot parse {path.name}") from exc
    return rows


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _reference_identity(plan: dict) -> str:
    binding = plan.get("reference_panel")
    frozen = plan.get("frozen_files")
    frozen = frozen if isinstance(frozen, dict) else {}
    frozen_digest = None
    if isinstance(binding, dict) and isinstance(binding.get("frozen_file"), str):
        frozen_digest = frozen.get(binding["frozen_file"])
    return _sha(_canonical({"reference_panel": binding, "frozen_file_sha256": frozen_digest}))


def _tree(root: Path) -> dict[str, str]:
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("Frozen batch contains a symbolic link")
        if not path.is_file():
            continue
        if path.name == ".env" or path.name.startswith(".env."):
            raise ValueError("Credential files cannot be M7 analysis inputs")
        if len(result) >= MAX_TREE_FILES:
            raise ValueError("Frozen batch exceeds its file-count budget")
        result[path.relative_to(root).as_posix()] = _sha(_read(path))
    return result


def _safe_id(value: object, *, name: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"Invalid {name}")
    return value


def _nonnegative(value: object) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _bool(value: object) -> bool | None:
    return value if type(value) is bool else None


def _finite(value: object) -> int | float | None:
    if type(value) not in (int, float):
        return None
    try:
        return value if value >= 0 and math.isfinite(value) else None
    except OverflowError:
        return None


def _validate_plan(batch: Path) -> tuple[dict, list[dict], str]:
    from agentdojo_lab.neurotaint_eval import read_neurotaint_eval_plan

    plan = read_neurotaint_eval_plan(
        batch,
        check_implementation=True,
        require_evidence=True,
    )
    return plan, plan["schedule"], _sha(_read(batch / "plan.json"))


_VERIFIER: ModuleType | None = None


def _load_verifier() -> ModuleType:
    global _VERIFIER
    if _VERIFIER is not None:
        return _VERIFIER
    script = Path(__file__).resolve().parents[2] / "scripts" / "verify_online_causal.py"
    spec = importlib.util.spec_from_file_location("agentdojo_lab_saved_m7_verifier", script)
    if spec is None or spec.loader is None:
        raise RuntimeError("Saved M7 verifier is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _VERIFIER = module
    return module


def _verify_run(run: Path) -> dict:
    """Use the repository's independent saved-run verifier without any API call."""
    value = _load_verifier().verify(run)
    if not isinstance(value, dict):
        raise ValueError("Saved M7 verifier returned an invalid result")
    return value


def _run_identity(slot: dict, run: Path, manifest: dict, summary: dict, causal: list[dict]) -> None:
    config = manifest.get("config")
    assignment = manifest.get("evaluation")
    attack = manifest.get("attack")
    evaluation = summary.get("evaluation")
    reported = summary.get("online_causal_audit")
    if not all(
        isinstance(value, dict)
        for value in (config, assignment, attack, evaluation, reported)
    ):
        raise ValueError("Run identity objects are missing")
    expected_budget = slot["judge_request_limit"]
    if (
        config.get("user_tasks") != [slot["user_task_id"]]
        or assignment != slot
        or manifest.get("input_condition") != "passive"
        or attack.get("condition") != slot["condition"]
        or attack.get("injection_task_id") != slot["injection_task_id"]
        or attack.get("vector_id") != slot["vector_id"]
        or attack.get("injection_assigned") is not (slot["condition"] == "injected")
        or config.get("canary_enabled") is not False
        or config.get("online_provenance") is not True
        or config.get("online_causal_audit") is not True
        or config.get("causal_max_requests") != expected_budget
        or evaluation.get("protocol") != PROTOCOL
        or evaluation.get("case_id") != slot["case_id"]
        or evaluation.get("condition") != slot["condition"]
        or evaluation.get("injection_task_id") != slot["injection_task_id"]
        or reported.get("complete") is not True
        or reported.get("request_budget") != expected_budget
        or reported.get("action_enforcement") != "none"
        or reported.get("model_weight_updates") != "none"
    ):
        raise ValueError("Run identity differs from its frozen matrix slot")
    rows = [row for row in causal if row.get("record_type") == "causal_analysis"]
    if not rows or any(
        row.get("run_id") != run.name or row.get("task_id") != slot["user_task_id"] for row in rows
    ):
        raise ValueError("Causal rows differ from the frozen run or task identity")


def _pairs(call: dict) -> list[dict]:
    result = []
    fields = call.get("fields")
    lineage = call.get("lineage")
    if not isinstance(fields, list) or not isinstance(lineage, dict):
        raise ValueError("Verified provenance call lacks bounded pair inventories")
    for field in fields:
        if not isinstance(field, dict) or not isinstance(field.get("nt_style_cascade"), list):
            raise ValueError("Verified provenance field has an invalid cascade inventory")
        result.extend(field["nt_style_cascade"])
    recovered = lineage.get("comparisons")
    if not isinstance(recovered, list):
        raise ValueError("Verified provenance lineage has an invalid comparison inventory")
    result.extend(recovered)
    if any(not isinstance(row, dict) for row in result):
        raise ValueError("Verified pair inventories contain a non-object")
    return result


def _explicit_negative(pair: dict) -> bool:
    return (
        pair.get("status") == "scored"
        and pair.get("matched") is False
        and pair.get("complete") is True
        and pair.get("truncated") is False
        and pair.get("first_matched_tier") is None
    )


def _ratio(count: int, denominator: int, *, unknown_count: int = 0) -> dict:
    return {
        "count": count,
        "denominator": denominator,
        "rate": count / denominator if denominator else None,
        "unknown_count": unknown_count,
    }


def _distribution(values: list[int | float | None]) -> dict:
    known = sorted(value for value in values if value is not None)
    if not known:
        return {
            "known_sum": None,
            "known_count": 0,
            "unknown_count": len(values),
            "minimum": None,
            "median": None,
            "p95_nearest_rank": None,
            "maximum": None,
        }
    median = (
        known[len(known) // 2]
        if len(known) % 2
        else (known[len(known) // 2 - 1] + known[len(known) // 2]) / 2
    )
    return {
        "known_sum": sum(known),
        "known_count": len(known),
        "unknown_count": len(values) - len(known),
        "minimum": known[0],
        "median": median,
        "p95_nearest_rank": known[math.ceil(0.95 * len(known)) - 1],
        "maximum": known[-1],
    }


def _normalized_proposals(slot: dict, run: Path, provenance: list[dict], causal: list[dict]) -> list[dict]:
    provenance_by_id = {}
    for row in provenance:
        if row.get("record_type") != "call_analysis":
            continue
        identifier = _safe_id(row.get("proposal_event_id"), name="proposal event ID")
        if identifier in provenance_by_id or not isinstance(row.get("call"), dict):
            raise ValueError("Verified provenance proposal inventory is not unique")
        provenance_by_id[identifier] = row
    causal_by_id = {}
    timing_by_id = {}
    for row in causal:
        if row.get("record_type") == "causal_analysis":
            identifier = _safe_id(row.get("proposal_event_id"), name="proposal event ID")
            if identifier in causal_by_id:
                raise ValueError("Verified causal proposal inventory is not unique")
            causal_by_id[identifier] = row
        elif row.get("record_type") == "causal_runtime_timing":
            identifier = _safe_id(row.get("proposal_event_id"), name="proposal event ID")
            if identifier in timing_by_id:
                raise ValueError("Verified runtime proposal inventory is not unique")
            timing_by_id[identifier] = row
    if set(provenance_by_id) != set(causal_by_id):
        raise ValueError("Verified provenance and causal proposal inventories differ")
    rows = []
    for identifier, causal_row in sorted(
        causal_by_id.items(), key=lambda item: item[1].get("record_sequence", -1)
    ):
        call = provenance_by_id[identifier]["call"]
        decision = causal_row.get("decision")
        plan = causal_row.get("plan")
        results = causal_row.get("results")
        prediction = causal_row.get("prediction_summary")
        if not all(isinstance(value, dict) for value in (decision, plan, prediction)) or not isinstance(
            results, list
        ):
            raise ValueError("Verified causal proposal lacks normalized evidence objects")
        function = call.get("function")
        if not isinstance(function, str) or not _FUNCTION.fullmatch(function):
            raise ValueError("Verified proposal function is not an English identifier")
        selected = call.get("policy", {}).get("sink", {}).get("selected")
        if type(selected) is not bool or decision.get("selected_sink") is not selected:
            raise ValueError("Verified proposal selected-sink binding differs")
        pairs = _pairs(call)
        first_hits = Counter(
            pair["first_matched_tier"]
            for pair in pairs
            if pair.get("first_matched_tier") in {"tier1", "tier2", "tier3", "tier4"}
        )
        explicit_unknowns = sum(
            not _explicit_negative(pair)
            and not (
                pair.get("status") == "scored"
                and pair.get("matched") is True
                and pair.get("complete") is True
                and pair.get("truncated") is False
                and pair.get("first_matched_tier")
                in {"tier1", "tier2", "tier3", "tier4"}
            )
            for pair in pairs
        )
        statuses = Counter()
        attempted = 0
        budget_exhausted = 0
        token_usage = defaultdict(list)
        for result in results:
            if not isinstance(result, dict):
                raise ValueError("Verified causal result inventory contains a non-object")
            status = result.get("status")
            if status not in _JUDGMENT_STATUSES:
                raise ValueError("Verified causal result has an unsupported status")
            statuses[status] += 1
            request_attempted = result.get("request_attempted") is True
            attempted += request_attempted
            budget_exhausted += result.get("reason") == "request_budget_exhausted"
            usage = result.get("usage")
            if not isinstance(usage, dict):
                raise ValueError("Verified causal result lacks explicit usage accounting")
            if request_attempted:
                for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
                    token_usage[key].append(_nonnegative(usage.get(key)))
        plan_status = plan.get("status")
        decision_status = decision.get("status")
        if plan_status not in _PLAN_STATUSES or decision_status not in _DECISION_STATUSES:
            raise ValueError("Verified causal proposal has an unsupported plan or decision status")
        timing_row = timing_by_id.get(identifier)
        before_runtime = (
            timing_row.get("analysis_before_runtime") is True
            and timing_row.get("receipt_before_runtime") is True
            if timing_row is not None
            else None
        )
        usage_summary = {
            key: _distribution(values) for key, values in sorted(token_usage.items())
        }
        causal_judgment = {
            "prediction_status": prediction.get("status")
            if prediction.get("status") in _PREDICTION_STATUSES
            else None,
            "judgment_status_counts": {
                status: statuses.get(status, 0)
                for status in ("valid", "invalid", "error", "not_run")
            },
        }
        rows.append(
            {
                "schema_version": 1,
                "proposal_id": identifier,
                "trial_id": slot["trial_id"],
                "case_id": slot["case_id"],
                "condition": slot["condition"],
                "domain": slot["domain"],
                "repeat": slot["repeat"],
                "run_id": run.name,
                "proposal_event_id": identifier,
                "function": function,
                "selected_sink": selected,
                "pair_count": len(pairs),
                "first_hit_counts": {
                    tier: first_hits.get(tier, 0) for tier in ("tier1", "tier2", "tier3", "tier4")
                },
                "all_explicit_negative_pair_count": sum(_explicit_negative(pair) for pair in pairs),
                "explicit_pair_unknown_count": explicit_unknowns,
                "causal_eligible": True
                if plan_status == "eligible"
                else False
                if plan_status == "not_eligible"
                else None,
                "causal_eligibility": plan_status,
                "plan_status": plan_status,
                "decision_status": decision_status,
                "decision_resolved": _bool(decision.get("decision_resolved")),
                "detector_positive": _bool(decision.get("detector_positive")),
                "independent_causal_accuracy": None,
                "maliciousness": "not_assessed",
                "planned_probe_count": len(results),
                "request_attempt_count": attempted,
                "judgment_status_counts": {
                    status: statuses.get(status, 0)
                    for status in ("valid", "invalid", "error", "not_run")
                },
                "routing": {
                    "pair_count": len(pairs),
                    "first_hit_counts": {
                        tier: first_hits.get(tier, 0)
                        for tier in ("tier1", "tier2", "tier3", "tier4")
                    },
                    "all_explicit_negative_pair_count": sum(
                        _explicit_negative(pair) for pair in pairs
                    ),
                    "unknown_pair_count": explicit_unknowns,
                },
                "causal_judgment": causal_judgment,
                "request_budget_exhausted_count": budget_exhausted,
                "prediction_status": prediction.get("status")
                if prediction.get("status") in _PREDICTION_STATUSES
                else None,
                "analysis_and_receipt_before_runtime": before_runtime,
                "audit_compute_elapsed_ns": _nonnegative(
                    causal_row.get("timing", {}).get("audit_compute_elapsed_ns")
                ),
                "latency": {
                    "audit_compute_elapsed_ns": _nonnegative(
                        causal_row.get("timing", {}).get("audit_compute_elapsed_ns")
                    )
                },
                "reported_usage": usage_summary,
                "usage": usage_summary,
                "verification": {
                    "saved_run_verifier_passed": True,
                    "flush_binding_verified": True,
                    "runtime_binding_verified": before_runtime,
                },
                "interpretation": (
                    "Recorded detector and isolated-judge predictions only; no attribution truth, "
                    "maliciousness, or causal correctness is inferred."
                ),
            }
        )
    return rows


def _slot(slot: dict, batch: Path, output: Path) -> tuple[dict, list[dict], list[dict], dict]:
    run = batch / "runs" / slot["trial_id"]
    job = batch / "jobs" / slot["trial_id"]
    base = {
        "trial_id": slot["trial_id"],
        "case_id": slot["case_id"],
        "condition": slot["condition"],
        "domain": slot["domain"],
        "repeat": slot["repeat"],
        "started": run.exists() or job.exists(),
        "m7_status": "unstarted",
        "proposal_count": None,
        "report": None,
    }
    if not base["started"]:
        return base, [], [], {"kind": "unstarted"}
    missing = sorted(name for name in _REQUIRED_RUN_FILES if not (run / name).is_file())
    if missing:
        base["m7_status"] = "unknown_missing_evidence"
        return base, [], [], {"kind": "missing_evidence", "missing_file_count": len(missing)}
    try:
        verification = _verify_run(run)
        if verification.get("passed") is not True:
            raise ValueError("saved verifier did not pass")
        checks = verification.get("checks")
        required_checks = {
            "event_identity_inventory_valid",
            "provenance_calls_and_flush_hashes_match",
            "causal_schema_sequence_and_inventory_match",
            "plans_requests_budget_and_judgments_revalidate",
            "causal_flush_precedes_matching_runtime",
            "close_and_summary_counts_recompute",
            "source_files_unchanged",
        }
        if not isinstance(checks, dict) or any(checks.get(name) is not True for name in required_checks):
            raise ValueError("saved verifier did not establish required M7 bindings")
        manifest = _json(run / "manifest.json")
        summary = _json(run / "summary.json")
        provenance = _jsonl(run / "provenance.jsonl")
        causal = _jsonl(run / "causal-online.jsonl")
        graph = _json(run / "causal-online-graph.json")
        _run_identity(slot, run, manifest, summary, causal)
        proposals = _normalized_proposals(slot, run, provenance, causal)
        if verification.get("proposal_count") != len(proposals):
            raise ValueError("Verifier and normalized proposal counts differ")
        base.update(
            m7_status="verified",
            proposal_count=len(proposals),
            report=os.path.relpath(run / "report.html", output).replace(os.sep, "/")
            if (run / "report.html").is_file()
            else None,
        )
        for proposal in proposals:
            proposal["report"] = base["report"]
        return base, proposals, [summary], graph
    except (
        OSError,
        UnicodeError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
        RuntimeError,
    ) as exc:
        base["m7_status"] = "unknown_invalid_evidence"
        return base, [], [], {"kind": "invalid_evidence", "error_type": type(exc).__name__}


def _funnel(proposals: list[dict], unknown_slots: int) -> list[dict]:
    proposal_count = len(proposals)
    selected = [row for row in proposals if row["selected_sink"] is True]
    pair_count = sum(row["pair_count"] for row in proposals)
    unknown_pairs = sum(row["explicit_pair_unknown_count"] for row in proposals)
    known_pairs = pair_count - unknown_pairs
    all_negative_proposals = [
        row
        for row in selected
        if row["pair_count"] > 0
        and row["explicit_pair_unknown_count"] == 0
        and row["all_explicit_negative_pair_count"] == row["pair_count"]
    ]
    unknown_negative_proposals = sum(
        row["explicit_pair_unknown_count"] > 0 for row in selected
    )
    planned = sum(row["planned_probe_count"] for row in proposals)
    stages = [
        {
            "stage": "selected_sinks",
            "unit": "proposals",
            **_ratio(len(selected), proposal_count),
        }
    ]
    for tier in ("tier1", "tier2", "tier3", "tier4"):
        stages.append(
            {
                "stage": f"{tier}_first_hits",
                "unit": "explicit_pairs",
                **_ratio(
                    sum(row["first_hit_counts"][tier] for row in proposals),
                    known_pairs,
                    unknown_count=unknown_pairs,
                ),
            }
        )
    stages.extend(
        [
            {
                "stage": "all_explicit_negative",
                "unit": "selected_sink_proposals",
                **_ratio(
                    len(all_negative_proposals),
                    len(selected),
                    unknown_count=unknown_negative_proposals,
                ),
            },
            {
                "stage": "explicit_negative_pairs_diagnostic",
                "unit": "explicit_pairs",
                **_ratio(
                    sum(row["all_explicit_negative_pair_count"] for row in proposals),
                    known_pairs,
                    unknown_count=unknown_pairs,
                ),
            },
            {
                "stage": "causal_eligible",
                "unit": "selected_sink_proposals",
                **_ratio(
                    sum(row["causal_eligible"] is True for row in selected),
                    sum(type(row["causal_eligible"]) is bool for row in selected),
                    unknown_count=sum(row["causal_eligible"] is None for row in selected),
                ),
            },
            {"stage": "planned_probes", "unit": "probes", **_ratio(planned, planned)},
            {
                "stage": "attempted_requests",
                "unit": "probes",
                **_ratio(sum(row["request_attempt_count"] for row in proposals), planned),
            },
        ]
    )
    for status in ("valid", "invalid", "error"):
        stages.append(
            {
                "stage": f"{status}_judgments",
                "unit": "probes",
                **_ratio(
                    sum(row["judgment_status_counts"][status] for row in proposals), planned
                ),
            }
        )
    stages.append(
        {
            "stage": "request_budget_exhausted",
            "unit": "probes",
            **_ratio(sum(row["request_budget_exhausted_count"] for row in proposals), planned),
        }
    )
    for row in stages:
        row["unknown_slot_count"] = unknown_slots
        row["unknown_slot_scope"] = "Slots without verified M7 evidence have no proposal denominator."
    return stages


def _aggregate_summaries(summaries: list[dict], proposals: list[dict]) -> tuple[dict, dict]:
    latency_values = {key: [] for key in _TIMING_FIELDS}
    for summary in summaries:
        timing = summary.get("online_causal_audit", {}).get("timing", {})
        for key in _TIMING_FIELDS:
            latency_values[key].append(_nonnegative(timing.get(key)))
    latency_values["proposal_audit_compute_ns"] = [
        row["audit_compute_elapsed_ns"] for row in proposals
    ]
    latency = {
        "scope": "Saved M7 wall-clock totals per verified run and compute time per proposal.",
        **{key: _distribution(values) for key, values in latency_values.items()},
    }
    attempted = sum(row["request_attempt_count"] for row in proposals)
    # Re-read the already normalized per-proposal counts without estimating
    # absent provider fields.  Multi-request totals remain explicit sums.
    tokens = {
        "scope": "Returned judge API token fields only; missing usage is not estimated.",
        "attempted_request_count": attempted,
    }
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        known_sum = sum(
            row["reported_usage"].get(key, {}).get("known_sum") or 0 for row in proposals
        )
        known_count = sum(
            row["reported_usage"].get(key, {}).get("known_count", 0) for row in proposals
        )
        tokens[key] = {
            "known_sum": known_sum if known_count else None,
            "known_count": known_count,
            "unknown_count": attempted - known_count,
        }
    return latency, tokens


def _causal_summary(proposals: list[dict], graphs: list[dict], unknown_slots: int) -> dict:
    selected = [row for row in proposals if row["selected_sink"]]
    eligible = [row for row in selected if row["causal_eligible"] is True]
    known_eligibility = [row for row in selected if type(row["causal_eligible"]) is bool]
    status_counts = Counter(
        status
        for row in proposals
        for status, count in row["judgment_status_counts"].items()
        for _ in range(count)
    )
    decisions = Counter(row["decision_status"] for row in proposals)
    edge_relations = Counter()
    for graph in graphs:
        edges = graph.get("added_edges")
        if isinstance(edges, list):
            edge_relations.update(
                row.get("relation")
                for row in edges
                if isinstance(row, dict)
                and row.get("relation") in {"source_set_membership", "predicted_control"}
            )
    planned = sum(row["planned_probe_count"] for row in proposals)
    return {
        "scope": (
            "Verified saved detector and isolated-judge predictions; no observed counterfactual "
            "behavior, attribution truth, maliciousness, or calibrated causal correctness."
        ),
        "verified_proposal_count": len(proposals),
        "selected_sinks": _ratio(len(selected), len(proposals)),
        "causal_reachability": _ratio(
            len(eligible),
            len(known_eligibility),
            unknown_count=len(selected) - len(known_eligibility),
        ),
        "planned_probe_count": planned,
        "request_attempt_count": sum(row["request_attempt_count"] for row in proposals),
        "judgment_status_counts": {
            status: status_counts.get(status, 0)
            for status in ("valid", "invalid", "error", "not_run")
        },
        "unknown_judgment_count": planned - status_counts.get("valid", 0),
        "decision_status_counts": dict(sorted(decisions.items())),
        "before_runtime_verified": _ratio(
            sum(row["analysis_and_receipt_before_runtime"] is True for row in proposals),
            sum(row["analysis_and_receipt_before_runtime"] is not None for row in proposals),
            unknown_count=sum(
                row["analysis_and_receipt_before_runtime"] is None for row in proposals
            ),
        ),
        "typed_edge_counts": {
            relation: edge_relations.get(relation, 0)
            for relation in ("source_set_membership", "predicted_control")
        },
        "unknown_slot_count": unknown_slots,
        "causal_correctness": None,
        "attribution_truth": None,
        "maliciousness": "not_assessed",
        "action_enforcement": "none",
        "model_weight_updates": "none",
    }


def analyze_m7_batch(batch: Path, output: Path) -> dict:
    """Create a new immutable M7 aggregate without modifying the frozen batch."""
    batch = Path(batch).expanduser().absolute()
    output = Path(output).expanduser().absolute()
    if batch.is_symlink() or not batch.is_dir():
        raise ValueError("Batch must be a non-symlink directory")
    batch = batch.resolve()
    if output.exists():
        raise FileExistsError(output)
    resolved_output = output.resolve()
    if resolved_output.is_relative_to(batch) or batch.is_relative_to(resolved_output):
        raise ValueError("Analysis output must be separate from the frozen batch")
    before = _tree(batch)
    plan, schedule, plan_sha256 = _validate_plan(batch)
    slots, proposals, summaries, graphs, failures = [], [], [], [], []
    unknown_counts = Counter()
    for item in schedule:
        slot, slot_proposals, slot_summaries, detail = _slot(item, batch, output)
        slots.append(slot)
        proposals.extend(slot_proposals)
        summaries.extend(slot_summaries)
        if detail.get("kind") in {"unstarted", "missing_evidence", "invalid_evidence"}:
            unknown_counts[detail["kind"]] += 1
        if detail.get("kind") in {"missing_evidence", "invalid_evidence"}:
            failures.append(
                {
                    "trial_id": item["trial_id"],
                    "type": f"m7_{detail['kind']}",
                    **(
                        {"missing_file_count": detail["missing_file_count"]}
                        if "missing_file_count" in detail
                        else {"error_type": detail["error_type"]}
                    ),
                }
            )
        if isinstance(detail, dict) and "added_edges" in detail:
            graphs.append(detail)
    unknown_slots = sum(slot["m7_status"] != "verified" for slot in slots)
    routing = _funnel(proposals, unknown_slots)
    latency, tokens = _aggregate_summaries(summaries, proposals)
    after = _tree(batch)
    if before != after:
        raise ValueError("Frozen batch changed during M7 analysis")
    source_snapshot_sha256 = _sha(_canonical(before))
    batch_identity = {
        "schema_version": 1,
        "authority": "verified_frozen_plan_and_read_only_full_batch_snapshot",
        "protocol": plan["protocol"],
        "batch_id": plan["batch_id"],
        "plan_identity_sha256": _sha(_canonical(plan)),
        "exact_plan_json_sha256": plan_sha256,
        "frozen_plan_digest": plan_sha256,
        "reference_identity_sha256": _reference_identity(plan),
        "source_batch_snapshot_sha256": source_snapshot_sha256,
        "source_batch_snapshot_scope": _SNAPSHOT_SCOPE,
        "source_batch_file_count": len(before),
    }
    summary = {
        "schema_version": 1,
        "method": METHOD,
        "status": "completed"
        if not unknown_slots
        else "partial"
        if unknown_counts["unstarted"]
        else "completed_with_unknowns",
        "protocol": PROTOCOL,
        "batch_id": plan["batch_id"],
        "plan_sha256": plan_sha256,
        "exact_plan_json_sha256": plan_sha256,
        "frozen_plan_digest": plan_sha256,
        "batch_identity": batch_identity,
        "planned_slot_count": len(schedule),
        "verified_slot_count": len(schedule) - unknown_slots,
        "routing_funnel": routing,
        "causal_summary": _causal_summary(proposals, graphs, unknown_slots),
        "latency": latency,
        "tokens": tokens,
        "failures": failures,
        "unknowns": {
            "unstarted_slots": unknown_counts["unstarted"],
            "missing_evidence_slots": unknown_counts["missing_evidence"],
            "invalid_evidence_slots": unknown_counts["invalid_evidence"],
            "unknown_m7_slots": unknown_slots,
            "unknown_proposal_count": None if unknown_slots else 0,
            "unknown_proposal_count_reason": (
                "Unverified slots have no trustworthy proposal inventory."
                if unknown_slots
                else None
            ),
        },
        "slots": slots,
        "proposals": proposals,
        "proposal_scope": {
            "status": "verified_saved_rows" if proposals else "no_verified_proposals",
            "file": "proposals.jsonl",
            "truth_rescored": False,
            "causal_correctness_inferred": False,
        },
        "integrity": {
            "plan_digest_verified": True,
            "frozen_file_hashes_verified": True,
            "verified_runs_use_independent_saved_m7_verifier": True,
            "flush_and_runtime_bindings_required": True,
            "source_files_unchanged_during_analysis": True,
            "source_tree_sha256": source_snapshot_sha256,
            "source_tree_scope": _SNAPSHOT_SCOPE,
            "source_tree_file_count": len(before),
        },
        "normalization": {
            "slot_order": "frozen_plan_schedule",
            "missing_or_malformed_evidence": "unknown",
            "attribution_truth_inferred": False,
            "maliciousness_inferred": False,
            "causal_correctness_inferred": False,
            "model_or_api_requests": 0,
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=output.parent, prefix=".m7-analysis-") as temporary:
        staged = Path(temporary) / "result"
        staged.mkdir()
        aggregate_path = staged / "m7-aggregates.json"
        proposal_path = staged / "proposals.jsonl"
        aggregate_path.write_bytes(_canonical(summary) + b"\n")
        proposal_path.write_bytes(b"".join(_canonical(row) + b"\n" for row in proposals))
        manifest = {
            "schema_version": 1,
            "method": METHOD,
            "batch_id": plan["batch_id"],
            "batch_identity": batch_identity,
            "scope": "new_immutable_output; frozen_source_read_only",
            "files": {
                path.name: _sha(path.read_bytes()) for path in (aggregate_path, proposal_path)
            },
        }
        (staged / "manifest.json").write_bytes(_canonical(manifest) + b"\n")
        staged.replace(output)
    return summary

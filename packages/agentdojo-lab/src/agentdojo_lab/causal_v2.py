"""Opt-in bounded counterfactual coverage and joint auditor predictions.

No agent reruns or model clients are constructed. Version 1 behavior stays separate.
"""

from __future__ import annotations

import argparse
import copy
import html
import itertools
import json
import math
from collections import Counter
from pathlib import Path

from agentdojo_lab import counterfactual as v1
from agentdojo_lab import judgment_formats
from agentdojo_lab.profiles import get_profile

PROTOCOL = "counterfactual-joint-coverage-v2"
MAX_SOURCES = 8
MAX_PAIRS = 28
SCOPE = "self_reported_auditor_predictions_only; not_observed_behavior_or_calibrated_causality"


def explicit_coverage(pair: dict, *, canary_enabled: bool) -> dict:
    """Classify complete negative active stages without treating failures as negatives."""
    result = {"status": "unknown", "reason": None, "stages": {}, "profile": None}
    try:
        v1._require(type(canary_enabled) is bool and isinstance(pair, dict), "invalid_condition_or_pair")
        v1._bounded_json(pair)
        metadata = pair.get("metadata", {})
        profile = get_profile(metadata.get("profile", "ordinary"))
        result["profile"] = profile.name
        v1._require(metadata.get("canary_enabled") is canary_enabled, "condition_evidence_mismatch")
        v1._require(metadata.get("semantic_enabled") is True, "active_semantic_configuration_missing")
        thresholds = {
            "tier2_lcs": profile.lexical_threshold,
            "tier3_cosine": profile.semantic_threshold,
            "tier4_cosine": profile.semantic_threshold,
            "tier4_coverage": profile.coverage_threshold,
        }
        v1._require(metadata.get("thresholds") == thresholds, "profile_threshold_mismatch")
        if pair.get("matched") is True:
            return {**result, "status": "not_eligible", "reason": "explicit_candidate_present"}
        v1._require(
            pair.get("status") == "scored"
            and pair.get("matched") is False
            and pair.get("complete") is True
            and pair.get("truncated") is False
            and pair.get("first_matched_tier") is None,
            "incomplete_explicit_evidence",
        )
        stages = pair.get("stages", {})
        for name in ("tier1", "tier2", "tier3", "tier4"):
            stage = stages.get(name, {})
            status = stage.get("status")
            if name == "tier1" and status in {"disabled_condition", "not_applicable"}:
                expected = (
                    ("disabled_condition", "passive_input_unchanged_no_canary")
                    if not canary_enabled
                    else ("not_applicable", "source_has_no_validated_exposed_canary")
                )
                v1._require(
                    (status, stage.get("reason")) == expected
                    and stage.get("score") is None
                    and stage.get("matched") is None
                    and stage.get("complete") is False
                    and stage.get("truncated") is False,
                    "invalid_inapplicable_tier1",
                )
                result["stages"][name] = {"status": status, "negative_measurement": False}
                continue
            v1._require(name != "tier1" or canary_enabled, "unexpected_passive_tier1_measurement")
            v1._require(
                status == "scored"
                and stage.get("matched") is False
                and stage.get("complete") is True
                and stage.get("truncated") is False,
                "incomplete_active_stage",
            )
            score = stage.get("score")
            v1._require(type(score) in (int, float) and math.isfinite(score), "missing_active_stage_score")
            if name == "tier1":
                valid = score == 0
            elif name == "tier2":
                valid = 0 <= score < profile.lexical_threshold
            elif name == "tier3":
                valid = -1 <= score < profile.semantic_threshold
            else:
                coverage = stage.get("coverage")
                valid = (
                    type(coverage) in (int, float)
                    and math.isfinite(coverage)
                    and 0 <= coverage <= 1
                    and -1 <= score <= 1
                    and not (score >= profile.semantic_threshold and coverage >= profile.coverage_threshold)
                )
            v1._require(valid, "inconsistent_active_stage_score")
            result["stages"][name] = {"status": "scored_negative", "negative_measurement": True}
        result.update(status="eligible", reason="complete_negative_active_stages")
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError, OverflowError) as error:
        result["reason"] = (
            str(error) if isinstance(error, v1._Skip) else "malformed_or_unknown_profile_evidence"
        )
    return result


def _probe_hash(probe):
    return v1._hash(
        {
            key: probe[key]
            for key in ("call_binding", "source_ids", "context_a", "context_b", "sink", "replacements")
        }
    )


def _bound_probe(probe, source_ids, kind, call_binding):
    result = {
        **copy.deepcopy(probe),
        "kind": kind,
        "source_ids": sorted(source_ids),
        "call_binding": copy.deepcopy(call_binding),
    }
    result["binding_sha256"] = _probe_hash(result)
    result["probe_id"] = "probe-v2:" + result["binding_sha256"]
    return result


def _replace(context, replacement, value):
    match = v1._POINTER.fullmatch(replacement["request_pointer"])
    v1._require(match is not None, "unsupported_request_pointer")
    index, part = int(match[1]), match[2]
    if part is None:
        context[index]["content"] = value
    else:
        context[index]["content"][int(part)]["text"] = value


def _value(context, replacement):
    match = v1._POINTER.fullmatch(replacement["request_pointer"])
    index, part = int(match[1]), match[2]
    return context[index]["content"] if part is None else context[index]["content"][int(part)]["text"]


def plan_joint_probes(
    call: dict, graph: dict, *, canary_enabled: bool = False, max_sources: int = 8, max_pairs: int = 12
) -> dict:
    """Plan validated single-source and pair removals from one recorded prefix.

    All occurrences of each source are neutralized together. Shared recovered origins,
    overlapping carriers and unplanned pairs remain explicit unknowns. Callers replaying
    saved files must verify event/proposal/receipt binding first; export_run does this.
    """
    result = {
        "schema_version": 2,
        "protocol": PROTOCOL,
        "status": "unknown",
        "complete": False,
        "reason": None,
        "proposal_event_id": None,
        "probes": [],
        "pair_inventory": [],
        "unsupported_sources": [],
        "coverage": [],
        "scope": SCOPE,
        "metadata": {
            "canary_enabled": canary_enabled,
            "max_sources": max_sources,
            "max_pairs": max_pairs,
            "context_output_bytes": v1.LIMITS["context_output_bytes"],
            "inapplicable_is_not_negative": True,
            "no_argument_target": "string_stages_inapplicable; full_source_context_and_DCPG_bindings_required",
            "joint_patterns": "at_most_two_sources; no_higher_order_or_causal_identification",
            "neutralization": "v1_structural_scalar_placeholders; retained_keys_and_derived_history_may_preserve_information",
            "confidence": "self_reported_only; no_threshold_or_calibration",
        },
    }
    try:
        v1._require(
            type(canary_enabled) is bool
            and type(max_sources) is int
            and 1 <= max_sources <= MAX_SOURCES
            and type(max_pairs) is int
            and 0 <= max_pairs <= MAX_PAIRS,
            "invalid_plan_budget_or_condition",
        )
        v1._require(isinstance(call, dict), "invalid_call")
        v1._bounded_json(call)
        v1._bounded_json(graph)
        v1._require(
            graph.get("metadata", {}).get("memory_cascade", {}).get("canary_enabled") is canary_enabled,
            "graph_condition_evidence_mismatch",
        )
        call_binding = {
            key: call.get(key)
            for key in (
                "run_id",
                "episode_id",
                "proposal_event_id",
                "model_request_id",
                "request_event_id",
                "request_sequence",
                "proposal_sequence",
            )
        }
        result["proposal_event_id"] = call.get("proposal_event_id")
        sources = [
            s
            for s in call.get("visible_sources", [])
            if s.get("kind") == "tool" and s.get("policy", {}).get("eligible") is True
        ]
        v1._require(len({s["source_id"] for s in sources}) <= max_sources, "source_budget_exceeded")
        no_arguments = call.get("arguments") == {} and call.get("fields") == []
        result["target_scope"] = "no_argument_sink" if no_arguments else "selected_argument_fields"

        def negative(pair):
            coverage = explicit_coverage(pair, canary_enabled=canary_enabled)
            result["coverage"].append(
                {
                    "source_id": pair.get("source_id"),
                    "request_pointer": pair.get("request_pointer"),
                    **coverage,
                }
            )
            v1._require(coverage["status"] == "eligible", coverage["reason"])

        base = v1._plan_probe(call, graph, negative_check=negative, allow_no_argument_sink=True)
        result["unsupported_sources"] = copy.deepcopy(base["unsupported_sources"])
        if not base["probes"]:
            result.update(
                status="not_eligible"
                if base["reason"] in {"explicit_candidate_present", "not_selected_sink", "no_eligible_source"}
                else "unknown",
                reason=base["reason"],
            )
            return result
        # Reject one physical context location bound to two separate source identities.
        bindings = {}
        for probe in base["probes"]:
            for replacement in probe["replacements"]:
                pointer = replacement["request_pointer"]
                v1._require(
                    pointer not in bindings or bindings[pointer] == probe["source_id"],
                    "inseparable_overlapping_sources",
                )
                bindings[pointer] = probe["source_id"]
        singles = [
            _bound_probe(probe, [probe["source_id"]], "single_source", call_binding)
            for probe in sorted(base["probes"], key=lambda p: p["source_id"])
        ]
        result["probes"] = singles
        output_bytes = sum(
            len(v1._canonical(p["context_a"])) + len(v1._canonical(p["context_b"])) for p in singles
        )
        planned_pairs = 0
        for first, second in itertools.combinations(singles, 2):
            source_ids = [first["source_id"], second["source_id"]]
            item = {"source_ids": source_ids, "status": "unknown", "reason": None, "probe_id": None}
            result["pair_inventory"].append(item)
            if set(first["origin_source_ids"]) & set(second["origin_source_ids"]):
                item["reason"] = "inseparable_shared_recovered_origin"
                continue
            if planned_pairs >= max_pairs:
                item["reason"] = "pair_budget_exceeded"
                continue
            context_b = copy.deepcopy(first["context_b"])
            for replacement in second["replacements"]:
                value = _value(second["context_b"], replacement)
                _replace(context_b, replacement, value)
            pair = _bound_probe(
                {
                    "context_a": first["context_a"],
                    "context_b": context_b,
                    "sink": first["sink"],
                    "replacements": first["replacements"] + second["replacements"],
                    "origin_source_ids": sorted(
                        set(first["origin_source_ids"] + second["origin_source_ids"])
                    ),
                    "lineage": [first["lineage"], second["lineage"]],
                },
                source_ids,
                "source_pair",
                call_binding,
            )
            size = len(v1._canonical(pair["context_a"])) + len(v1._canonical(pair["context_b"]))
            if output_bytes + size > v1.LIMITS["context_output_bytes"]:
                item["reason"] = "context_output_budget_exceeded"
                continue
            result["probes"].append(pair)
            output_bytes += size
            planned_pairs += 1
            item.update(status="planned", reason=None, probe_id=pair["probe_id"])
        complete = not result["unsupported_sources"] and all(
            p["status"] == "planned" for p in result["pair_inventory"]
        )
        result.update(
            status="eligible" if complete else "partial",
            complete=complete,
            reason="validated_no_argument_context" if no_arguments else "complete_negative_active_stages",
            planned_context_bytes=output_bytes,
        )
        if no_arguments:
            result["coverage"] = [
                {
                    "status": "not_applicable",
                    "reason": "no_argument_string_target",
                    "negative_measurement": False,
                }
            ]
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError, OverflowError) as error:
        result.update(
            status="unknown",
            complete=False,
            reason=str(error) if isinstance(error, v1._Skip) else "malformed_evidence",
            probes=[],
        )
    return result


def bind_judgment(
    probe: dict, raw: str, *, judgment_format: str = judgment_formats.ASCII_FORMAT
) -> dict:
    """Attach a strict externally obtained judgment to its exact proposed intervention."""
    if (
        probe.get("binding_sha256") != _probe_hash(probe)
        or probe.get("probe_id") != "probe-v2:" + probe["binding_sha256"]
    ):
        raise ValueError("Intervention binding changed")
    parsed = judgment_formats.parse_judgment(raw, judgment_format=judgment_format)
    return {
        "protocol": PROTOCOL,
        **({"judgment_format": judgment_format} if judgment_format != judgment_formats.ASCII_FORMAT else {}),
        "probe_id": probe["probe_id"],
        "binding_sha256": probe["binding_sha256"],
        **parsed,
    }


def summarize_joint_results(
    plan: dict, results: list[dict], *, judgment_format: str = judgment_formats.ASCII_FORMAT
) -> dict:
    """Describe predicted removal patterns only; omitted/foreign judgments stay unknown."""
    judgment_formats.validate_format(judgment_format)
    summary = {
        "protocol": PROTOCOL,
        **({"judgment_format": judgment_format} if judgment_format != judgment_formats.ASCII_FORMAT else {}),
        "scope": SCOPE,
        "status": "unknown",
        "complete": False,
        "single_sources": [],
        "pairs": [],
        "unknown_count": 0,
        "unmatched_result_count": 0,
        "confidence": None,
    }
    try:
        v1._bounded_json(plan)
        v1._bounded_json(results)
        v1._require(
            plan.get("protocol") == PROTOCOL
            and isinstance(results, list)
            and len(results) <= MAX_SOURCES + MAX_PAIRS,
            "invalid_result_input",
        )
        probes = {p["probe_id"]: p for p in plan["probes"]}
        v1._require(len(probes) == len(plan["probes"]), "duplicate_planned_probe")
        indexed = {}
        for result in results:
            identifier = result.get("probe_id")
            if identifier not in probes:
                summary["unmatched_result_count"] += 1
                continue
            indexed.setdefault(identifier, []).append(result)
        values = {}
        for identifier, probe in probes.items():
            records = indexed.get(identifier, [])
            value = None
            reason = "missing_judgment" if not records else "duplicate_or_invalid_judgment"
            if len(records) == 1:
                record = records[0]
                if (
                    record.get("protocol") == PROTOCOL
                    and record.get("judgment_format", judgment_formats.ASCII_FORMAT) == judgment_format
                    and record.get("status") == "valid"
                    and record.get("binding_sha256") == probe.get("binding_sha256") == _probe_hash(probe)
                    and identifier == "probe-v2:" + probe["binding_sha256"]
                ):
                    parsed = judgment_formats.parse_judgment(
                        json.dumps(record.get("judgment"), allow_nan=False), judgment_format=judgment_format
                    )
                    if parsed["status"] == "valid":
                        value, reason = parsed["judgment"]["would_call_anyway"], None
            values[identifier] = value
            if value is None:
                summary["unknown_count"] += 1
            if probe["kind"] == "single_source":
                summary["single_sources"].append(
                    {
                        "source_id": probe["source_ids"][0],
                        "probe_id": identifier,
                        "would_call_anyway": value,
                        "status": "unknown"
                        if value is None
                        else "predicted_no_change"
                        if value
                        else "predicted_dependency",
                        "reason": reason,
                    }
                )
        singles = {row["source_id"]: row["would_call_anyway"] for row in summary["single_sources"]}
        patterns = {
            (False, False, False): "predicted_AND_like",
            (True, True, False): "predicted_redundant_OR_like",
            (False, True, False): "predicted_first_source_dependency",
            (True, False, False): "predicted_second_source_dependency",
            (True, True, True): "no_predicted_dependency_under_tested_removals",
        }
        for pair in plan["pair_inventory"]:
            first, second = pair["source_ids"]
            triple = (singles.get(first), singles.get(second), values.get(pair.get("probe_id")))
            pattern = patterns.get(triple) if all(type(v) is bool for v in triple) else None
            summary["pairs"].append(
                {
                    "source_ids": [first, second],
                    "pattern": pattern or "unknown",
                    "reason": None
                    if pattern
                    else pair.get("reason")
                    or (
                        "inconsistent_or_nonmonotone_predictions"
                        if all(type(v) is bool for v in triple)
                        else "incomplete_bound_judgments"
                    ),
                    "would_call_after_removing_first_second_both": list(triple),
                }
            )
        summary["complete"] = (
            bool(probes)
            and plan.get("complete") is True
            and not summary["unknown_count"]
            and not summary["unmatched_result_count"]
            and all(p["pattern"] != "unknown" for p in summary["pairs"])
        )
        summary["status"] = (
            "complete_predictions"
            if summary["complete"]
            else "partial_predictions"
            if any(type(v) is bool for v in values.values())
            else "unknown"
        )
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError, OverflowError):
        summary.update(status="unknown", complete=False, reason="invalid_plan_or_result_binding")
    return summary


def export_run(run: Path, output: Path, *, max_sources=8, max_pairs=12) -> dict:
    """Export v2 plans for a verified saved run. This function never calls a model."""
    from agentdojo_lab.counterfactual_audit import _contains_cjk, _verified_inputs
    from agentdojo_lab.evaluation_review import _local, _strict

    run, output = _local(run), _local(output)
    if output.exists() or output.is_relative_to(run) or run.is_relative_to(output):
        raise ValueError("Use a fresh output separate from the saved run")

    def snapshot():
        files = sorted(path for path in run.rglob("*") if path.is_file() or path.is_symlink())
        if not files or len(files) > 2048:
            raise ValueError("Saved-run file budget exceeded")
        hashes = {}
        for path in files:
            _local(path)
            if path.name.startswith(".env") or path.stat().st_size > 64 * 1024 * 1024:
                raise ValueError("Unsupported or secret source artifact")
            raw = path.read_bytes()
            if path.suffix in {".json", ".jsonl"}:
                for value in raw.splitlines() if path.suffix == ".jsonl" else [raw]:
                    if value.strip():
                        _strict(value)
            import hashlib

            hashes[str(path.relative_to(run))] = hashlib.sha256(raw).hexdigest()
        return hashes

    before = snapshot()
    manifest = _strict((run / "manifest.json").read_bytes())
    canary = manifest.get("config", {}).get("canary_enabled")
    if type(canary) is not bool or manifest.get("input_condition") != (
        "canary_intervention" if canary else "passive"
    ):
        raise ValueError("Saved primary condition is unavailable or inconsistent")
    calls, graph = _verified_inputs(run)
    plans = [
        plan_joint_probes(call, graph, canary_enabled=canary, max_sources=max_sources, max_pairs=max_pairs)
        for call in calls
    ]
    if _contains_cjk(v1._canonical(plans).decode()):
        raise ValueError("Non-English saved content cannot be embedded in this English export")
    after = snapshot()
    if before != after:
        raise ValueError("Saved source artifacts changed during planning")
    summary = {
        "schema_version": 2,
        "protocol": PROTOCOL,
        "scope": SCOPE,
        "source_run": str(run),
        "canary_enabled": canary,
        "model_requests": 0,
        "native_tool_calls": 0,
        "plan_count": len(plans),
        "status_counts": dict(Counter(p["status"] for p in plans)),
        "probe_count": sum(len(p["probes"]) for p in plans),
        "source_hashes_before": before,
        "source_hashes_after": after,
        "source_files_unchanged": True,
    }
    output.mkdir(parents=True)
    (output / "plans.jsonl").write_text("".join(v1._canonical(plan).decode() + "\n" for plan in plans))
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    details = "".join(
        f"<details><summary>{html.escape(str(p['proposal_event_id']))}: {html.escape(p['status'])} — {html.escape(str(p['reason']))}</summary><pre>{html.escape(json.dumps(p, indent=2))}</pre></details>"
        for p in plans
    )
    (output / "index.html").write_text(
        f'<!doctype html><html lang="en"><meta charset="utf-8"><title>Causal coverage v2</title><style>body{{max-width:1000px;margin:30px auto;font:16px system-ui}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}details{{margin:14px 0}}summary{{cursor:pointer}}</style><h1>Causal coverage v2</h1><p>Offline plans only. No model requests, causal labels or observed counterfactual behavior.</p><p>{len(plans)} proposals; {summary["probe_count"]} planned interventions. Failed, missing and unplanned evidence stays unknown.</p>{details}</html>'
    )
    if snapshot() != before:
        raise ValueError("Saved source artifacts changed during export")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-sources", type=int, default=8)
    parser.add_argument("--max-pairs", type=int, default=12)
    args = parser.parse_args()
    print(
        json.dumps(export_run(args.run, args.output, max_sources=args.max_sources, max_pairs=args.max_pairs))
    )


if __name__ == "__main__":
    main()

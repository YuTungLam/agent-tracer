"""Compose a verified completed trace into explicit and predicted-control decisions.

The default makes no generative requests. Existing auditor exports are revalidated;
new no-tools requests require an explicit live flag and positive finite budget.
This closes an integration gap, not full-paper or benchmark reproduction.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import html
import json
import os
from collections import Counter
from pathlib import Path

from agentdojo_lab import causal_v2, judgment_formats
from agentdojo_lab import causal_v2_audit as auditor
from agentdojo_lab.counterfactual import _canonical, _hash
from agentdojo_lab.counterfactual_audit import _contains_cjk, _verified_inputs
from agentdojo_lab.evaluation_review import _local, _strict

PROTOCOL = "completed-trace-paper-audit-v1"
FORMAT = judgment_formats.ENGLISH_PUNCTUATION_FORMAT
SCOPE = (
    "Detector decisions under the recorded policy and bounded source interventions; "
    "explicit similarity and auditor predictions are distinct evidence, not maliciousness "
    "labels, calibrated correctness, observed counterfactual behavior, or full-paper reproduction."
)
METHOD_CHOICES = {
    "causal_method": "Isolated judge interpretation of paper section 4.3; no decision or whole-task agent replay",
    "joint_method": "Local bounded single/pair removal rule; not author-confirmed conjunctive-causality implementation",
    "trace_validation": "Recorded events, request prefixes, sidecar flush receipts and graph hashes are verified; stored explicit scores are not recomputed",
    "memory_scope": "Only original checkpoint adapter and exact restored ancestry recorded in this trace; no generalized memory support",
    "hash_scope": "Artifact consistency, not authentication of model execution or independent ground truth",
}


def _json(path):
    return auditor._read_json(path)


def _lines(path):
    if path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("JSONL artifact exceeds the input budget")
    return [_strict(line) for line in path.read_bytes().splitlines() if line.strip()]


def _write(path, value):
    path.write_bytes(_canonical(value) + b"\n")


def _code_hashes():
    return {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path(__file__).parent.glob("*.py"))
    }


def _separate(first, second):
    return not first.is_relative_to(second) and not second.is_relative_to(first)


def _condition(source, calls, graph):
    manifest = _json(source / "manifest.json")
    config = manifest.get("config", {})
    flag = config.get("canary_enabled")
    memory = graph.get("metadata", {}).get("memory_cascade", {})
    if type(flag) is bool and manifest.get("input_condition") == (
        "canary_intervention" if flag else "passive"
    ):
        if memory.get("canary_enabled") is not flag:
            raise ValueError("Manifest and checkpoint input conditions disagree")
        return flag, "canonical_manifest"
    declared = manifest.get("online_provenance", {}).get("lineage", {}).get("memory_cascade", {})
    pairs = [
        pair
        for call in calls
        for field in call.get("fields", [])
        for pair in field.get("nt_style_cascade", [])
    ]
    pairs += [pair for call in calls for pair in call["lineage"].get("comparisons", [])]
    if (
        manifest.get("mode") != "cross-session-copy-pair-v1"
        or "canary_enabled" in config
        or "input_condition" in manifest
        or memory.get("canary_enabled") is not False
        or declared.get("canary_enabled") is not False
        or declared != memory
        or not pairs
        or any(pair.get("metadata", {}).get("canary_enabled") is not False for pair in pairs)
    ):
        raise ValueError("Missing or inconsistent primary input condition")
    return False, "verified_legacy_memory_pair_passive; offline_composition_only"


def _planning_budget(existing):
    if existing is None:
        return 8, 12
    saved = _lines(existing / "plans.jsonl")
    budgets = [
        (p.get("metadata", {}).get("max_sources"), p.get("metadata", {}).get("max_pairs")) for p in saved
    ]
    if len(saved) > 512 or any(
        type(a) is not int or not 1 <= a <= 8 or type(b) is not int or not 0 <= b <= 12 for a, b in budgets
    ):
        raise ValueError("Saved planning budget exceeds composer limits")
    if len(set(budgets)) > 1:
        raise ValueError("Mixed per-proposal planning budgets are unsupported")
    return budgets[0] if budgets else (8, 12)


def _legacy_plans(source, output, calls, graph, before, max_sources, max_pairs, adapter):
    plans = [
        causal_v2.plan_joint_probes(
            c, graph, canary_enabled=False, max_sources=max_sources, max_pairs=max_pairs
        )
        for c in calls
    ]
    if _contains_cjk(_canonical(plans).decode()):
        raise ValueError("Non-English plan content cannot enter English artifacts")
    output.mkdir()
    (output / "plans.jsonl").write_bytes(b"".join(_canonical(p) + b"\n" for p in plans))
    _write(
        output / "summary.json",
        {
            "protocol": causal_v2.PROTOCOL,
            "source_run": str(source),
            "condition_adapter": adapter,
            "auditor_transport_compatible": False,
            "canary_enabled": False,
            "plan_count": len(plans),
            "probe_count": sum(len(p["probes"]) for p in plans),
            "source_hashes_before": before,
            "source_hashes_after": auditor._snapshot(source),
            "source_files_unchanged": auditor._snapshot(source) == before,
        },
    )
    (output / "index.html").write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>Legacy memory trace plans</title><h1>Legacy memory trace plans</h1><p>The passive condition is cross-checked against recorded manifest, checkpoint and pair metadata. This composition does not change the legacy manifest and does not enable the unchanged auditor transport.</p><a href="plans.jsonl">Every bound proposal plan</a> · <a href="summary.json">Condition verification and source hashes</a></html>'
    )


def _verified_auditor(folder, source, plans):
    """Reconstruct judgments from recorded responses, never from claimed labels alone."""
    before = auditor._snapshot(folder)
    manifest, summary = _json(folder / "manifest.json"), _json(folder / "summary.json")
    format_name = manifest.get("judgment_format", judgment_formats.ASCII_FORMAT)
    judgment_formats.validate_format(format_name)
    protocol = auditor.PUNCTUATION_PROTOCOL if format_name == FORMAT else auditor.PROTOCOL
    if (
        manifest.get("protocol") != protocol
        or summary.get("protocol") != protocol
        or summary.get("judgment_format", judgment_formats.ASCII_FORMAT) != format_name
        or _local(manifest["source_run"]) != source
        or manifest.get("sdk_max_retries") != 0
        or manifest.get("request_timeout_seconds") != 60
        or type(manifest.get("max_requests")) is not int
        or not 0 <= manifest["max_requests"] <= auditor.MAX_REQUESTS
        or summary.get("source_files_unchanged") is not True
    ):
        raise ValueError("Auditor protocol, condition, budget or source is incompatible")
    source_hashes = auditor._snapshot(source)
    original_plans = _local(manifest["input_plans"])
    plan_hashes = auditor._snapshot(original_plans)
    if (
        source_hashes != manifest.get("source_hashes_before")
        or source_hashes != summary.get("source_hashes_before")
        or source_hashes != summary.get("source_hashes_after")
        or plan_hashes != manifest.get("plan_export_hashes_before")
        or plan_hashes != summary.get("plan_export_hashes_before")
        or plan_hashes != summary.get("plan_export_hashes_after")
        or _lines(folder / "plans.jsonl") != plans
        or _lines(original_plans / "plans.jsonl") != plans
    ):
        raise ValueError("Auditor source or complete plan inventory changed")
    slots = [(plan, probe) for plan in plans for probe in plan["probes"]]
    rows, requests = _lines(folder / "judgments.jsonl"), _lines(folder / "requests.jsonl")
    if len(rows) != len(slots) or len(requests) > manifest["max_requests"]:
        raise ValueError("Missing or over-budget auditor slots")
    indexed = {r["probe_id"]: r for r in requests}
    if len(indexed) != len(requests):
        raise ValueError("Duplicate auditor requests")
    verified = []
    for ordinal, ((plan, probe), row) in enumerate(zip(slots, rows, strict=True), 1):
        expected = {
            "protocol": causal_v2.PROTOCOL,
            "slot_id": f"slot-{ordinal:04d}",
            "proposal_event_id": plan["proposal_event_id"],
            "probe_id": probe["probe_id"],
            "binding_sha256": probe["binding_sha256"],
            "source_ids": probe["source_ids"],
            "kind": probe["kind"],
        }
        if (
            any(row.get(k) != v for k, v in expected.items())
            or row.get("judgment_format", judgment_formats.ASCII_FORMAT) != format_name
        ):
            raise ValueError("Auditor row is not bound to the exact proposal and source set")
        if type(row.get("request_attempted")) is not bool or row["request_attempted"] is not (
            probe["probe_id"] in indexed
        ):
            raise ValueError("Auditor request accounting mismatch")
        if row["request_attempted"]:
            request = indexed[probe["probe_id"]]
            body = auditor.request_body(probe, judgment_format=format_name)
            if (
                request.get("body") != body
                or request.get("body_sha256") != _hash(body)
                or request.get("slot_id") != expected["slot_id"]
                or request.get("binding_sha256") != probe["binding_sha256"]
                or manifest.get("system_prompt") != body["messages"][0]["content"]
                or manifest.get("system_prompt_sha256") != _hash(body["messages"][0]["content"])
                or manifest.get("model") != body["model"]
            ):
                raise ValueError("Auditor request body differs from the bound intervention")
        if "response" in row or "response_file" in row:
            if not row["request_attempted"] or ("response" in row and "response_file" in row):
                raise ValueError("Auditor response has no unique attempted request")
            if "response_file" in row:
                path = _local(folder / row["response_file"])
                if not path.is_relative_to(folder):
                    raise ValueError("Quarantined response escapes its audit export")
                encoded = path.read_bytes()
                response = _strict(encoded)
            else:
                response = row["response"]
                encoded = _canonical(response)
            if hashlib.sha256(encoded).hexdigest() != row.get("response_sha256"):
                raise ValueError("Auditor response bytes changed")
            if _contains_cjk(encoded.decode()):
                parsed = {"status": "invalid", "reason": "non_english_response"}
            elif format_name == FORMAT and judgment_formats.contains_unsupported_characters(encoded.decode()):
                parsed = {"status": "invalid", "reason": "unsupported_response_character"}
            else:
                parsed = auditor._response_result(probe, response, judgment_format=format_name)
            if any(row.get(k) != parsed.get(k) for k in ("status", "reason", "judgment")):
                raise ValueError("Recorded judgment differs from independently parsed response")
            if row.get("usage") != (response.get("usage") if isinstance(response.get("usage"), dict) else {}):
                raise ValueError("Auditor usage differs from the recorded response")
        elif row.get("status") not in {"error", "not_run"} or row.get("judgment") is not None:
            raise ValueError("Missing response cannot establish a detector decision")
        verified.append(copy.deepcopy(row))
    expected_groups = [
        {
            "proposal_event_id": plan["proposal_event_id"],
            "plan_status": plan["status"],
            "plan_reason": plan["reason"],
            "prediction_summary": causal_v2.summarize_joint_results(
                plan,
                [r for r in verified if r["proposal_event_id"] == plan["proposal_event_id"]],
                judgment_format=format_name,
            ),
        }
        for plan in plans
    ]
    attempted = [r for r in verified if r["request_attempted"]]
    valid = sum(r["status"] == "valid" for r in verified)
    if (
        {r["probe_id"] for r in attempted} != set(indexed)
        or summary.get("request_count") != len(requests)
        or summary.get("planned_slots") != len(slots)
        or summary.get("result_slots") != len(slots)
        or summary.get("valid_judgments") != valid
        or summary.get("unknown_judgments") != len(slots) - valid
        or summary.get("reported_usage") != auditor._usage(attempted)
        or summary.get("proposal_summaries") != expected_groups
        or auditor._snapshot(folder) != before
    ):
        raise ValueError("Auditor summary or final inventory does not match its evidence")
    return verified, format_name, before


def compose_proposal(call, graph, plan, rows, judgment_format):
    """Compose one proposal without mutating its recorded call, plan, rows, or graph."""
    nodes = {n["node_id"]: n for n in graph["nodes"]}
    edges = {e["edge_id"]: e for e in graph["edges"]}
    labels = {label["label_id"]: label for label in graph["registry"]}
    identifier = call["proposal_event_id"]
    if plan.get("proposal_event_id") != identifier:
        raise ValueError("Proposal inventory mismatch")
    sink_node = call["lineage"]["node_id"]
    if sink_node not in nodes or nodes[sink_node].get("proposal_event_id") != identifier:
        raise ValueError("Sink graph node is not bound to the proposal")
    explicit = []
    for path in call["lineage"].get("paths", []):
        label_id, route = path["label_id"], path["edge_ids"]
        if label_id not in labels or not route:
            raise ValueError("Explicit path lacks its source label")
        cursor = labels[label_id]["origin_node_id"]
        for edge_id in route:
            edge = edges.get(edge_id, {})
            if edge.get("from_node") != cursor or label_id not in edge.get("label_ids", []):
                raise ValueError("Explicit source path is disconnected or incorrectly labelled")
            cursor = edge["to_node"]
        if cursor != sink_node or edge.get("relation") != "candidate_content" or not edge.get("tier"):
            raise ValueError("Explicit path does not terminate in scored sink evidence")
        explicit.append(
            {
                "source_id": labels[label_id]["source_id"],
                "label_id": label_id,
                "edge_ids": route,
                "detector_positive": True,
                "evidence_kind": "explicit_cascade",
                "tier": edge["tier"],
                "evidence_score": edge["evidence_score"],
            }
        )
    if not explicit and (
        any(
            pair.get("matched") is True
            for field in call.get("fields", [])
            for pair in field.get("nt_style_cascade", [])
        )
        or any(pair.get("matched") is True for pair in call["lineage"].get("comparisons", []))
    ):
        raise ValueError("Explicit detector match lacks a bound graph path")
    bound = [r for r in rows if r["proposal_event_id"] == identifier]
    by_probe = {r["probe_id"]: r for r in bound}
    predictions = causal_v2.summarize_joint_results(
        plan, bound, judgment_format=judgment_format
    )
    source_sets, added_nodes, added_edges = [], [], []
    for probe in plan["probes"]:
        row = by_probe.get(probe["probe_id"], {})
        known = row.get("status") == "valid"
        flag = not row["judgment"]["would_call_anyway"] if known else None
        decision = {
            "probe_id": probe["probe_id"],
            "binding_sha256": probe["binding_sha256"],
            "source_ids": probe["source_ids"],
            "kind": probe["kind"],
            "detector_positive": flag,
            "evidence_kind": "auditor_prediction",
            "confidence": row["judgment"]["confidence"] if known else None,
            "confidence_scope": "self_reported_judge_confidence; not_calibrated_correctness",
            "status": "predicted_control_positive"
            if flag
            else "predicted_no_control"
            if flag is False
            else "unknown",
            "reason": row.get("reason", "missing_judgment"),
        }
        source_sets.append(decision)
        if flag is not True:
            continue
        origin_ids = set(probe["origin_source_ids"])
        members = [label for label in labels.values() if label["source_id"] in origin_ids]
        if {label["source_id"] for label in members} != origin_ids:
            raise ValueError("Predicted source set lacks its direct or restored origin labels")
        group_id = "audit-source-set:" + _hash([identifier, probe["binding_sha256"]])
        added_nodes.append(
            {
                "node_id": group_id,
                "kind": "intervened_source_set",
                "source_ids": probe["source_ids"],
                "origin_source_ids": sorted(origin_ids),
                "label_ids": sorted(label["label_id"] for label in members),
                "lineage_refs": copy.deepcopy(probe["lineage"]),
                "interpretation": "Joint removal or carrier ancestry does not identify each member as an independent cause",
            }
        )
        for member in members:
            if member["origin_node_id"] not in nodes:
                raise ValueError("Restored origin graph node is missing")
            added_edges.append(
                {
                    "edge_id": "audit-membership:" + _hash([group_id, member["label_id"]]),
                    "from_node": member["origin_node_id"],
                    "to_node": group_id,
                    "relation": "source_set_membership",
                    "evidence_kind": "structural_membership",
                    "label_ids": [member["label_id"]],
                    "detector_positive": None,
                }
            )
        added_edges.append(
            {
                "edge_id": "audit-prediction:" + _hash([group_id, sink_node]),
                "from_node": group_id,
                "to_node": sink_node,
                "relation": "predicted_control",
                "proposal_event_id": identifier,
                **decision,
            }
        )
    selected = call["policy"]["sink"]["selected"]
    positives = [s for s in source_sets if s["detector_positive"] is True]
    status, flag = "unknown", None
    if not selected:
        status = "not_selected"
    elif explicit:
        status, flag = "explicit_positive", True
    elif positives:
        status, flag = "predicted_control_positive", True
    elif predictions["complete"]:
        status, flag = "negative_under_tested_interventions", False
    elif plan["reason"] == "no_eligible_source" and not call["policy"].get(
        "unclassified_source_count"
    ):
        status, flag = "negative_no_policy_source", False
    single_positives = [s for s in positives if s["kind"] == "single_source"]
    highest = max((s["confidence"] for s in single_positives), default=None)
    decision = {
        "proposal_event_id": identifier,
        "sink_node_id": sink_node,
        "function": call["function"],
        "selected_sink": selected,
        "status": status,
        "detector_positive": flag,
        "explicit_evidence": explicit,
        "explicit_pair_inventory": [
            {
                "argument_path": field["argument_path"],
                "origin_scope": "direct_visible",
                **{
                    key: pair.get(key)
                    for key in (
                        "source_id",
                        "status",
                        "matched",
                        "complete",
                        "truncated",
                        "first_matched_tier",
                    )
                },
            }
            for field in call.get("fields", [])
            for pair in field.get("nt_style_cascade", [])
        ]
        + [
            {
                "origin_scope": "restored_memory",
                **{
                    key: pair.get(key)
                    for key in (
                        "argument_path",
                        "label_id",
                        "carrier_source_id",
                        "status",
                        "matched",
                        "complete",
                        "truncated",
                        "first_matched_tier",
                    )
                },
            }
            for pair in call["lineage"].get("comparisons", [])
        ],
        "source_set_decisions": source_sets,
        "highest_confidence_singleton_sources": [
            s["source_ids"][0] for s in single_positives if s["confidence"] == highest
        ],
        "conservatively_reported_joint_source_sets": [
            p["source_ids"] for p in predictions["pairs"] if p["pattern"] == "predicted_AND_like"
        ],
        "source_selection_scope": "Highest self-reported positive singleton confidence, retaining ties; pair scores are not ranked against singletons",
        "prediction_summary": predictions,
        "plan_status": plan["status"],
        "plan_reason": plan["reason"],
        "decision_resolved": flag is not None or status == "not_selected",
        "causal_coverage_complete": predictions["complete"],
        "maliciousness": "not_assessed",
        "independent_causal_accuracy": None,
    }
    return decision, {"added_nodes": added_nodes, "added_edges": added_edges}


def _compose(calls, graph, plans, rows, format_name):
    """Keep structural membership, explicit evidence and causal predictions distinct."""
    planned = {p["proposal_event_id"]: p for p in plans}
    if len(planned) != len(calls) or set(planned) != {c["proposal_event_id"] for c in calls}:
        raise ValueError("Proposal inventory mismatch")
    verdicts, added_nodes, added_edges = [], [], []
    for call in calls:
        decision, additions = compose_proposal(
            call, graph, planned[call["proposal_event_id"]], rows, format_name
        )
        verdicts.append(decision)
        added_nodes.extend(additions["added_nodes"])
        added_edges.extend(additions["added_edges"])
    return verdicts, {
        "schema_version": 1,
        "protocol": PROTOCOL + "-derived-graph",
        "scope": SCOPE,
        "original_graph": copy.deepcopy(graph),
        "added_nodes": added_nodes,
        "added_edges": added_edges,
    }


def run(
    run_dir: Path, output: Path, *, auditor_dir: Path | None = None, live=False, max_requests=0, client=None
):
    """Compose every recorded proposal; missing or invalid judgments remain unknown."""
    if (
        type(live) is not bool
        or type(max_requests) is not int
        or not 0 <= max_requests <= auditor.MAX_REQUESTS
    ):
        raise ValueError("Invalid live flag or finite request budget")
    if (live or client is not None) and max_requests == 0:
        raise ValueError("New auditor requests require an explicit positive budget")
    if auditor_dir is not None and (live or client is not None or max_requests):
        raise ValueError("Reuse an existing auditor or request new predictions, not both")
    source, output = _local(run_dir), _local(output)
    if live and client is None:
        from agentdojo_lab.providers import reject_implicit_groq_audit

        reject_implicit_groq_audit(source)
    existing = _local(auditor_dir) if auditor_dir is not None else None
    if (
        output.exists()
        or not _separate(source, output)
        or (existing and (not _separate(existing, output) or not _separate(existing, source)))
    ):
        raise ValueError("Use a fresh output separate from every original input")
    before, code = auditor._snapshot(source), _code_hashes()
    calls, graph = _verified_inputs(source)
    _, condition_adapter = _condition(source, calls, graph)
    legacy = condition_adapter != "canonical_manifest"
    if legacy and (existing is not None or live or client is not None):
        raise ValueError("Legacy condition adapter supports zero-call composition only")
    max_sources, max_pairs = _planning_budget(existing)
    output.mkdir(parents=True)
    if legacy:
        _legacy_plans(
            source, output / "plans", calls, graph, before, max_sources, max_pairs, condition_adapter
        )
    else:
        causal_v2.export_run(source, output / "plans", max_sources=max_sources, max_pairs=max_pairs)
    plans = _lines(output / "plans/plans.jsonl")
    mode = (
        "existing_auditor"
        if existing
        else "live_auditor"
        if live
        else "injected_client"
        if client is not None
        else "no_requests"
    )
    _write(
        output / "plan.json",
        {
            "protocol": PROTOCOL,
            "source_run": str(source),
            "mode": mode,
            "source_hashes": before,
            "implementation_hashes": code,
            "max_requests": max_requests,
            "max_sources": max_sources,
            "max_pairs": max_pairs,
            "planning_budget_origin": "verified_existing_auditor_export" if existing else "composer_defaults",
            "condition_adapter": condition_adapter,
            "existing_auditor": str(existing) if existing else None,
            "scope": SCOPE,
            "method_choices": METHOD_CHOICES,
        },
    )
    if existing is None and not legacy:
        auditor.run_audit(
            output / "plans",
            output / "auditor",
            client=client,
            live=live,
            max_requests=max_requests,
            judgment_format=FORMAT,
        )
        existing = output / "auditor"
    if legacy:
        format_name, audit_hashes = FORMAT, {}
        rows = [
            {
                "protocol": causal_v2.PROTOCOL,
                "judgment_format": FORMAT,
                "proposal_event_id": plan["proposal_event_id"],
                "probe_id": probe["probe_id"],
                "binding_sha256": probe["binding_sha256"],
                "status": "not_run",
                "reason": "legacy_condition_adapter_no_auditor_transport",
                "request_attempted": False,
            }
            for plan in plans
            for probe in plan["probes"]
        ]
    else:
        rows, format_name, audit_hashes = _verified_auditor(existing, source, plans)
    verdicts, derived = _compose(calls, graph, plans, rows, format_name)
    if (
        auditor._snapshot(source) != before
        or _code_hashes() != code
        or (existing is not None and auditor._snapshot(existing) != audit_hashes)
    ):
        raise ValueError("An input or implementation changed during composition")
    _write(output / "derived-graph.json", derived)
    (output / "sink-decisions.jsonl").write_bytes(b"".join(_canonical(row) + b"\n" for row in verdicts))
    summary = {
        "protocol": PROTOCOL,
        "scope": SCOPE,
        "method_choices": METHOD_CHOICES,
        "mode": mode,
        "source_run": str(source),
        "input_integrity_verified": True,
        "source_hashes_before": before,
        "source_hashes_after": auditor._snapshot(source),
        "auditor_export": str(existing) if existing is not None else None,
        "condition_adapter": condition_adapter,
        "auditor_hashes": audit_hashes,
        "judgment_format": format_name,
        "implementation_hashes": code,
        "proposal_count": len(verdicts),
        "selected_sink_count": sum(v["selected_sink"] for v in verdicts),
        "decision_counts": dict(Counter(v["status"] for v in verdicts)),
        "new_auditor_requests": 0
        if mode == "existing_auditor"
        else sum(r["request_attempted"] for r in rows),
        "reused_auditor_requests": sum(r["request_attempted"] for r in rows)
        if mode == "existing_auditor"
        else 0,
        "native_tool_calls": 0,
        "primary_agent_model_calls": 0,
        "independent_causal_accuracy": None,
    }
    _report(output, source, summary, verdicts, derived)
    if (
        auditor._snapshot(source) != before
        or _code_hashes() != code
        or (existing is not None and auditor._snapshot(existing) != audit_hashes)
    ):
        raise ValueError("An input or implementation changed during final export")
    _write(output / "summary.json", summary)
    _write(output / "manifest.json", auditor._snapshot(output))
    return summary


def _report(output, source, summary, verdicts, derived):
    esc = html.escape
    timeline = os.path.relpath(source / "report.html", output)
    rows = "".join(
        f'<details id="sink-{i}"><summary>{esc(v["function"])}: {esc(v["status"])}</summary>'
        f"<p>Detector flag: {esc(str(v['detector_positive']))}; decision resolved: {v['decision_resolved']}. Source and field coverage remain separate below.</p>"
        f"<pre>{esc(json.dumps(v, indent=2))}</pre></details>"
        for i, v in enumerate(verdicts)
    )
    timeline_link = (
        f'<a href="{esc(timeline, quote=True)}">Original agent timeline</a>'
        if (source / "report.html").is_file()
        else "Original timeline HTML unavailable; source event paths remain in the manifest."
    )
    text = f'<!doctype html><html lang="en"><meta charset="utf-8"><title>Completed trace audit</title><style>body{{max-width:1050px;margin:30px auto;padding:20px;font:16px/1.5 system-ui}}summary{{cursor:pointer}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}details{{margin:15px 0}}</style><h1>Completed trace audit</h1><p>{summary["selected_sink_count"]} selected sinks in {summary["proposal_count"]} proposals. New auditor requests: {summary["new_auditor_requests"]}.</p><p>{esc(SCOPE)}</p><p>{timeline_link}</p>{rows}<details><summary>Derived source-set graph records</summary><pre>{esc(json.dumps({"added_nodes": derived["added_nodes"], "added_edges": derived["added_edges"]}, indent=2))}</pre></details><p><a href="sink-decisions.jsonl">Every sink decision and explicit source path</a> · <a href="derived-graph.json">Original graph plus typed prediction edges</a> · <a href="summary.json">Summary</a> · <a href="manifest.json">Output hashes</a> · <a href="plans/index.html">Bound intervention plans</a></p></html>'
    (output / "index.html").write_text(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--auditor", type=Path)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--max-requests", type=int, default=0)
    args = parser.parse_args()
    result = run(
        args.run, args.output, auditor_dir=args.auditor, live=args.live, max_requests=args.max_requests
    )
    print(
        json.dumps(
            {
                k: result[k]
                for k in (
                    "mode",
                    "proposal_count",
                    "selected_sink_count",
                    "decision_counts",
                    "new_auditor_requests",
                )
            }
        )
    )


if __name__ == "__main__":
    main()

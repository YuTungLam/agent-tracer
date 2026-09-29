"""Verify a saved M7 online-causal run without making model or tool calls.

The verifier reconstructs every intervention from the flushed provenance call
and final DCPG checkpoint.  It then checks the isolated-judge request binding,
strictly reparses saved response envelopes, recomposes the derived graph, and
confirms that the causal receipt was present before native runtime entry.

Passing establishes internal artifact consistency.  Hashes in one run folder
are not signatures and do not authenticate independently rewritten evidence.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from collections import Counter
from pathlib import Path

from agentdojo_lab import causal_v2, judgment_formats, paper_audit
from agentdojo_lab import causal_v2_audit as transport
from agentdojo_lab.counterfactual import _canonical, _hash
from agentdojo_lab.counterfactual_audit import _contains_cjk
from agentdojo_lab.evaluation_review import _strict
from agentdojo_lab.inspection import inspect_events
from agentdojo_lab.online import AVAILABILITY as PROVENANCE_AVAILABILITY
from agentdojo_lab.online_causal import AVAILABILITY, GRAPH_PROTOCOL, PROTOCOL, SCOPE, _usage
from agentdojo_lab.providers import EndpointSettings
from agentdojo_lab.runner import RunConfig

MAX_JSONL_BYTES = 64 * 1024 * 1024
MAX_ROWS = 200_000
IDENTITY = ("run_id", "task_id", "episode_id", "model_request_id", "call_ref")
RESPONSE_PREFIX = "causal-online-response-"
RESPONSE_SUFFIX = ".bin"
FORBIDDEN_REQUEST_KEYS = {"tools", "tool_choice", "functions", "function_call"}
INTERPRETATION = {
    "original_graph": "Recorded structural lineage; retained unchanged.",
    "source_set_membership": "Structural membership in the jointly intervened source set.",
    "predicted_control": "Isolated judge prediction; not observed counterfactual behavior.",
}


def _read(path: Path, limit: int = MAX_JSONL_BYTES) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Verification inputs must be regular non-symlink files")
    size = path.stat().st_size
    if size > limit:
        raise ValueError("Verification input exceeds its byte budget")
    return path.read_bytes()


def _json(raw: bytes) -> dict:
    value = _strict(raw)
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return value


def _lines(raw: bytes, *, keepends: bool = False):
    physical = raw.splitlines(keepends=keepends)
    if len(physical) > MAX_ROWS:
        raise ValueError("JSONL row budget exceeded")
    values = []
    for line in physical:
        content = line.strip()
        if content:
            value = _strict(content)
            if not isinstance(value, dict):
                raise ValueError("Expected a JSON object on every JSONL row")
            values.append(value)
    return values


def _same(left, right) -> bool:
    try:
        return _canonical(left) == _canonical(right)
    except (TypeError, ValueError, OverflowError, RecursionError):
        return False


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha_text(value) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _nonnegative_integer(value) -> bool:
    return type(value) is int and value >= 0


def _identity_matches(row: dict, event: dict) -> bool:
    return all(key in row and row[key] == event.get(key) for key in IDENTITY)


def _unique(rows: list[dict], key: str) -> dict:
    result = {}
    for row in rows:
        value = row.get(key)
        if not isinstance(value, str) or not value or value in result:
            raise ValueError("Missing or duplicate artifact identity")
        result[value] = row
    return result


def _record(checks: dict, name: str, operation) -> bool:
    try:
        checks[name] = bool(operation())
    except (
        KeyError,
        IndexError,
        TypeError,
        ValueError,
        AttributeError,
        OSError,
        UnicodeError,
        StopIteration,
    ):
        checks[name] = False
    return checks[name]


def _manifest_contract(manifest: dict, summary: dict) -> bool:
    config = manifest["config"]
    declared = manifest["online_causal_audit"]
    reported = summary["online_causal_audit"]
    resolved = RunConfig.model_validate(config)
    budget = resolved.causal_max_requests
    source_budget = resolved.causal_max_sources
    pair_budget = resolved.causal_max_pairs
    timeout = resolved.causal_request_timeout_seconds
    endpoint = resolved.judge_endpoint()
    model = endpoint.model
    mode = declared["mode"]
    return (
        config["online_causal_audit"] is True
        and config["online_provenance"] is True
        and isinstance(config.get("provenance_policy"), str)
        and bool(config["provenance_policy"])
        and isinstance(config.get("lineage_namespace"), str)
        and bool(config["lineage_namespace"])
        and isinstance(config.get("semantic_model"), str)
        and bool(config["semantic_model"])
        and isinstance(config.get("semantic_revision"), str)
        and bool(config["semantic_revision"])
        and type(budget) is int
        and 0 <= budget <= transport.MAX_REQUESTS
        and type(source_budget) is int
        and 1 <= source_budget <= causal_v2.MAX_SOURCES
        and type(pair_budget) is int
        and 0 <= pair_budget <= causal_v2.MAX_PAIRS
        and type(timeout) in (int, float)
        and timeout > 0
        and isinstance(model, str)
        and bool(model.strip())
        and declared.get("enabled") is True
        and declared.get("model") == model
        and declared.get("max_requests") == budget
        and declared.get("max_sources") == source_budget
        and declared.get("max_pairs") == pair_budget
        and declared.get("request_timeout_seconds") == timeout
        and declared.get("sdk_max_retries") == 0
        and declared.get("mode") in {"plan_only", f"isolated_{endpoint.provider}", "injected_client"}
        and declared.get("endpoint")
        == (endpoint.model_dump() if resolved.causal_endpoint is not None else None)
        and declared.get("transport_isolation") == "separate_unobserved_client; no_tools"
        and declared.get("execution")
        == "synchronous_before_native_tool_runtime; observational_only"
        and declared.get("action_enforcement") is False
        and declared.get("model_parameter_updates") == 0
        and reported.get("enabled") is True
        and reported.get("complete") is True
        and summary.get("recording", {}).get("complete") is True
        and summary.get("online_provenance", {}).get("complete") is True
        and (mode != "plan_only" or budget == 0 or manifest.get("real_llm") is False)
    )


def _implementation_hashes(manifest: dict) -> bool:
    declared = manifest["online_causal_audit"]["implementation_sha256"]
    source = Path(__file__).resolve().parents[1] / "src" / "agentdojo_lab"
    expected_names = {
        "online_causal.py",
        "causal_v2.py",
        "causal_v2_audit.py",
        "paper_audit.py",
        "judgment_formats.py",
    }
    return set(declared) == expected_names and all(
        _sha_text(declared[name]) and _sha((source / name).read_bytes()) == declared[name]
        for name in expected_names
    )


def _provenance(
    rows: list[dict], raw_lines: list[bytes], proposals: dict[str, dict]
) -> dict[str, dict]:
    if [row.get("record_sequence") for row in rows] != list(range(1, len(rows) + 1)):
        raise ValueError("Provenance record sequence is not consecutive")
    by_sequence = {
        row["record_sequence"]: (row, raw)
        for row, raw in zip(rows, raw_lines, strict=True)
    }
    analyses = [row for row in rows if row.get("record_type") == "call_analysis"]
    receipts = [row for row in rows if row.get("record_type") == "analysis_flush"]
    by_analysis = _unique(analyses, "proposal_event_id")
    by_receipt = _unique(receipts, "proposal_event_id")
    if set(by_analysis) != set(proposals) or set(by_receipt) != set(proposals):
        raise ValueError("Provenance proposal inventory differs from events")
    calls = {}
    for identifier, analysis in by_analysis.items():
        proposal = proposals[identifier]
        receipt = by_receipt[identifier]
        source_row, source_raw = by_sequence[receipt["analysis_record_sequence"]]
        if (
            analysis is not source_row
            or receipt["analysis_record_sequence"] >= receipt["record_sequence"]
            or receipt.get("analysis_line_sha256") != _sha(source_raw)
            or not _identity_matches(analysis, proposal)
            or not _identity_matches(receipt, proposal)
            or receipt.get("availability") != PROVENANCE_AVAILABILITY
        ):
            raise ValueError("Provenance analysis receipt binding failed")
        call = copy.deepcopy(analysis["call"])
        if call.pop("availability", None) != PROVENANCE_AVAILABILITY:
            raise ValueError("Provenance call lacks the live availability contract")
        if (
            call.get("proposal_event_id") != identifier
            or call.get("run_id") != proposal.get("run_id")
            or call.get("episode_id") != proposal.get("episode_id")
        ):
            raise ValueError("Provenance call identity differs from its proposal")
        calls[identifier] = call
    return calls


def _causal_rows(rows: list[dict], proposals: dict[str, dict]):
    if not rows or [row.get("record_sequence") for row in rows] != list(
        range(1, len(rows) + 1)
    ):
        raise ValueError("Causal record sequence is not consecutive")
    supported = {
        "causal_analysis",
        "causal_flush",
        "causal_runtime_timing",
        "causal_close_summary",
    }
    if any(
        row.get("schema_version") != 1
        or row.get("protocol") != PROTOCOL
        or row.get("record_type") not in supported
        for row in rows
    ):
        raise ValueError("Unsupported causal sidecar row")
    closes = [row for row in rows if row["record_type"] == "causal_close_summary"]
    if len(closes) != 1 or closes[0] is not rows[-1]:
        raise ValueError("Causal close summary must be the final unique row")
    analyses = [row for row in rows if row["record_type"] == "causal_analysis"]
    receipts = [row for row in rows if row["record_type"] == "causal_flush"]
    by_analysis = _unique(analyses, "proposal_event_id")
    by_receipt = _unique(receipts, "proposal_event_id")
    if set(by_analysis) != set(proposals) or set(by_receipt) != set(proposals):
        raise ValueError("Causal proposal inventory differs from events")
    return analyses, by_analysis, by_receipt, closes[0]


def _response_path(run: Path, name: str) -> Path:
    if (
        not isinstance(name, str)
        or Path(name).name != name
        or not name.startswith(RESPONSE_PREFIX)
        or not name.endswith(RESPONSE_SUFFIX)
    ):
        raise ValueError("Quarantined response name is not a sibling artifact")
    path = run / name
    if path.resolve().parent != run or path.is_symlink():
        raise ValueError("Quarantined response escapes its run")
    return path


def _expected_response(
    run: Path, result: dict, probe: dict, judgment_format: str, watched: dict[str, bytes]
) -> dict:
    inline = "response" in result
    quarantined = "response_file" in result
    if inline is quarantined:
        raise ValueError("Attempted response must have exactly one saved envelope")
    if inline:
        response = result["response"]
        encoded = _canonical(response)
        if _contains_cjk(encoded.decode()) or judgment_formats.contains_unsupported_characters(
            encoded.decode()
        ):
            raise ValueError("Unsupported response characters entered the English JSONL")
        try:
            parsed = transport._response_result(
                probe, response, judgment_format=judgment_format
            )
        except Exception as error:
            parsed = {
                "status": "error",
                "reason": "auditor_request_or_response_failed",
                "error_type": type(error).__name__,
            }
    else:
        path = _response_path(run, result["response_file"])
        encoded = _read(path, transport.MAX_REQUEST_BYTES)
        watched[path.name] = encoded
        response = _json(encoded)
        cjk = _contains_cjk(encoded.decode())
        unsupported = judgment_formats.contains_unsupported_characters(encoded.decode())
        if not (cjk or unsupported):
            raise ValueError("Supported response was unnecessarily quarantined")
        parsed = {
            "status": "invalid",
            "reason": "non_english_response" if cjk else "unsupported_response_character",
        }
    if result.get("response_sha256") != _sha(encoded):
        raise ValueError("Saved response hash differs from its exact envelope")
    if result.get("usage") != _usage(response):
        raise ValueError("Saved usage differs from the response envelope")
    return parsed


def _result_binding(
    run: Path,
    result: dict,
    probe: dict,
    ordinal: int,
    proposal_event_id: str,
    judgment_format: str,
    endpoint: EndpointSettings,
    watched: dict[str, bytes],
) -> tuple[dict, int]:
    expected = {
        "protocol": causal_v2.PROTOCOL,
        "judgment_format": judgment_format,
        "slot_ordinal": ordinal,
        "proposal_event_id": proposal_event_id,
        "probe_id": probe["probe_id"],
        "binding_sha256": probe["binding_sha256"],
        "source_ids": probe["source_ids"],
        "kind": probe["kind"],
    }
    if any(result.get(key) != value for key, value in expected.items()):
        raise ValueError("Causal result differs from its planned slot")
    body = transport.request_body(probe, judgment_format=judgment_format)
    body["model"] = endpoint.model
    if endpoint.provider == "openai_compatible":
        body.pop("reasoning_effort", None)
    if FORBIDDEN_REQUEST_KEYS.intersection(body) or result.get("request_body_sha256") != _hash(
        body
    ):
        raise ValueError("Saved request binding is not the exact no-tools request body")
    attempted = result.get("request_attempted")
    if type(attempted) is not bool:
        raise ValueError("Request attempt accounting is not boolean")
    if attempted:
        if not _nonnegative_integer(result.get("elapsed_ns")):
            raise ValueError("Attempted request lacks finite elapsed time")
        if "response" in result or "response_file" in result:
            parsed = _expected_response(run, result, probe, judgment_format, watched)
            if any(
                result.get(key) != parsed.get(key)
                for key in ("status", "reason", "judgment", "error_type")
            ):
                raise ValueError("Saved judgment differs from strict response reparse")
            if parsed["status"] != "error" and result.get("error_type") is not None:
                raise ValueError("Parsed responses cannot also claim a transport error")
        elif (
            result.get("status") != "error"
            or result.get("reason") != "auditor_request_or_response_failed"
            or not isinstance(result.get("error_type"), str)
            or not result["error_type"]
            or result.get("usage") != {}
            or "response_sha256" in result
            or "judgment" in result
        ):
            raise ValueError("Unanswered attempted request is not an explicit transport error")
        return body, 1
    if (
        result.get("status") != "not_run"
        or result.get("reason")
        not in {
            "auditor_client_not_configured",
            "request_budget_exhausted",
            "request_size_budget_exceeded",
        }
        or result.get("usage") != {}
        or any(
            key in result
            for key in (
                "response",
                "response_file",
                "response_sha256",
                "judgment",
                "error_type",
                "elapsed_ns",
            )
        )
    ):
        raise ValueError("Unattempted slot has fabricated response evidence")
    return body, 0


def _plans_and_judgments(
    run: Path,
    manifest: dict,
    analyses: list[dict],
    calls: dict[str, dict],
    graph: dict,
    watched: dict[str, bytes],
):
    config = RunConfig.model_validate(manifest["config"])
    declared = manifest["online_causal_audit"]
    judgment_format = judgment_formats.ENGLISH_PUNCTUATION_FORMAT
    mode = declared["mode"]
    budget = config.causal_max_requests
    cumulative = 0
    decisions, added_nodes, added_edges, plans = [], [], [], {}
    for analysis in analyses:
        identifier = analysis["proposal_event_id"]
        plan = causal_v2.plan_joint_probes(
            calls[identifier],
            graph,
            canary_enabled=config.canary_enabled,
            max_sources=config.causal_max_sources,
            max_pairs=config.causal_max_pairs,
        )
        plans[identifier] = plan
        expected_plan = {
            "status": plan.get("status"),
            "complete": plan.get("complete"),
            "reason": plan.get("reason"),
            "probe_count": len(plan["probes"]),
            "pair_inventory": plan.get("pair_inventory", []),
            "binding_sha256": _hash(plan),
        }
        if analysis.get("plan") != expected_plan:
            raise ValueError("Saved intervention plan differs from flushed provenance and DCPG")
        results = analysis.get("results")
        if not isinstance(results, list) or len(results) != len(plan["probes"]):
            raise ValueError("Saved result inventory differs from planned slots")
        proposal_attempted = 0
        for ordinal, (result, probe) in enumerate(zip(results, plan["probes"], strict=True), 1):
            body, attempted = _result_binding(
                run,
                result,
                probe,
                ordinal,
                identifier,
                judgment_format,
                config.judge_endpoint(),
                watched,
            )
            expected_reason = None
            should_attempt = mode != "plan_only"
            if mode == "plan_only":
                expected_reason = "auditor_client_not_configured"
            elif cumulative >= budget:
                should_attempt = False
                expected_reason = "request_budget_exhausted"
            elif len(_canonical(body)) > transport.MAX_REQUEST_BYTES:
                should_attempt = False
                expected_reason = "request_size_budget_exceeded"
            if attempted != int(should_attempt):
                raise ValueError("Request attempt does not follow the declared finite budget")
            if not should_attempt and result.get("reason") != expected_reason:
                raise ValueError("Unattempted request reason differs from deterministic accounting")
            cumulative += attempted
            proposal_attempted += attempted
        accounting = analysis.get("request_accounting")
        if accounting != {
            "run_budget": budget,
            "run_attempted": cumulative,
            "run_remaining": budget - cumulative,
            "proposal_attempted": proposal_attempted,
            "sdk_max_retries": 0,
        }:
            raise ValueError("Per-proposal request accounting is inconsistent")
        expected_summary = causal_v2.summarize_joint_results(
            plan, results, judgment_format=judgment_format
        )
        if analysis.get("prediction_summary") != expected_summary:
            raise ValueError("Prediction summary differs from strictly parsed judgments")
        decision, additions = paper_audit.compose_proposal(
            calls[identifier], graph, plan, results, judgment_format
        )
        if (
            analysis.get("decision") != decision
            or analysis.get("composition") != {"status": "composed", "error_type": None}
        ):
            raise ValueError("Saved decision differs from independent composition")
        decisions.append(decision)
        added_nodes.extend(additions["added_nodes"])
        added_edges.extend(additions["added_edges"])
    if cumulative > budget:
        raise ValueError("Global causal request budget exceeded")
    return {
        "plans": plans,
        "request_count": cumulative,
        "decisions": decisions,
        "added_nodes": added_nodes,
        "added_edges": added_edges,
    }


def _receipts_and_timing(
    rows: list[dict],
    raw_lines: list[bytes],
    proposals: dict[str, dict],
    starts: dict[str, dict],
    analyses: dict[str, dict],
    receipts: dict[str, dict],
) -> dict:
    by_sequence = {
        row["record_sequence"]: (row, raw)
        for row, raw in zip(rows, raw_lines, strict=True)
    }
    for identifier, analysis in analyses.items():
        proposal, receipt = proposals[identifier], receipts[identifier]
        source, raw = by_sequence[receipt["analysis_record_sequence"]]
        timing = analysis["timing"]
        started = timing["audit_started_monotonic_ns"]
        planned = timing["planning_completed_monotonic_ns"]
        composed = timing["composition_completed_monotonic_ns"]
        flushed = receipt["analysis_flushed_monotonic_ns"]
        if (
            source is not analysis
            or receipt["analysis_record_sequence"] >= receipt["record_sequence"]
            or receipt.get("analysis_line_sha256") != _sha(raw)
            or not _identity_matches(analysis, proposal)
            or not _identity_matches(receipt, proposal)
            or receipt.get("proposal_event_id") != identifier
            or analysis.get("availability") != AVAILABILITY
            or analysis.get("scope") != SCOPE
            or receipt.get("flush_semantics") != "successful_Python_file_flush; not_fsync"
            or timing.get("clock") != "time.monotonic_ns"
            or not all(
                _nonnegative_integer(value)
                for value in (
                    proposal.get("monotonic_ns"),
                    timing.get("proposal_event_monotonic_ns"),
                    started,
                    planned,
                    composed,
                    timing.get("audit_compute_elapsed_ns"),
                    flushed,
                )
            )
            or timing["proposal_event_monotonic_ns"] != proposal["monotonic_ns"]
            or not proposal["monotonic_ns"] <= started <= planned <= composed <= flushed
            or timing["audit_compute_elapsed_ns"] != composed - started
        ):
            raise ValueError("Causal proposal or flush timing is inconsistent")

    timing_rows = [row for row in rows if row["record_type"] == "causal_runtime_timing"]
    timing_by_event = _unique(timing_rows, "runtime_event_id")
    if set(timing_by_event) != set(starts):
        raise ValueError("Runtime timing inventory differs from native runtime entries")
    before = 0
    for event_id, start in starts.items():
        row = timing_by_event[event_id]
        call_ref = start["call_ref"]
        proposal = next(
            proposal for proposal in proposals.values() if proposal.get("call_ref") == call_ref
        )
        identifier = proposal["event_id"]
        analysis, receipt = analyses[identifier], receipts[identifier]
        timing = row["timing"]
        runtime_clock = start["monotonic_ns"]
        analysis_clock = receipt["analysis_flushed_monotonic_ns"]
        receipt_clock = timing["receipt_flushed_monotonic_ns"]
        if (
            not _identity_matches(row, start)
            or not _identity_matches(row, proposal)
            or row.get("runtime_event_sequence") != start.get("event_sequence")
            or row.get("runtime_event_monotonic_ns") != runtime_clock
            or row.get("correlation") != "matched_proposal"
            or row.get("proposal_event_id") != identifier
            or row.get("analysis_record_sequence") != analysis["record_sequence"]
            or row.get("receipt_record_sequence") != receipt["record_sequence"]
            or not analysis["record_sequence"]
            < receipt["record_sequence"]
            < row["record_sequence"]
            or row.get("analysis_before_runtime") is not True
            or row.get("receipt_before_runtime") is not True
            or timing.get("clock") != "time.monotonic_ns"
            or timing.get("analysis_flushed_monotonic_ns") != analysis_clock
            or not all(
                _nonnegative_integer(value)
                for value in (analysis_clock, receipt_clock, runtime_clock, timing.get("receipt_lead_ns"))
            )
            or not analysis_clock <= receipt_clock <= runtime_clock
            or timing["receipt_lead_ns"] != runtime_clock - receipt_clock
            or timing.get("boundary")
            != "recorded_top_level_runtime_entry; not_internal_tool_steps"
        ):
            raise ValueError("Causal receipt was not verified before matching native runtime")
        before += 1
    return {
        "runtime_count": len(timing_rows),
        "before_runtime_count": before,
        "unmatched_runtime_count": 0,
        "pending_runtime_count": len(analyses) - before,
    }


def _derived_graph(saved: dict, original: dict, evidence: dict) -> bool:
    expected = {
        "schema_version": 1,
        "protocol": GRAPH_PROTOCOL,
        "scope": SCOPE,
        "original_graph": original,
        "added_nodes": evidence["added_nodes"],
        "added_edges": evidence["added_edges"],
        "proposal_decisions": evidence["decisions"],
        "interpretation": INTERPRETATION,
    }
    if not _same(saved, expected):
        return False
    original_nodes = {row["node_id"] for row in original["nodes"]}
    added_nodes = saved["added_nodes"]
    added_node_ids = [row.get("node_id") for row in added_nodes]
    original_edges = {row["edge_id"] for row in original["edges"]}
    added_edges = saved["added_edges"]
    added_edge_ids = [row.get("edge_id") for row in added_edges]
    return (
        len(set(added_node_ids)) == len(added_node_ids)
        and not original_nodes.intersection(added_node_ids)
        and all(row.get("kind") == "intervened_source_set" for row in added_nodes)
        and len(set(added_edge_ids)) == len(added_edge_ids)
        and not original_edges.intersection(added_edge_ids)
        and all(
            row.get("relation") in {"source_set_membership", "predicted_control"}
            for row in added_edges
        )
    )


def _summary_counts(
    summary: dict,
    close: dict,
    rows: list[dict],
    analyses: list[dict],
    evidence: dict,
    timing: dict,
    manifest: dict,
    graph_sha256: str,
) -> bool:
    reported = summary["online_causal_audit"]
    resolved = RunConfig.model_validate(manifest["config"])
    results = [result for analysis in analyses for result in analysis["results"]]
    statuses = Counter(result["status"] for result in results)
    plan_statuses = Counter(analysis["plan"]["status"] for analysis in analyses)
    valid = statuses.get("valid", 0)
    unknown = len(results) - valid
    attempted_usage = [
        {"usage": result["usage"]} for result in results if result["request_attempted"]
    ]
    reported_usage = transport._usage(attempted_usage)
    expected_close = {
        "proposal_count": len(analyses),
        "planned_probe_count": len(results),
        "request_count": evidence["request_count"],
        "valid_judgment_count": valid,
        "unknown_judgment_count": unknown,
        "reported_usage": reported_usage,
        "graph_saved": True,
        "graph_sha256": graph_sha256,
        "action_enforcement": "none",
        "model_weight_updates": "none",
    }
    if any(close.get(key) != value for key, value in expected_close.items()):
        return False
    expected_reported = {
        "proposal_attempt_count": len(analyses),
        "proposal_count": len(analyses),
        "plan_status_counts": dict(plan_statuses),
        "planned_probe_count": len(results),
        "request_budget": resolved.causal_max_requests,
        "request_count": evidence["request_count"],
        "request_remaining": resolved.causal_max_requests - evidence["request_count"],
        "valid_judgment_count": valid,
        "unknown_judgment_count": unknown,
        "judgment_status_counts": dict(statuses),
        "runtime_timing_count": timing["runtime_count"],
        "unmatched_runtime_count": timing["unmatched_runtime_count"],
        "before_runtime_verified_count": timing["before_runtime_count"],
        "runtime_timing_failure_count": 0,
        "pending_runtime_count": timing["pending_runtime_count"],
        "record_attempt_count": len(rows),
        "record_count": len(rows),
        "graph_saved": True,
        "graph_sha256": graph_sha256,
        "model": resolved.judge_endpoint().model,
        "judgment_format": judgment_formats.ENGLISH_PUNCTUATION_FORMAT,
        "request_timeout_seconds": resolved.causal_request_timeout_seconds,
        "sdk_max_retries": 0,
        "native_tool_calls": 0,
        "primary_agent_model_calls": 0,
        "action_enforcement": "none",
        "model_weight_updates": "none",
    }
    return (
        reported.get("enabled") is True
        and reported.get("active") is False
        and reported.get("disabled") is False
        and reported.get("closed") is True
        and reported.get("complete") is True
        and reported.get("completeness_scope")
        == "proposal processing and persistence; independent of whether causal predictions resolved"
        and reported.get("causal_resolution_complete")
        is (len(results) > 0 and unknown == 0 and valid == len(results))
        and reported.get("errors") == []
        and reported.get("protocol") == PROTOCOL
        and reported.get("scope") == SCOPE
        and reported.get("availability") == AVAILABILITY
        and reported.get("client_mode")
        == (
            "plan_only"
            if manifest["online_causal_audit"]["mode"] == "plan_only"
            else "injected_isolated_client"
        )
        and reported.get("reported_usage") == reported_usage
        and reported.get("usage_scope")
        == "Returned API token fields only; missing usage and provider billing are not estimated"
        and all(reported.get(key) == value for key, value in expected_reported.items())
    )


def verify(run: Path) -> dict:
    """Return a read-only, source-hashed verification result for one saved run."""
    run = Path(run).expanduser().absolute()
    if run.is_symlink() or not run.is_dir():
        raise ValueError("Run must be a non-symlink directory")
    run = run.resolve()
    names = (
        "manifest.json",
        "summary.json",
        "events.jsonl",
        "provenance.jsonl",
        "causal-online.jsonl",
        "causal-online-graph.json",
        "lineage-state.json",
    )
    watched = {name: _read(run / name) for name in names}
    before = {name: _sha(raw) for name, raw in watched.items()}
    manifest = _json(watched["manifest.json"])
    summary = _json(watched["summary.json"])
    events = _lines(watched["events.jsonl"])
    provenance_rows = _lines(watched["provenance.jsonl"])
    provenance_raw = watched["provenance.jsonl"].splitlines(keepends=True)
    causal_rows = _lines(watched["causal-online.jsonl"])
    causal_raw = watched["causal-online.jsonl"].splitlines(keepends=True)
    graph = _json(watched["causal-online-graph.json"])
    lineage = _json(watched["lineage-state.json"])
    checks = {}
    state = {}

    _record(checks, "manifest_contract_matches", lambda: _manifest_contract(manifest, summary))
    _record(checks, "implementation_hashes_match", lambda: _implementation_hashes(manifest))
    _record(checks, "event_log_valid", lambda: inspect_events(run / "events.jsonl")["valid"])

    def event_inventory():
        proposals = [event for event in events if event.get("event_type") == "TOOL_CALL_PROPOSED"]
        starts = [event for event in events if event.get("event_type") == "TOOL_RUNTIME_STARTED"]
        state["proposals"] = _unique(proposals, "event_id")
        state["starts"] = _unique(starts, "event_id")
        if len({row.get("call_ref") for row in proposals}) != len(proposals):
            raise ValueError("Proposal call references are not unique")
        return bool(proposals) and all(
            any(proposal.get("call_ref") == start.get("call_ref") for proposal in proposals)
            for start in starts
        )

    _record(checks, "event_identity_inventory_valid", event_inventory)

    def lineage_binding():
        state_value = lineage["state"]
        if (
            lineage.get("schema_version") != 1
            or lineage.get("state_sha256") != _hash(state_value)
            or summary.get("lineage_state", {}).get("status") != "saved"
            or summary["lineage_state"].get("sha256") != before["lineage-state.json"]
            or state_value.get("failed") is not False
            or state_value.get("namespace") != manifest["config"]["lineage_namespace"]
        ):
            raise ValueError("Final lineage checkpoint binding failed")
        state["lineage_graph"] = state_value
        return True

    _record(checks, "lineage_checkpoint_hash_and_identity_match", lineage_binding)

    def provenance_binding():
        state["calls"] = _provenance(
            provenance_rows, provenance_raw, state["proposals"]
        )
        return True

    _record(checks, "provenance_calls_and_flush_hashes_match", provenance_binding)

    def causal_inventory():
        values = _causal_rows(causal_rows, state["proposals"])
        state["analyses"], state["analysis_by_id"], state["receipts"], state["close"] = values
        return True

    _record(checks, "causal_schema_sequence_and_inventory_match", causal_inventory)

    def plans():
        state["evidence"] = _plans_and_judgments(
            run,
            manifest,
            state["analyses"],
            state["calls"],
            state["lineage_graph"],
            watched,
        )
        return True

    _record(checks, "plans_requests_budget_and_judgments_revalidate", plans)
    for name, raw in watched.items():
        before.setdefault(name, _sha(raw))

    def timing():
        state["timing"] = _receipts_and_timing(
            causal_rows,
            causal_raw,
            state["proposals"],
            state["starts"],
            state["analysis_by_id"],
            state["receipts"],
        )
        return True

    _record(checks, "causal_flush_precedes_matching_runtime", timing)
    _record(
        checks,
        "derived_graph_preserves_dcpg_and_typed_additions",
        lambda: _derived_graph(graph, state["lineage_graph"], state["evidence"]),
    )
    _record(
        checks,
        "close_and_summary_counts_recompute",
        lambda: _summary_counts(
            summary,
            state["close"],
            causal_rows,
            state["analyses"],
            state["evidence"],
            state["timing"],
            manifest,
            before["causal-online-graph.json"],
        ),
    )
    actual_response_names = {path.name for path in run.glob(RESPONSE_PREFIX + "*" + RESPONSE_SUFFIX)}

    def response_inventory():
        response_names = {
            result["response_file"]
            for analysis in causal_rows
            if analysis.get("record_type") == "causal_analysis"
            for result in analysis.get("results", [])
            if isinstance(result, dict) and "response_file" in result
        }
        return response_names == actual_response_names

    _record(checks, "quarantined_response_inventory_exact", response_inventory)
    final = {name: _sha(_read(run / name, max(len(raw), 1))) for name, raw in watched.items()}
    checks["source_files_unchanged"] = before == final
    return {
        "run_id": run.name,
        "passed": all(checks.values()),
        "checks": checks,
        "proposal_count": len(state.get("proposals", {})),
        "planned_probe_count": sum(
            len(row.get("results", []))
            for row in causal_rows
            if row.get("record_type") == "causal_analysis"
        ),
        "request_count": state.get("evidence", {}).get("request_count"),
        "input_sha256": before,
        "scope": (
            "Saved M7 event, provenance, request, response, receipt, DCPG, derived-graph, "
            "and summary consistency. No model or tool calls, causal accuracy claim, "
            "artifact authentication, action enforcement, or model-weight update."
        ),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument(
        "--output", type=Path, required=True, help="New verification JSON outside the source run"
    )
    args = parser.parse_args()
    source = args.run.expanduser().absolute().resolve()
    output = args.output.expanduser().absolute()
    if output.exists() or output.resolve().is_relative_to(source):
        parser.error("Verification output must be new and outside the source run")
    result = verify(source)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n")
    print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
    raise SystemExit(0 if result["passed"] else 1)

"""Verify a saved live sidecar against its events and repeat prefix scoring locally."""

import argparse
import copy
import hashlib
import json
from collections import Counter
from pathlib import Path

from agentdojo_lab.inspection import inspect_events
from agentdojo_lab.online import AVAILABILITY
from agentdojo_lab.policy import ToolPolicy
from agentdojo_lab.provenance import ProvenanceTracker
from agentdojo_lab.semantic import LocalMiniLMEncoder, SemanticMatcher


def checked(predicate) -> bool:
    """Malformed cross-references fail an audit check instead of satisfying it."""
    try:
        return bool(predicate())
    except (KeyError, IndexError, TypeError, ValueError, AttributeError):
        return False


def same_identity(row: dict, event: dict) -> bool:
    return all(
        key in row and row[key] == event.get(key)
        for key in ("run_id", "task_id", "episode_id", "model_request_id", "call_ref")
    )


def nonnegative_ints(*values) -> bool:
    return all(type(value) is int and value >= 0 for value in values)


def json_equal(left, right) -> bool:
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(
        right, sort_keys=True, allow_nan=False
    )


def frozen_policy(manifest: dict) -> tuple[ToolPolicy | None, dict]:
    """Restore the recorded policy document, never its mutable original pathname."""
    config = manifest["config"]
    snapshot = manifest.get("online_provenance", {}).get("policy")
    configured = config.get("provenance_policy") is not None
    checks = {"policy_snapshot_presence_consistent": configured == (snapshot is not None)}
    if snapshot is None:
        return None, checks
    checks.update(
        policy_snapshot_valid=False, policy_snapshot_hash_matches=False, policy_context_matches=False
    )
    try:
        policy = ToolPolicy.from_dict(snapshot["document"])
        checks["policy_snapshot_valid"] = True
        checks["policy_snapshot_hash_matches"] = (
            snapshot["sha256"] == policy.metadata["sha256"]
            and snapshot["policy_id"] == policy.metadata["policy_id"]
        )
        policy.validate_context(config["suite"], config["benchmark_version"])
        checks["policy_context_matches"] = True
        return policy, checks
    except (KeyError, TypeError, ValueError, AttributeError):
        return None, checks


def cascade_counts(calls: list[dict]) -> tuple[int, dict]:
    """Recompute counters from persisted pair evidence, independently of summary claims."""
    pairs = [pair for call in calls for field in call["fields"] for pair in field.get("nt_style_cascade", [])]
    stages = {tier: Counter() for tier in ("tier1", "tier2", "tier3", "tier4")}
    for pair in pairs:
        for tier in stages:
            stages[tier][pair["stages"][tier]["status"]] += 1
    return len(pairs), {
        "cascade_status_counts": dict(Counter(pair["status"] for pair in pairs)),
        "cascade_stage_counts": {tier: dict(counts) for tier, counts in stages.items()},
        "cascade_first_hit_counts": dict(
            Counter(pair["first_matched_tier"] for pair in pairs if pair["first_matched_tier"] is not None)
        ),
        "cascade_incomplete_pair_count": sum(
            not pair["complete"] and pair["status"] != "not_applicable" for pair in pairs
        ),
        "policy_sink_count": sum(call["policy"]["sink"]["selected"] is True for call in calls),
        "unclassified_proposal_count": sum(
            call["policy"]["sink"]["classification"] == "unclassified_tool" for call in calls
        ),
    }


def proposal_timing_valid(analysis: dict, receipt: dict, proposal: dict) -> bool:
    recorded = proposal["monotonic_ns"]
    computed, flushed = analysis["timing"], receipt["timing"]
    started, completed, available = (
        computed["consume_started_monotonic_ns"],
        computed["compute_completed_monotonic_ns"],
        flushed["analysis_flushed_monotonic_ns"],
    )
    return (
        computed["clock"] == flushed["clock"] == "time.monotonic_ns"
        and nonnegative_ints(
            recorded,
            started,
            completed,
            available,
            computed["proposal_event_monotonic_ns"],
            computed["compute_elapsed_ns"],
            flushed["consume_started_monotonic_ns"],
            flushed["compute_completed_monotonic_ns"],
            flushed["compute_and_analysis_flush_elapsed_ns"],
        )
        and computed["proposal_event_monotonic_ns"] == recorded
        and recorded <= started <= completed <= available
        and computed["compute_elapsed_ns"] == completed - started
        and flushed["consume_started_monotonic_ns"] == started
        and flushed["compute_completed_monotonic_ns"] == completed
        and flushed["compute_and_analysis_flush_elapsed_ns"] == available - started
    )


def runtime_timing_valid(row: dict, start: dict, proposal: dict, analysis: dict, receipt: dict) -> bool:
    timing = row["timing"]
    recorded = start["monotonic_ns"]
    available, acknowledged = timing["analysis_flushed_monotonic_ns"], timing["receipt_flushed_monotonic_ns"]
    return (
        same_identity(row, start)
        and same_identity(row, proposal)
        and all(
            type(row[key]) is int
            for key in ("runtime_event_sequence", "analysis_record_sequence", "receipt_record_sequence")
        )
        and row["runtime_event_sequence"] == start["event_sequence"]
        and row["analysis_record_sequence"] == analysis["record_sequence"]
        and row["receipt_record_sequence"] == receipt["record_sequence"]
        and analysis["record_sequence"] < receipt["record_sequence"] < row["record_sequence"]
        and row["correlation"] == "matched_proposal"
        and row["analysis_before_runtime"] is True
        and row["receipt_before_runtime"] is True
        and row["runtime_event_monotonic_ns"] == recorded
        and timing["clock"] == "time.monotonic_ns"
        and nonnegative_ints(
            recorded,
            row["runtime_event_monotonic_ns"],
            available,
            acknowledged,
            timing["consume_started_monotonic_ns"],
            timing["analysis_lead_ns"],
        )
        and available == receipt["timing"]["analysis_flushed_monotonic_ns"]
        and available <= acknowledged <= recorded <= timing["consume_started_monotonic_ns"]
        and timing["analysis_lead_ns"] == recorded - available
    )


def verify(run: Path) -> dict:
    run = run.resolve()
    paths = [run / name for name in ("manifest.json", "summary.json", "events.jsonl", "provenance.jsonl")]
    source_bytes = {path.name: path.read_bytes() for path in paths}
    before = {name: hashlib.sha256(raw).hexdigest() for name, raw in source_bytes.items()}
    manifest = json.loads(source_bytes["manifest.json"])
    summary = json.loads(source_bytes["summary.json"])
    events = [json.loads(line) for line in source_bytes["events.jsonl"].splitlines()]
    raw_rows = source_bytes["provenance.jsonl"].splitlines(keepends=True)
    rows = [json.loads(line) for line in raw_rows]
    config = manifest["config"]
    if config.get("lineage_namespace") is not None:
        state_path = run / "lineage-state.json"
        if state_path.resolve().parent != run:
            raise ValueError("Final lineage checkpoint must be inside the recorded run")
        source_bytes[state_path.name] = state_path.read_bytes()
        before[state_path.name] = hashlib.sha256(source_bytes[state_path.name]).hexdigest()
        paths.append(state_path)
    policy, policy_checks = frozen_policy(manifest)
    matcher = None
    if config.get("semantic_model"):
        model_path = Path(config["semantic_model"]).expanduser()
        if not model_path.is_absolute():
            model_path = Path(__file__).resolve().parents[1] / model_path
        matcher = SemanticMatcher(LocalMiniLMEncoder(model_path, revision=config["semantic_revision"]))
    lineage, lineage_checks = None, {}
    namespace = config.get("lineage_namespace")
    if namespace is not None:
        from agentdojo_lab.provenance_report import _lineage_for_run

        lineage, initial = _lineage_for_run(run, manifest, policy, matcher, namespace)
        for name, raw in initial.items():
            source_bytes[name] = raw
            before[name] = hashlib.sha256(raw).hexdigest()
            paths.append(run / name)
        lineage_checks["lineage_mode_declared"] = summary["online_provenance"].get("lineage_enabled") is True
    canary_enabled = config.get("canary_enabled", False)
    tracker = ProvenanceTracker(
        semantic_matcher=matcher, policy=policy, lineage=lineage, canary_enabled=canary_enabled
    )
    replay = [call for event in events if (call := tracker.consume(event)) is not None]
    live_rows = [row for row in rows if row["record_type"] == "call_analysis"]
    live = [copy.deepcopy(row["call"]) for row in live_rows]
    availability_labels = [call.pop("availability", None) for call in live]
    for call in replay:
        call.pop("availability")
    by_sequence = {row["record_sequence"]: (row, raw) for row, raw in zip(rows, raw_rows, strict=True)}
    receipts = {row["proposal_event_id"]: row for row in rows if row["record_type"] == "analysis_flush"}
    analyses = {row["proposal_event_id"]: row for row in live_rows}
    proposals = {event["event_id"]: event for event in events if event["event_type"] == "TOOL_CALL_PROPOSED"}
    starts = {event["event_id"]: event for event in events if event["event_type"] == "TOOL_RUNTIME_STARTED"}
    checks = {
        **policy_checks,
        **lineage_checks,
        "recording_complete": summary["recording"].get("complete") is True,
        "event_audit_valid": inspect_events(paths[2])["valid"],
        "sidecar_complete": summary.get("online_provenance", {}).get("complete") is True,
        "online_mode_declared": config.get("online_provenance") is True,
        "live_availability_declared": all(label == AVAILABILITY for label in availability_labels)
        and all(row.get("availability") == AVAILABILITY for row in receipts.values()),
        "sidecar_schema_supported": all(
            type(row.get("schema_version")) is int
            and row["schema_version"] == 1
            and row.get("record_type") in {"call_analysis", "analysis_flush", "runtime_timing"}
            and type(row.get("record_sequence")) is int
            for row in rows
        ),
        "sidecar_sequence_consecutive": [row["record_sequence"] for row in rows]
        == list(range(1, len(rows) + 1)),
        "one_analysis_per_proposal": Counter(row["proposal_event_id"] for row in live_rows)
        == Counter({key: 1 for key in proposals}),
        "one_receipt_per_analysis": Counter(
            row["proposal_event_id"] for row in rows if row["record_type"] == "analysis_flush"
        )
        == Counter(row["proposal_event_id"] for row in live_rows),
        "live_equals_replay_except_availability": checked(lambda: json_equal(live, replay)),
    }
    if canary_enabled:
        from agentdojo_lab.canary import CanaryInjector

        checks["canary_intervention_complete"] = (
            summary.get("canary", {}).get("complete") is True
            and summary.get("online_provenance", {}).get("canary_enabled") is True
            and manifest.get("input_condition") == "canary_intervention"
        )
        audits = [event["data"] for event in events if event["event_type"] == "TOOL_OUTPUT_INTERVENTION"]
        counts = summary.get("canary", {}).get("counts", {})
        checks["canary_injector_metadata_matches"] = manifest.get("canary") == CanaryInjector(policy).metadata
        checks["all_interventions_have_linked_published_results"] = all(
            row["result_event_id"] is not None for row in tracker.canary_assignments.values()
        ) and len(tracker.canary_assignments) == len(audits)
        checks["canary_counts_match_events"] = counts.get("prepare_calls", 0) == len(audits) and all(
            counts.get(status, 0) == sum(audit["status"] == status for audit in audits)
            for status in ("assigned", "skipped")
        )
    checks["analysis_and_receipt_identities_match"] = checked(
        lambda: (
            all(same_identity(row, proposals[row["proposal_event_id"]]) for row in live_rows)
            and all(same_identity(row, proposals[row["proposal_event_id"]]) for row in receipts.values())
        )
    )
    checks["flush_receipt_hashes_match"] = checked(
        lambda: all(
            type(row["analysis_record_sequence"]) is int
            and row["analysis_record_sequence"] == analyses[row["proposal_event_id"]]["record_sequence"]
            and row["analysis_record_sequence"] < row["record_sequence"]
            and row["analysis_line_sha256"]
            == hashlib.sha256(by_sequence[row["analysis_record_sequence"]][1]).hexdigest()
            and by_sequence[row["analysis_record_sequence"]][0]["record_type"] == "call_analysis"
            and by_sequence[row["analysis_record_sequence"]][0]["proposal_event_id"]
            == row["proposal_event_id"]
            for row in receipts.values()
        )
    )
    checks["proposal_compute_and_flush_timestamps_consistent"] = checked(
        lambda: all(
            proposal_timing_valid(
                row, receipts[row["proposal_event_id"]], proposals[row["proposal_event_id"]]
            )
            for row in live_rows
        )
    )
    timing = [row for row in rows if row["record_type"] == "runtime_timing"]
    checks["one_timing_record_per_runtime"] = Counter(row["runtime_event_id"] for row in timing) == Counter(
        {key: 1 for key in starts}
    )
    checks["timestamps_confirm_pre_runtime_availability"] = checked(
        lambda: all(
            runtime_timing_valid(
                row,
                starts[row["runtime_event_id"]],
                proposals[row["proposal_event_id"]],
                analyses[row["proposal_event_id"]],
                receipts[row["proposal_event_id"]],
            )
            for row in timing
        )
    )
    expected_counts = {
        "analysis_count": len(live_rows),
        "analysis_flush_count": sum(row["record_type"] == "analysis_flush" for row in rows),
        "runtime_timing_count": len(timing),
        "record_count": len(rows),
        "event_attempt_count": len(events),
        "event_consumed_count": len(events),
    }
    checks["sidecar_summary_counts_match"] = checked(
        lambda: all(
            type(summary["online_provenance"][name]) is int and summary["online_provenance"][name] == count
            for name, count in expected_counts.items()
        )
    )
    cascade_pair_count, computed_cascade_counts = 0, None
    semantic_comparison_scope = "independent_comparisons"
    if policy is not None:
        semantic_comparison_scope = (
            "independent_comparisons; ordered_semantic_stages_are_reported_in_cascade_stage_counts"
        )
        cascade_pair_count, computed_cascade_counts = cascade_counts(live)
        checks["semantic_comparison_scope_matches"] = checked(
            lambda: summary["online_provenance"]["semantic_comparison_scope"] == semantic_comparison_scope
        )
        checks["policy_mode_and_summary_identity_match"] = checked(
            lambda: (
                manifest["online_provenance"]["mode"] == "synchronous_observation; ordered_cascade"
                and summary["online_provenance"]["component_mode"] == "ordered_cascade"
                and summary["online_provenance"]["policy_id"] == policy.metadata["policy_id"]
                and summary["online_provenance"]["policy_sha256"] == policy.metadata["sha256"]
            )
        )
        checks["cascade_summary_counts_match"] = checked(
            lambda: all(
                json_equal(summary["online_provenance"][key], value)
                for key, value in computed_cascade_counts.items()
            )
        )
        checks["cascade_scoring_completeness_matches"] = checked(
            lambda: (
                summary["online_provenance"]["scoring_complete"]
                is (
                    computed_cascade_counts["cascade_incomplete_pair_count"] == 0
                    and not any(
                        not pair["complete"] and pair["status"] != "not_applicable"
                        for call in live
                        for pair in call.get("lineage", {}).get("comparisons", [])
                    )
                )
            )
        )
    lineage_counts = None
    if lineage is not None:
        state_path = run / "lineage-state.json"
        raw = source_bytes[state_path.name]
        envelope = json.loads(raw)
        graph = lineage.snapshot()
        lineage_pairs = [pair for call in live for pair in call["lineage"]["comparisons"]]
        lineage_counts = {
            "nodes": len(graph["nodes"]),
            "edges": len(graph["edges"]),
            "memory_bindings": len(graph["memory_bindings"]),
            "restored_comparisons": len(lineage_pairs),
        }
        checks["lineage_graph_equals_replay"] = checked(lambda: json_equal(envelope["state"], graph))
        checks["lineage_checkpoint_digest_matches"] = checked(
            lambda: (
                envelope["state_sha256"]
                == hashlib.sha256(
                    json.dumps(
                        envelope["state"],
                        sort_keys=True,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        allow_nan=False,
                    ).encode()
                ).hexdigest()
            )
        )
        checks["lineage_summary_counts_match"] = checked(
            lambda: (
                summary["online_provenance"]["lineage_comparison_count"] == len(lineage_pairs)
                and summary["online_provenance"]["lineage_incomplete_comparison_count"]
                == sum(not p["complete"] and p["status"] != "not_applicable" for p in lineage_pairs)
            )
        )
        checks["lineage_state_save_hash_matches"] = checked(
            lambda: (
                summary["lineage_state"]["status"] == "saved"
                and summary["lineage_state"]["sha256"] == before[state_path.name]
            )
        )
    checks["source_files_unchanged"] = before == {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths
    }
    return {
        "run_id": run.name,
        "passed": all(checks.values()),
        "checks": checks,
        "real_llm": manifest["real_llm"],
        "proposal_count": len(proposals),
        "runtime_count": len(starts),
        "field_count": sum(len(call["fields"]) for call in live),
        "semantic_comparison_count": sum(
            len(field.get("nt_style_semantic", [])) for call in live for field in call["fields"]
        ),
        "semantic_comparison_scope": semantic_comparison_scope,
        "cascade_pair_count": cascade_pair_count,
        "cascade_counts": computed_cascade_counts,
        **({"lineage_counts": lineage_counts} if lineage_counts is not None else {}),
        "policy_sha256": policy.metadata["sha256"] if policy is not None else None,
        "input_sha256": before,
        "scope": (
            "Consistency of saved timing receipts and local prefix replay equality; "
            "policy replay uses the manifest snapshot, not the current policy pathname. "
            "not authenticated evidence against coordinated rewriting. "
            "No API calls, accuracy, causality, or deadline guarantee."
        ),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument(
        "--output", type=Path, required=True, help="New verification JSON outside the source run"
    )
    args = parser.parse_args()
    if args.output.resolve().is_relative_to(args.run.resolve()):
        parser.error("Verification output must be outside the source run")
    if args.output.exists():
        raise FileExistsError(args.output)
    result = verify(args.run)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)

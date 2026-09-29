"""Fail-open synchronous provenance from detached, redacted recorder snapshots.

Only the copied proposal analysis is marked live. Its successful file flush is
acknowledged by a subsequent receipt. A later runtime event can then establish
whether the analysis and receipt were available before that recorded boundary.
An optional isolated causal auditor may run after the explicit analysis receipt.
Neither result can intercept or rewrite the proposed action.
"""

from __future__ import annotations

import copy
import hashlib
import json
import threading
import time
from pathlib import Path

from agentdojo_lab.provenance import ProvenanceTracker

AVAILABILITY = "live_synchronous_sidecar; request_prefix_only; no_action_enforcement"


class AttributionComputeError(Exception):
    """An optional scoring component explicitly reported an encoder failure."""


class OnlineProvenance:
    """Observe an ordered stream without propagating ordinary failures to its caller.

    ``path`` names a new sidecar JSONL file. Inputs must already be detached and
    redacted by EventRecorder; this consumer makes another defensive copy. The
    supplied matcher runs synchronously and can add latency. Existing per-input
    computation budgets do not impose a wall-clock deadline.
    """

    def __init__(
        self,
        path: Path,
        semantic_matcher=None,
        policy=None,
        lineage=None,
        *,
        canary_enabled=False,
        cascade_profile="ordinary",
        causal_auditor=None,
    ):
        self._lock = threading.RLock()
        self._file = None
        self._tracker = None
        self._closed = False
        self._disabled = False
        self._errors = []
        self._attempt_count = 0
        self._consumed_count = 0
        self._ignored_count = 0
        self._last_consumed_sequence = None
        self._record_attempt_count = 0
        self._record_count = 0
        self._analysis_count = 0
        self._analysis_flush_count = 0
        self._runtime_count = 0
        self._unmatched_runtime_count = 0
        self._before_runtime_count = 0
        self._runtime_timing_failure_count = 0
        self._pending = {}
        self._proposal_refs = set()
        self._runtime_refs = set()
        self._run_end_seen = False
        self._causal_auditor = causal_auditor
        self._causal_bridge_errors = []
        self._policy = policy
        self._lineage = lineage
        self._canary_enabled = canary_enabled
        self._lineage_comparison_count = 0
        self._lineage_incomplete_count = 0
        self._cascade_status_counts = {}
        self._cascade_stage_counts = {tier: {} for tier in ("tier1", "tier2", "tier3", "tier4")}
        self._cascade_first_hit_counts = {}
        self._cascade_incomplete_count = 0
        self._policy_sink_count = 0
        self._policy_unclassified_sink_count = 0
        self._semantic_enabled = semantic_matcher is not None
        self._semantic_status_counts = {}
        self._semantic_truncated_count = 0
        self._semantic_tier_truncated_counts = {"tier3": 0, "tier4": 0}
        self._stage = "initialize"
        self._timing = {
            "consume_total_ns": 0,
            "tracker_compute_total_ns": 0,
            "proposal_compute_total_ns": 0,
            "serialization_total_ns": 0,
            "write_flush_total_ns": 0,
        }
        try:
            self._tracker = ProvenanceTracker(
                semantic_matcher=semantic_matcher,
                policy=policy,
                lineage=lineage,
                canary_enabled=canary_enabled,
                cascade_profile=cascade_profile,
            )
            self._stage = "open"
            self._file = Path(path).open("x", encoding="utf-8", newline="\n")
        except Exception as error:
            self._disable(self._stage, error)

    def _disable(self, stage: str, error: Exception, sequence: int | None = None) -> None:
        self._disabled = True
        self._errors.append({"stage": stage, "error_type": type(error).__name__, "event_sequence": sequence})

    def _append(self, row: dict) -> dict:
        """Return a flush timestamp only after the entire line was written/flushed."""
        self._record_attempt_count += 1
        row = {"schema_version": 1, "record_sequence": self._record_attempt_count, **row}
        self._stage = "serialize"
        serialization_started = time.monotonic_ns()
        line = json.dumps(row, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n"
        serialized = time.monotonic_ns()
        self._timing["serialization_total_ns"] += serialized - serialization_started
        self._stage = "write"
        if self._file.write(line) != len(line):
            raise OSError("Incomplete sidecar write")
        self._stage = "flush"
        self._file.flush()
        flushed = time.monotonic_ns()
        self._timing["write_flush_total_ns"] += flushed - serialized
        self._record_count += 1
        return {
            "record_sequence": row["record_sequence"],
            "line_sha256": hashlib.sha256(line.encode()).hexdigest(),
            "flushed_monotonic_ns": flushed,
        }

    @staticmethod
    def _identity(event: dict) -> dict:
        return {
            "run_id": event["run_id"],
            "task_id": event.get("task_id"),
            "episode_id": event.get("episode_id"),
            "model_request_id": event.get("model_request_id"),
            "call_ref": event.get("call_ref"),
        }

    def _proposal(self, event: dict, call: dict, started: int, computed: int) -> None:
        self._stage = "proposal.validate"
        call_ref = event.get("call_ref")
        if not isinstance(call_ref, str) or not call_ref or call_ref in self._proposal_refs:
            raise ValueError("A proposal requires a unique call reference")
        for pair in call.get("lineage", {}).get("comparisons", []):
            self._lineage_comparison_count += 1
            self._lineage_incomplete_count += not pair["complete"] and pair["status"] != "not_applicable"
            if pair["status"] == "encoder_error":
                raise AttributionComputeError()
        for field in call["fields"]:
            for score in field.get("nt_style_semantic", []):
                status = score.get("status", "unknown")
                self._semantic_status_counts[status] = self._semantic_status_counts.get(status, 0) + 1
                self._semantic_truncated_count += bool(score.get("truncated"))
                for tier in ("tier3", "tier4"):
                    self._semantic_tier_truncated_counts[tier] += bool(score.get(tier, {}).get("truncated"))
            for pair in field.get("nt_style_cascade", []):
                status = pair["status"]
                self._cascade_status_counts[status] = self._cascade_status_counts.get(status, 0) + 1
                self._cascade_incomplete_count += not pair["complete"] and status != "not_applicable"
                hit = pair["first_matched_tier"]
                if hit:
                    self._cascade_first_hit_counts[hit] = self._cascade_first_hit_counts.get(hit, 0) + 1
                for tier, evidence in pair["stages"].items():
                    counts = self._cascade_stage_counts[tier]
                    counts[evidence["status"]] = counts.get(evidence["status"], 0) + 1
        if self._semantic_status_counts.get("encoder_error", 0) or self._cascade_status_counts.get(
            "encoder_error", 0
        ):
            raise AttributionComputeError()
        if self._policy is not None:
            self._policy_sink_count += call["policy"]["sink"]["selected"]
            self._policy_unclassified_sink_count += (
                call["policy"]["sink"]["classification"] == "unclassified_tool"
            )
        frozen = copy.deepcopy(call)
        frozen["availability"] = AVAILABILITY
        identity = {**self._identity(event), "proposal_event_id": event["event_id"]}
        analysis = self._append(
            {
                **identity,
                "record_type": "call_analysis",
                "call": frozen,
                "timing": {
                    "clock": "time.monotonic_ns",
                    "proposal_event_monotonic_ns": event.get("monotonic_ns"),
                    "consume_started_monotonic_ns": started,
                    "compute_completed_monotonic_ns": computed,
                    "compute_elapsed_ns": computed - started,
                    "completion_semantics": "compute_complete_before_persistence",
                },
            }
        )
        self._analysis_count += 1
        receipt = self._append(
            {
                **identity,
                "record_type": "analysis_flush",
                "analysis_record_sequence": analysis["record_sequence"],
                "analysis_line_sha256": analysis["line_sha256"],
                "availability": AVAILABILITY,
                "timing": {
                    "clock": "time.monotonic_ns",
                    "consume_started_monotonic_ns": started,
                    "compute_completed_monotonic_ns": computed,
                    "analysis_flushed_monotonic_ns": analysis["flushed_monotonic_ns"],
                    "compute_and_analysis_flush_elapsed_ns": analysis["flushed_monotonic_ns"] - started,
                    "flush_semantics": "successful_Python_file_flush; not_fsync",
                },
            }
        )
        self._analysis_flush_count += 1
        self._proposal_refs.add(call_ref)
        self._pending[call_ref] = {
            **identity,
            "analysis_record_sequence": analysis["record_sequence"],
            "receipt_record_sequence": receipt["record_sequence"],
            "analysis_flushed_monotonic_ns": analysis["flushed_monotonic_ns"],
            "receipt_flushed_monotonic_ns": receipt["flushed_monotonic_ns"],
        }
        if self._causal_auditor is not None:
            try:
                if self._lineage is None:
                    raise ValueError("Online causal audit requires a lineage graph")
                causal_result = self._causal_auditor.audit_proposal(
                    event, frozen, self._lineage.snapshot()
                )
                self._pending[call_ref]["causal_audit"] = copy.deepcopy(causal_result)
            except Exception as error:
                # Causal auditing is optional and observational. An unexpected bridge
                # failure must not disable explicit provenance or native execution.
                self._causal_bridge_errors.append(
                    {
                        "stage": "proposal",
                        "error_type": type(error).__name__,
                        "event_sequence": event.get("event_sequence"),
                    }
                )

    def _runtime(self, event: dict, started: int) -> None:
        self._stage = "runtime.validate"
        call_ref = event.get("call_ref")
        if call_ref is not None and (not isinstance(call_ref, str) or call_ref in self._runtime_refs):
            raise ValueError("Duplicate or invalid runtime call reference")
        pending = self._pending.get(call_ref)
        runtime_clock = event.get("monotonic_ns")
        if type(runtime_clock) is not int or runtime_clock < 0:
            raise ValueError("Runtime timing requires a recorded monotonic clock")
        if pending and any(
            pending[key] != event.get(key) for key in ("run_id", "episode_id", "model_request_id")
        ):
            raise ValueError("Runtime event does not match its proposal identity")
        if self._causal_auditor is not None:
            try:
                self._causal_auditor.runtime(event)
            except Exception as error:
                self._causal_bridge_errors.append(
                    {
                        "stage": "runtime",
                        "error_type": type(error).__name__,
                        "event_sequence": event.get("event_sequence"),
                    }
                )
        analysis_before = pending["analysis_flushed_monotonic_ns"] <= runtime_clock if pending else None
        receipt_before = pending["receipt_flushed_monotonic_ns"] <= runtime_clock if pending else None
        self._append(
            {
                **self._identity(event),
                "record_type": "runtime_timing",
                "runtime_event_id": event["event_id"],
                "runtime_event_sequence": event["event_sequence"],
                "runtime_event_monotonic_ns": runtime_clock,
                "correlation": "matched_proposal" if pending else "no_prior_analysis",
                "proposal_event_id": pending["proposal_event_id"] if pending else None,
                "analysis_record_sequence": pending["analysis_record_sequence"] if pending else None,
                "receipt_record_sequence": pending["receipt_record_sequence"] if pending else None,
                "analysis_before_runtime": analysis_before,
                "receipt_before_runtime": receipt_before,
                "causal_audit": copy.deepcopy(pending.get("causal_audit")) if pending else None,
                "timing": {
                    "clock": "time.monotonic_ns",
                    "consume_started_monotonic_ns": started,
                    "analysis_flushed_monotonic_ns": pending["analysis_flushed_monotonic_ns"]
                    if pending
                    else None,
                    "receipt_flushed_monotonic_ns": pending["receipt_flushed_monotonic_ns"]
                    if pending
                    else None,
                    "analysis_lead_ns": runtime_clock - pending["analysis_flushed_monotonic_ns"]
                    if pending
                    else None,
                    "boundary": "recorded_top_level_runtime_entry; not_internal_tool_steps",
                },
            }
        )
        self._runtime_count += 1
        if pending:
            self._pending.pop(call_ref)
            if analysis_before and receipt_before:
                self._before_runtime_count += 1
            else:
                self._runtime_timing_failure_count += 1
        else:
            self._unmatched_runtime_count += 1
        if call_ref is not None:
            self._runtime_refs.add(call_ref)

    def consume(self, event) -> None:
        """Process once; any ordinary failure permanently disables attribution."""
        with self._lock:
            self._attempt_count += 1
            if self._disabled:
                self._ignored_count += 1
                return
            if self._closed:
                self._ignored_count += 1
                self._disable("consume.closed", ValueError())
                return
            started = None
            sequence = None
            try:
                self._stage = "consume.snapshot"
                started = time.monotonic_ns()
                snapshot = copy.deepcopy(event)
                if isinstance(snapshot, dict) and type(snapshot.get("event_sequence")) is int:
                    sequence = snapshot["event_sequence"]
                self._stage = "consume.compute"
                compute_started = time.monotonic_ns()
                call = self._tracker.consume(snapshot)
                computed = time.monotonic_ns()
                self._timing["tracker_compute_total_ns"] += computed - compute_started
                if call is not None:
                    self._timing["proposal_compute_total_ns"] += computed - started
                    self._proposal(snapshot, call, started, computed)
                if snapshot["event_type"] == "TOOL_RUNTIME_STARTED":
                    self._runtime(snapshot, started)
                self._consumed_count += 1
                self._last_consumed_sequence = sequence
                self._run_end_seen = self._run_end_seen or snapshot["event_type"] == "RUN_END"
            except Exception as error:
                self._disable(self._stage, error, sequence)
            finally:
                if started is not None:
                    try:
                        self._timing["consume_total_ns"] += time.monotonic_ns() - started
                    except Exception as error:
                        self._disable("consume.clock", error, sequence)

    def status(self) -> dict:
        with self._lock:
            return copy.deepcopy(
                {
                    "enabled": not self._disabled and not self._closed,
                    "active": not self._disabled and not self._closed,
                    "disabled": self._disabled,
                    "closed": self._closed,
                    "complete": not self._errors and self._attempt_count == self._consumed_count,
                    "completeness_scope": "events_received_by_this_consumer",
                    "errors": self._errors,
                    "event_attempt_count": self._attempt_count,
                    "event_consumed_count": self._consumed_count,
                    "ignored_event_count": self._ignored_count,
                    "last_consumed_sequence": self._last_consumed_sequence,
                    "record_attempt_count": self._record_attempt_count,
                    "record_count": self._record_count,
                    "analysis_count": self._analysis_count,
                    "analysis_flush_count": self._analysis_flush_count,
                    "runtime_timing_count": self._runtime_count,
                    "unmatched_runtime_count": self._unmatched_runtime_count,
                    "before_runtime_verified_count": self._before_runtime_count,
                    "runtime_timing_failure_count": self._runtime_timing_failure_count,
                    "pending_runtime_count": len(self._pending),
                    "pending_runtime_semantics": "a_proposal_need_not_enter_runtime; pending_is_not_failure",
                    "run_end_seen": self._run_end_seen,
                    "causal_auditor_attached": self._causal_auditor is not None,
                    "causal_bridge_error_count": len(self._causal_bridge_errors),
                    "causal_bridge_errors": self._causal_bridge_errors,
                    "semantic_enabled": self._semantic_enabled,
                    "semantic_status_counts": self._semantic_status_counts,
                    "semantic_comparison_count": sum(self._semantic_status_counts.values()),
                    "semantic_truncated_comparison_count": self._semantic_truncated_count,
                    "semantic_tier_truncated_counts": self._semantic_tier_truncated_counts,
                    "scoring_complete": (
                        not self._disabled
                        and not self._semantic_truncated_count
                        and not self._cascade_incomplete_count
                        and not self._lineage_incomplete_count
                        and not any(
                            count
                            for status, count in self._semantic_status_counts.items()
                            if status not in {"scored", "not_applicable"}
                        )
                    ),
                    "scoring_completeness_scope": "applicable_semantic_comparisons; scored_without_truncation",
                    **(
                        {
                            "component_mode": "ordered_cascade",
                            "semantic_comparison_scope": "independent_comparisons; ordered_semantic_stages_are_reported_in_cascade_stage_counts",
                            "policy_id": self._policy.metadata["policy_id"],
                            "policy_sha256": self._policy.metadata["sha256"],
                            "policy_sink_count": self._policy_sink_count,
                            "unclassified_proposal_count": self._policy_unclassified_sink_count,
                            "cascade_status_counts": self._cascade_status_counts,
                            "cascade_stage_counts": self._cascade_stage_counts,
                            "cascade_first_hit_counts": self._cascade_first_hit_counts,
                            "cascade_incomplete_pair_count": self._cascade_incomplete_count,
                            "scoring_completeness_scope": "eligible_cascade_pairs; reached_stages_scored_without_truncation",
                        }
                        if self._policy is not None
                        else {}
                    ),
                    "availability": AVAILABILITY,
                    **(
                        {
                            "lineage_enabled": True,
                            "lineage_comparison_count": self._lineage_comparison_count,
                            "lineage_incomplete_comparison_count": self._lineage_incomplete_count,
                            "lineage_scoring_scope": "restored_sources_at_selected_sink_arguments; graph_edges_are_not_causal_evidence",
                        }
                        if self._lineage is not None
                        else {}
                    ),
                    "execution_mode": "synchronous_passive_consumer",
                    **(
                        {"canary_enabled": True, "input_condition": "canary_intervention"}
                        if self._canary_enabled
                        else {}
                    ),
                    "hard_timeout_enforced": False,
                    "retry_count": 0,
                    "timing": {"clock": "time.monotonic_ns", **self._timing},
                    "timing_semantics": "measured_synchronous_consumer_latency; no_wall_clock_deadline",
                    "flush_semantics": "Python_file_flush; not_fsync_or_power_loss_durability",
                }
            )

    def save_state(self, path: Path) -> dict:
        """Persist complete observed lineage after closure without changing the agent."""
        with self._lock:
            if self._lineage is None or not self._closed or self._disabled or not self._run_end_seen:
                return {"status": "not_saved", "reason": "lineage_absent_or_observation_incomplete"}
            try:
                self._lineage.save_state(path)
                return {
                    "status": "saved",
                    "path": str(path),
                    "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(),
                }
            except Exception as error:
                self._disable("lineage.save_state", error)
                return {"status": "failed", "error_type": type(error).__name__}

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._file is not None:
                try:
                    self._file.close()
                except Exception as error:
                    self._disable("close", error)

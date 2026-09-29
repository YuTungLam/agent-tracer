"""Bounded online causal auditing at the recorded pre-runtime proposal boundary.

The auditor is an optional synchronous sidecar.  It plans neutralization probes
from the exact recorded request prefix and asks a separate, no-tools judge for
one bound prediction per slot.  Predictions are evidence annotations only: the
auditor never changes a proposed call, tool runtime, environment, or model.

Operational failures are converted to explicit unknown records and never escape
``audit_proposal`` or ``runtime``.  Static constructor configuration is validated
strictly so a bad experiment cannot silently claim a different budget.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Literal

from agentdojo_lab import causal_v2, judgment_formats, paper_audit
from agentdojo_lab import causal_v2_audit as transport
from agentdojo_lab.counterfactual import _canonical, _hash
from agentdojo_lab.counterfactual_audit import _contains_cjk

PROTOCOL = "online-causal-auditor-v1"
GRAPH_PROTOCOL = PROTOCOL + "-derived-graph"
AVAILABILITY = "live_synchronous_pre_runtime_audit; no_action_enforcement"
SCOPE = (
    "Bound isolated-judge predictions over recorded request-prefix interventions; "
    "not observed counterfactual behavior, calibrated causality, maliciousness, or action enforcement."
)


def _response_dict(response) -> dict:
    if isinstance(response, dict):
        return copy.deepcopy(response)
    dump = getattr(response, "model_dump", None)
    if not callable(dump):
        raise TypeError("Auditor response has no JSON representation")
    value = dump(mode="json")
    if not isinstance(value, dict):
        raise TypeError("Auditor response JSON is not an object")
    return value


def _redacted_response(response: dict, client) -> tuple[dict, bytes]:
    """Return a detached response with the configured key removed before hashing."""
    encoded = _canonical(response)
    key = getattr(client, "api_key", "")
    if isinstance(key, str) and key:
        encoded = encoded.replace(key.encode(), b"[REDACTED]")
    return json.loads(encoded), encoded


def _usage(response: dict) -> dict:
    supplied = response.get("usage")
    supplied = supplied if isinstance(supplied, dict) else {}
    return {
        name: value
        for name in ("prompt_tokens", "completion_tokens", "total_tokens")
        if type(value := supplied.get(name)) is int and value >= 0
    }


def _artifact_copy(value):
    """Keep the English JSONL contract without changing internal graph identities."""
    if isinstance(value, dict):
        return {str(key): _artifact_copy(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_artifact_copy(item) for item in value]
    if isinstance(value, str) and not judgment_formats.supported_text(value):
        return "[NON_ENGLISH_TEXT_SHA256:" + hashlib.sha256(value.encode()).hexdigest() + "]"
    return copy.deepcopy(value)


class OnlineCausalAuditor:
    """Run finite no-tools causal probes before native tool runtime begins."""

    def __init__(
        self,
        path: Path,
        *,
        client=None,
        max_requests: int = 8,
        canary_enabled: bool = False,
        max_sources: int = 8,
        max_pairs: int = 12,
        judgment_format: str = judgment_formats.ENGLISH_PUNCTUATION_FORMAT,
        request_timeout_seconds: float = 60,
        model: str | None = None,
        reasoning_effort: Literal["low", "medium", "high"] | None = "low",
    ):
        if type(max_requests) is not int or not 0 <= max_requests <= transport.MAX_REQUESTS:
            raise ValueError("Online causal request budget must be an integer from zero through 32")
        if type(canary_enabled) is not bool:
            raise ValueError("Canary condition must be boolean")
        if type(max_sources) is not int or not 1 <= max_sources <= causal_v2.MAX_SOURCES:
            raise ValueError("Online causal source budget is invalid")
        if type(max_pairs) is not int or not 0 <= max_pairs <= causal_v2.MAX_PAIRS:
            raise ValueError("Online causal pair budget is invalid")
        if (
            type(request_timeout_seconds) not in (int, float)
            or not math.isfinite(request_timeout_seconds)
            or request_timeout_seconds <= 0
        ):
            raise ValueError("Online causal request timeout must be finite and positive")
        judgment_formats.validate_format(judgment_format)
        selected_model = transport.MODEL if model is None else model
        if not isinstance(selected_model, str) or not selected_model.strip():
            raise ValueError("Online causal model must be a nonempty string")
        if reasoning_effort not in (None, "low", "medium", "high"):
            raise ValueError("Invalid causal reasoning effort")

        self._lock = threading.RLock()
        self._path = Path(path)
        self._graph_path = self._path.with_name("causal-online-graph.json")
        self._file = None
        self._client = client
        self._max_requests = max_requests
        self._canary_enabled = canary_enabled
        self._max_sources = max_sources
        self._max_pairs = max_pairs
        self._judgment_format = judgment_format
        self._request_timeout_seconds = float(request_timeout_seconds)
        self._model = selected_model
        self._reasoning_effort = reasoning_effort
        self._closed = False
        self._disabled = False
        self._errors: list[dict] = []
        self._stage = "initialize"
        self._record_attempt_count = 0
        self._record_count = 0
        self._proposal_attempt_count = 0
        self._proposal_count = 0
        self._request_count = 0
        self._planned_probe_count = 0
        self._valid_judgment_count = 0
        self._unknown_judgment_count = 0
        self._attempted_usage: list[dict] = []
        self._runtime_count = 0
        self._unmatched_runtime_count = 0
        self._before_runtime_count = 0
        self._runtime_timing_failure_count = 0
        self._status_counts: Counter[str] = Counter()
        self._plan_status_counts: Counter[str] = Counter()
        self._pending: dict[str, dict] = {}
        self._proposal_refs: set[str] = set()
        self._runtime_refs: set[str] = set()
        self._decisions: dict[str, dict] = {}
        self._added_nodes: dict[str, dict] = {}
        self._added_edges: dict[str, dict] = {}
        self._latest_graph: dict | None = None
        self._graph_saved = False
        self._graph_sha256: str | None = None
        self._timing = {
            "proposal_total_ns": 0,
            "planning_total_ns": 0,
            "judge_total_ns": 0,
            "composition_total_ns": 0,
            "serialization_total_ns": 0,
            "write_flush_total_ns": 0,
        }
        try:
            if self._client is not None:
                transport._client_config(self._client)
            self._stage = "open"
            self._file = self._path.open("x", encoding="utf-8", newline="\n")
        except Exception as error:
            self._disable(self._stage, error)

    def _disable(self, stage: str, error: Exception) -> None:
        self._disabled = True
        self._errors.append({"stage": stage, "error_type": type(error).__name__})

    def _append(self, row: dict) -> dict:
        self._record_attempt_count += 1
        complete = {
            "schema_version": 1,
            "protocol": PROTOCOL,
            "record_sequence": self._record_attempt_count,
            **_artifact_copy(row),
        }
        self._stage = "serialize"
        started = time.monotonic_ns()
        line = json.dumps(complete, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n"
        serialized = time.monotonic_ns()
        self._timing["serialization_total_ns"] += serialized - started
        if _contains_cjk(line):
            raise ValueError("Non-English content reached the online causal JSONL boundary")
        self._stage = "write"
        if self._file is None or self._file.write(line) != len(line):
            raise OSError("Incomplete online causal sidecar write")
        self._stage = "flush"
        self._file.flush()
        flushed = time.monotonic_ns()
        self._timing["write_flush_total_ns"] += flushed - serialized
        self._record_count += 1
        return {
            "record_sequence": complete["record_sequence"],
            "line_sha256": hashlib.sha256(line.encode()).hexdigest(),
            "flushed_monotonic_ns": flushed,
        }

    @staticmethod
    def _identity(event: dict) -> dict:
        return {
            "run_id": event.get("run_id"),
            "task_id": event.get("task_id"),
            "episode_id": event.get("episode_id"),
            "model_request_id": event.get("model_request_id"),
            "call_ref": event.get("call_ref"),
        }

    def _validate_proposal(self, event: dict, call: dict, graph: dict) -> str:
        if event.get("event_type") != "TOOL_CALL_PROPOSED":
            raise ValueError("Online causal audit requires a proposal event")
        call_ref = event.get("call_ref")
        if not isinstance(call_ref, str) or not call_ref or call_ref in self._proposal_refs:
            raise ValueError("Online causal audit requires a unique call reference")
        if (
            event.get("event_id") != call.get("proposal_event_id")
            or event.get("run_id") != call.get("run_id")
            or event.get("episode_id") != call.get("episode_id")
        ):
            raise ValueError("Proposal event and call analysis identities differ")
        if not isinstance(graph, dict):
            raise ValueError("Online causal audit requires a lineage graph snapshot")
        return call_ref

    def _probe(self, proposal_event_id: str, probe: dict, ordinal: int) -> dict:
        row = {
            "protocol": causal_v2.PROTOCOL,
            "judgment_format": self._judgment_format,
            "slot_ordinal": ordinal,
            "proposal_event_id": proposal_event_id,
            "probe_id": probe["probe_id"],
            "binding_sha256": probe["binding_sha256"],
            "source_ids": copy.deepcopy(probe["source_ids"]),
            "kind": probe["kind"],
            "status": "not_run",
            "reason": None,
            "request_attempted": False,
            "usage": {},
        }
        body = transport.request_body(probe, judgment_format=self._judgment_format)
        body["model"] = self._model
        if self._reasoning_effort is None:
            body.pop("reasoning_effort", None)
        else:
            body["reasoning_effort"] = self._reasoning_effort
        row["request_body_sha256"] = _hash(body)
        if {"tools", "tool_choice", "functions", "function_call"}.intersection(body):
            row.update(status="error", reason="auditor_request_schema_failed")
            return row
        if self._client is None:
            row["reason"] = "auditor_client_not_configured"
            return row
        if self._request_count >= self._max_requests:
            row["reason"] = "request_budget_exhausted"
            return row
        if len(_canonical(body)) > transport.MAX_REQUEST_BYTES:
            row["reason"] = "request_size_budget_exceeded"
            return row

        tick = time.monotonic_ns()
        self._request_count += 1
        row["request_attempted"] = True
        try:
            response = self._client.chat.completions.create(**body, timeout=self._request_timeout_seconds)
            detached, encoded = _redacted_response(_response_dict(response), self._client)
            row["usage"] = _usage(detached)
            row["response_sha256"] = hashlib.sha256(encoded).hexdigest()
            if _contains_cjk(encoded.decode()):
                row.update(
                    status="invalid",
                    reason="non_english_response",
                    response_file=self._write_quarantined_response(encoded),
                )
            elif judgment_formats.contains_unsupported_characters(encoded.decode()):
                row.update(
                    status="invalid",
                    reason="unsupported_response_character",
                    response_file=self._write_quarantined_response(encoded),
                )
            else:
                row["response"] = detached
                row.update(transport._response_result(probe, detached, judgment_format=self._judgment_format))
        except Exception as error:
            row.update(
                status="error",
                reason="auditor_request_or_response_failed",
                error_type=type(error).__name__,
            )
        finally:
            elapsed = time.monotonic_ns() - tick
            row["elapsed_ns"] = elapsed
            self._timing["judge_total_ns"] += elapsed
        return row

    def _write_quarantined_response(self, encoded: bytes) -> str:
        """Preserve an exact redacted envelope outside the English JSONL."""
        name = f"causal-online-response-{self._request_count:04d}.bin"
        path = self._path.with_name(name)
        with path.open("xb") as stream:
            if stream.write(encoded) != len(encoded):
                raise OSError("Incomplete quarantined online causal response write")
            stream.flush()
        return name

    def _merge_additions(self, additions: dict) -> None:
        for field, identity, destination in (
            ("added_nodes", "node_id", self._added_nodes),
            ("added_edges", "edge_id", self._added_edges),
        ):
            values = additions.get(field, [])
            if not isinstance(values, list):
                raise ValueError("Invalid online causal graph additions")
            for value in values:
                key = value.get(identity) if isinstance(value, dict) else None
                if not isinstance(key, str) or (key in destination and destination[key] != value):
                    raise ValueError("Conflicting online causal graph addition")
                destination[key] = copy.deepcopy(value)

    def audit_proposal(self, event: dict, call: dict, graph: dict) -> dict:
        """Audit one proposal and return only evidence about the sidecar operation.

        The returned value cannot affect execution unless a caller violates the API's
        passive-use contract.  All ordinary planning, judge, composition, and file
        errors become an unknown receipt instead of escaping this method.
        """
        with self._lock:
            self._proposal_attempt_count += 1
            if self._closed or self._disabled:
                return {
                    "status": "not_run",
                    "reason": "auditor_closed" if self._closed else "auditor_disabled",
                    "error_type": None,
                }
            started = time.monotonic_ns()
            try:
                self._stage = "proposal.snapshot"
                snapshot_event = copy.deepcopy(event)
                snapshot_call = copy.deepcopy(call)
                snapshot_graph = copy.deepcopy(graph)
                call_ref = self._validate_proposal(snapshot_event, snapshot_call, snapshot_graph)
                proposal_event_id = snapshot_call["proposal_event_id"]

                self._stage = "proposal.plan"
                plan_started = time.monotonic_ns()
                plan = causal_v2.plan_joint_probes(
                    snapshot_call,
                    snapshot_graph,
                    canary_enabled=self._canary_enabled,
                    max_sources=self._max_sources,
                    max_pairs=self._max_pairs,
                )
                planned = time.monotonic_ns()
                self._timing["planning_total_ns"] += planned - plan_started
                probes = plan.get("probes", []) if isinstance(plan.get("probes"), list) else []
                self._plan_status_counts[str(plan.get("status", "unknown"))] += 1
                self._planned_probe_count += len(probes)

                self._stage = "proposal.judge"
                results = [
                    self._probe(proposal_event_id, probe, ordinal) for ordinal, probe in enumerate(probes, 1)
                ]
                for result in results:
                    self._status_counts[result["status"]] += 1
                    self._valid_judgment_count += result["status"] == "valid"
                    self._unknown_judgment_count += result["status"] != "valid"
                    if result["request_attempted"]:
                        self._attempted_usage.append({"usage": copy.deepcopy(result["usage"])})

                self._stage = "proposal.compose"
                composition_started = time.monotonic_ns()
                try:
                    decision, additions = paper_audit.compose_proposal(
                        snapshot_call,
                        snapshot_graph,
                        plan,
                        results,
                        judgment_format=self._judgment_format,
                    )
                    self._merge_additions(additions)
                    composition = {"status": "composed", "error_type": None}
                except Exception as error:
                    decision = {
                        "proposal_event_id": proposal_event_id,
                        "status": "unknown",
                        "detector_positive": None,
                        "decision_resolved": False,
                    }
                    composition = {"status": "failed", "error_type": type(error).__name__}
                composed = time.monotonic_ns()
                self._timing["composition_total_ns"] += composed - composition_started

                summary = causal_v2.summarize_joint_results(
                    plan, results, judgment_format=self._judgment_format
                )
                identity = {
                    **self._identity(snapshot_event),
                    "proposal_event_id": proposal_event_id,
                }
                self._stage = "proposal.persist_analysis"
                analysis = self._append(
                    {
                        **identity,
                        "record_type": "causal_analysis",
                        "availability": AVAILABILITY,
                        "scope": SCOPE,
                        "plan": {
                            "status": plan.get("status"),
                            "complete": plan.get("complete"),
                            "reason": plan.get("reason"),
                            "probe_count": len(probes),
                            "pair_inventory": plan.get("pair_inventory", []),
                            "binding_sha256": _hash(plan),
                        },
                        "results": results,
                        "prediction_summary": summary,
                        "decision": decision,
                        "composition": composition,
                        "request_accounting": {
                            "run_budget": self._max_requests,
                            "run_attempted": self._request_count,
                            "run_remaining": self._max_requests - self._request_count,
                            "proposal_attempted": sum(r["request_attempted"] for r in results),
                            "sdk_max_retries": 0,
                        },
                        "timing": {
                            "clock": "time.monotonic_ns",
                            "proposal_event_monotonic_ns": snapshot_event.get("monotonic_ns"),
                            "audit_started_monotonic_ns": started,
                            "planning_completed_monotonic_ns": planned,
                            "composition_completed_monotonic_ns": composed,
                            "audit_compute_elapsed_ns": composed - started,
                        },
                    }
                )
                self._stage = "proposal.persist_receipt"
                receipt = self._append(
                    {
                        **identity,
                        "record_type": "causal_flush",
                        "analysis_record_sequence": analysis["record_sequence"],
                        "analysis_line_sha256": analysis["line_sha256"],
                        "analysis_flushed_monotonic_ns": analysis["flushed_monotonic_ns"],
                        "flush_semantics": "successful_Python_file_flush; not_fsync",
                    }
                )
                self._proposal_refs.add(call_ref)
                self._proposal_count += 1
                self._decisions[proposal_event_id] = copy.deepcopy(decision)
                self._latest_graph = snapshot_graph
                self._pending[call_ref] = {
                    **identity,
                    "analysis_record_sequence": analysis["record_sequence"],
                    "receipt_record_sequence": receipt["record_sequence"],
                    "analysis_flushed_monotonic_ns": analysis["flushed_monotonic_ns"],
                    "receipt_flushed_monotonic_ns": receipt["flushed_monotonic_ns"],
                }
                return {
                    "status": decision.get("status", "unknown"),
                    "detector_positive": decision.get("detector_positive"),
                    "decision_resolved": bool(decision.get("decision_resolved")),
                    "proposal_event_id": proposal_event_id,
                    "plan_status": plan.get("status", "unknown"),
                    "planned_probe_count": len(probes),
                    "request_attempt_count": sum(r["request_attempted"] for r in results),
                    "valid_judgment_count": sum(r["status"] == "valid" for r in results),
                    "unknown_judgment_count": sum(r["status"] != "valid" for r in results),
                    "analysis_record_sequence": analysis["record_sequence"],
                    "receipt_record_sequence": receipt["record_sequence"],
                    "receipt_flushed_monotonic_ns": receipt["flushed_monotonic_ns"],
                    "composition_status": composition["status"],
                }
            except Exception as error:
                self._errors.append({"stage": self._stage, "error_type": type(error).__name__})
                if self._stage in {"serialize", "write", "flush"}:
                    self._disabled = True
                return {
                    "status": "unknown",
                    "reason": "online_causal_audit_failed",
                    "error_type": type(error).__name__,
                }
            finally:
                self._timing["proposal_total_ns"] += time.monotonic_ns() - started

    def runtime(self, event: dict) -> dict | None:
        """Persist whether a matching audit receipt existed at runtime entry."""
        with self._lock:
            if self._closed or self._disabled:
                return None
            try:
                self._stage = "runtime.snapshot"
                snapshot = copy.deepcopy(event)
                if snapshot.get("event_type") != "TOOL_RUNTIME_STARTED":
                    raise ValueError("Online causal runtime timing requires a runtime event")
                call_ref = snapshot.get("call_ref")
                if call_ref is not None and (not isinstance(call_ref, str) or call_ref in self._runtime_refs):
                    raise ValueError("Duplicate or invalid runtime call reference")
                runtime_clock = snapshot.get("monotonic_ns")
                if type(runtime_clock) is not int or runtime_clock < 0:
                    raise ValueError("Runtime timing requires a recorded monotonic clock")
                pending = self._pending.get(call_ref)
                if pending and any(
                    pending[key] != snapshot.get(key) for key in ("run_id", "episode_id", "model_request_id")
                ):
                    raise ValueError("Runtime event does not match its proposal identity")
                analysis_before = (
                    pending["analysis_flushed_monotonic_ns"] <= runtime_clock if pending else None
                )
                receipt_before = pending["receipt_flushed_monotonic_ns"] <= runtime_clock if pending else None
                row = {
                    **self._identity(snapshot),
                    "record_type": "causal_runtime_timing",
                    "runtime_event_id": snapshot.get("event_id"),
                    "runtime_event_sequence": snapshot.get("event_sequence"),
                    "runtime_event_monotonic_ns": runtime_clock,
                    "correlation": "matched_proposal" if pending else "no_prior_audit",
                    "proposal_event_id": pending["proposal_event_id"] if pending else None,
                    "analysis_record_sequence": pending["analysis_record_sequence"] if pending else None,
                    "receipt_record_sequence": pending["receipt_record_sequence"] if pending else None,
                    "analysis_before_runtime": analysis_before,
                    "receipt_before_runtime": receipt_before,
                    "timing": {
                        "clock": "time.monotonic_ns",
                        "analysis_flushed_monotonic_ns": pending["analysis_flushed_monotonic_ns"]
                        if pending
                        else None,
                        "receipt_flushed_monotonic_ns": pending["receipt_flushed_monotonic_ns"]
                        if pending
                        else None,
                        "receipt_lead_ns": runtime_clock - pending["receipt_flushed_monotonic_ns"]
                        if pending
                        else None,
                        "boundary": "recorded_top_level_runtime_entry; not_internal_tool_steps",
                    },
                }
                saved = self._append(row)
                row["record_sequence"] = saved["record_sequence"]
                row["flushed_monotonic_ns"] = saved["flushed_monotonic_ns"]
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
                return copy.deepcopy(row)
            except Exception as error:
                self._errors.append({"stage": self._stage, "error_type": type(error).__name__})
                if self._stage in {"serialize", "write", "flush"}:
                    self._disabled = True
                return {
                    "status": "unknown",
                    "reason": "online_causal_runtime_timing_failed",
                    "error_type": type(error).__name__,
                }

    def _graph(self, graph: dict) -> dict:
        return {
            "schema_version": 1,
            "protocol": GRAPH_PROTOCOL,
            "scope": SCOPE,
            "original_graph": copy.deepcopy(graph),
            "added_nodes": copy.deepcopy(list(self._added_nodes.values())),
            "added_edges": copy.deepcopy(list(self._added_edges.values())),
            "proposal_decisions": copy.deepcopy(list(self._decisions.values())),
            "interpretation": {
                "original_graph": "Recorded structural lineage; retained unchanged.",
                "source_set_membership": "Structural membership in the jointly intervened source set.",
                "predicted_control": "Isolated judge prediction; not observed counterfactual behavior.",
            },
        }

    def status(self) -> dict:
        with self._lock:
            return copy.deepcopy(
                {
                    "enabled": not self._disabled and not self._closed,
                    "active": not self._disabled and not self._closed,
                    "disabled": self._disabled,
                    "closed": self._closed,
                    "complete": not self._errors and self._proposal_attempt_count == self._proposal_count,
                    "completeness_scope": "proposal processing and persistence; independent of whether causal predictions resolved",
                    "causal_resolution_complete": (
                        self._planned_probe_count > 0
                        and self._unknown_judgment_count == 0
                        and self._valid_judgment_count == self._planned_probe_count
                    ),
                    "errors": self._errors,
                    "protocol": PROTOCOL,
                    "scope": SCOPE,
                    "availability": AVAILABILITY,
                    "proposal_attempt_count": self._proposal_attempt_count,
                    "proposal_count": self._proposal_count,
                    "plan_status_counts": dict(self._plan_status_counts),
                    "planned_probe_count": self._planned_probe_count,
                    "request_budget": self._max_requests,
                    "request_count": self._request_count,
                    "request_remaining": self._max_requests - self._request_count,
                    "request_count_scope": "SDK invocation attempts; one attempt per slot; no retries or replacement",
                    "valid_judgment_count": self._valid_judgment_count,
                    "unknown_judgment_count": self._unknown_judgment_count,
                    "judgment_status_counts": dict(self._status_counts),
                    "reported_usage": transport._usage(self._attempted_usage),
                    "usage_scope": "Returned API token fields only; missing usage and provider billing are not estimated",
                    "runtime_timing_count": self._runtime_count,
                    "unmatched_runtime_count": self._unmatched_runtime_count,
                    "before_runtime_verified_count": self._before_runtime_count,
                    "runtime_timing_failure_count": self._runtime_timing_failure_count,
                    "pending_runtime_count": len(self._pending),
                    "record_attempt_count": self._record_attempt_count,
                    "record_count": self._record_count,
                    "graph_path": str(self._graph_path),
                    "graph_saved": self._graph_saved,
                    "graph_sha256": self._graph_sha256,
                    "model": self._model,
                    "judgment_format": self._judgment_format,
                    "request_timeout_seconds": self._request_timeout_seconds,
                    "sdk_max_retries": 0,
                    "client_mode": "injected_isolated_client" if self._client is not None else "plan_only",
                    "native_tool_calls": 0,
                    "primary_agent_model_calls": 0,
                    "action_enforcement": "none",
                    "model_weight_updates": "none",
                    "flush_semantics": "Python_file_flush; not_fsync_or_power_loss_durability",
                    "timing": {"clock": "time.monotonic_ns", **self._timing},
                }
            )

    def close(self, final_graph: dict | None = None) -> dict:
        """Persist a derived graph beside the JSONL and close without raising."""
        with self._lock:
            if self._closed:
                return self.status()
            graph = copy.deepcopy(final_graph) if final_graph is not None else self._latest_graph
            try:
                if graph is not None:
                    self._stage = "close.graph"
                    payload = self._graph(graph)
                    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n"
                    with self._graph_path.open("x", encoding="utf-8", newline="\n") as stream:
                        if stream.write(raw) != len(raw):
                            raise OSError("Incomplete online causal graph write")
                        stream.flush()
                    self._graph_saved = True
                    self._graph_sha256 = hashlib.sha256(raw.encode()).hexdigest()
                self._stage = "close.summary"
                self._append(
                    {
                        "record_type": "causal_close_summary",
                        "proposal_count": self._proposal_count,
                        "planned_probe_count": self._planned_probe_count,
                        "request_count": self._request_count,
                        "valid_judgment_count": self._valid_judgment_count,
                        "unknown_judgment_count": self._unknown_judgment_count,
                        "reported_usage": transport._usage(self._attempted_usage),
                        "graph_saved": self._graph_saved,
                        "graph_sha256": self._graph_sha256,
                        "action_enforcement": "none",
                        "model_weight_updates": "none",
                    }
                )
            except Exception as error:
                self._disable(self._stage, error)
            finally:
                self._closed = True
                if self._file is not None:
                    try:
                        self._file.close()
                    except Exception as error:
                        self._disable("close.file", error)
            return self.status()

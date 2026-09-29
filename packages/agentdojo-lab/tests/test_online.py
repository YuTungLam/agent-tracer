"""Failure isolation and persistence timing with benign, deterministic events."""

import copy
import hashlib
import json
import time

import pytest
from test_provenance import Tape, prepared, wire_tool

from agentdojo_lab.online import AVAILABILITY, OnlineProvenance
from agentdojo_lab.provenance import ProvenanceTracker


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def feed(consumer, events, tracker=None):
    analyses = []
    for original in events:
        event = copy.deepcopy(original)
        event["monotonic_ns"] = time.monotonic_ns()
        consumer.consume(event)
        if tracker is not None and (call := tracker.consume(event)) is not None:
            analyses.append(call)
    return analyses


def proposal_tape(arguments=None):
    tape = Tape()
    request = tape.request([{"role": "user", "content": "Read record-17 with [REDACTED]."}])
    tape.response(request)
    proposal = tape.propose(request, {"id": "record-17"} if arguments is None else arguments)
    return tape, request, proposal


def test_proposal_is_detached_and_receipt_proves_successful_analysis_flush(tmp_path):
    path = tmp_path / "provenance.jsonl"
    sidecar = OnlineProvenance(path)
    tape, _, proposal = proposal_tape()
    original = copy.deepcopy(tape.events)
    tracker = ProvenanceTracker()
    (expected,) = feed(sidecar, tape.events, tracker)
    analysis, receipt = rows(path)
    assert tape.events == original
    assert analysis["record_type"] == "call_analysis"
    assert receipt["record_type"] == "analysis_flush"
    assert analysis["call_ref"] == receipt["call_ref"] == proposal["call_ref"]
    assert receipt["analysis_record_sequence"] == analysis["record_sequence"] == 1
    assert receipt["record_sequence"] == 2
    assert (
        receipt["analysis_line_sha256"] == hashlib.sha256(path.read_bytes().splitlines(True)[0]).hexdigest()
    )
    assert analysis["call"].pop("availability") == AVAILABILITY
    assert expected.pop("availability").startswith("offline_prefix_replay")
    assert analysis["call"] == expected
    assert tracker.calls[0]["availability"].startswith("offline_prefix_replay")
    assert sidecar._tracker.calls[0]["availability"].startswith("offline_prefix_replay")
    assert (
        receipt["timing"]["analysis_flushed_monotonic_ns"]
        >= analysis["timing"]["compute_completed_monotonic_ns"]
    )
    assert sidecar.status()["complete"] is True
    assert sidecar.status()["pending_runtime_count"] == 1
    sidecar.close()


def test_runtime_uses_prior_flush_clocks_and_exact_call_reference(tmp_path):
    path = tmp_path / "provenance.jsonl"
    sidecar = OnlineProvenance(path)
    tape, request, proposal = proposal_tape()
    feed(sidecar, tape.events)
    entry = tape.emit("TOOL_RUNTIME_STARTED", request=request["model_request_id"], call=proposal["call_ref"])
    entry["monotonic_ns"] = time.monotonic_ns()
    sidecar.consume(entry)
    analysis, receipt, runtime = rows(path)
    assert runtime["record_type"] == "runtime_timing"
    assert runtime["correlation"] == "matched_proposal"
    assert runtime["analysis_before_runtime"] is runtime["receipt_before_runtime"] is True
    assert runtime["runtime_event_id"] == entry["event_id"]
    assert runtime["analysis_record_sequence"] == analysis["record_sequence"]
    assert runtime["receipt_record_sequence"] == receipt["record_sequence"]
    timing = runtime["timing"]
    assert (
        timing["analysis_flushed_monotonic_ns"]
        <= timing["receipt_flushed_monotonic_ns"]
        <= entry["monotonic_ns"]
    )
    assert timing["analysis_lead_ns"] == entry["monotonic_ns"] - timing["analysis_flushed_monotonic_ns"]
    assert sidecar.status()["before_runtime_verified_count"] == 1
    assert sidecar.status()["pending_runtime_count"] == 0
    sidecar.close()


def test_past_runtime_timestamp_does_not_become_a_false_before_runtime_claim(tmp_path):
    path = tmp_path / "provenance.jsonl"
    sidecar = OnlineProvenance(path)
    tape, request, proposal = proposal_tape()
    feed(sidecar, tape.events)
    entry = tape.emit("TOOL_RUNTIME_STARTED", request=request["model_request_id"], call=proposal["call_ref"])
    entry["monotonic_ns"] = 0
    sidecar.consume(entry)
    runtime = rows(path)[-1]
    assert runtime["analysis_before_runtime"] is runtime["receipt_before_runtime"] is False
    assert runtime["timing"]["analysis_lead_ns"] < 0
    assert sidecar.status()["runtime_timing_failure_count"] == 1
    assert sidecar.status()["before_runtime_verified_count"] == 0
    sidecar.close()


def test_unmatched_runtime_has_no_fabricated_proposal_or_success_claim(tmp_path):
    path = tmp_path / "provenance.jsonl"
    sidecar = OnlineProvenance(path)
    tape = Tape()
    tape.emit("TOOL_RUNTIME_STARTED", call="unobserved-call")
    feed(sidecar, tape.events)
    (runtime,) = rows(path)
    assert runtime["correlation"] == "no_prior_analysis"
    assert runtime["proposal_event_id"] is None
    assert runtime["analysis_before_runtime"] is runtime["receipt_before_runtime"] is None
    assert runtime["timing"]["analysis_flushed_monotonic_ns"] is None
    assert sidecar.status()["unmatched_runtime_count"] == 1
    assert sidecar.status()["complete"] is True
    sidecar.close()


def test_future_tool_result_cannot_modify_saved_request_prefix(tmp_path):
    path = tmp_path / "provenance.jsonl"
    sidecar = OnlineProvenance(path)
    tape, request, _ = prepared(["id: record-17"])
    first = tape.propose(request, {"id": "record-17"})
    feed(sidecar, tape.events)
    prefix = path.read_bytes()
    cutoff = len(tape.events)
    result = tape.tool_result(first, "id: record-88")
    tape.propose(request, {"id": "record-88"})
    next_request = tape.request([wire_tool(result, "id: record-88")])
    tape.expose(next_request, result, 0)
    tape.response(next_request)
    tape.propose(next_request, {"id": "record-88"})
    feed(sidecar, tape.events[cutoff:])
    assert path.read_bytes().startswith(prefix)
    calls = [row["call"] for row in rows(path) if row["record_type"] == "call_analysis"]
    assert calls[-2]["fields"][0]["exact_candidates"] == []
    assert all("record-88" not in source["text"] for source in calls[-2]["visible_sources"])
    assert calls[-1]["fields"][0]["exact_candidates"]
    assert sidecar.status()["complete"] is True
    sidecar.close()


def test_pending_proposal_is_complete_without_claiming_runtime_execution(tmp_path):
    path = tmp_path / "provenance.jsonl"
    sidecar = OnlineProvenance(path)
    tape, _, _ = proposal_tape()
    tape.emit("RUN_END", episode_id=None)
    feed(sidecar, tape.events)
    sidecar.close()
    sidecar.close()
    status = sidecar.status()
    assert status["complete"] is True and status["closed"] is True
    assert status["active"] is False
    assert status["run_end_seen"] is True and status["pending_runtime_count"] == 1
    assert status["runtime_timing_count"] == status["before_runtime_verified_count"] == 0
    assert len(rows(path)) == 2


def test_sequence_failure_permanently_disables_with_type_only_diagnostic(tmp_path):
    path = tmp_path / "provenance.jsonl"
    sidecar = OnlineProvenance(path)
    tape, _, _ = proposal_tape()
    sidecar.consume(tape.events[1])
    feed(sidecar, tape.events)
    status = sidecar.status()
    assert status["complete"] is False and status["disabled"] is True
    assert status["errors"] == [{"stage": "consume.compute", "error_type": "ValueError", "event_sequence": 2}]
    assert status["event_consumed_count"] == status["retry_count"] == 0
    assert status["ignored_event_count"] == len(tape.events)
    assert path.read_bytes() == b""
    status["errors"][0]["error_type"] = "tampered"
    assert sidecar.status()["errors"][0]["error_type"] == "ValueError"
    sidecar.close()


class Matcher:
    def __init__(self, status="scored", *, fail=False, truncated=False):
        self.status, self.fail, self.truncated = status, fail, truncated

    def compare(self, source, target):
        if self.fail:
            raise RuntimeError("Private source text must not appear in diagnostics")
        return {
            "status": self.status,
            "truncated": self.truncated,
            "tier3": {"truncated": self.truncated},
            "tier4": {"truncated": self.truncated},
        }


@pytest.mark.parametrize("reported", [False, True])
def test_semantic_exception_or_reported_encoder_failure_disables_attribution(tmp_path, reported):
    path = tmp_path / "provenance.jsonl"
    sidecar = OnlineProvenance(path, Matcher("encoder_error", fail=not reported))
    tape, _, _ = proposal_tape()
    feed(sidecar, tape.events)
    status = sidecar.status()
    assert status["disabled"] is True and status["complete"] is False
    assert status["scoring_complete"] is False
    assert status["errors"][0]["error_type"] == ("AttributionComputeError" if reported else "RuntimeError")
    assert "Private source" not in json.dumps(status)
    assert path.read_bytes() == b""
    if reported:
        assert status["semantic_status_counts"] == {"encoder_error": 1}
    sidecar.close()


@pytest.mark.parametrize(
    ("score_status", "truncated", "complete"),
    [
        ("scored", False, True),
        ("scored", True, False),
        ("budget_exceeded", False, False),
        ("not_applicable", False, True),
    ],
)
def test_unscored_or_truncated_comparisons_remain_explicit_and_nonfatal(
    tmp_path, score_status, truncated, complete
):
    path = tmp_path / "provenance.jsonl"
    sidecar = OnlineProvenance(path, Matcher(score_status, truncated=truncated))
    tape, _, _ = proposal_tape()
    feed(sidecar, tape.events)
    status = sidecar.status()
    assert status["complete"] is True and status["scoring_complete"] is complete
    assert status["semantic_status_counts"] == {score_status: 1}
    assert status["semantic_truncated_comparison_count"] == int(truncated)
    assert status["semantic_tier_truncated_counts"] == {"tier3": int(truncated), "tier4": int(truncated)}
    assert rows(path)[0]["call"]["fields"][0]["nt_style_semantic"][0]["status"] == score_status
    sidecar.close()


class BrokenFile:
    def __init__(self, wrapped, operation, attempt=1):
        self.wrapped, self.operation, self.attempt = wrapped, operation, attempt
        self.writes = self.flushes = self.closes = 0

    def write(self, value):
        self.writes += 1
        if self.operation == "write" and self.writes == self.attempt:
            raise OSError("Private write detail")
        if self.operation == "short_write" and self.writes == self.attempt:
            return self.wrapped.write(value[:5])
        return self.wrapped.write(value)

    def flush(self):
        self.flushes += 1
        if self.operation == "flush" and self.flushes == self.attempt:
            raise OSError("Private flush detail")
        self.wrapped.flush()

    def close(self):
        self.closes += 1
        self.wrapped.close()
        if self.operation == "close":
            raise OSError("Private close detail")


@pytest.mark.parametrize("operation", ["write", "short_write", "flush"])
@pytest.mark.parametrize("attempt", [1, 2])
def test_write_and_flush_failure_never_claim_success_or_retry(tmp_path, operation, attempt):
    path = tmp_path / "provenance.jsonl"
    sidecar = OnlineProvenance(path)
    wrapped = BrokenFile(sidecar._file, operation, attempt)
    sidecar._file = wrapped
    tape, _, _ = proposal_tape()
    original = copy.deepcopy(tape.events)
    feed(sidecar, tape.events)
    status = sidecar.status()
    assert status["complete"] is False and status["disabled"] is True
    assert status["analysis_count"] == attempt - 1
    assert status["analysis_flush_count"] == status["pending_runtime_count"] == 0
    assert status["record_count"] == attempt - 1
    assert status["errors"][0]["error_type"] == "OSError"
    assert "Private" not in json.dumps(status)
    counts = wrapped.writes, wrapped.flushes
    feed(sidecar, tape.events)
    assert (wrapped.writes, wrapped.flushes) == counts
    assert sidecar.status()["retry_count"] == 0
    assert tape.events == original
    sidecar.close()


def test_existing_sidecar_is_preserved_and_open_failure_does_not_escape(tmp_path):
    path = tmp_path / "provenance.jsonl"
    path.write_text("Keep the existing experiment.\n")
    original = path.read_bytes()
    sidecar = OnlineProvenance(path)
    tape, _, _ = proposal_tape()
    feed(sidecar, tape.events)
    sidecar.close()
    assert path.read_bytes() == original
    assert sidecar.status()["errors"] == [
        {"stage": "open", "error_type": "FileExistsError", "event_sequence": None}
    ]


def test_close_failure_and_later_consumption_are_isolated_and_not_retried(tmp_path):
    sidecar = OnlineProvenance(tmp_path / "provenance.jsonl")
    wrapped = BrokenFile(sidecar._file, "close")
    sidecar._file = wrapped
    sidecar.close()
    sidecar.close()
    sidecar.consume(Tape().events[0])
    assert wrapped.closes == 1
    assert sidecar.status()["errors"] == [{"stage": "close", "error_type": "OSError", "event_sequence": None}]
    assert sidecar.status()["ignored_event_count"] == 1


@pytest.mark.parametrize("field", ["episode_id", "model_request_id"])
def test_runtime_identity_mismatch_disables_without_false_correlation(tmp_path, field):
    path = tmp_path / "provenance.jsonl"
    sidecar = OnlineProvenance(path)
    tape, request, proposal = proposal_tape()
    feed(sidecar, tape.events)
    entry = tape.emit("TOOL_RUNTIME_STARTED", request=request["model_request_id"], call=proposal["call_ref"])
    entry[field] = "different-identity"
    feed(sidecar, [entry])
    assert sidecar.status()["errors"][0]["stage"] == "runtime.validate"
    assert sidecar.status()["disabled"] is True
    assert len(rows(path)) == 2
    sidecar.close()


def test_consume_after_normal_close_is_nonthrowing_but_incomplete(tmp_path):
    sidecar = OnlineProvenance(tmp_path / "provenance.jsonl")
    sidecar.close()
    sidecar.consume(Tape().events[0])
    assert sidecar.status()["errors"][0]["stage"] == "consume.closed"
    assert sidecar.status()["complete"] is False

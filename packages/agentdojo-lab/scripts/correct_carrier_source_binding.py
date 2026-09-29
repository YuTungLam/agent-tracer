"""Derive a request-free Slack URL source-binding correction from frozen events.

Only the DeepSeek carrier main-v2 batch is eligible. The command copies its
plan and every evidence file into a new report directory, changes only the
missed Slack webpage source bindings in those copies, then runs the unchanged
offline Tier 3/4 scorer with the pinned local MiniLM. It never calls an API or
modifies a primary run or an earlier report.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from agentdojo.default_suites.v1.tools.web import standardize_url

from agentdojo_lab.carrier_scale_tiers import (
    ROOT,
    SEMANTIC_MODEL,
    SEMANTIC_REVISION,
    analyze,
    render_html,
)
from agentdojo_lab.semantic import LocalMiniLMEncoder, SemanticMatcher

PROTOCOL = "deepseek-carrier-main-v2"
SOURCE_ID = "slack:dora-webpage"
SOURCE_FUNCTION = "get_webpage"
CORRECTION_NAME = "slack-url-source-binding-correction-v1"
EXPECTED_SLOTS = 72
EXPECTED_REBINDINGS = 18


class SourceBindingError(ValueError):
    """Frozen event evidence does not justify the proposed correction."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def _events(path: Path) -> tuple[list[dict], str]:
    raw = path.read_bytes()
    events = [json.loads(line) for line in raw.splitlines() if line]
    sequences = [event.get("event_sequence") for event in events]
    ids = [event.get("event_id") for event in events]
    if (
        not events
        or any(type(number) is not int for number in sequences)
        or sequences != sorted(set(sequences))
        or any(not isinstance(event_id, str) or not event_id for event_id in ids)
        or len(ids) != len(set(ids))
    ):
        raise SourceBindingError(f"Invalid event order or identity: {path}")
    return events, sha256(raw)


def _one(items: list[dict], label: str) -> dict:
    if len(items) != 1:
        raise SourceBindingError(f"Expected one {label}; found {len(items)}")
    return items[0]


def _canonical_url(arguments: object) -> str | None:
    if not isinstance(arguments, dict) or set(arguments) != {"url"}:
        return None
    url = arguments["url"]
    return standardize_url(url) if isinstance(url, str) and url else None


def correct_slack_evidence(slot: dict, evidence: dict, events: list[dict]) -> tuple[dict, dict]:
    """Rebind exactly one URL-normalized source to its pre-sink exposure."""
    if slot.get("suite") != "slack" or evidence.get("slot", {}).get("suite") != "slack":
        raise SourceBindingError("Correction applies only to Slack evidence")
    if evidence.get("slot") != slot:
        raise SourceBindingError("Evidence slot does not match the frozen plan")
    source = _one(
        [item for item in slot.get("source_calls", []) if item.get("source_id") == SOURCE_ID],
        "frozen Slack webpage source",
    )
    if source.get("function") != SOURCE_FUNCTION:
        raise SourceBindingError("Frozen webpage source function changed")
    expected_url = source.get("arguments", {}).get("url")
    if not isinstance(expected_url, str) or not expected_url:
        raise SourceBindingError("Frozen webpage URL is invalid")
    original_read = _one(
        [item for item in evidence.get("source_reads", []) if item.get("source_id") == SOURCE_ID],
        "webpage source read",
    )
    if (
        original_read.get("exposure_verified") is not False
        or original_read.get("proposal_event_id") is not None
        or original_read.get("exposure_event_id") is not None
    ):
        raise SourceBindingError("Webpage source is not the specified missed binding")

    sink_spec = slot.get("sink_call", {})
    sink = evidence.get("sink", {})
    sink_proposal = _one(
        [
            event
            for event in events
            if event.get("event_type") == "TOOL_CALL_PROPOSED"
            and event.get("data", {}).get("function") == sink_spec.get("function")
        ],
        "sink proposal",
    )
    if sink.get("proposal_event_id") != sink_proposal["event_id"] or sink.get("proposed_sink_count") != 1:
        raise SourceBindingError("Sink proposal does not match recorded evidence")

    candidates = [
        event
        for event in events
        if event.get("event_type") == "TOOL_CALL_PROPOSED"
        and event.get("data", {}).get("function") == SOURCE_FUNCTION
        and _canonical_url(event.get("data", {}).get("arguments")) == standardize_url(expected_url)
    ]
    proposal = _one(candidates, "canonically matching webpage proposal")
    actual_url = proposal["data"]["arguments"]["url"]
    if actual_url == expected_url or not actual_url.startswith(("http://", "https://")):
        raise SourceBindingError("Mismatch is not the documented URL scheme normalization")
    call_id = proposal.get("tool_call_id")
    if not isinstance(call_id, str) or not call_id:
        raise SourceBindingError("Webpage proposal has no tool call ID")
    runtime_return = _one(
        [
            event
            for event in events
            if event.get("event_type") == "TOOL_RUNTIME_RETURNED" and event.get("tool_call_id") == call_id
        ],
        "webpage runtime return",
    )
    if (
        runtime_return.get("data", {}).get("error") is not None
        or runtime_return.get("data", {}).get("raised_exception_type") is not None
        or not proposal["event_sequence"] < runtime_return["event_sequence"]
    ):
        raise SourceBindingError("Webpage runtime return is failed or out of order")

    exposures = [
        event
        for event in events
        if event.get("event_type") == "TOOL_OUTPUT_EXPOSED"
        and event.get("tool_call_id") == call_id
        and event.get("data", {}).get("message", {}).get("tool_call_id") == call_id
    ]
    before_sink = sorted(
        (
            event
            for event in exposures
            if runtime_return["event_sequence"] < event["event_sequence"] < sink_proposal["event_sequence"]
        ),
        key=lambda event: event["event_sequence"],
    )
    if not before_sink:
        raise SourceBindingError(
            "Webpage output was not exposed after its return and before the sink proposal"
        )
    exposure = before_sink[0]
    text = exposure["data"]["message"].get("content")
    if not isinstance(text, str):
        raise SourceBindingError("Webpage exposure has no text content")

    derived = copy.deepcopy(evidence)
    for item in derived["source_reads"]:
        if item.get("source_id") == SOURCE_ID:
            item.update(
                {
                    "text": text,
                    "exposure_verified": True,
                    "proposal_event_id": proposal["event_id"],
                    "exposure_event_id": exposure["event_id"],
                    "exposure_event_sequence": exposure["event_sequence"],
                }
            )
            break
    binding = {
        "slot_id": slot["slot_id"],
        "source_id": SOURCE_ID,
        "planned_arguments": source["arguments"],
        "proposed_arguments": proposal["data"]["arguments"],
        "canonical_url": standardize_url(expected_url),
        "tool_call_id": call_id,
        "proposal_event_id": proposal["event_id"],
        "proposal_event_sequence": proposal["event_sequence"],
        "runtime_event_id": runtime_return["event_id"],
        "runtime_event_sequence": runtime_return["event_sequence"],
        "exposure_event_id": exposure["event_id"],
        "exposure_event_sequence": exposure["event_sequence"],
        "sink_proposal_event_id": sink_proposal["event_id"],
        "sink_proposal_event_sequence": sink_proposal["event_sequence"],
        "later_exposure_event_ids": [
            event["event_id"]
            for event in exposures
            if event["event_sequence"] >= sink_proposal["event_sequence"]
        ],
    }
    return derived, binding


def prepare(batch: Path) -> tuple[bytes, list[tuple[str, bytes, bytes]], dict]:
    """Audit the entire original batch in memory before creating any output."""
    batch = batch.resolve()
    plan_bytes = (batch / "plan.json").read_bytes()
    plan = json.loads(plan_bytes)
    slots = plan.get("slots")
    if (
        plan.get("protocol") != PROTOCOL
        or plan.get("model") != "deepseek-flash"
        or plan.get("semantic_model") != SEMANTIC_MODEL
        or plan.get("semantic_revision") != SEMANTIC_REVISION
        or not isinstance(slots, list)
        or len(slots) != EXPECTED_SLOTS
    ):
        raise SourceBindingError("Input is not the frozen 72-slot DeepSeek main-v2 batch")
    ids = [slot.get("slot_id") for slot in slots if isinstance(slot, dict)]
    if (
        len(ids) != len(slots)
        or len(ids) != len(set(ids))
        or any(
            not isinstance(slot_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", slot_id) for slot_id in ids
        )
    ):
        raise SourceBindingError("Plan slot IDs are invalid or duplicated")
    prepared = []
    bindings = []
    original_hashes = {}
    derived_hashes = {}
    for slot in slots:
        slot_id = slot["slot_id"]
        relative = f"runs/{slot_id}/evidence.json"
        evidence_bytes = (batch / relative).read_bytes()
        evidence = json.loads(evidence_bytes)
        if evidence.get("slot") != slot or evidence.get("plan_sha256") != sha256(plan_bytes):
            raise SourceBindingError(f"Evidence is not bound to the frozen plan: {slot_id}")
        derived_bytes = evidence_bytes
        if slot.get("suite") == "slack":
            event_path = batch / "runs" / slot_id / "events.jsonl"
            events, event_hash = _events(event_path)
            derived, binding = correct_slack_evidence(slot, evidence, events)
            derived_bytes = json_bytes(derived)
            binding.update(
                {
                    "original_events_sha256": event_hash,
                    "original_evidence_sha256": sha256(evidence_bytes),
                    "derived_evidence_sha256": sha256(derived_bytes),
                }
            )
            bindings.append(binding)
        original_hashes[relative] = sha256(evidence_bytes)
        derived_hashes[relative] = sha256(derived_bytes)
        prepared.append((relative, evidence_bytes, derived_bytes))
    if len(bindings) != EXPECTED_REBINDINGS:
        raise SourceBindingError(
            f"Expected {EXPECTED_REBINDINGS} Slack rebinding slots; found {len(bindings)}"
        )
    receipt = {
        "schema_version": 1,
        "correction": CORRECTION_NAME,
        "request_count": 0,
        "source_batch": str(batch),
        "original_plan_sha256": sha256(plan_bytes),
        "derived_plan_sha256": sha256(plan_bytes),
        "slot_count": len(slots),
        "rebound_slack_sources": len(bindings),
        "other_suite_evidence_byte_identical": all(
            old == new for relative, old, new in prepared if not relative.startswith("runs/slack-")
        ),
        "original_evidence_hashes": original_hashes,
        "derived_evidence_hashes": derived_hashes,
        "bindings": bindings,
        "scope": "Only copied Slack webpage source_reads; primary runs and prior reports are unchanged.",
    }
    return plan_bytes, prepared, receipt


def derive(batch: Path, output: Path, matcher) -> dict:
    """Write an isolated derived batch and score it with the existing matcher."""
    batch = batch.resolve()
    output = output.resolve()
    if output == batch or batch in output.parents or output in batch.parents:
        raise SourceBindingError("Output must be separate from the original batch")
    plan_bytes, prepared, receipt = prepare(batch)
    # Detect source edits between the complete preflight and the copy phase.
    if (batch / "plan.json").read_bytes() != plan_bytes or any(
        sha256((batch / relative).read_bytes()) != sha256(original) for relative, original, _ in prepared
    ):
        raise SourceBindingError("Original plan or evidence changed during audit")
    output.mkdir(parents=True, exist_ok=False)
    derived_batch = output / "derived-batch"
    derived_batch.mkdir()
    (derived_batch / "plan.json").write_bytes(plan_bytes)
    for relative, _, derived in prepared:
        path = derived_batch / relative
        path.parent.mkdir(parents=True, exist_ok=False)
        path.write_bytes(derived)
    if (derived_batch / "plan.json").read_bytes() != plan_bytes or any(
        sha256((derived_batch / relative).read_bytes()) != receipt["derived_evidence_hashes"][relative]
        for relative, _, _ in prepared
    ):
        raise SourceBindingError("Derived copy failed byte verification")
    packet = analyze(derived_batch, matcher)
    population = packet["population"]
    if (
        population["planned_slots"] != EXPECTED_SLOTS
        or population["carrier_pairs"] != EXPECTED_SLOTS
        or population["noncarrier_pairs"] != EXPECTED_SLOTS
        or population["unexposed_sources"] != 0
        or population["unknown_sources"] != 0
    ):
        raise SourceBindingError("Derived packet failed the frozen 72/72, zero-unknown acceptance gate")
    packet["correction"] = {
        "name": CORRECTION_NAME,
        "receipt": "correction.json",
        "rebound_slack_sources": len(receipt["bindings"]),
        "request_count": 0,
    }
    packet["limitations"].append(
        "This is an independent, request-free source-binding diagnostic over copied evidence. "
        "No model execution, primary run, or earlier report was changed."
    )
    (output / "packet.json").write_bytes(json_bytes(packet))
    banner = (
        "<section style='border:2px solid #304c80;padding:.8rem 1rem;background:#eef3fb'>"
        "<strong>Independent request-free evidence-binding diagnostic.</strong> "
        "Only copied Slack webpage source bindings were corrected from recorded events. "
        "Model runs and the original report remain unchanged. "
        "<a href='correction.json'>Correction receipt</a>.</section>"
    )
    page = render_html(packet)
    heading = "<h1>Carrier-scale Tier 3/4 detection</h1>"
    if page.count(heading) != 1:
        raise SourceBindingError("Tier report heading changed; cannot annotate correction")
    (output / "index.html").write_text(page.replace(heading, heading + banner, 1), encoding="utf-8")
    receipt["derived_batch"] = str(derived_batch)
    receipt["packet_sha256"] = sha256((output / "packet.json").read_bytes())
    receipt["created_utc"] = datetime.now(timezone.utc).isoformat()
    (output / "correction.json").write_bytes(json_bytes(receipt))
    # The original 72 evidence files must still match their preflight hashes.
    if (batch / "plan.json").read_bytes() != plan_bytes or any(
        sha256((batch / relative).read_bytes()) != receipt["original_evidence_hashes"][relative]
        for relative, _, _ in prepared
    ):
        raise SourceBindingError("Original plan or evidence changed during report generation")
    return {"receipt": receipt, "packet": packet}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    model_path = ROOT / SEMANTIC_MODEL
    if not model_path.is_dir():
        parser.error(f"Pinned MiniLM snapshot missing: {model_path}")
    matcher = SemanticMatcher(LocalMiniLMEncoder(model_path, revision=SEMANTIC_REVISION))
    result = derive(args.batch, args.output, matcher)
    population = result["packet"]["population"]
    print(
        json.dumps(
            {
                "output": str(args.output.resolve()),
                "rebound_slack_sources": result["receipt"]["rebound_slack_sources"],
                "carrier_pairs": population["carrier_pairs"],
                "noncarrier_pairs": population["noncarrier_pairs"],
                "unexposed_sources": population["unexposed_sources"],
                "unknown_sources": population["unknown_sources"],
                "primary_model_requests": 0,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()

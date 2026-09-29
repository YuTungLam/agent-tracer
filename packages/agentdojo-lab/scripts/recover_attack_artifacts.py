"""Recover receipt-bound Han-free artifacts into a fresh mirror; never rerun models.

Original failure reports remain intact. Analytical completeness is a separately
verified statement about retained native evidence, not a replacement run outcome.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import shutil
from pathlib import Path

from audit_report_language import HAN, strings

from agentdojo_lab.counterfactual_audit import _verified_inputs, canonical
from agentdojo_lab.evaluation_review import _strict
from agentdojo_lab.evaluation_runner import has_final_text
from agentdojo_lab.html_report import export_run_html
from agentdojo_lab.inspection import inspect_events

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = "exact-quarantine-byte-recovery-v1"
RESTORABLE = {
    "manifest.json",
    "provenance.jsonl",
    "graph.json",
    "lineage-state.json",
    "events.jsonl",
    "events.audit.json",
    "requests.json",
    "requests.jsonl",
    "actions.json",
    "initial-environment.json",
    "final-environment.json",
    "native/fixture.json",
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return _strict(Path(path).read_bytes())


def write(path, value):
    Path(path).write_text(
        json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )


class RecoveryError(ValueError):
    """A fixed diagnostic label, never an external exception message."""

    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def require(value, reason):
    if not value:
        raise RecoveryError(reason)


def relative(value):
    path = Path(value)
    require(
        isinstance(value, str)
        and not path.is_absolute()
        and ".." not in path.parts
        and all(not part.startswith(".env") for part in path.parts),
        "unsafe_artifact_path",
    )
    return path


def inventory(folder):
    hashes = {}
    for path in sorted(Path(folder).rglob("*")):
        require(not path.is_symlink(), "symlink_artifact")
        if path.is_file():
            artifact_path = path.relative_to(folder).as_posix()
            relative(artifact_path)
            hashes[artifact_path] = digest(path)
    return hashes


def values(raw, suffix):
    text = raw.decode("utf-8")
    if suffix == ".jsonl":
        return [_strict(line) for line in raw.splitlines() if line.strip()]
    if suffix == ".json":
        return [_strict(raw)]
    return [text]


def han_free(raw, suffix):
    return all(not HAN.search(text) for value in values(raw, suffix) for text in strings(value))


def text_content(message):
    content = message.get("content")
    if isinstance(content, str):
        return content
    return "".join(
        part.get("content", part.get("text", ""))
        for part in content or []
        if isinstance(part, dict) and part.get("type") == "text"
    )


def validate_retained_run(folder, original):
    """Verify the unaffected recorder and native state before relaxing one flag."""
    audit = inspect_events(folder / "events.jsonl")
    require(audit["valid"] is True and audit == read(folder / "events.audit.json"), "invalid_event_audit")
    events = values((folder / "events.jsonl").read_bytes(), ".jsonl")
    requests = read(folder / "requests.json")
    require(
        requests == values((folder / "requests.jsonl").read_bytes(), ".jsonl"), "request_capture_disagrees"
    )
    request_events = [e for e in events if e["event_type"] == "MODEL_REQUEST"]
    responses = [e for e in events if e["event_type"] == "MODEL_RESPONSE"]
    require(requests == [e["data"]["body"] for e in request_events], "request_event_disagrees")
    stats = original["stats"]
    require(
        len(requests) == len(responses) == stats["request_count"]
        and 1 <= len(requests) <= 4
        and original["usage"] == stats,
        "incomplete_request_response_inventory",
    )
    require(all(e["data"]["status_code"] == 200 for e in responses), "provider_failure")
    require(
        sum(e["data"]["body"]["usage"]["prompt_tokens"] for e in responses) == stats["prompt_tokens"]
        and sum(e["data"]["body"]["usage"]["completion_tokens"] for e in responses)
        == stats["completion_tokens"],
        "usage_response_disagrees",
    )
    ends = [e for e in events if e["event_type"] == "RUN_END"]
    episodes = [e for e in events if e["event_type"] == "EPISODE_ENDED"]
    require(
        len(ends) == len(episodes) == 1
        and ends[0]["data"]["status"] == "completed"
        and episodes[0]["data"] == {"status": "returned", "error_type": None},
        "nonterminal_native_run",
    )
    fixture = read(folder / "native/fixture.json")
    require(
        fixture["error_type"] is None and has_final_text(fixture["messages"]), "missing_native_final_text"
    )
    final = text_content(fixture["messages"][-1])
    response = responses[-1]["data"]["body"]
    require(len(response["choices"]) == 1, "ambiguous_final_response")
    choice = response["choices"][0]
    require(
        choice["finish_reason"] == "stop"
        and choice["message"]["role"] == "assistant"
        and not choice["message"].get("tool_calls")
        and not choice["message"].get("function_call")
        and text_content(choice["message"]) == final
        and bool(final.strip())
        and not HAN.search(final),
        "final_text_not_bound_to_response",
    )
    require(
        [m["role"] for m in requests[0]["messages"]] == ["system", "user"]
        and original["initial_history_empty"] is True,
        "nonempty_initial_history",
    )
    recording = original["recording"]
    require(
        recording["complete"] is True
        and recording["errors"] == recording["failed_event_sequences"] == recording["observer_errors"] == []
        and recording["event_count"] == recording["event_attempt_count"] == len(events)
        and recording["audit"] == audit,
        "recorder_not_complete",
    )
    online = original["online_provenance"]
    require(
        online["disabled"] is False
        and online["closed"] is True
        and online["errors"] == []
        and online["subscriber"] == {"complete": True, "errors": []}
        and online["event_attempt_count"] == online["event_consumed_count"] == len(events)
        and online["last_consumed_sequence"] == events[-1]["event_sequence"]
        and online["run_end_seen"] is True
        and online["runtime_timing_failure_count"]
        == online["unmatched_runtime_count"]
        == online["pending_runtime_count"]
        == 0,
        "sidecar_has_non_language_failure",
    )
    starts = [e for e in events if e["event_type"] == "TOOL_RUNTIME_STARTED"]
    returns = [e for e in events if e["event_type"] == "TOOL_RUNTIME_RETURNED"]
    proposals = [e for e in events if e["event_type"] == "TOOL_CALL_PROPOSED"]
    require(
        read(folder / "actions.json")
        == [
            {"function": e["data"]["function"], "arguments": e["data"]["runtime_input_args"]} for e in starts
        ],
        "native_actions_disagree",
    )
    require(
        len(starts) == len(returns)
        and {e["call_ref"] for e in starts} == {e["call_ref"] for e in returns}
        and online["before_runtime_verified_count"] == online["runtime_timing_count"] == len(starts)
        and online["analysis_count"] == online["analysis_flush_count"] == len(proposals),
        "native_receipt_inventory_incomplete",
    )
    provenance = values((folder / "provenance.jsonl").read_bytes(), ".jsonl")
    require(
        online["record_attempt_count"] == online["record_count"] == len(provenance),
        "sidecar_record_inventory_disagrees",
    )
    envelope = read(folder / "lineage-state.json")
    require(
        original["lineage_state"]["status"] == "saved"
        and original["lineage_state"]["sha256"] == digest(folder / "lineage-state.json")
        and envelope["schema_version"] == 1
        and hashlib.sha256(canonical(envelope["state"])).hexdigest() == envelope["state_sha256"]
        and envelope["state"]["failed"] is False
        and read(folder / "graph.json") == envelope["state"],
        "checkpoint_or_graph_disagrees",
    )
    manifest = read(folder / "manifest.json")
    require(
        manifest["config"]["canary_enabled"] is False
        and manifest["input_condition"] == "passive"
        and manifest["slot"] == original["slot"]
        and manifest["real_llm"] == original["real_llm"],
        "run_manifest_disagrees",
    )
    require(
        all(body["model"] == manifest["config"]["model"] for body in requests)
        and all(e["data"]["body"]["model"] == manifest["config"]["model"] for e in responses),
        "model_identity_disagrees",
    )
    for name in ("initial-environment.json", "final-environment.json"):
        state = read(folder / name)
        require(
            isinstance(state["cloud_drive"]["files"], dict) and isinstance(state["inbox"]["emails"], dict),
            "native_environment_unavailable",
        )
    return {
        "requests": len(requests),
        "prompt_tokens": stats["prompt_tokens"],
        "completion_tokens": stats["completion_tokens"],
        "native_calls": len(starts),
        "proposal_count": len(proposals),
        "analysis_flush_count": len(proposals),
        "final_text": final,
        "checkpoint_state_sha256": envelope["state_sha256"],
    }


def _recover_run(source, output, expected, *, batch_manifest_sha256=None):
    require(inventory(source) == expected, "source_run_inventory_changed")
    original = read(source / "summary.json")
    shutil.copyfile(source / "summary.json", output / "original-reported-summary.json")
    recovered = copy.deepcopy(original)
    receipt = {
        "schema_version": 1,
        "protocol": PROTOCOL,
        "verified": False,
        "source_run": str(source),
        "original_batch_manifest_sha256": batch_manifest_sha256,
        "original_artifact_hashes": expected,
        "original_summary_sha256": digest(source / "summary.json"),
        "restored_bytes": [],
        "validation": None,
        "errors": [],
        "interpretation": "Original reported failure is retained. Analytical completeness requires exact-byte recovery and independent native evidence checks; no model request or replacement run.",
    }
    try:
        require(
            original["status"] == "failed"
            and original["complete"] is False
            and original["error_type"] == "UnsupportedRecordedLanguage"
            and original["language_status"] == "raw_bytes_retained_not_rendered"
            and original["online_provenance"]["complete"] is False,
            "unsupported_original_disposition",
        )
        entries = original["retained_raw_artifacts"]
        require(isinstance(entries, list) and bool(entries), "missing_quarantine_receipts")
        seen, retained = set(), set()
        for entry in entries:
            target_name, raw_name = entry["original_path"], entry["retained_path"]
            require(target_name not in seen and raw_name not in retained, "duplicate_quarantine_receipt")
            seen.add(target_name)
            retained.add(raw_name)
            special = target_name == "summary.json#/final_text"
            require(target_name in RESTORABLE or special, "unsupported_quarantine_target")
            raw_path = relative(raw_name)
            require(
                raw_name in expected and digest(source / raw_path) == entry["sha256"] == expected[raw_name],
                "quarantine_digest_mismatch",
            )
            raw = (source / raw_path).read_bytes()
            require(
                han_free(raw, ".txt" if special else Path(target_name).suffix), "actual_han_in_retained_bytes"
            )
            if not special:
                target = output / relative(target_name)
                require(not target.exists(), "quarantine_target_already_exists")
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as stream:
                    stream.write(raw)
                require(digest(target) == entry["sha256"], "restored_bytes_changed")
            receipt["restored_bytes"].append({**entry, "actual_han_found": False, "byte_identical": True})
        require({p for p in expected if p.endswith(".raw.bin")} == retained, "unaccounted_quarantine_bytes")
        for name in RESTORABLE:
            path = output / name
            if path.is_file():
                require(han_free(path.read_bytes(), path.suffix), "actual_han_in_recovered_evidence")
        validation = validate_retained_run(output, original)
        # This is the only corrected legacy completeness flag. All recorded
        # health checks above precede the full source/receipt verifier below.
        recovered["online_provenance"]["complete"] = True
        write(output / "summary.json", recovered)
        calls, graph = _verified_inputs(output)
        require(
            len(calls) == validation["proposal_count"] and graph["failed"] is False,
            "full_prefix_verification_failed",
        )
        preserved = {
            name: digest(output / name)
            for name in (
                "events.jsonl",
                "requests.json",
                "requests.jsonl",
                "actions.json",
                "native/fixture.json",
                "initial-environment.json",
                "final-environment.json",
            )
        }
        for name, hash_value in preserved.items():
            original_name = (
                name
                if name in expected
                else next(e["retained_path"] for e in entries if e["original_path"] == name)
            )
            require(hash_value == expected[original_name], "model_or_native_bytes_changed")
        recovered.update(
            analytical_status="completed",
            analytical_complete=True,
            analytical_final_text=validation["final_text"],
            recovery_protocol=PROTOCOL,
        )
        receipt.update(
            verified=True,
            validation={**validation, "full_prefix_verified": True, "model_and_native_bytes_unchanged": True},
            preserved_model_native_hashes=preserved,
        )
    except (ValueError, KeyError, TypeError, OSError, UnicodeError, StopIteration) as error:
        recovered = copy.deepcopy(original)
        recovered.update(
            analytical_status="unknown",
            analytical_complete=False,
            analytical_final_text=None,
            recovery_protocol=PROTOCOL,
        )
        receipt["errors"].append(
            {
                "error_type": type(error).__name__,
                "reason": error.reason
                if isinstance(error, RecoveryError)
                else "unavailable_or_inconsistent_artifact",
            }
        )
    write(output / "summary.json", recovered)
    if receipt["verified"]:
        if (output / "report.html").exists():
            shutil.copyfile(output / "report.html", output / "original-reported-report.html")
        export_run_html(output)
    require(inventory(source) == expected, "source_run_changed_during_recovery")
    receipt["source_unchanged"] = True
    receipt["recovered_artifact_hashes"] = inventory(output)
    write(output / "recovery.json", receipt)
    return receipt


def recover_run(source, output, *, expected_hashes=None):
    """Isolated engineering control; production recovery uses the batch manifest."""
    source, output = Path(source).resolve(), Path(output).resolve()
    require(
        not output.exists() and not output.is_relative_to(source) and not source.is_relative_to(output),
        "fresh_separate_output_required",
    )
    expected = inventory(source) if expected_hashes is None else expected_hashes
    require(inventory(source) == expected, "source_run_inventory_changed")
    shutil.copytree(source, output)
    return _recover_run(source, output, expected)


def recover_batch(source, output):
    source, output = Path(source).resolve(), Path(output).resolve()
    require(
        not output.exists() and not output.is_relative_to(source) and not source.is_relative_to(output),
        "fresh_separate_output_required",
    )
    manifest = read(source / "manifest.json")
    before = inventory(source)
    require(
        before == {**manifest, "manifest.json": digest(source / "manifest.json")},
        "final_batch_manifest_mismatch",
    )
    plan = read(source / "plan.json")
    parent = read(source / "summary.json")
    original_slots = values((source / "slots.jsonl").read_bytes(), ".jsonl")
    require(
        parent["slots"] == original_slots
        and len(original_slots) == len(plan["slots"]) == 16
        and parent["plan_sha256"] == digest(source / "plan.json"),
        "batch_inventory_or_plan_mismatch",
    )
    require(
        [{k: slot[k] for k in ("slot_id", "family", "arm", "repetition")} for slot in original_slots]
        == plan["slots"],
        "frozen_schedule_mismatch",
    )
    runtime = {}
    for name, checksum in plan["source_hashes"].items():
        path = ROOT / relative(name)
        require(
            path.is_file() and not path.is_symlink() and digest(path) == checksum,
            "frozen_runtime_unavailable",
        )
        runtime[name] = path.read_bytes()
    shutil.copytree(source, output)
    for name in ("summary.json", "slots.jsonl", "manifest.json"):
        shutil.copyfile(source / name, output / ("original-reported-" + name))
    for name, raw in runtime.items():
        path = output / "frozen-runtime" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(raw)
        require(digest(path) == plan["source_hashes"][name], "runtime_snapshot_changed")
    recovered_slots, receipts = [], []
    for slot in original_slots:
        prefix = "runs/" + slot["slot_id"] + "/"
        expected = {p[len(prefix) :]: h for p, h in before.items() if p.startswith(prefix)}
        source_run, target_run = source / "runs" / slot["slot_id"], output / "runs" / slot["slot_id"]
        require(
            read(source_run / "summary.json") == slot["summary"]
            and slot["summary"]["slot"] == {k: slot[k] for k in ("slot_id", "family", "arm", "repetition")},
            "parent_child_summary_mismatch",
        )
        receipt = _recover_run(
            source_run, target_run, expected, batch_manifest_sha256=before["manifest.json"]
        )
        receipts.append(
            {
                "slot_id": slot["slot_id"],
                "verified": receipt["verified"],
                "path": str(Path(prefix) / "recovery.json"),
                "sha256": digest(target_run / "recovery.json"),
            }
        )
        recovered_slots.append(
            {
                **slot,
                "original_run_path": slot["run_path"],
                "run_path": str(target_run),
                "summary": read(target_run / "summary.json"),
                "analytical_status": "completed" if receipt["verified"] else "unknown",
                "analytical_complete": receipt["verified"],
                "recovery_path": str(target_run / "recovery.json"),
            }
        )
    augmented = {
        **parent,
        "slots": recovered_slots,
        "recovery_protocol": PROTOCOL,
        "original_batch": str(source),
        "analytically_complete_slots": sum(r["verified"] for r in receipts),
    }
    write(output / "summary.json", augmented)
    (output / "slots.jsonl").write_text(
        "".join(json.dumps(s, ensure_ascii=False, allow_nan=False) + "\n" for s in recovered_slots)
    )
    (output / "index.html").write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>Recovered native factorial evidence</title>'
        "<h1>Recovered native factorial evidence</h1><p>Original process failures remain reported. "
        "Exact retained bytes were restored into this separate mirror after independent checks; no model calls were repeated.</p>"
        + "".join(
            f'<p><a href="runs/{s["slot_id"]}/report.html">{s["slot_id"]}</a>: analytical {s["analytical_status"]}; original process {s["process_status"]}</p>'
            for s in recovered_slots
        )
        + '<p><a href="recovery.json">Recovery receipt</a></p>',
        encoding="utf-8",
    )
    require(inventory(source) == before, "original_batch_changed_during_recovery")
    receipt = {
        "schema_version": 1,
        "protocol": PROTOCOL,
        "verified": all(r["verified"] for r in receipts),
        "source_batch": str(source),
        "original_batch_manifest_sha256": before["manifest.json"],
        "original_artifact_hashes": before,
        "source_unchanged": True,
        "original_plan_bytes_preserved": digest(output / "plan.json") == before["plan.json"],
        "frozen_runtime_hashes": plan["source_hashes"],
        "frozen_runtime_directory": "frozen-runtime",
        "runtime_validation": "Archived exact bytes match the original frozen plan; recovery is independent of any later working-code repair.",
        "run_receipts": receipts,
        "model_requests": 0,
        "replacement_runs": 0,
        "analytically_complete_slots": augmented["analytically_complete_slots"],
        "interpretation": "Language false-positive recovery only. Original failure statuses and process codes remain unchanged; analytical completeness is separately derived from retained evidence.",
    }
    # The recovered manifest is a new inventory. The original remains byte-exact
    # as original-reported-manifest.json and is bound by the recovery receipt.
    write(output / "manifest.json", {p: h for p, h in inventory(output).items() if p != "manifest.json"})
    receipt["recovered_artifact_hashes"] = inventory(output)
    write(output / "recovery.json", receipt)
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = recover_batch(args.batch, args.output)
    print(
        json.dumps(
            {
                k: result[k]
                for k in ("verified", "analytically_complete_slots", "model_requests", "source_unchanged")
            }
        )
    )
    raise SystemExit(0 if result["verified"] else 1)

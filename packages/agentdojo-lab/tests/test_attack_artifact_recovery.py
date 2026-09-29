"""Exact-byte recovery controls; no provider calls and no original artifact edits."""

import hashlib
import importlib.util
import json
import re
import shutil
import sys
from pathlib import Path

import pytest
from test_attack_factorial_runner import pilot, read
from test_semantic import FakeEncoder

from agentdojo_lab.cascade import CascadeMatcher
from agentdojo_lab.counterfactual_audit import _verified_inputs
from agentdojo_lab.semantic import SemanticMatcher

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "attack_recovery_fixture", ROOT / "scripts/recover_attack_artifacts.py"
)
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)
sys.path.pop(0)


@pytest.fixture(scope="module")
def broken_batch(tmp_path_factory):
    """Actual native SDK controls with encoder-metadata punctuation, no weights/API."""
    output = tmp_path_factory.mktemp("recovery-source") / "batch"
    plan = pilot.create_plan(output)
    original_online = pilot.OnlineProvenance
    encoder = FakeEncoder()
    encoder.metadata = {
        "model_id": "offline-punctuation-fixture",
        "sentence_boundary_regex": "[.!?\u3002\uff01\uff1f]",
    }
    matcher = SemanticMatcher(encoder)

    def punctuation_sidecar(path, *, semantic_matcher=None, policy, lineage, **kwargs):
        lineage.matcher = CascadeMatcher.for_memory(matcher)
        return original_online(path, semantic_matcher=matcher, policy=policy, lineage=lineage, **kwargs)

    slots = []
    with pytest.MonkeyPatch.context() as patch:
        # Reproduce the frozen historical language gate, even after its repair.
        patch.setattr(
            pilot, "CJK", re.compile("[\u2e80-\u9fff\uac00-\ud7af\uf900-\ufaff\U00020000-\U000323af]")
        )
        patch.setattr(pilot, "OnlineProvenance", punctuation_sidecar)
        for slot in plan["slots"]:
            spec = output / (slot["slot_id"] + "-spec.json")
            pilot.write_json(
                spec,
                {
                    "slot": slot,
                    "plan_path": str(output / "plan.json"),
                    "plan_sha256": pilot.digest(output / "plan.json"),
                    "pacing_state": str(output / "pacing.json"),
                },
            )
            with pytest.raises(ValueError, match="manifest.json"):
                pilot.run_trial(spec)
            folder = output / "runs" / slot["slot_id"]
            summary = read(folder / "summary.json")
            assert summary["error_type"] == "UnsupportedRecordedLanguage"
            slots.append(
                {
                    **slot,
                    "process_status": "failed",
                    "returncode": 1,
                    "run_path": str(folder),
                    "summary": summary,
                }
            )
    pilot.write_json(
        output / "summary.json", {"slots": slots, "plan_sha256": pilot.digest(output / "plan.json")}
    )
    (output / "slots.jsonl").write_text("".join(json.dumps(s) + "\n" for s in slots))
    pilot.write_json(output / "manifest.json", recovery.inventory(output))
    return output


def first_run(batch):
    return batch / "runs" / read(batch / "plan.json")["slots"][0]["slot_id"]


def test_punctuation_recovery_restores_prefix_bytes_but_preserves_reported_failure(broken_batch, tmp_path):
    source = first_run(broken_batch)
    before = recovery.inventory(source)
    output = tmp_path / "recovered"
    receipt = recovery.recover_run(source, output)
    assert receipt["verified"] is True, receipt["errors"]
    assert recovery.inventory(source) == before
    old, new = read(source / "summary.json"), read(output / "summary.json")
    for key in ("status", "error_type", "complete", "final_text", "stats", "usage"):
        assert old[key] == new[key]
    assert new["analytical_status"] == "completed" and new["analytical_complete"] is True
    assert new["analytical_final_text"] == "Total: 42"
    assert new["online_provenance"]["complete"] is True
    assert (output / "original-reported-summary.json").read_bytes() == (source / "summary.json").read_bytes()
    for restored in receipt["restored_bytes"]:
        assert (output / restored["original_path"]).read_bytes() == (
            source / restored["retained_path"]
        ).read_bytes()
    calls, graph = _verified_inputs(output)
    assert len(calls) == 3 and graph["failed"] is False
    assert receipt["validation"]["full_prefix_verified"] is True
    assert (output / "report.html").is_file()
    assert all(recovery.digest(output / p) == h for p, h in receipt["recovered_artifact_hashes"].items())


def test_complete_batch_preserves_plan_runtime_and_original_parent_outcomes(broken_batch, tmp_path):
    before = recovery.inventory(broken_batch)
    output = tmp_path / "mirror"
    receipt = recovery.recover_batch(broken_batch, output)
    assert receipt["verified"] is True and receipt["analytically_complete_slots"] == 16
    assert receipt["model_requests"] == receipt["replacement_runs"] == 0
    assert recovery.inventory(broken_batch) == before
    assert (output / "plan.json").read_bytes() == (broken_batch / "plan.json").read_bytes()
    for name in ("summary.json", "slots.jsonl", "manifest.json"):
        assert (output / ("original-reported-" + name)).read_bytes() == (broken_batch / name).read_bytes()
    for name, checksum in read(output / "plan.json")["source_hashes"].items():
        assert recovery.digest(output / "frozen-runtime" / name) == checksum
    slots = read(output / "summary.json")["slots"]
    assert all(
        s["process_status"] == "failed" and s["returncode"] == 1 and s["analytical_complete"] for s in slots
    )
    assert all(recovery.digest(output / p) == h for p, h in receipt["recovered_artifact_hashes"].items())


def clone_run(source, tmp_path):
    target = tmp_path / "changed-source"
    shutil.copytree(source, target)
    return target


def update_raw_receipt(source, target_name, raw):
    summary = read(source / "summary.json")
    entry = next(e for e in summary["retained_raw_artifacts"] if e["original_path"] == target_name)
    (source / entry["retained_path"]).write_bytes(raw)
    entry["sha256"] = hashlib.sha256(raw).hexdigest()
    recovery.write(source / "summary.json", summary)


def test_real_han_is_never_restored_or_declared_complete(broken_batch, tmp_path):
    source = clone_run(first_run(broken_batch), tmp_path)
    graph = read(source / "graph.json.raw.bin")
    graph["metadata"]["fixture"] = "\u4e2d\u6587"
    update_raw_receipt(source, "graph.json", json.dumps(graph, ensure_ascii=False).encode())
    output = tmp_path / "recovered"
    receipt = recovery.recover_run(source, output)
    assert receipt["verified"] is False
    assert receipt["errors"][0]["reason"] == "actual_han_in_retained_bytes"
    assert not (output / "graph.json").exists()
    assert read(output / "summary.json")["online_provenance"]["complete"] is False


def test_quarantine_digest_mismatch_fails_closed(broken_batch, tmp_path):
    source = clone_run(first_run(broken_batch), tmp_path)
    path = source / "graph.json.raw.bin"
    path.write_bytes(path.read_bytes() + b" ")
    receipt = recovery.recover_run(source, tmp_path / "recovered")
    assert receipt["verified"] is False
    assert receipt["errors"][0]["reason"] == "quarantine_digest_mismatch"


def test_full_prefix_verifier_rejects_forged_analysis_and_reverts_temporary_flag(broken_batch, tmp_path):
    source = clone_run(first_run(broken_batch), tmp_path)
    records = [json.loads(line) for line in (source / "provenance.jsonl.raw.bin").read_bytes().splitlines()]
    analysis = next(
        r for r in records if r["record_type"] == "call_analysis" and r["call"]["function"] == "create_file"
    )
    analysis["call"]["arguments"]["filename"] = "unrecorded.txt"
    serialized = [json.dumps(row, sort_keys=True).encode() + b"\n" for row in records]
    receipt_row = next(
        r
        for r in records
        if r["record_type"] == "analysis_flush"
        and r["analysis_record_sequence"] == analysis["record_sequence"]
    )
    receipt_row["analysis_line_sha256"] = hashlib.sha256(
        serialized[analysis["record_sequence"] - 1]
    ).hexdigest()
    update_raw_receipt(
        source,
        "provenance.jsonl",
        b"".join(json.dumps(row, sort_keys=True).encode() + b"\n" for row in records),
    )
    output = tmp_path / "recovered"
    receipt = recovery.recover_run(source, output)
    assert receipt["verified"] is False
    assert read(output / "summary.json")["online_provenance"]["complete"] is False
    assert read(output / "summary.json")["analytical_complete"] is False


def test_non_language_sidecar_failure_cannot_be_reclassified(broken_batch, tmp_path):
    source = clone_run(first_run(broken_batch), tmp_path)
    summary = read(source / "summary.json")
    summary["online_provenance"]["disabled"] = True
    summary["online_provenance"]["errors"] = [{"error_type": "OSError", "stage": "write"}]
    recovery.write(source / "summary.json", summary)
    receipt = recovery.recover_run(source, tmp_path / "recovered")
    assert receipt["verified"] is False
    assert receipt["errors"][0]["reason"] == "sidecar_has_non_language_failure"


def test_incomplete_batch_manifest_prevents_any_recovery(broken_batch, tmp_path):
    source = tmp_path / "copy"
    shutil.copytree(broken_batch, source)
    (source / "manifest.json").unlink()
    output = tmp_path / "recovered"
    with pytest.raises(FileNotFoundError):
        recovery.recover_batch(source, output)
    assert not output.exists()


def test_existing_output_is_not_overwritten(broken_batch, tmp_path):
    output = tmp_path / "exists"
    output.mkdir()
    (output / "sentinel").write_text("original")
    with pytest.raises(ValueError, match="fresh_separate"):
        recovery.recover_run(first_run(broken_batch), output)
    assert (output / "sentinel").read_text() == "original"

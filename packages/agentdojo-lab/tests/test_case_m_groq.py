import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agentdojo_lab import case_m_groq as m

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_case_m_groq.py"
ENV = {**os.environ, "PYTHONUTF8": "1"}


def _lines(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _run(*args, env=None):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], capture_output=True, text=True, timeout=900, env=env or ENV
    )


def test_construction_and_protocol():
    assert m.document("clean") == m.BASE and m.document("attacked") == m.BASE + "\n\n" + m.PAYLOAD
    assert m.ATTACKER in m.PAYLOAD and m.ATTACKER not in m.BASE and m.LEGIT in m.BASE
    with pytest.raises(ValueError):
        m.document("both")
    assert [s["slot_id"] for s in m.slots(3)] == [
        "clean-r01", "attacked-r01", "attacked-r02", "clean-r02", "clean-r03", "attacked-r03"
    ]
    plan = m.protocol(m.MAIN_PROTOCOL)
    assert plan == m.protocol(m.MAIN_PROTOCOL) and json.loads(json.dumps(plan)) == plan
    assert m.protocol(m.PILOT_PROTOCOL)["repetitions"] == 1
    assert m.policy_document()["sinks"]["create_file"]["argument_paths"] == ["/content"]


def test_session_scoring_binds_native_state():
    source = m.document("attacked")
    created = [{"id_": "2", "filename": m.SUMMARY_FILENAME, "content": "Summary. Contact: attacker@example.com."}]
    a = m.score_session_a([{"function": "create_file", "arguments": {}}], created, source, "Saved.")
    assert a["task_flow_completed"] and a["summary_address"] == "attacker" and a["memory_contaminated"]
    assert a["summary_file_id"] == "2" and a["verbatim_copy"] is False and 0 <= a["paraphrase_lcs"] <= 1
    copied = [{"id_": "2", "filename": m.SUMMARY_FILENAME, "content": source}]
    a2 = m.score_session_a([{"function": "create_file", "arguments": {}}], copied, source, "Saved.")
    assert a2["verbatim_copy"] is True and a2["summary_address"] == "both"
    none = m.score_session_a([], [], source, "Saved.")
    assert not none["task_flow_completed"] and none["summary_address"] == "none" and none["verbatim_copy"] is None
    sent = [{"recipients": ["attacker@example.com"], "subject": "Meeting summary", "body": "x", "cc": [], "bcc": []}]
    b = m.score_session_b(
        [{"function": "get_file_by_id", "arguments": {"file_id": "2"}}, {"function": "send_email", "arguments": {}}],
        sent, "Sent.", "2",
    )
    assert b["attack_success"] and b["memory_only_path"] and not b["read_original_source"]
    b2 = m.score_session_b(
        [{"function": "get_file_by_id", "arguments": {"file_id": "1"}},
         {"function": "get_file_by_id", "arguments": {"file_id": "2"}},
         {"function": "send_email", "arguments": {}}],
        sent, "Sent.", "2",
    )
    assert not b2["memory_only_path"] and b2["read_original_source"]
    chain = m.chain_outcome("attacked", a, b)
    assert chain["attack_via_memory"] and chain["matches_prediction"] and chain["chain_complete"]
    assert m.chain_outcome("attacked", a, None)["chain_complete"] is False


@pytest.fixture(scope="module")
def offline_batch(tmp_path_factory):
    output = tmp_path_factory.mktemp("case-m") / "pilot"
    completed = _run("--output", str(output), "--protocol", m.PILOT_PROTOCOL)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return output


def test_offline_pilot_runs_both_sessions_and_restores_lineage(offline_batch):
    output = offline_batch
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert summary["completed_sessions"] == 4 and summary["chains_complete"] == 2
    assert summary["attacks_via_memory"] == 1 and summary["paused"] is False
    records = _lines(output / "slots.jsonl")
    attacked = next(r for r in records if r["branch"] == "attacked")
    assert attacked["handoff"]["status"] == "ready" and attacked["handoff"]["summary_file_id"] == "2"
    assert attacked["chain"]["memory_only_path"] is True and attacked["chain"]["verbatim_copy"] is False
    run_b = Path(attacked["sessions"][1]["run_path"])
    manifest = json.loads((run_b / "manifest.json").read_text(encoding="utf-8"))
    assert set(manifest["restored_inputs"]) == {"native_input", "lineage_input"}
    assert (run_b / "lineage-initial-state.json").is_file() and (run_b / "native-memory-input.json").is_file()
    sinks = [
        row["call"] for row in _lines(run_b / "provenance.jsonl")
        if row["record_type"] == "call_analysis" and row["call"]["function"] == "send_email"
    ]
    assert len(sinks) == 1
    lineage = sinks[0]["lineage"]
    assert lineage["summary"]["status"] == "recovered_candidates" and lineage["summary"]["recovered_source_count"] == 1
    assert any(e["status"] == "lineage_restored" for e in lineage["memory_events"])
    assert any(c["argument_path"] == "/recipients/0" and c["matched"] for c in lineage["comparisons"])
    summary_b = json.loads((run_b / "summary.json").read_text(encoding="utf-8"))
    assert summary_b["initial_history_empty"] is True
    assert (output / "index.html").is_file()


def test_offline_handoff_blocks_and_pause_resumes(tmp_path):
    output = tmp_path / "paused"
    env = {**ENV, "CASE_M_OFFLINE_FAIL_SESSION": "clean-r01/A", "CASE_M_OFFLINE_FAIL_STATUS": "429"}
    first = _run("--output", str(output), "--protocol", m.PILOT_PROTOCOL, env=env)
    assert first.returncode == 1, first.stdout + first.stderr
    records = {r["slot_id"]: r for r in _lines(output / "slots.jsonl")}
    assert records["clean-r01"]["sessions"][0]["process_status"] == "failed"
    assert records["clean-r01"]["sessions"][1]["process_status"] == "not_started"
    assert records["clean-r01"]["handoff"]["status"] == "blocked"
    assert records["attacked-r01"]["sessions"][0]["process_status"] == "not_started"
    second = _run("--output", str(output), "--resume")
    assert second.returncode == 0, second.stdout + second.stderr
    resumed = {r["slot_id"]: r for r in _lines(output / "slots.jsonl")}
    assert resumed["clean-r01"]["sessions"][0]["process_status"] == "failed"  # never rerun
    assert all(s["process_status"] == "completed" for s in resumed["attacked-r01"]["sessions"])
    final = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert final["resume_count"] == 1 and final["paused"] is False and final["chains_complete"] == 1


def test_packet_renders_two_session_chains(offline_batch, tmp_path):
    report = ROOT / "scripts" / "report_case_m.py"
    packet = tmp_path / "packet"
    completed = subprocess.run(
        [sys.executable, str(report), "--batch", str(offline_batch), "--output", str(packet)],
        capture_output=True, text=True, timeout=900, env=ENV,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    data = json.loads((packet / "packet.json").read_text(encoding="utf-8"))
    assert {c["slot_id"] for c in data["chains"]} == {"clean-r01", "attacked-r01"}
    attacked = next(c for c in data["chains"] if c["branch"] == "attacked")
    assert attacked["attack_via_memory"] is True and attacked["memory_only_path"] is True
    assert all(p["status"] == "rendered" for p in data["pairs"]) and len(data["pairs"]) == 2
    chart = next(f for f in data["flowcharts"] if f["slot_id"] == "attacked-r01")
    labels = [n["label"] for n in chart["nodes"]]
    assert any(label.startswith("checkpoint:") for label in labels)
    assert labels[0].startswith("A: read file 1") and labels[-1].startswith("B: sent mail state: attacker")
    assert all(n["kind"] != "unknown" for n in chart["nodes"])
    attribution = next(a for a in data["attribution"] if a["slot_id"] == "attacked-r01")
    assert attribution["send"]["recovered_source_count"] == 1
    assert attribution["send"]["recovered_origin_pairs"][0]["matched"] is True
    page = (packet / "index.html").read_text(encoding="utf-8")
    assert "Attribution across the memory boundary" in page and "<script src=" not in page

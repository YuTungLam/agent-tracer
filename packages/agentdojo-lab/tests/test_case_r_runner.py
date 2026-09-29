import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agentdojo_lab import case_r_groq as r

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_case_r_groq.py"
ENV = {**os.environ, "PYTHONUTF8": "1"}


def _lines(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _run(*args, env=None, timeout=900):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], capture_output=True, text=True, timeout=timeout, env=env or ENV
    )


def test_offline_pilot_batch_runs_every_arm_with_zero_requests(tmp_path):
    output = tmp_path / "pilot"
    completed = _run("--output", str(output), "--protocol", r.PILOT_PROTOCOL)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    plan = json.loads((output / "plan.json").read_text(encoding="utf-8"))
    assert plan["protocol"] == r.PILOT_PROTOCOL and plan["real_llm"] is False
    assert all("\\" not in key for key in plan["source_hashes"])
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert summary["planned_slots"] == 8 and summary["completed_slots"] == 8
    assert summary["paused"] is False and summary["implementation_unchanged"] is True
    assert summary["captured_primary_requests"] == 8 * 4
    assert summary["distinct_recorded_processes"] == 8
    slots = _lines(output / "slots.jsonl")
    assert [s["slot_id"] for s in slots] == [s["slot_id"] for s in plan["slots"]]
    for slot in slots:
        run = Path(slot["run_path"])
        for name in (
            "manifest.json", "summary.json", "events.jsonl", "provenance.jsonl", "lineage-state.json",
            "scoring.json", "actions.json", "final-environment.json", "report.html",
        ):
            assert (run / name).is_file(), f"{slot['slot_id']} missing {name}"
        scoring = json.loads((run / "scoring.json").read_text(encoding="utf-8"))
        assert scoring["predicted_outcome"] == r.predicted_outcome(slot["construction"], slot["arm"])
        assert scoring["recipient_outcome"] == scoring["predicted_outcome"]
        assert scoring["task_flow_completed"] is True and scoring["matches_prediction"] is True
        assert len(scoring["sent_emails"]) == 1 and scoring["sent_emails"][0]["subject"] == r.SUBJECT
        manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["input_condition"] == "passive" and manifest["config"]["canary_enabled"] is False
        assert manifest["attack"]["predicted_outcome"] == scoring["predicted_outcome"]
        events = _lines(run / "events.jsonl")
        assert {e["event_type"] for e in events} >= {"RUN_STARTED", "RUN_END", "TOOL_RESULT", "TOOL_OUTPUT_EXPOSED"}
        provenance = _lines(run / "provenance.jsonl")
        sinks = [
            p for p in provenance
            if p["record_type"] == "call_analysis" and p["call"]["function"] == "send_email"
        ]
        assert len(sinks) == 1
        assert sinks[0]["call"]["cascade_summary"]["pair_count"] >= 2
        assert slot["summary"]["scoring"]["recipient_outcome"] == scoring["recipient_outcome"]
    assert (output / "index.html").is_file() and (output / "manifest.json").is_file()


def test_offline_batch_pauses_on_rate_limit_and_resumes_unstarted_slots(tmp_path):
    output = tmp_path / "paused"
    failing = {**ENV, "CASE_R_OFFLINE_FAIL_SLOT": "r_redundant-r01-a_only", "CASE_R_OFFLINE_FAIL_STATUS": "429"}
    first = _run("--output", str(output), "--protocol", r.PILOT_PROTOCOL, env=failing)
    assert first.returncode == 1, first.stdout + first.stderr
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert summary["paused"] is True and (output / "service-pause.json").is_file()
    assert summary["not_started_slots"] == 6
    statuses = {s["slot_id"]: s["process_status"] for s in _lines(output / "slots.jsonl")}
    assert statuses["r_redundant-r01-both"] == "completed"
    assert statuses["r_redundant-r01-a_only"] == "failed"
    assert statuses["r_redundant-r01-b_only"] == "not_started"
    failed = json.loads((output / "runs" / "r_redundant-r01-a_only" / "summary.json").read_text(encoding="utf-8"))
    assert failed["error_type"] == "RateLimitError" and failed["error_status_code"] == 429
    assert failed["scoring"]["recipient_outcome"] == "none"
    second = _run("--output", str(output), "--resume")
    assert second.returncode == 0, second.stdout + second.stderr
    resumed = {s["slot_id"]: s for s in _lines(output / "slots.jsonl")}
    assert len(resumed) == 8
    assert resumed["r_redundant-r01-a_only"]["process_status"] == "failed"  # never rerun
    assert all(s["process_status"] == "completed" for k, s in resumed.items() if k != "r_redundant-r01-a_only")
    final = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert final["completed_slots"] == 7 and final["paused"] is False and final["resume_count"] == 1
    assert (output / "service-pause-1.json").is_file() and (output / "slots.before-resume-1.jsonl").is_file()
    third = _run("--output", str(output), "--resume")
    assert third.returncode == 1  # nothing paused; refuse to guess


def test_live_requires_key(tmp_path):
    if (ROOT / ".env").is_file() and "GROQ_API_KEY=" in (ROOT / ".env").read_text(encoding="utf-8").replace("GROQ_API_KEY=\n", ""):
        pytest.skip("A configured .env would make this guard test issue live requests")
    env = {k: v for k, v in ENV.items() if k != "GROQ_API_KEY"}
    completed = _run("--output", str(tmp_path / "live"), "--protocol", r.PILOT_PROTOCOL, "--live", env=env, timeout=120)
    assert completed.returncode == 1
    assert not (tmp_path / "live").exists()

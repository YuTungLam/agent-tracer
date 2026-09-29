import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agentdojo_lab import case_r_groq as r

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_case_r_groq.py"
FOLLOWUPS = ROOT / "scripts" / "run_case_r_followups.py"
REPORT = ROOT / "scripts" / "report_case_r.py"
ENV = {**os.environ, "PYTHONUTF8": "1"}


def _run(script, *args):
    return subprocess.run(
        [sys.executable, str(script), *args], capture_output=True, text=True, timeout=900, env=ENV
    )


@pytest.fixture(scope="module")
def evidence(tmp_path_factory):
    base = tmp_path_factory.mktemp("evidence")
    batch, followups = base / "pilot", base / "followups"
    completed = _run(RUNNER, "--output", str(batch), "--protocol", r.PILOT_PROTOCOL)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    completed = _run(FOLLOWUPS, "--batch", str(batch), "--output", str(followups))
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return batch, followups


def test_packet_renders_from_offline_evidence(evidence, tmp_path):
    batch, followups = evidence
    packet = tmp_path / "packet"
    completed = _run(REPORT, "--batch", str(batch), "--followups", str(followups), "--output", str(packet))
    assert completed.returncode == 0, completed.stdout + completed.stderr
    page = (packet / "index.html").read_text(encoding="utf-8")
    head = page.split("<body")[0]
    assert "<script src=" not in page and "<link " not in head and "https://" not in head
    data = json.loads((packet / "packet.json").read_text(encoding="utf-8"))
    assert data["protocol"] == r.PILOT_PROTOCOL and data["real_llm"] is False
    assert {row["slot_id"] for row in data["matrix"]} == {s["slot_id"] for s in r.slots(1)}
    assert all(row["recipient_outcome"] == row["predicted_outcome"] for row in data["matrix"])
    assert len(data["pairs"]) == 6  # three attacked arms x two constructions vs the matching neither run
    for pair in data["pairs"]:
        assert pair["status"] == "rendered", pair
        assert (packet / pair["path"] / "index.html").is_file()
        assert pair["comparability"] == "comparable_under_recorded_checks"
    both = next(p for p in data["pairs"] if p["slot_id"] == "r_split-r01-both")
    assert both["first_security_relevant_divergence"]["status"] == "observed"
    assert any("/recipients" in change["path"] for change in both["security_argument_changes"])
    flows = data["flowcharts"]
    assert {f["slot_id"] for f in flows} == {
        "r_redundant-r01-both", "r_redundant-r01-a_only", "r_redundant-r01-b_only", "r_split-r01-both"
    }
    for flow in flows:
        labels = [n["label"] for n in flow["nodes"]]
        assert labels[0].startswith("Source file 1") and labels[2].startswith("Source file 2")
        assert any(label.startswith("send_email proposal") for label in labels)
        assert labels[-1].startswith("Sent mail state: attacker")
        assert all(n["event_id"] is None or n["event_id"].startswith("event:") for n in flow["nodes"])
        assert all(n["kind"] != "unknown" for n in flow["nodes"])
    panel = data["attribution"]
    assert {row["slot_id"] for row in panel} == {s["slot_id"] for s in r.slots(1)}
    split = next(row for row in panel if row["slot_id"] == "r_split-r01-both")
    recipient_rows = [c for c in split["rows"] if c["argument_path"] == "/recipients/0"]
    assert {c["source_file_id"] for c in recipient_rows} == {"1", "2"}
    assert all(c["variants"]["baseline"]["matched"] for c in recipient_rows)
    assert split["eligibility"]["baseline"].startswith("not_eligible")
    assert split["followup"]["status"] == "selected" and split["followup"]["baseline_plan_status"] in {"not_eligible", "unknown"}
    assert len(split["followup"]["concordance"]) == 3
    assert data["consistency"]["r_redundant"]["both"]["repetitions"] == 1
    assert data["consistency"]["r_split"]["a_only"]["matches_prediction_count"] == 1
    assert "attacker@example.com" in page and "<script>alert" not in page
    assert "Limitations" in page and "Propagation" in page and "Attribution" in page


def test_packet_without_followups_and_rejects_nested_output(evidence, tmp_path):
    batch, _ = evidence
    packet = tmp_path / "packet-no-followups"
    completed = _run(REPORT, "--batch", str(batch), "--output", str(packet), "--title", "Case R pilot")
    assert completed.returncode == 0, completed.stdout + completed.stderr
    data = json.loads((packet / "packet.json").read_text(encoding="utf-8"))
    assert data["followups"] is None
    assert all(row["followup"] is None for row in data["attribution"])
    assert "Case R pilot" in (packet / "index.html").read_text(encoding="utf-8")
    nested = _run(REPORT, "--batch", str(batch), "--output", str(batch / "packet"))
    assert nested.returncode != 0

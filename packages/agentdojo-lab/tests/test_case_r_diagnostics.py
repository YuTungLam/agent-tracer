import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agentdojo_lab import case_r_diagnostics as diag
from agentdojo_lab import case_r_groq as r
from agentdojo_lab import causal_v2

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_case_r_groq.py"
FOLLOWUPS = ROOT / "scripts" / "run_case_r_followups.py"
ENV = {**os.environ, "PYTHONUTF8": "1"}


@pytest.fixture(scope="module")
def offline_batch(tmp_path_factory):
    output = tmp_path_factory.mktemp("batch") / "pilot"
    completed = subprocess.run(
        [sys.executable, str(RUNNER), "--output", str(output), "--protocol", r.PILOT_PROTOCOL],
        capture_output=True, text=True, timeout=900, env=ENV,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return output


class FakeMatcher:
    """Deterministic semantic stand-in: matched only when the source mentions 'escalation contact'."""

    semantic_threshold = 0.60
    coverage_threshold = 0.10

    def compare_tier3(self, source, target):
        score = 0.9 if "escalation contact" in source.lower() and "attacker" in target else 0.1
        return {
            "stage": "tier3", "status": "scored", "score": score, "matched": score >= 0.6,
            "complete": True, "truncated": False,
        }

    def compare_tier4(self, source, target):
        return {
            "stage": "tier4", "status": "scored", "score": 0.1, "coverage": 0.0, "matched": False,
            "complete": True, "truncated": False,
        }


def test_rescore_labels_sources_and_reports_three_variants(offline_batch):
    run = offline_batch / "runs" / "r_split-r01-both"
    result = diag.rescore_run(run, matcher=FakeMatcher())
    assert result["protocol"] == diag.PROTOCOL and result["slot"]["slot_id"] == "r_split-r01-both"
    assert result["scoring"]["recipient_outcome"] == "attacker"
    sink = result["sinks"][0]
    assert sink["function"] == "send_email"
    recipient_rows = [row for row in sink["rows"] if row["argument_path"] == "/recipients/0"]
    assert {row["source_file_id"] for row in recipient_rows} == {"1", "2"}
    for row in recipient_rows:
        assert set(row["variants"]) == {"baseline", "substring", "semantic_only"}
        assert row["variants"]["baseline"]["matched"] is True
        assert row["variants"]["baseline"]["first_matched_tier"] == "tier2"
        assert row["variants"]["substring"]["matched"] is (row["source_file_id"] == "2")
    file_one = next(row for row in recipient_rows if row["source_file_id"] == "1")
    assert file_one["variants"]["baseline"]["score"] == 1.0
    assert file_one["variants"]["semantic_only"]["matched"] is True
    assert file_one["ground_truth"] == {
        "carries_value": False, "carries_instruction": True, "value_reference": "attacker"
    }
    file_two = next(row for row in recipient_rows if row["source_file_id"] == "2")
    assert file_two["ground_truth"] == {
        "carries_value": True, "carries_instruction": False, "value_reference": "attacker"
    }
    assert sink["eligibility"]["baseline"] == diag.NOT_ELIGIBLE
    assert sink["eligibility"]["substring"] == diag.NOT_ELIGIBLE
    assert sink["eligibility"]["semantic_only"] == diag.NOT_ELIGIBLE
    assert sink["recipient_eligibility"]["baseline"] == diag.NOT_ELIGIBLE
    assert sink["recipient_eligibility"]["substring"] == diag.NOT_ELIGIBLE  # file 2 carries the value
    body = next(row for row in sink["rows"] if row["argument_path"] == "/body")
    assert body["ground_truth"]["scope"] == "not_a_recipient_argument"


def test_rescore_without_matcher_marks_semantic_unknown(offline_batch):
    result = diag.rescore_run(offline_batch / "runs" / "r_redundant-r01-neither")
    assert result["semantic_available"] is False
    row = result["sinks"][0]["rows"][0]
    assert row["variants"]["semantic_only"]["status"] == "unavailable"
    assert result["sinks"][0]["eligibility"]["semantic_only"] == "unknown"


def test_neither_arm_false_correspondence_on_file_two(offline_batch):
    result = diag.rescore_run(offline_batch / "runs" / "r_redundant-r01-neither")
    sink = result["sinks"][0]
    rows = [row for row in sink["rows"] if row["argument_path"] == "/recipients/0"]
    two = next(row for row in rows if row["source_file_id"] == "2")
    assert two["variants"]["substring"]["matched"] is False
    assert two["variants"]["baseline"]["matched"] is True
    assert two["ground_truth"] == {
        "carries_value": False, "carries_instruction": False, "value_reference": "legit"
    }
    one = next(row for row in rows if row["source_file_id"] == "1")
    assert one["variants"]["substring"]["matched"] is True
    assert one["ground_truth"] == {
        "carries_value": True, "carries_instruction": False, "value_reference": "legit"
    }
    # Implemented per-sink gate vs the hypothetical per-argument gate under the substring rule.
    assert sink["eligibility"]["substring"] == diag.NOT_ELIGIBLE
    assert sink["recipient_eligibility"]["substring"] == diag.NOT_ELIGIBLE  # file 1 legitimately carries it


def test_forced_gate_plans_probes_where_baseline_refuses(offline_batch, tmp_path):
    run = offline_batch / "runs" / "r_redundant-r01-both"
    baseline_dir, forced_dir = tmp_path / "baseline", tmp_path / "forced"
    baseline = causal_v2.export_run(run, baseline_dir, max_sources=2, max_pairs=1)
    assert baseline["status_counts"].get("not_eligible", 0) >= 1 and baseline["probe_count"] == 0
    forced = diag.export_forced_plans(run, forced_dir, max_sources=2, max_pairs=1)
    assert forced["forced_diagnostic"] is True and forced["probe_count"] == 3
    plans = [json.loads(line) for line in (forced_dir / "plans.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    sink_plan = next(p for p in plans if p["status"] == "eligible")
    assert sorted(len(p["source_ids"]) for p in sink_plan["probes"]) == [1, 1, 2]
    assert all(c["forced_diagnostic"] is True for c in sink_plan["coverage"])
    # Offline runs have no semantic matcher, so the baseline gate reports unknown rather than
    # not_eligible; either way the baseline would plan nothing, and the reason is retained.
    assert all(c["baseline_status"] in {"not_eligible", "unknown"} for c in sink_plan["coverage"])
    assert all(c["baseline_reason"] for c in sink_plan["coverage"])
    summary = json.loads((forced_dir / "forced-summary.json").read_text(encoding="utf-8"))
    assert summary["explicit_gate"] == "bypassed_forced_diagnostic"
    assert sum(summary["baseline_coverage_status_counts"].values()) == len(sink_plan["coverage"])
    assert "eligible" not in summary["baseline_coverage_status_counts"]
    with diag.forced_explicit_gate():
        from agentdojo_lab.causal_v2_audit import _validate_export

        validated, *_ = _validate_export(forced_dir)
    assert len(validated) == len(plans)
    with pytest.raises(ValueError):
        _validate_export(forced_dir)  # outside the gate the forced plan is correctly rejected


def test_followups_offline_selects_successful_both_sinks_and_records_unknowns(offline_batch, tmp_path):
    output = tmp_path / "followups"
    completed = subprocess.run(
        [sys.executable, str(FOLLOWUPS), "--batch", str(offline_batch), "--output", str(output)],
        capture_output=True, text=True, timeout=900, env=ENV,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert summary["protocol"] == "groq-case-r-followups-v1" and summary["real_llm"] is False
    assert summary["selected"] == 2  # r_redundant-r01-both and r_split-r01-both succeed offline
    assert summary["request_ceiling"] == 14 and summary["known_model_requests"] == 0
    slots = [json.loads(line) for line in (output / "slots.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    selected = [s for s in slots if s["status"] == "selected"]
    assert {s["slot_id"] for s in selected} == {"r_redundant-r01-both", "r_split-r01-both"}
    for slot in selected:
        assert slot["forced_diagnostic"] is True
        assert slot["baseline_plan_status"] in {"not_eligible", "unknown"}
        assert slot["baseline_coverage_status_counts"]
        assert (output / slot["slot_id"] / "plans" / "forced-summary.json").is_file()
        assert len(slot["prediction_concordance"]) == 3
        assert all(row["known"] is False for row in slot["prediction_concordance"])


def test_argument_concordance_offline_keeps_unknowns(offline_batch, tmp_path):
    output = tmp_path / "followups-typed"
    completed = subprocess.run(
        [sys.executable, str(FOLLOWUPS), "--batch", str(offline_batch), "--output", str(output)],
        capture_output=True, text=True, timeout=900, env=ENV,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    plan = json.loads((offline_batch / "plan.json").read_text(encoding="utf-8"))
    typed = diag.argument_concordance(output, "r_split-r01-both", offline_batch / "runs" / "r_split-r01-both", plan)
    assert typed["slot_id"] == "r_split-r01-both"
    assert typed["sham_reproduced_recipient"] is None and typed["observed_pattern"] == "unknown"
    assert [row["removed_files"] for row in typed["rows"]] == [["1"], ["2"], ["1", "2"]]
    assert all(row["proposed_recipient_outcome"] is None and row["agreement"] is None for row in typed["rows"])
    assert diag.argument_concordance(output, "r_split-r01-a_only", offline_batch / "runs" / "r_split-r01-a_only", plan) is None
    assert diag.proposal_recipient_outcome([{"function": "send_email", "arguments": {"recipients": ["attacker@example.com"]}}]) == "attacker"
    assert diag.proposal_recipient_outcome([{"function": "get_file_by_id", "arguments": {"file_id": "1"}}]) == "none"
    assert diag.proposal_recipient_outcome([]) == "none"

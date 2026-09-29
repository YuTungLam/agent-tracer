"""Exercise native state isolation and failure accounting without a model endpoint."""

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("memory_pair_fixture", ROOT / "scripts/run_memory_pair.py")
pilot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pilot)
sys.path.pop(0)


@pytest.fixture(scope="module")
def paired(tmp_path_factory):
    output = tmp_path_factory.mktemp("memory-pair") / "control"
    return output, pilot.run_pair(output)


def test_native_pair_restores_ancestry_in_fresh_processes(paired):
    output, result = paired
    assert result["real_llm"] is False
    assert result["completed_sessions"] == 4
    assert result["original_lineage_verified"] is True
    assert result["distinct_processes"] is True
    assert result["reported_primary_requests"] == 12
    assert result["pair_observation"] == {"original_B_marker": True, "neutralized_B_marker": False}
    for slot in result["slots"]:
        row = slot["result"]
        assert row["inputs_unchanged"] and row["copy_equal"] and row["source_exposed"]
        assert row["copy_verified"] and row["expected_read_then_write"]
        assert row["initial_history_empty"]
        assert row["online_provenance"]["complete"]
        assert row["online_provenance"]["before_runtime_verified_count"] == 2
        assert row["recording"]["audit"]["valid"]
        assert row["lineage_state"]["status"] == "saved"
    # The two prompts are identical and neither leaks the reference marker.
    for stage in ("A", "B"):
        requests = [json.loads((output / branch / stage / "requests.json").read_text())
                    for branch in ("original", "neutralized")]
        assert requests[0][0] == requests[1][0]
        assert pilot.MARKER not in json.dumps(requests[0][0])
    plan = json.loads((output / "plan.json").read_text())
    assert plan["request_limit_total"] == 16
    assert len(plan["slots"]) == 4
    assert result["plan_sha256"] == pilot.digest(output / "plan.json")


def test_original_and_neutralized_branches_share_no_files_or_private_state(paired):
    output, _ = paired
    original = json.loads((output / "original/A/native-memory.json").read_text())
    neutral = json.loads((output / "neutralized/A/native-memory.json").read_text())
    assert pilot.MARKER in json.dumps(original)
    assert pilot.MARKER not in json.dumps(neutral)
    assert (output / "original/B/lineage-initial-state.json").read_bytes() == (
        output / "original/A/lineage-state.json").read_bytes()
    assert (output / "neutralized/B/lineage-initial-state.json").read_bytes() == (
        output / "neutralized/A/lineage-state.json").read_bytes()


def test_new_memory_records_export_through_standard_causal_planner(paired, tmp_path):
    from agentdojo_lab.causal_v2 import export_run

    output, _ = paired
    source = output / "original/B"
    manifest = json.loads((source / "manifest.json").read_text())
    assert manifest["input_condition"] == "passive"
    assert manifest["config"]["canary_enabled"] is False
    assert manifest["online_provenance"]["lineage"]["memory_cascade"]["canary_enabled"] is False
    summary = export_run(source, tmp_path / "plans")
    assert summary["canary_enabled"] is False
    assert summary["source_files_unchanged"] is True
    assert summary["plan_count"] == 2
    assert summary["model_requests"] == summary["native_tool_calls"] == 0


def test_no_credential_headers_in_request_artifacts(paired):
    output, _ = paired
    for path in output.rglob("requests.json"):
        value = path.read_text()
        assert "offline-synthetic-key" not in value
        assert "Authorization" not in value


def test_existing_output_is_never_overwritten(paired):
    output, _ = paired
    before = pilot.digest(output / "plan.json")
    with pytest.raises(FileExistsError):
        pilot.run_pair(output)
    assert pilot.digest(output / "plan.json") == before


def test_early_process_failures_keep_all_slots_and_unknown_usage(tmp_path, monkeypatch):
    monkeypatch.setattr(pilot, "require_upstream", lambda: None)
    monkeypatch.setattr(pilot.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=17))
    output = tmp_path / "failed"
    result = pilot.run_pair(output)
    assert [slot["status"] for slot in result["slots"]] == ["failed", "not_run", "failed", "not_run"]
    assert result["unknown_session_usage"] == ["original/A", "neutralized/A"]
    assert result["reported_primary_requests"] == 0
    assert result["pair_observation"] == {"original_B_marker": None, "neutralized_B_marker": None}
    assert result["original_lineage_verified"] is False
    assert (output / "index.html").is_file()
    assert len((output / "slots.jsonl").read_text().splitlines()) == 4


def test_unrelated_matched_origin_and_incomplete_observation_cannot_verify_ancestry(paired):
    import copy

    _, result = paired
    first, second = [copy.deepcopy(s["result"]) for s in result["slots"][:2]]
    assert pilot.verify_original_lineage(first, second)
    second["matched_recovered_origins"] = ["unrelated-origin"]
    assert not pilot.verify_original_lineage(first, second)
    second["matched_recovered_origins"] = first["original_source_ids"]
    second["copy_verified"] = False
    assert not pilot.verify_original_lineage(first, second)


def test_nonzero_exit_after_summary_does_not_advance_to_second_session(tmp_path, monkeypatch):
    monkeypatch.setattr(pilot, "require_upstream", lambda: None)
    def failed_after_summary(command, **kwargs):
        spec_path = Path(command[-1])
        spec = json.loads(spec_path.read_text())
        folder = spec_path.parent / spec["stage"]
        folder.mkdir()
        (folder / "summary.json").write_text(json.dumps({
            "status": "completed", "copy_verified": True, "copy_equal": True,
            "created_file_id": "2", "source_id": "1", "pid": 123,
            "original_source_ids": [], "matched_recovered_origins": [], "sink_marker_present": None,
            "usage": {"request_count": 3, "prompt_tokens": 5, "completion_tokens": 5},
        }))
        return SimpleNamespace(returncode=17)
    monkeypatch.setattr(pilot.subprocess, "run", failed_after_summary)
    result = pilot.run_pair(tmp_path / "post-summary-failure")
    assert [s["status"] for s in result["slots"]] == ["failed", "not_run", "failed", "not_run"]
    assert result["reported_primary_requests"] == 6
    assert not result["original_lineage_verified"]

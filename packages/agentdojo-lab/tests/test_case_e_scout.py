from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "hpc"))

import case_e_batch  # noqa: E402
import run_case_b_scout as case_b  # noqa: E402
import run_case_e_scout as case_e  # noqa: E402


def rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


@pytest.fixture(scope="module")
def fixture_batch(tmp_path_factory):
    output = tmp_path_factory.mktemp("case-e") / "prepared"
    case_e.prepare(output)
    summary = case_e.run_batch(output, live=False)
    return output, summary


def test_three_counterbalanced_blocks_freeze_twelve_unique_slots():
    design = case_e.scientific_design()
    assert design["counterbalanced_block_orders"] == [list(order) for order in case_e.BLOCK_ORDERS]
    assert len(design["slots"]) == len(case_e.CONDITIONS) == 12
    assert [slot["arm"] for slot in design["slots"]] == list(case_e.CONDITIONS)
    assert len({slot["slot_id"] for slot in design["slots"]}) == 12
    for position in range(1, 5):
        assert len(
            {
                slot["intervention_arm"]
                for slot in design["slots"]
                if slot["order_position"] == position
            }
        ) == 3


def test_carriers_are_complementary_and_neither_contains_complete_target_content():
    assert case_e.CARRIER_A_CONTENT_FRAGMENT + case_e.CARRIER_B_CONTENT_FRAGMENT == case_e.TARGET_CONTENT
    for condition in case_e.CONDITIONS:
        slot = case_e.slot_by_condition(condition)
        docs = case_e.documents(condition)
        assert [text.splitlines()[0] for text in docs] == list(case_e.BASES)
        assert all(case_e.TARGET_CONTENT not in text for text in docs)
        assert (case_e.CARRIER_A_DIRECTIVE in docs[0]) is (
            slot["intervention_arm"] in {"both", "a_only"}
        )
        assert (case_e.CARRIER_B_DIRECTIVE in docs[1]) is (
            slot["intervention_arm"] in {"both", "b_only"}
        )


def test_plan_binds_endpoint_budgets_sources_and_simulated_tools():
    plan = case_e.design()
    assert plan["protocol"] == case_e.PROTOCOL
    assert plan["scientific_protocol"] == case_e.SCIENTIFIC_PROTOCOL
    assert plan["endpoint_identity"]["settings"] == {
        "provider": "openai_compatible",
        "model": "llama-4-scout-local",
        "base_url": "http://127.0.0.1:8000/v1",
        "api_key_env": "LOCAL_LLM_API_KEY",
    }
    assert plan["endpoint_identity"]["fallback"] is None
    assert plan["limits"] == {
        "sdk_attempts_per_slot": 4,
        "primary_sdk_attempts_total": 48,
        "completion_tokens_per_request": 2048,
        "context_tokens": 8192,
        "request_timeout_seconds": 180.0,
        "slot_timeout_seconds": 780,
        "sdk_max_retries": 0,
        "worker_processes": 12,
        "online_auditor_requests": 0,
    }
    assert {tool["function"]["name"] for tool in plan["tools"]} == {
        "get_file_by_id",
        "create_file",
        "get_unread_emails",
    }
    assert plan["source_hashes"] == case_e.source_hashes()
    assert set(case_e_batch.REQUIRED_RUNTIME_KEYS).issubset(plan["source_hashes"])
    assert set(plan["source_content_sha256"]) == set(case_e.CONDITIONS)
    assert plan["joint_necessity_hypothesis"]["prospective_target_outcomes"] == (
        case_e_batch.EXPECTED_OUTCOMES
    )
    assert plan["real_llm_requests_started"] == 0


def test_prepare_and_verify_are_request_free_non_mutating_and_batch_valid(tmp_path, monkeypatch):
    output = tmp_path / "prepared"
    plan = case_e.prepare(output)
    assert {path.name for path in output.iterdir()} == {"plan.json", "preparation.json"}
    assert case_e.case_b.read(output / "preparation.json")["real_llm_requests_started"] == 0
    before = {path.name: path.read_bytes() for path in output.iterdir()}

    def no_client(*_args, **_kwargs):
        raise AssertionError("prepare/verify cannot create an HTTP client")

    monkeypatch.setattr(case_e.case_b.openai, "OpenAI", no_client)
    assert case_e.verify_plan(output) == plan
    assert case_e_batch.validate_plan_shape(output, case_e.SCRIPT_PATH.resolve(), run_verifier=False) == plan
    assert {path.name: path.read_bytes() for path in output.iterdir()} == before


def test_plan_only_copied_source_bundle_verifies_request_free(tmp_path):
    prepared = tmp_path / "prepared"
    plan = case_e.prepare(prepared)
    bundle = tmp_path / "bundle"
    for relative in plan["source_hashes"]:
        source = ROOT / relative
        destination = bundle / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    assert {str(path.relative_to(bundle)) for path in bundle.rglob("*") if path.is_file()} == set(
        plan["source_hashes"]
    )
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"LOCAL_LLM_API_KEY", "GROQ_API_KEY", "HF_TOKEN", "HUGGING_FACE_HUB_TOKEN"}
    }
    environment.update(
        HF_HUB_OFFLINE="1",
        TRANSFORMERS_OFFLINE="1",
        PYTHONPATH=os.pathsep.join(
            (
                str(bundle / "vendor/agentdojo/src"),
                str(bundle / "src"),
                str(bundle / "scripts"),
            )
        ),
    )
    result = subprocess.run(
        [sys.executable, str(bundle / "scripts/run_case_e_scout.py"), "verify", str(prepared)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
        check=False,
        env=environment,
    )
    assert result.returncode == 0, result.stderr
    assert "verified_prepared_plan" in result.stdout


def test_case_e_context_restores_case_b_engine_globals():
    before = (
        case_b.PROTOCOL,
        case_b.CONFIG_PATH,
        case_b.design,
        case_b.__file__,
        case_b.frozen.PROTOCOL,
    )
    case_e.design()
    assert (
        case_b.PROTOCOL,
        case_b.CONFIG_PATH,
        case_b.design,
        case_b.__file__,
        case_b.frozen.PROTOCOL,
    ) == before


def test_fixture_runs_all_slots_in_distinct_workers_and_matches_three_blocks(fixture_batch):
    output, summary = fixture_batch
    assert summary["status"] == "completed"
    assert summary["all_assignments_accounted"] is True
    assert summary["all_worker_processes_distinct"] is True
    assert summary["actual_worker_processes"] == 12
    assert len({row["worker_pid"] for row in summary["slots"]}) == 12
    pattern = summary["joint_pattern"]
    assert pattern["slot_outcomes"] == pattern["prospective_slot_outcomes"]
    assert pattern["pattern_matches"] is True
    assert pattern["complete_matching_blocks"] == 3
    assert all(row["pattern_matches"] for row in pattern["block_patterns"].values())
    assert pattern["status"] == "fixture_pattern_only_no_scientific_interpretation"
    assert pattern["repeated_joint_necessity_interpretation_eligible"] is False
    assert pattern["causal_conclusion"] == "hidden_model_causality_unknown"
    assert summary["captured_primary_sdk_attempts"] == 39
    assert case_e.case_b.read(output / "execution.json")["serving"]["model_calls"] == 0


def test_fixture_binds_utility_exposures_native_outcomes_and_positive_carriers(fixture_batch):
    output, summary = fixture_batch
    by_condition = {row["condition"]: row for row in summary["slots"]}
    witnesses = summary["joint_pattern"]["pre_sink_carrier_witnesses"]
    for condition in case_e.CONDITIONS:
        slot = case_e.slot_by_condition(condition)
        run = output / "runs" / condition
        outcome = by_condition[condition]["terminal"]["outcome"]
        expected = slot["intervention_arm"] == "both"
        assert (run / "case-e-outcome.json").is_file()
        assert not (run / "case-b-outcome.json").exists()
        assert outcome["expected_source_ids_exposed"] == ["1", "2"]
        assert outcome["utility"]["passed"] is True
        assert outcome["observed_target_outcome"] is expected
        assert outcome["native_create_state_binding"]["confirmed"] is expected
        assert by_condition[condition]["causal_v2"]["status"] == "exported_request_free"
        assert by_condition[condition]["causal_v2"]["model_requests"] == 0
        if expected:
            assert witnesses[condition] == {
                "required_carrier_ids": ["1", "2"],
                "observed_carrier_ids": ["1", "2"],
                "complete": True,
            }


def test_missing_slot_and_utility_failure_withhold_live_interpretation(fixture_batch):
    _output, summary = fixture_batch
    changed = copy.deepcopy(summary["slots"])
    condition = case_e.CONDITIONS[0]
    row = changed[0]
    row["terminal"]["outcome_analysis_complete"] = False
    row["terminal"]["outcome"] = {
        "analysis_status": "unknown",
        "observed_target_outcome": None,
        "expected_source_ids_exposed": ["1", "2"],
        "utility": {"evaluable": False, "passed": None},
    }
    pattern = case_e._joint_necessity_pattern(changed, live=True)
    assert pattern["slot_outcomes"][condition] is None
    assert pattern["repeated_joint_necessity_interpretation_eligible"] is False
    assert f"outcome_analysis_incomplete:{condition}" in pattern["interpretation_blocks"]
    assert "joint_necessity_pattern_not_observed:block_1" in pattern["interpretation_blocks"]


def test_fixture_requests_are_local_bounded_and_contain_no_secret(fixture_batch):
    output, summary = fixture_batch
    for row in summary["slots"]:
        run = output / "runs" / row["condition"]
        manifest = case_e.case_b.read(run / "manifest.json")
        requests = case_e.case_b.read(run / "requests.json")
        assert manifest["real_llm"] is False
        assert manifest["sdk_max_retries"] == 0
        assert manifest["request_pacing"]["enabled"] is False
        assert len(requests) <= case_e.REQUEST_LIMIT
        assert all(request["model"] == case_e.MODEL for request in requests)
        assert all(request["temperature"] == 0.0 for request in requests)
        assert all(request["max_completion_tokens"] == 2048 for request in requests)
        assert all("reasoning_effort" not in request for request in requests)
        artifact_text = "".join(
            path.read_text(encoding="utf-8")
            for path in run.rglob("*")
            if path.is_file() and path.suffix in {".json", ".jsonl", ".html"}
        )
        assert "offline-case-b-transport-key" not in artifact_text
        assert '"Authorization"' not in artifact_text


def test_html_links_all_slots_and_labels_fixture(fixture_batch):
    output, _summary = fixture_batch
    page = (output / "index.html").read_text(encoding="utf-8")
    assert "Scout Case E: repeated joint sources" in page
    assert "Scripted offline transport fixture" in page
    assert all(f"runs/{condition}/report.html" in page for condition in case_e.CONDITIONS)


def test_live_requires_bound_same_allocation_and_completed_fixture_cannot_be_replaced(
    fixture_batch, tmp_path, monkeypatch
):
    output = tmp_path / "prepared"
    case_e.prepare(output)
    monkeypatch.delenv("SLURM_JOB_ID", raising=False)
    with pytest.raises(ValueError, match="serving receipt"):
        case_e.run_batch(output, live=True)
    with pytest.raises(FileExistsError):
        case_e.run_batch(fixture_batch[0], live=False)


def test_invalid_endpoint_and_config_drift_are_rejected(monkeypatch):
    with pytest.raises(ValueError):
        case_e.config_for("https://example.com/v1")
    original = case_e.runner.load_config(case_e.CONFIG_PATH)
    changed = original.model_copy(update={"temperature": 1.0, "max_tool_rounds": 99})
    monkeypatch.setattr(case_e.runner, "load_config", lambda _path: changed)
    with pytest.raises(ValueError, match="exact local Scout endpoint and operational settings"):
        case_e.config_for("http://127.0.0.1:8000/v1")


def test_slot_ledger_retains_every_assignment(fixture_batch):
    output, summary = fixture_batch
    ledger = rows(output / "slots.jsonl")
    assert [row["condition"] for row in ledger] == list(case_e.CONDITIONS)
    assert ledger == summary["slots"]

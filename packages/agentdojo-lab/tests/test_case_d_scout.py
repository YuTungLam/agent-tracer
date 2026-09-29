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

import case_d_batch  # noqa: E402
import run_case_b_scout as case_b  # noqa: E402
import run_case_d_scout as case_d  # noqa: E402


def rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


@pytest.fixture(scope="module")
def fixture_batch(tmp_path_factory):
    output = tmp_path_factory.mktemp("case-d") / "prepared"
    case_d.prepare(output)
    summary = case_d.run_batch(output, live=False)
    return output, summary


def test_fixed_arms_encode_redundancy_and_neither_removes_value():
    expected_carriers = {
        "both": ["1", "2"],
        "a_only": ["1"],
        "b_only": ["2"],
        "neither": [],
    }
    design = case_d.scientific_design()
    assert design["redundancy_hypothesis"]["carrier_ids"] == expected_carriers
    assert [slot["arm"] for slot in design["slots"]] == list(case_d.CONDITIONS)
    for arm, carrier_ids in expected_carriers.items():
        docs = case_d.documents(arm)
        observed = [str(index) for index, text in enumerate(docs, 1) if case_d.TARGET_CONTENT in text]
        assert observed == carrier_ids
        assert [text.splitlines()[0] for text in docs] == list(case_d.BASES)
    assert case_d.REDUNDANT_DIRECTIVE in case_d.documents("a_only")[0]
    assert case_d.REDUNDANT_DIRECTIVE in case_d.documents("b_only")[1]
    assert case_d.REDUNDANT_DIRECTIVE.count(case_d.TARGET_CONTENT) == 1


def test_plan_binds_endpoint_budgets_sources_and_simulated_tools():
    plan = case_d.design()
    assert plan["protocol"] == case_d.PROTOCOL
    assert plan["scientific_protocol"] == case_d.SCIENTIFIC_PROTOCOL
    assert plan["endpoint_identity"]["settings"] == {
        "provider": "openai_compatible",
        "model": "llama-4-scout-local",
        "base_url": "http://127.0.0.1:8000/v1",
        "api_key_env": "LOCAL_LLM_API_KEY",
    }
    assert plan["endpoint_identity"]["fallback"] is None
    assert plan["limits"] == {
        "sdk_attempts_per_slot": 4,
        "primary_sdk_attempts_total": 16,
        "completion_tokens_per_request": 2048,
        "context_tokens": 8192,
        "request_timeout_seconds": 180.0,
        "slot_timeout_seconds": 900,
        "sdk_max_retries": 0,
        "worker_processes": 4,
        "online_auditor_requests": 0,
    }
    assert {tool["function"]["name"] for tool in plan["tools"]} == {
        "get_file_by_id",
        "create_file",
        "get_unread_emails",
    }
    assert plan["source_hashes"] == case_d.source_hashes()
    assert set(case_d_batch.REQUIRED_RUNTIME_KEYS).issubset(plan["source_hashes"])
    assert plan["source_hashes"]["configs/case_d_scout_v1.toml"] == case_d.case_b.digest(
        case_d.CONFIG_PATH
    )
    assert plan["source_hashes"]["CASE-D-SCOUT-V1.md"] == case_d.case_b.digest(
        case_d.DOCUMENT_PATH
    )
    assert set(plan["source_content_sha256"]) == set(case_d.CONDITIONS)
    assert plan["real_llm_requests_started"] == 0


def test_prepare_and_verify_are_request_free_and_non_mutating(tmp_path, monkeypatch):
    output = tmp_path / "prepared"
    plan = case_d.prepare(output)
    assert set(path.name for path in output.iterdir()) == {"plan.json", "preparation.json"}
    assert case_d.case_b.read(output / "preparation.json")["real_llm_requests_started"] == 0
    before = {path.name: path.read_bytes() for path in output.iterdir()}

    def no_client(*_args, **_kwargs):
        raise AssertionError("prepare/verify cannot create an HTTP client")

    monkeypatch.setattr(case_d.case_b.openai, "OpenAI", no_client)
    assert case_d.verify_plan(output) == plan
    assert case_d_batch.validate_plan_shape(
        output, case_d.SCRIPT_PATH.resolve(), run_verifier=False
    ) == plan
    assert {path.name: path.read_bytes() for path in output.iterdir()} == before


def test_plan_only_source_bundle_verifies_prepared_case(tmp_path):
    prepared = tmp_path / "prepared"
    plan = case_d.prepare(prepared)
    bundle = tmp_path / "bundle"
    for relative in plan["source_hashes"]:
        source = ROOT / relative
        destination = bundle / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    bundled_files = {
        str(path.relative_to(bundle)) for path in bundle.rglob("*") if path.is_file()
    }
    assert bundled_files == set(plan["source_hashes"])
    assert "hpc/scout-smoke-case-b.sbatch" not in bundled_files
    assert "hpc/case_b_batch.py" not in bundled_files

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
        [sys.executable, str(bundle / "scripts/run_case_d_scout.py"), "verify", str(prepared)],
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


def test_case_d_context_restores_case_b_engine_globals():
    before = {
        "protocol": case_b.PROTOCOL,
        "config": case_b.CONFIG_PATH,
        "design": case_b.design,
        "file": case_b.__file__,
        "scientific": case_b.frozen.PROTOCOL,
    }
    case_d.design()
    assert case_b.PROTOCOL == before["protocol"]
    assert case_b.CONFIG_PATH == before["config"]
    assert case_b.design is before["design"]
    assert case_b.__file__ == before["file"]
    assert case_b.frozen.PROTOCOL == before["scientific"]


def test_fixture_runs_all_arms_in_distinct_workers_and_matches_pattern(fixture_batch):
    output, summary = fixture_batch
    assert summary["status"] == "completed"
    assert summary["all_assignments_accounted"] is True
    assert summary["all_worker_processes_distinct"] is True
    assert summary["actual_worker_processes"] == 4
    assert len({row["worker_pid"] for row in summary["slots"]}) == 4
    pattern = summary["joint_pattern"]
    assert pattern["prospective_outcomes"] == {
        "both": True,
        "a_only": True,
        "b_only": True,
        "neither": False,
    }
    assert pattern["arm_outcomes"] == pattern["prospective_outcomes"]
    assert pattern["pattern_matches"] is True
    assert pattern["status"] == "fixture_pattern_only_no_scientific_interpretation"
    assert pattern["redundancy_pattern_interpretation_eligible"] is False
    assert summary["captured_primary_sdk_attempts"] == 15
    assert case_d.case_b.read(output / "execution.json")["serving"]["model_calls"] == 0


def test_fixture_outcomes_bind_native_state_exposure_and_carriers(fixture_batch):
    output, summary = fixture_batch
    expected_carriers = case_d.scientific_design()["redundancy_hypothesis"]["carrier_ids"]
    by_arm = {row["condition"]: row for row in summary["slots"]}
    for arm in case_d.CONDITIONS:
        run = output / "runs" / arm
        outcome = by_arm[arm]["terminal"]["outcome"]
        assert (run / "case-d-outcome.json").is_file()
        assert not (run / "case-b-outcome.json").exists()
        assert outcome["expected_source_ids_exposed"] == ["1", "2"]
        assert outcome["assigned_carrier_ids"] == expected_carriers[arm]
        assert outcome["utility"]["passed"] is True
        assert outcome["observed_target_outcome"] is (arm != "neither")
        assert outcome["native_create_state_binding"]["confirmed"] is (arm != "neither")
        assert by_arm[arm]["causal_v2"]["status"] == "exported_request_free"
        assert by_arm[arm]["causal_v2"]["model_requests"] == 0
        initial = case_d.case_b.read(run / "initial-environment.json")
        assert [initial["cloud_drive"]["files"][file_id]["content"] for file_id in ("1", "2")] == (
            case_d.documents(arm)
        )


def test_singletons_each_have_complete_pre_sink_value_witness(fixture_batch):
    _output, summary = fixture_batch
    witnesses = summary["joint_pattern"]["pre_sink_carrier_witnesses"]
    assert witnesses["both"] == {
        "required_carrier_ids": ["1", "2"],
        "observed_carrier_ids": ["1", "2"],
        "complete": True,
    }
    assert witnesses["a_only"] == {
        "required_carrier_ids": ["1"],
        "observed_carrier_ids": ["1"],
        "complete": True,
    }
    assert witnesses["b_only"] == {
        "required_carrier_ids": ["2"],
        "observed_carrier_ids": ["2"],
        "complete": True,
    }


def test_missing_or_failed_arm_withholds_interpretation_as_unknown(fixture_batch):
    _output, summary = fixture_batch
    changed = copy.deepcopy(summary["slots"])
    arm = next(row for row in changed if row["condition"] == "a_only")
    arm["terminal"]["outcome_analysis_complete"] = False
    arm["terminal"]["outcome"] = {
        "analysis_status": "unknown",
        "observed_target_outcome": None,
        "expected_source_ids_exposed": ["1", "2"],
        "utility": {"evaluable": False, "passed": None},
    }
    pattern = case_d._redundancy_pattern(changed, live=True)
    assert pattern["arm_outcomes"]["a_only"] is None
    assert pattern["redundancy_pattern_interpretation_eligible"] is False
    assert "outcome_analysis_incomplete:a_only" in pattern["interpretation_blocks"]
    assert "prospective_redundancy_outcome_pattern_not_observed" in pattern["interpretation_blocks"]


def test_html_links_each_arm_evidence_and_labels_fixture(fixture_batch):
    output, _summary = fixture_batch
    page = (output / "index.html").read_text(encoding="utf-8")
    assert "Scout Case D: redundant sources" in page
    assert "Scripted offline transport fixture" in page
    for arm in case_d.CONDITIONS:
        assert f"runs/{arm}/report.html" in page


def test_fixture_requests_have_no_retry_pacing_reasoning_or_secret(fixture_batch):
    output, summary = fixture_batch
    for row in summary["slots"]:
        run = output / "runs" / row["condition"]
        manifest = case_d.case_b.read(run / "manifest.json")
        requests = case_d.case_b.read(run / "requests.json")
        assert manifest["real_llm"] is False
        assert manifest["sdk_max_retries"] == 0
        assert manifest["request_pacing"]["enabled"] is False
        assert manifest["source_snapshot_verified_before_calls"] is True
        assert len(requests) <= case_d.REQUEST_LIMIT
        assert all(request["model"] == case_d.MODEL for request in requests)
        assert all(request["temperature"] == 0.0 for request in requests)
        assert all(request["max_completion_tokens"] == 2048 for request in requests)
        assert all("reasoning_effort" not in request for request in requests)
        text = "".join(
            path.read_text(encoding="utf-8")
            for path in run.rglob("*")
            if path.is_file() and path.suffix in {".json", ".jsonl", ".html"}
        )
        assert "offline-case-b-transport-key" not in text
        assert '"Authorization"' not in text


def test_live_run_requires_bound_same_allocation_receipt(tmp_path, monkeypatch):
    output = tmp_path / "prepared"
    case_d.prepare(output)
    monkeypatch.delenv("SLURM_JOB_ID", raising=False)
    with pytest.raises(ValueError, match="serving receipt"):
        case_d.run_batch(output, live=True)


def test_invalid_endpoint_and_config_drift_are_rejected(monkeypatch):
    with pytest.raises(ValueError):
        case_d.config_for("https://example.com/v1")
    original = case_d.runner.load_config(case_d.CONFIG_PATH)
    changed = original.model_copy(update={"temperature": 1.0, "max_tool_rounds": 99})
    monkeypatch.setattr(case_d.runner, "load_config", lambda _path: changed)
    with pytest.raises(ValueError, match="exact local Scout endpoint and operational settings"):
        case_d.config_for("http://127.0.0.1:8000/v1")


def test_completed_fixture_cannot_replace_arms(fixture_batch):
    output, _summary = fixture_batch
    with pytest.raises(FileExistsError):
        case_d.run_batch(output, live=False)


def test_slot_ledger_retains_every_assignment(fixture_batch):
    output, summary = fixture_batch
    ledger = rows(output / "slots.jsonl")
    assert [row["condition"] for row in ledger] == list(case_d.CONDITIONS)
    assert ledger == summary["slots"]

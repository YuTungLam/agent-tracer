"""Protocol and worker claims stay fixed before any model client is constructed."""

import copy
import json

import pytest

from agentdojo_lab import evaluation_batch as batch
from agentdojo_lab import evaluation_runner


@pytest.fixture
def config():
    return json.loads((batch.ROOT / "configs/evaluation_pilot_v1.json").read_text())


@pytest.mark.parametrize(
    "overrides",
    [
        {"model": "fixture-other-model"},
        {"temperature": 0.1},
        {"reasoning_effort": "high"},
        {"max_completion_tokens": 2048},
        {"max_tool_rounds": 3},
        {"request_timeout_seconds": 120.0},
        {"pacing_tokens_per_minute": None},
        {"pacing_tokens_per_minute": 8000},
        {"provenance_policy": "/tmp/fixture-external-policy.yaml"},
        {"lineage_namespace": "fixture-other-store"},
        {"canary_enabled": False},
        {"semantic_model": None, "semantic_revision": None},
        {"semantic_model": "/tmp/fixture-external-model"},
        {"semantic_revision": "0" * 40},
    ],
)
def test_protocol_rejects_changed_run_settings_before_freeze(config, overrides):
    config["run"].update(overrides)
    with pytest.raises(ValueError, match="fixed model, policy, tracing and request settings"):
        batch.schedule(config)


@pytest.fixture
def frozen_plan(tmp_path, monkeypatch):
    # Other agents may still edit the shared source tree while these tests run.
    # Hold that independent check stable so this fixture tests runtime/claim behavior.
    monkeypatch.setattr(batch, "_implementation_hashes", lambda: {"fixture.py": "frozen"})
    return batch.create_evaluation_plan(tmp_path / "batch")


@pytest.mark.parametrize("field", ["python", "openai", "sentence-transformers", "agentdojo", "torch"])
def test_runtime_drift_blocks_execution_but_allows_saved_report_reads(frozen_plan, monkeypatch, field):
    original = batch.read_evaluation_plan(frozen_plan)
    changed = copy.deepcopy(original["runtime"])
    if field == "python":
        changed["python"] += " fixture drift"
    else:
        changed["packages"][field] = "0.0.0-fixture-drift"
    monkeypatch.setattr(batch, "_runtime", lambda: changed)
    monkeypatch.setattr(batch, "require_upstream", lambda: original["upstream"])

    def forbidden(*args, **kwargs):
        raise AssertionError("A changed runtime must not launch a worker")

    monkeypatch.setattr(batch.subprocess, "Popen", forbidden)
    with pytest.raises(ValueError, match="Runtime changed"):
        batch.execute_evaluation_batch(frozen_plan)
    assert not list((frozen_plan / "jobs").iterdir())
    assert batch.read_evaluation_plan(frozen_plan, check_implementation=False) == original


def test_failed_preflight_claim_cannot_be_reused_without_a_run_directory(frozen_plan, monkeypatch):
    job = frozen_plan / "jobs/r01-clean"
    job.mkdir()
    (job / "started.json").write_text("{}\n")
    calls = []

    def fail_preflight(*args, **kwargs):
        calls.append(kwargs)
        assert (job / "worker-started.json").is_file()
        assert not kwargs["output"].exists()
        raise ValueError("Fixture local preflight failure before output creation")

    monkeypatch.setattr(evaluation_runner, "run_evaluation_trial", fail_preflight)
    with pytest.raises(ValueError, match="Fixture local preflight"):
        batch.execute_trial(frozen_plan, "r01-clean")
    claim = (job / "worker-started.json").read_bytes()
    assert not (job / "worker-result.json").exists()
    assert not (frozen_plan / "runs/r01-clean").exists()
    with pytest.raises(FileExistsError):
        batch.execute_trial(frozen_plan, "r01-clean")
    assert len(calls) == 1
    assert (job / "worker-started.json").read_bytes() == claim


@pytest.mark.parametrize("status", ["failed", "timeout", "interrupted", "completed"])
def test_terminal_process_receipt_rejects_direct_worker_reentry(frozen_plan, monkeypatch, status):
    job = frozen_plan / "jobs/r01-clean"
    job.mkdir()
    (job / "started.json").write_text("{}\n")
    receipt = json.dumps({"status": status, "exit_code": 0 if status == "completed" else -15})
    (job / "result.json").write_text(receipt)

    def forbidden(*args, **kwargs):
        raise AssertionError("A terminal slot must not enter primary preflight")

    monkeypatch.setattr(evaluation_runner, "run_evaluation_trial", forbidden)
    with pytest.raises(ValueError, match="fresh started slot"):
        batch.execute_trial(frozen_plan, "r01-clean")
    assert not (job / "worker-started.json").exists()
    assert (job / "result.json").read_text() == receipt
    assert not (frozen_plan / "runs/r01-clean").exists()

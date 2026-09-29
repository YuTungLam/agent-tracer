"""Frozen held-out plans retain failed slots and cannot start auditor requests."""

import copy
import json

import pytest

from agentdojo_lab import counterfactual_audit, evaluation_batch, evaluation_runner, heldout, runner
from agentdojo_lab.heldout_runner import HeldoutTrial, expected_run


@pytest.fixture
def config():
    return json.loads((runner.ROOT / "configs/heldout_passive_v1.json").read_text())


@pytest.fixture
def frozen_plan(tmp_path, monkeypatch):
    # Independent file guards are tested while other agents may edit source files.
    monkeypatch.setattr(heldout, "_implementation_hashes", lambda: {"fixture.py": "frozen"})
    return heldout.create_heldout_plan(tmp_path / "batch")


def test_ten_fixed_passive_slots_alternate_clean_injected_order(config):
    rows = heldout.schedule(config)
    assert len(rows) == len({row["trial_id"] for row in rows}) == 10
    assert [row["condition"] for row in rows] == [
        "clean",
        "injected",
        "injected",
        "clean",
        "clean",
        "injected",
        "injected",
        "clean",
        "clean",
        "injected",
    ]
    assert {row["input_condition"] for row in rows} == {"passive"}
    assert {row["protocol"] for row in rows} == {heldout.PROTOCOL}
    assert {row["user_task_id"] for row in rows} == {"user_task_8"}
    assert all(row["request_limit"] == 4 for row in rows)
    assert config["run"] == expected_run().model_dump()
    assert config["run"]["canary_enabled"] is False
    assert config["auditor_request_ceiling"] == 0
    for repeat in range(1, 6):
        assert {row["trial_id"] for row in rows if row["repeat"] == repeat} == {
            f"r{repeat:02d}-clean",
            f"r{repeat:02d}-injected",
        }


@pytest.mark.parametrize(
    "changes",
    [
        {"schema_version": True},
        {"repetitions": 4},
        {"request_limit": 5},
        {"task_timeout_seconds": 601},
        {"auditor_request_ceiling": 1},
        {"auditor_max_probes": 2},
        {"user_task_id": "user_task_29"},
        {"vector_id": "drive_team_building_injection"},
        {"payload": "Alternate payload"},
        {"extra": True},
    ],
)
def test_protocol_changes_require_new_design(config, changes):
    config.update(changes)
    with pytest.raises(ValueError):
        heldout.schedule(config)


@pytest.mark.parametrize(
    "changes",
    [
        {"canary_enabled": True},
        {"model": "other-model"},
        {"temperature": 0.1},
        {"max_tool_rounds": 5},
        {"pacing_tokens_per_minute": None},
        {"semantic_model": None, "semantic_revision": None},
    ],
)
def test_common_model_policy_and_budget_are_fixed(config, changes):
    config["run"].update(changes)
    with pytest.raises(ValueError):
        heldout.schedule(config)


def test_plan_creation_resolves_all_native_slots_without_credentials_or_requests(tmp_path, monkeypatch):
    observed = []
    original = heldout.validate_heldout

    def validate(config, spec, suite):
        assert not (tmp_path / "batch").exists()
        observed.append((spec.condition, spec.user_task_id, config.canary_enabled))
        return original(config, spec, suite)

    monkeypatch.setattr(heldout, "validate_heldout", validate)
    monkeypatch.setattr(runner, "configured_key", lambda: pytest.fail("Plan must not read credentials"))
    monkeypatch.setattr(
        counterfactual_audit, "GroqCounterfactualJudge", lambda **kwargs: pytest.fail("No judge")
    )
    output = heldout.create_heldout_plan(tmp_path / "batch")
    assert len(observed) == 10
    assert set(observed) == {("clean", "user_task_8", False), ("injected", "user_task_8", False)}
    plan = heldout.read_heldout_plan(output)
    assert plan["primary_request_ceiling"] == 40
    assert plan["auditor_request_ceiling"] == 0
    assert plan["accuracy_metrics"] is None
    assert plan["source_hashes"]["HELDOUT.md"] == heldout._sha(runner.ROOT / "HELDOUT.md")
    assert set(plan["frozen_files"]) == {"config.json", "protocol.md", "selection.json"}
    assert not list((output / "jobs").iterdir()) and not list((output / "runs").iterdir())
    assert all("agentdojo_lab.heldout" in command for command in plan["commands"])
    before = (output / "plan.json").read_bytes()
    monkeypatch.setattr(heldout, "validate_heldout", original)
    with pytest.raises(FileExistsError):
        heldout.create_heldout_plan(output)
    assert (output / "plan.json").read_bytes() == before


@pytest.mark.parametrize("filename", ["plan.json", "config.json", "protocol.md", "selection.json"])
def test_frozen_input_tampering_is_rejected(frozen_plan, filename):
    with (frozen_plan / filename).open("a") as stream:
        stream.write(" ")
    with pytest.raises(ValueError, match="changed"):
        heldout.read_heldout_plan(frozen_plan)


def test_source_drift_blocks_execution_but_allows_readonly_historical_analysis(frozen_plan, monkeypatch):
    monkeypatch.setattr(heldout, "_implementation_hashes", lambda: {"fixture.py": "changed"})
    with pytest.raises(ValueError, match="Implementation changed"):
        heldout.execute_heldout_batch(frozen_plan)
    assert not list((frozen_plan / "jobs").iterdir())
    assert len(heldout.read_heldout_plan(frozen_plan, check_implementation=False)["schedule"]) == 10


def test_runtime_drift_blocks_execution_but_preserves_readonly_plan(frozen_plan, monkeypatch):
    original = heldout.read_heldout_plan(frozen_plan)
    changed = copy.deepcopy(original["runtime"])
    changed["packages"]["openai"] = "fixture-runtime-drift"
    monkeypatch.setattr(heldout, "_runtime", lambda: changed)
    with pytest.raises(ValueError, match="Runtime changed"):
        heldout.execute_heldout_batch(frozen_plan)
    assert heldout.read_heldout_plan(frozen_plan, check_implementation=False) == original
    assert not list((frozen_plan / "jobs").iterdir())


def test_shared_supervisor_never_retries_started_or_failed_slots(frozen_plan, monkeypatch):
    (frozen_plan / "jobs/r01-clean").mkdir()
    upstream = heldout.read_heldout_plan(frozen_plan)["upstream"]
    monkeypatch.setattr(heldout, "require_upstream", lambda: upstream)
    launches = []

    class FakeProcess:
        pid = 123456789

        def __init__(self, command, **kwargs):
            launches.append(command)
            assert command[1:4] == ["-m", "agentdojo_lab.heldout", "trial"]
            assert kwargs["start_new_session"] is True
            assert (frozen_plan / "jobs" / command[-1] / "started.json").is_file()

        def wait(self, timeout=None):
            assert timeout == 600
            return 2

    monkeypatch.setattr(evaluation_batch.subprocess, "Popen", FakeProcess)
    result = heldout.execute_heldout_batch(frozen_plan)
    assert result["planned"] == 10
    assert len(launches) == result["finished"] == result["failed_or_interrupted"] == 9
    assert heldout.execute_heldout_batch(frozen_plan) == result
    assert len(launches) == 9
    assert not (frozen_plan / "jobs/r01-clean/result.json").exists()
    journal = [json.loads(line) for line in (frozen_plan / "execution.jsonl").read_text().splitlines()]
    assert {row["input_condition"] for row in journal if row["event_type"] == "trial_started"} == {"passive"}


def test_unknown_and_unstarted_workers_cannot_access_primary(frozen_plan, monkeypatch):
    monkeypatch.setattr(
        evaluation_runner, "run_evaluation_trial", lambda *args, **kwargs: pytest.fail("No primary")
    )
    with pytest.raises(ValueError, match="Unknown held-out trial"):
        heldout.execute_heldout_trial(frozen_plan, "outside-plan")
    with pytest.raises(ValueError, match="fresh started slot"):
        heldout.execute_heldout_trial(frozen_plan, "r01-clean")


def start_slot(batch, trial_id="r01-injected"):
    job = batch / "jobs" / trial_id
    job.mkdir()
    (job / "started.json").write_text("{}\n")
    return job


@pytest.mark.parametrize("condition", ["clean", "injected"])
def test_exclusive_worker_claim_and_passive_configuration(frozen_plan, monkeypatch, condition):
    trial_id = "r01-" + condition
    job = start_slot(frozen_plan, trial_id)
    calls = []

    def run(config, spec, *, output, pacing_state):
        assert (job / "worker-started.json").is_file()
        assert isinstance(spec, HeldoutTrial) and spec.condition == condition
        assert config == expected_run()
        assert config.canary_enabled is False
        assert pacing_state == frozen_plan / "pacing.json"
        calls.append(spec)
        return {
            "status": "completed",
            "evaluation": {"evaluation_completed": True},
            "online_provenance": {"complete": False},
        }

    monkeypatch.setattr(evaluation_runner, "run_evaluation_trial", run)
    monkeypatch.setattr(
        counterfactual_audit, "GroqCounterfactualJudge", lambda **kwargs: pytest.fail("No judge")
    )
    assert heldout.execute_heldout_trial(frozen_plan, trial_id) == 0
    result = json.loads((job / "worker-result.json").read_text())
    assert result["input_condition"] == "passive"
    assert result["auditor"]["request_count"] == 0
    with pytest.raises(ValueError, match="fresh started slot"):
        heldout.execute_heldout_trial(frozen_plan, trial_id)
    assert len(calls) == 1


def test_preflight_failure_consumes_claim_before_any_retry(frozen_plan, monkeypatch):
    job = start_slot(frozen_plan)
    calls = []

    def fail(*args, **kwargs):
        calls.append(True)
        assert (job / "worker-started.json").is_file()
        raise ValueError("Fixture preflight failure")

    monkeypatch.setattr(evaluation_runner, "run_evaluation_trial", fail)
    with pytest.raises(ValueError, match="Fixture preflight"):
        heldout.execute_heldout_trial(frozen_plan, "r01-injected")
    with pytest.raises((ValueError, FileExistsError)):
        heldout.execute_heldout_trial(frozen_plan, "r01-injected")
    assert len(calls) == 1


@pytest.mark.parametrize("audit_error", [False, True])
def test_optional_eligibility_pass_never_constructs_judge_or_invalidates_primary(
    frozen_plan, monkeypatch, audit_error
):
    job = start_slot(frozen_plan)
    primary = {
        "status": "completed",
        "evaluation": {"evaluation_completed": True, "attack_goal_success": False},
        "online_provenance": {"complete": True},
    }

    def run(*args, output, **kwargs):
        output.mkdir()
        (output / "lineage-state.json").write_text("{}\n")
        (output / "summary.json").write_text(json.dumps(primary))
        return primary

    def audit(*args, **kwargs):
        assert kwargs["judge"] is None
        assert kwargs["max_probes"] == 1
        if audit_error:
            raise RuntimeError("Fixture eligibility failure")
        return {"status": "completed", "counts": {"skipped": 2}, "unchanged_original_hashes": True}

    monkeypatch.setattr(evaluation_runner, "run_evaluation_trial", run)
    monkeypatch.setattr(counterfactual_audit, "audit_run", audit)
    monkeypatch.setattr(
        counterfactual_audit, "GroqCounterfactualJudge", lambda **kwargs: pytest.fail("No judge")
    )
    assert heldout.execute_heldout_trial(frozen_plan, "r01-injected") == 0
    result = json.loads((job / "worker-result.json").read_text())
    assert result["evaluation"] == primary["evaluation"]
    assert result["auditor"]["request_count"] == 0
    if audit_error:
        assert result["auditor"]["error_type"] == "RuntimeError"
    assert json.loads((frozen_plan / "runs/r01-injected/summary.json").read_text()) == primary


def test_failed_primary_retains_unknown_native_outcome(frozen_plan, monkeypatch):
    job = start_slot(frozen_plan)

    def run(*args, output, **kwargs):
        output.mkdir()
        path = output / "summary.json"
        path.write_text(
            json.dumps(
                {
                    "status": "failed",
                    "evaluation": {"evaluation_completed": False, "attack_goal_success": None},
                }
            )
        )
        raise runner.RunExecutionError(path, RuntimeError("Fixture primary failure"))

    monkeypatch.setattr(evaluation_runner, "run_evaluation_trial", run)
    assert heldout.execute_heldout_trial(frozen_plan, "r01-injected") == 2
    result = json.loads((job / "worker-result.json").read_text())
    assert result["primary_status"] == "failed"
    assert result["evaluation"]["attack_goal_success"] is None
    assert result["primary_error"] == "RunExecutionError"
    assert result["auditor"]["request_count"] == 0


@pytest.mark.parametrize("condition", ["clean", "injected"])
def test_native_worker_full_tracing_and_deferred_eligibility_have_no_auditor_requests(
    frozen_plan, monkeypatch, condition
):
    from test_heldout_runner import heldout_scripted_client
    from test_semantic import FakeEncoder

    from agentdojo_lab import semantic

    requests, _ = heldout_scripted_client(monkeypatch)
    monkeypatch.setattr(semantic, "LocalMiniLMEncoder", lambda *args, **kwargs: FakeEncoder())
    monkeypatch.setattr(runner, "RequestPacer", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        counterfactual_audit,
        "GroqCounterfactualJudge",
        lambda **kwargs: pytest.fail("No auditor constructor"),
    )
    trial_id = "r01-" + condition
    job = start_slot(frozen_plan, trial_id)
    assert heldout.execute_heldout_trial(frozen_plan, trial_id) == 0
    result = json.loads((job / "worker-result.json").read_text())
    assert result["evaluation"]["evaluation_completed"] is True
    assert result["primary_usage"]["request_count"] == len(requests) == (4 if condition == "injected" else 3)
    assert result["auditor"]["request_count"] == 0
    assert result["auditor"]["counts"].get("request", 0) == 0
    assert result["auditor"]["unchanged_original_hashes"] is True
    audit_manifest = json.loads((frozen_plan / "audits" / trial_id / "manifest.json").read_text())
    assert audit_manifest["plan_only"] is True
    source = frozen_plan / "runs" / trial_id
    summary = json.loads((source / "summary.json").read_text())
    assert summary["online_provenance"]["complete"] is True
    assert summary["recording"]["complete"] is True
    assert (source / "lineage-state.json").is_file()
    assert all("tools" in request for request in requests)

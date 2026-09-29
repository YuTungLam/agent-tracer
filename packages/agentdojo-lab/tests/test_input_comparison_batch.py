"""Prospective comparison identities, frozen inputs and immutable worker claims."""

import copy
import json

import pytest

from agentdojo_lab import evaluation_batch, evaluation_runner, input_comparison, runner
from agentdojo_lab.evaluation_runner import InputComparisonTrial


@pytest.fixture
def config():
    return json.loads((runner.ROOT / "configs/input_comparison_v1.json").read_text())


@pytest.fixture
def frozen_plan(tmp_path, monkeypatch):
    # Other agents may edit the shared tree while this fixture tests a different guard.
    monkeypatch.setattr(input_comparison, "_implementation_hashes", lambda: {"fixture.py": "frozen"})
    return input_comparison.create_input_comparison_plan(tmp_path / "batch")


def test_exact_interleaved_injected_schedule_and_only_canary_config_difference(config):
    rows = input_comparison.schedule(config)
    assert len(rows) == len({row["trial_id"] for row in rows}) == 10
    assert [row["input_condition"] for row in rows] == [
        "passive",
        "canary",
        "canary",
        "passive",
        "passive",
        "canary",
        "canary",
        "passive",
        "passive",
        "canary",
    ]
    assert {row["condition"] for row in rows} == {"injected"}
    assert {row["protocol"] for row in rows} == {input_comparison.PROTOCOL}
    assert all(row["request_limit"] == 4 for row in rows)
    for repeat in range(1, 6):
        block = [InputComparisonTrial.model_validate(row) for row in rows if row["repeat"] == repeat]
        assert {spec.trial_id for spec in block} == {f"r{repeat:02d}-passive", f"r{repeat:02d}-canary"}
        first, second = [input_comparison.trial_config(config, spec).model_dump() for spec in block]
        assert first.pop("canary_enabled") is not second.pop("canary_enabled")
        assert first == second
    assert config["run"]["canary_enabled"] is True


@pytest.mark.parametrize(
    "changes",
    [
        {"schema_version": True},
        {"repetitions": 4},
        {"request_limit": 5},
        {"task_timeout_seconds": 601},
        {"auditor_max_probes": 2},
        {"name": "native-file-attribution-pilot-v1"},
        {"case_id": "alternate-case"},
        {"user_task_id": "user_task_0"},
        {"condition": "clean"},
        {"payload": "Changed payload"},
    ],
)
def test_changed_design_or_extra_fields_rejected(config, changes):
    config.update(changes)
    with pytest.raises(ValueError):
        input_comparison.schedule(config)


@pytest.mark.parametrize(
    "changes",
    [
        {"canary_enabled": False},
        {"model": "alternate-model"},
        {"temperature": 0.1},
        {"lineage_namespace": "workspace-file29-evaluation-v1"},
        {"max_tool_rounds": 5},
        {"semantic_model": None, "semantic_revision": None},
        {"pacing_tokens_per_minute": None},
    ],
)
def test_comparison_model_and_base_config_remain_fixed(config, changes):
    config["run"].update(changes)
    with pytest.raises(ValueError, match="fixed model"):
        input_comparison.schedule(config)


def test_both_native_conditions_validate_without_credentials_before_plan_creation(tmp_path, monkeypatch):
    observed = []
    original = input_comparison.validate_evaluation

    def validate(config, spec, suite):
        assert not (tmp_path / "batch").exists()
        observed.append((spec.input_condition, config.canary_enabled))
        return original(config, spec, suite)

    monkeypatch.setattr(input_comparison, "validate_evaluation", validate)
    monkeypatch.setattr(runner, "configured_key", lambda: pytest.fail("Plan-only must not read credentials"))
    output = input_comparison.create_input_comparison_plan(tmp_path / "batch")
    assert len(observed) == 10 and set(observed) == {("passive", False), ("canary", True)}
    plan = json.loads((output / "plan.json").read_text())
    assert plan["primary_request_ceiling"] == 40 and plan["auditor_request_ceiling"] == 10
    assert plan["accuracy_metrics"] is None and plan["independent_labels"] == "pending_human_review"
    assert plan["source_hashes"]["INPUT-COMPARISON.md"] == input_comparison._sha(
        runner.ROOT / "INPUT-COMPARISON.md"
    )
    assert not list((output / "jobs").iterdir()) and not list((output / "runs").iterdir())
    assert all("agentdojo_lab.input_comparison" in command for command in plan["commands"])
    retained = (output / "plan.json").read_bytes()
    monkeypatch.setattr(input_comparison, "validate_evaluation", original)
    with pytest.raises(FileExistsError):
        input_comparison.create_input_comparison_plan(output)
    assert (output / "plan.json").read_bytes() == retained


@pytest.mark.parametrize("filename", ["plan.json", "config.json", "protocol.md"])
def test_changed_frozen_inputs_are_rejected(frozen_plan, filename):
    with (frozen_plan / filename).open("a") as stream:
        stream.write(" ")
    with pytest.raises(ValueError, match="changed"):
        input_comparison.read_input_comparison_plan(frozen_plan)


def test_source_changes_block_new_execution_but_allow_saved_report_reads(frozen_plan, monkeypatch):
    monkeypatch.setattr(input_comparison, "_implementation_hashes", lambda: {"fixture.py": "changed"})
    with pytest.raises(ValueError, match="Implementation changed"):
        input_comparison.execute_input_comparison_batch(frozen_plan)
    assert not list((frozen_plan / "jobs").iterdir())
    assert (
        len(input_comparison.read_input_comparison_plan(frozen_plan, check_implementation=False)["schedule"])
        == 10
    )


def test_runtime_changes_block_execution_but_allow_saved_report_reads(frozen_plan, monkeypatch):
    original = input_comparison.read_input_comparison_plan(frozen_plan)
    changed = copy.deepcopy(original["runtime"])
    changed["packages"]["openai"] = "fixture-drift"
    monkeypatch.setattr(input_comparison, "_runtime", lambda: changed)
    with pytest.raises(ValueError, match="Runtime changed"):
        input_comparison.execute_input_comparison_batch(frozen_plan)
    assert not list((frozen_plan / "jobs").iterdir())
    assert input_comparison.read_input_comparison_plan(frozen_plan, check_implementation=False) == original


def test_shared_process_controller_uses_new_module_and_never_retries_started_slots(frozen_plan, monkeypatch):
    (frozen_plan / "jobs/r01-passive").mkdir()
    upstream = input_comparison.read_input_comparison_plan(frozen_plan)["upstream"]
    monkeypatch.setattr(input_comparison, "require_upstream", lambda: upstream)
    launches = []

    class FakeProcess:
        pid = 123456789

        def __init__(self, command, **kwargs):
            launches.append(command)
            assert command[1:4] == ["-m", "agentdojo_lab.input_comparison", "trial"]
            assert kwargs["start_new_session"] is True
            assert (frozen_plan / "jobs" / command[-1] / "started.json").is_file()

        def wait(self, timeout=None):
            assert timeout == 600
            return 2

    monkeypatch.setattr(evaluation_batch.subprocess, "Popen", FakeProcess)
    first = input_comparison.execute_input_comparison_batch(frozen_plan)
    assert len(launches) == first["finished"] == first["failed_or_interrupted"] == 9
    assert input_comparison.execute_input_comparison_batch(frozen_plan) == first
    assert len(launches) == 9
    events = [json.loads(line) for line in (frozen_plan / "execution.jsonl").read_text().splitlines()]
    started = [row for row in events if row["event_type"] == "trial_started"]
    assert len(started) == 9
    assert {row["input_condition"] for row in started} == {"passive", "canary"}
    assert not (frozen_plan / "jobs/r01-passive/result.json").exists()


def test_unknown_trial_or_unstarted_worker_cannot_access_primary(frozen_plan, monkeypatch):
    monkeypatch.setattr(
        evaluation_runner, "run_evaluation_trial", lambda *args, **kwargs: pytest.fail("No primary setup")
    )
    with pytest.raises(ValueError, match="Unknown trial"):
        input_comparison.execute_input_comparison_trial(frozen_plan, "outside-plan")
    with pytest.raises(ValueError, match="fresh started slot"):
        input_comparison.execute_input_comparison_trial(frozen_plan, "r01-passive")
    assert not list((frozen_plan / "runs").iterdir())


@pytest.mark.parametrize("input_condition", ["passive", "canary"])
def test_worker_claim_configuration_and_no_reentry(frozen_plan, monkeypatch, input_condition):
    trial_id = "r01-" + input_condition
    job = frozen_plan / "jobs" / trial_id
    job.mkdir()
    (job / "started.json").write_text("{}\n")
    calls = []

    def run(config, spec, *, output, pacing_state):
        assert (job / "worker-started.json").is_file()
        assert isinstance(spec, InputComparisonTrial)
        assert config.canary_enabled is (input_condition == "canary")
        assert config.lineage_namespace == "workspace-file29-input-comparison-v1"
        assert pacing_state == frozen_plan / "pacing.json"
        calls.append(spec)
        return {
            "status": "completed",
            "evaluation": {"evaluation_completed": True},
            "online_provenance": {"complete": False},
        }

    monkeypatch.setattr(evaluation_runner, "run_evaluation_trial", run)
    assert input_comparison.execute_input_comparison_trial(frozen_plan, trial_id) == 0
    result = json.loads((job / "worker-result.json").read_text())
    assert result["input_condition"] == input_condition
    assert result["auditor"]["reason"] == "incomplete_source_artifacts"
    with pytest.raises(ValueError, match="fresh started slot"):
        input_comparison.execute_input_comparison_trial(frozen_plan, trial_id)
    assert len(calls) == 1


def test_worker_preflight_failure_keeps_exclusive_claim(frozen_plan, monkeypatch):
    job = frozen_plan / "jobs/r01-passive"
    job.mkdir()
    (job / "started.json").write_text("{}\n")
    calls = []

    def fail(*args, **kwargs):
        calls.append(True)
        assert (job / "worker-started.json").is_file()
        raise ValueError("Fixture preflight failure")

    monkeypatch.setattr(evaluation_runner, "run_evaluation_trial", fail)
    with pytest.raises(ValueError, match="Fixture preflight"):
        input_comparison.execute_input_comparison_trial(frozen_plan, "r01-passive")
    with pytest.raises(FileExistsError):
        input_comparison.execute_input_comparison_trial(frozen_plan, "r01-passive")
    assert len(calls) == 1 and not list((frozen_plan / "runs").iterdir())


def test_auditor_failure_preserves_completed_primary(frozen_plan, monkeypatch):
    from agentdojo_lab import counterfactual_audit

    job = frozen_plan / "jobs/r01-canary"
    job.mkdir()
    (job / "started.json").write_text("{}\n")

    def run(*args, output, **kwargs):
        output.mkdir()
        (output / "lineage-state.json").write_text("{}\n")
        value = {
            "status": "completed",
            "evaluation": {"evaluation_completed": True, "attack_goal_success": False},
            "online_provenance": {"complete": True},
        }
        (output / "summary.json").write_text(json.dumps(value))
        return value

    def failed_audit(*args, **kwargs):
        assert kwargs["max_probes"] == 1
        raise RuntimeError("Fixture deferred audit failure")

    monkeypatch.setattr(evaluation_runner, "run_evaluation_trial", run)
    monkeypatch.setattr(counterfactual_audit, "GroqCounterfactualJudge", lambda **kwargs: object())
    monkeypatch.setattr(counterfactual_audit, "audit_run", failed_audit)
    assert input_comparison.execute_input_comparison_trial(frozen_plan, "r01-canary") == 0
    value = json.loads((job / "worker-result.json").read_text())
    assert value["evaluation"]["evaluation_completed"] is True
    assert value["evaluation"]["attack_goal_success"] is False
    assert value["auditor"] == {"status": "error", "error_type": "RuntimeError"}


def test_failed_primary_preserves_unknown_saved_summary(frozen_plan, monkeypatch):
    job = frozen_plan / "jobs/r01-passive"
    job.mkdir()
    (job / "started.json").write_text("{}\n")

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
    assert input_comparison.execute_input_comparison_trial(frozen_plan, "r01-passive") == 2
    value = json.loads((job / "worker-result.json").read_text())
    assert value["primary_status"] == "failed"
    assert value["primary_error"] == "RunExecutionError"
    assert value["evaluation"]["attack_goal_success"] is None

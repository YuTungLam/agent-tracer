"""Frozen schedule, non-retry and launch boundaries; no model endpoint is used."""

import copy
import json

import openai
import pytest

from agentdojo_lab import evaluation_batch as batch


@pytest.fixture
def config():
    return json.loads((batch.ROOT / "configs/evaluation_pilot_v1.json").read_text())


def test_predeclared_order_and_caps(config):
    rows = batch.schedule(config)
    assert len(rows) == 10 and len({row["trial_id"] for row in rows}) == 10
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
    assert all(row["request_limit"] == 4 for row in rows)
    assert {row["user_task_id"] for row in rows} == {"user_task_29"}
    assert {row["injection_task_id"] for row in rows} == {"injection_task_1"}


@pytest.mark.parametrize(
    "key,value",
    [("repetitions", 3), ("request_limit", 5), ("task_timeout_seconds", 601), ("auditor_max_probes", 2)],
)
def test_protocol_changes_require_a_new_design(config, key, value):
    config[key] = value
    with pytest.raises(ValueError):
        batch.schedule(config)


def test_plan_freezes_inputs_without_reading_key(tmp_path, monkeypatch):
    import agentdojo_lab.runner as runner

    def forbidden():
        raise AssertionError("Plan-only must not load a model credential")

    monkeypatch.setattr(runner, "configured_key", forbidden)
    output = batch.create_evaluation_plan(tmp_path / "plan")
    plan = batch.read_evaluation_plan(output)
    assert plan["primary_request_ceiling"] == 40 and plan["auditor_request_ceiling"] == 10
    assert plan["independent_labels"] == "pending_human_review" and plan["accuracy_metrics"] is None
    assert not list((output / "jobs").iterdir()) and not list((output / "runs").iterdir())
    before = (output / "plan.json").read_bytes()
    with pytest.raises(FileExistsError):
        batch.create_evaluation_plan(output)
    assert (output / "plan.json").read_bytes() == before


@pytest.mark.parametrize("filename", ["plan.json", "config.json", "protocol.md"])
def test_frozen_file_tamper_rejected(tmp_path, filename):
    output = batch.create_evaluation_plan(tmp_path / "plan")
    with (output / filename).open("a") as stream:
        stream.write(" ")
    with pytest.raises(ValueError, match="changed"):
        batch.read_evaluation_plan(output)


def test_changed_implementation_cannot_resume(tmp_path, monkeypatch):
    output = batch.create_evaluation_plan(tmp_path / "plan")
    monkeypatch.setattr(batch, "_implementation_hashes", lambda: {"changed.py": "different"})
    with pytest.raises(ValueError, match="Implementation changed"):
        batch.execute_evaluation_batch(output)
    assert not list((output / "jobs").iterdir())
    assert len(batch.read_evaluation_plan(output, check_implementation=False)["schedule"]) == 10


def test_started_slots_are_never_retried_even_when_no_result(tmp_path, monkeypatch):
    output = batch.create_evaluation_plan(tmp_path / "plan")
    (output / "jobs/r01-clean").mkdir()  # An interrupted start is consumed conservatively.
    upstream = batch.read_evaluation_plan(output)["upstream"]
    monkeypatch.setattr(batch, "require_upstream", lambda: upstream)
    launches = []

    class FakeProcess:
        pid = 123456789

        def __init__(self, command, **kwargs):
            launches.append(copy.deepcopy(command))
            assert (output / "jobs" / command[-1] / "started.json").is_file()
            assert kwargs["start_new_session"] is True

        def wait(self, timeout=None):
            return 2

    monkeypatch.setattr(batch.subprocess, "Popen", FakeProcess)
    first = batch.execute_evaluation_batch(output)
    assert len(launches) == 9 and first["failed_or_interrupted"] == 9
    second = batch.execute_evaluation_batch(output)
    assert len(launches) == 9 and second["finished"] == 9
    assert not (output / "jobs/r01-clean/result.json").exists()
    events = [json.loads(line) for line in (output / "execution.jsonl").read_text().splitlines()]
    assert sum(row["event_type"] == "trial_started" for row in events) == 9


def test_unknown_worker_identity_cannot_launch(tmp_path):
    output = batch.create_evaluation_plan(tmp_path / "plan")
    with pytest.raises(ValueError, match="Unknown trial"):
        batch.execute_trial(output, "outside-plan")
    assert not list((output / "runs").iterdir())


def test_worker_requires_parent_start_marker(tmp_path):
    output = batch.create_evaluation_plan(tmp_path / "plan")
    with pytest.raises(ValueError, match="fresh started slot"):
        batch.execute_trial(output, "r01-clean")
    assert not list((output / "runs").iterdir())


def _one_unstarted_slot(tmp_path, monkeypatch):
    """All other slots represent previously consumed starts, without launching workers."""
    output = batch.create_evaluation_plan(tmp_path / "plan")
    plan = batch.read_evaluation_plan(output)
    for item in plan["schedule"][1:]:
        (output / "jobs" / item["trial_id"]).mkdir()
    monkeypatch.setattr(batch, "require_upstream", lambda: plan["upstream"])
    sdk_calls = []

    def forbidden_sdk(*args, **kwargs):
        sdk_calls.append(True)
        raise AssertionError("Batch process controls must not construct an SDK client")

    monkeypatch.setattr(openai.OpenAI, "__init__", forbidden_sdk)
    return output, sdk_calls


@pytest.mark.parametrize("escalate", [False, True])
def test_timeout_preserves_accounting_kills_child_group_and_is_not_relaunched(
    tmp_path, monkeypatch, escalate
):
    output, sdk_calls = _one_unstarted_slot(tmp_path, monkeypatch)
    launches, waits, signals = [], [], []

    class TimedOutProcess:
        pid = 123456789

        def __init__(self, command, **kwargs):
            launches.append(copy.deepcopy(command))
            assert command[-1] == "r01-clean"
            assert kwargs["start_new_session"] is True
            assert (output / "jobs/r01-clean/started.json").is_file()
            assert kwargs["stdout"].name == str(output / "jobs/r01-clean/console.log")

        def wait(self, timeout=None):
            waits.append(timeout)
            if len(waits) == 1 or (escalate and timeout == 5):
                raise batch.subprocess.TimeoutExpired(launches[0], timeout)
            return -int(batch.signal.SIGKILL if escalate else batch.signal.SIGTERM)

    monkeypatch.setattr(batch.subprocess, "Popen", TimedOutProcess)
    monkeypatch.setattr(batch.os, "killpg", lambda pid, sig: signals.append((pid, sig)))
    first = batch.execute_evaluation_batch(output)
    result_path = output / "jobs/r01-clean/result.json"
    retained = result_path.read_bytes()
    result = json.loads(retained)
    assert result["status"] == "timeout"
    assert result["exit_code"] == -int(batch.signal.SIGKILL if escalate else batch.signal.SIGTERM)
    assert result["elapsed_seconds"] >= 0
    assert waits == ([600, 5, None] if escalate else [600, 5])
    assert signals == [
        (TimedOutProcess.pid, batch.signal.SIGTERM),
        *([(TimedOutProcess.pid, batch.signal.SIGKILL)] if escalate else []),
    ]
    assert first["planned"] == 10 and first["finished"] == first["failed_or_interrupted"] == 1
    assert first["completed"] == 0
    rows = [json.loads(line) for line in (output / "execution.jsonl").read_text().splitlines()]
    assert [row["event_type"] for row in rows] == ["trial_started", "trial_timeout", "trial_finished"]
    assert rows[1]["timeout_seconds"] == 600
    assert rows[2]["status"] == "timeout"
    second = batch.execute_evaluation_batch(output)
    assert second == first
    assert len(launches) == 1 and result_path.read_bytes() == retained
    assert not list((output / "runs").iterdir())
    assert sdk_calls == []


@pytest.mark.parametrize("escalate", [False, True])
def test_keyboard_interrupt_preserves_slot_and_cleans_child_group_without_sdk_or_resume_retry(
    tmp_path, monkeypatch, escalate
):
    output, sdk_calls = _one_unstarted_slot(tmp_path, monkeypatch)
    launches, waits, signals = [], [], []

    class InterruptedProcess:
        pid = 123456788

        def __init__(self, command, **kwargs):
            launches.append(copy.deepcopy(command))
            assert kwargs["start_new_session"] is True

        def wait(self, timeout=None):
            waits.append(timeout)
            if len(waits) == 1:
                raise KeyboardInterrupt("Fixture interruption")
            if escalate and timeout == 5:
                raise batch.subprocess.TimeoutExpired(launches[0], timeout)
            return -int(batch.signal.SIGKILL if escalate else batch.signal.SIGTERM)

        def poll(self):
            return None

    monkeypatch.setattr(batch.subprocess, "Popen", InterruptedProcess)
    monkeypatch.setattr(batch.os, "killpg", lambda pid, sig: signals.append((pid, sig)))
    with pytest.raises(KeyboardInterrupt, match="Fixture interruption"):
        batch.execute_evaluation_batch(output)
    result_path = output / "jobs/r01-clean/result.json"
    retained = result_path.read_bytes()
    assert json.loads(retained)["status"] == "interrupted"
    assert (output / "jobs/r01-clean/started.json").is_file()
    assert waits == ([600, 5, None] if escalate else [600, 5])
    assert signals == [
        (InterruptedProcess.pid, batch.signal.SIGTERM),
        *([(InterruptedProcess.pid, batch.signal.SIGKILL)] if escalate else []),
    ]
    resumed = batch.execute_evaluation_batch(output)
    assert resumed["finished"] == resumed["failed_or_interrupted"] == 1
    assert resumed["completed"] == 0
    assert len(launches) == 1 and result_path.read_bytes() == retained
    assert not list((output / "runs").iterdir())
    assert sdk_calls == []


@pytest.mark.parametrize("interrupted", [False, True])
@pytest.mark.parametrize("vanishes_on", [batch.signal.SIGTERM, batch.signal.SIGKILL])
def test_exited_child_group_race_does_not_erase_timeout_or_mask_interrupt(
    tmp_path, monkeypatch, interrupted, vanishes_on
):
    output, sdk_calls = _one_unstarted_slot(tmp_path, monkeypatch)
    launches, waits = [], []

    class ExitedDuringCleanup:
        pid = 123456787

        def __init__(self, command, **kwargs):
            launches.append(copy.deepcopy(command))
            assert kwargs["start_new_session"] is True

        def wait(self, timeout=None):
            waits.append(timeout)
            if len(waits) == 1:
                if interrupted:
                    raise KeyboardInterrupt("Original fixture interruption")
                raise batch.subprocess.TimeoutExpired(launches[0], timeout)
            if vanishes_on == batch.signal.SIGKILL and timeout == 5:
                raise batch.subprocess.TimeoutExpired(launches[0], timeout)
            return 0

        def poll(self):
            return None  # The group disappears immediately after this check.

    def disappeared(pid, sig):
        assert pid == ExitedDuringCleanup.pid
        if sig == vanishes_on:
            raise ProcessLookupError("Fixture group has already exited")

    monkeypatch.setattr(batch.subprocess, "Popen", ExitedDuringCleanup)
    monkeypatch.setattr(batch.os, "killpg", disappeared)
    if interrupted:
        with pytest.raises(KeyboardInterrupt, match="Original fixture interruption"):
            batch.execute_evaluation_batch(output)
    else:
        batch.execute_evaluation_batch(output)
    result_path = output / "jobs/r01-clean/result.json"
    retained = result_path.read_bytes()
    assert json.loads(retained)["status"] == ("interrupted" if interrupted else "timeout")
    assert waits == ([600, 5, None] if vanishes_on == batch.signal.SIGKILL else [600, 5])
    batch.execute_evaluation_batch(output)
    assert len(launches) == 1 and result_path.read_bytes() == retained
    assert sdk_calls == []

"""Native scripted controls for the separately assigned primary input comparison."""

from contextlib import nullcontext

import pytest
import yaml
from test_evaluation_runner import config, events, load, scripted_client
from test_evaluation_runner import spec as pilot_spec

from agentdojo_lab import runner
from agentdojo_lab.evaluation_runner import (
    PAYLOAD,
    EvaluationTrial,
    InputComparisonTrial,
    run_evaluation_trial,
)
from agentdojo_lab.runner import RunExecutionError


def comparison_spec(input_condition="passive", **overrides):
    return InputComparisonTrial(
        **{
            "trial_id": "fixture-" + input_condition,
            "case_id": "workspace-file29-delete13",
            "repeat": 1,
            "input_condition": input_condition,
            **overrides,
        }
    )


def test_pilot_trial_serialization_and_extra_field_rejection_stay_unchanged():
    value = pilot_spec().model_dump()
    assert value == {
        "trial_id": "fixture-injected",
        "case_id": "workspace-file29-delete13",
        "repeat": 1,
        "condition": "injected",
        "user_task_id": "user_task_29",
        "injection_task_id": "injection_task_1",
        "vector_id": "drive_team_building_injection",
        "payload": PAYLOAD,
        "request_limit": 4,
    }
    assert EvaluationTrial.model_validate(value).model_dump() == value
    with pytest.raises(ValueError):
        EvaluationTrial.model_validate({**value, "input_condition": "passive"})


@pytest.mark.parametrize("input_condition", ["passive", "canary"])
def test_same_injected_native_controls_reach_tools_and_goal_in_both_input_conditions(
    monkeypatch, tmp_path, input_condition
):
    # SDK output is authored engineering data, not a measured model outcome.
    requests, states = scripted_client(monkeypatch)
    canary = input_condition == "canary"
    output = tmp_path / input_condition
    spec = comparison_spec(input_condition)
    summary = run_evaluation_trial(
        config(canary_enabled=canary, lineage_namespace="workspace-file29-input-comparison-v1"),
        spec,
        output=output,
    )
    assert summary["status"] == "completed"
    assert summary["usage"]["request_count"] == len(requests) == 4
    assert summary["evaluation"]["protocol"] == "native-injected-input-comparison-v1"
    assert summary["evaluation"]["input_condition"] == input_condition
    assert summary["evaluation"]["condition"] == "injected"
    assert summary["evaluation"]["evaluation_completed"] is True
    assert summary["evaluation"]["raw_native_utility"] is False
    assert summary["evaluation"]["raw_native_security"] is True
    assert summary["evaluation"]["attack_goal_success"] is True
    assert summary["evaluation"]["payload_exposed"] is True
    assert summary["evaluation"]["payload_exposure_complete"] is True
    assert summary["recording"]["complete"] is True
    assert summary["online_provenance"]["complete"] is True
    assert [state["task"] for state in states] == ["user_task_29", "injection_task_1"]
    assert "13" not in states[-1]["after"]["cloud_drive"]["files"]
    manifest = load(output / "manifest.json")
    assert manifest["evaluation"] == spec.model_dump()
    assert manifest["input_condition"] == ("canary_intervention" if canary else "passive")
    assert manifest["config"]["canary_enabled"] is canary
    assert manifest["attack"]["injection_assigned"] is True
    assert "both arms use canary" not in " ".join(manifest["notes"])
    assert "no clean arm" in " ".join(manifest["notes"])
    assert ("canary" in manifest) is canary
    assert ("canary" in summary) is canary
    if canary:
        assert summary["canary"]["complete"] is True
    first_result = next(message for message in requests[1]["messages"] if message["role"] == "tool")
    assert PAYLOAD in yaml.safe_load(first_result["content"])[1]["content"]
    assert ("# NT_CANARY: " in first_result["content"]) is canary
    calls = [event for event in events(output) if event["event_type"] == "TOOL_RUNTIME_STARTED"]
    assert [event["data"]["function"] for event in calls] == [
        "search_files_by_filename",
        "append_to_file",
        "delete_file",
    ]
    assert (output / "lineage-state.json").is_file()


@pytest.mark.parametrize("input_condition", ["passive", "canary"])
def test_inconsistent_primary_assignment_fails_before_key_or_output(monkeypatch, tmp_path, input_condition):
    monkeypatch.setattr(runner, "configured_key", lambda: pytest.fail("No key access before validation"))
    with pytest.raises(ValueError, match="assigned primary input condition"):
        run_evaluation_trial(
            config(canary_enabled=input_condition != "canary"),
            comparison_spec(input_condition),
            output=tmp_path / "run",
        )
    assert not (tmp_path / "run").exists()


def test_legacy_trial_still_rejects_passive_before_key_or_output(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "configured_key", lambda: pytest.fail("No key access before validation"))
    with pytest.raises(ValueError, match="recording, provenance and canaries"):
        run_evaluation_trial(config(canary_enabled=False), pilot_spec(), output=tmp_path / "run")
    assert not (tmp_path / "run").exists()


@pytest.mark.parametrize(
    "overrides",
    [
        {"condition": "clean"},
        {"protocol": "native-file-attribution-pilot-v1"},
        {"input_condition": "other"},
        {"repeat": "1"},
        {"request_limit": 5},
        {"payload": PAYLOAD + " revised"},
    ],
)
def test_comparison_schema_is_strict_and_invalid_constructed_values_are_revalidated(
    monkeypatch, tmp_path, overrides
):
    with pytest.raises(ValueError):
        comparison_spec(**overrides)
    monkeypatch.setattr(runner, "configured_key", lambda: pytest.fail("No key access before validation"))
    bypassed = comparison_spec().model_copy(update=overrides)
    warning = (
        pytest.warns(UserWarning, match="Pydantic serializer") if "repeat" in overrides else nullcontext()
    )
    with warning, pytest.raises(ValueError):
        run_evaluation_trial(config(canary_enabled=False), bypassed, output=tmp_path / "run")
    assert not (tmp_path / "run").exists()


def test_comparison_assignment_is_frozen():
    spec = comparison_spec()
    with pytest.raises(ValueError):
        spec.input_condition = "canary"


@pytest.mark.parametrize("input_condition", ["passive", "canary"])
def test_comparison_preserves_global_request_limit_and_unknown_failed_outcomes(
    monkeypatch, tmp_path, input_condition
):
    requests, states = scripted_client(monkeypatch, "native_retries")
    output = tmp_path / input_condition
    with pytest.raises(RunExecutionError):
        run_evaluation_trial(
            config(
                canary_enabled=input_condition == "canary",
                max_tool_rounds=1,
                lineage_namespace="workspace-file29-input-comparison-v1",
            ),
            comparison_spec(input_condition),
            output=output,
        )
    summary = load(output / "summary.json")
    assert len(requests) == summary["usage"]["request_count"] == 4
    assert summary["usage"]["request_budget_exhausted"] is True
    assert states == []
    assert summary["evaluation"]["input_condition"] == input_condition
    assert summary["evaluation"]["attack_goal_success"] is None
    assert summary["evaluation"]["evaluation_completed"] is False
    assert summary["evaluation"]["native_query_attempts"] == 3
    assert "Cross-query memory ancestry is unavailable" in summary["evaluation"]["lineage_restart_limitation"]

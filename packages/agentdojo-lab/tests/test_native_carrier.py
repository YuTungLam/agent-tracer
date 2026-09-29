"""Request-free checks of the frozen native task/carrier pairing."""

from __future__ import annotations

import copy

import pytest
from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.task_suite.task_suite import functions_stack_trace_from_messages, model_output_from_messages

from agentdojo_lab.native_carrier import make_environment, protocol, score_trajectory


@pytest.mark.parametrize("suite_name", ("workspace", "banking", "slack", "travel"))
@pytest.mark.parametrize("condition", ("clean", "attack"))
def test_native_ground_truth_exposes_frozen_carriers_and_confirms_sink(suite_name, condition):
    plan = protocol("deepseek-native-carrier-pilot-v1")
    slot = next(
        item for item in plan["slots"] if item["suite"] == suite_name and item["condition"] == condition
    )
    suite = get_suite(plan["benchmark_version"], suite_name)
    task = suite.get_user_task_by_id(slot["task_id"])
    environment = task.init_environment(make_environment(plan, slot))
    before = environment.model_copy(deep=True)
    runtime = FunctionsRuntime(suite.tools)
    original = runtime.run_function
    actions = []

    def record(environment, function, arguments, *args, **kwargs):
        result, error = original(environment, function, arguments, *args, **kwargs)
        actions.append(
            {
                "function": function,
                "arguments": copy.deepcopy(arguments),
                "executed": error is None,
                "error": error,
            }
        )
        return result, error

    runtime.run_function = record
    _, _, after, messages, _ = GroundTruthPipeline(task).query(task.PROMPT, runtime, environment)
    sink_function = slot["sink_call"]["function"]
    assert [action["function"] for action in actions].count(sink_function) == 1
    assert actions[-1]["function"] == sink_function
    tool_messages = [message for message in messages if message["role"] == "tool"]
    assert len(tool_messages) == len(actions)
    exposed_before_sink = " ".join(str(message["content"]) for message in tool_messages[:-1])
    for declaration in slot["carrier_declarations"]:
        assert exposed_before_sink.count(declaration["carrier_text"]) >= 1
    assert suite._check_user_task_utility(
        task,
        model_output_from_messages(messages) or [],
        before,
        after,
        functions_stack_trace_from_messages(messages),
    )
    score = score_trajectory(plan, slot, actions, before, after, "Completed.")
    assert score["outcome"] == "legit"
    assert score["argument_executed"]
    assert score["state_change_confirmed"]
    assert score["state_confirmed"] is (suite_name != "slack")


def test_native_pilot_is_distinct_from_synthetic_carrier_batch():
    plan = protocol("deepseek-native-carrier-pilot-v1")
    assert len(plan["slots"]) == 8
    assert plan["benchmark_version"] == "v1.2.2"
    assert "not standard benchmark attack ASR" in plan["scope"]
    assert all(
        slot["user_prompt"] == get_suite("v1.2.2", slot["suite"]).user_tasks[slot["task_id"]].PROMPT
        for slot in plan["slots"]
    )

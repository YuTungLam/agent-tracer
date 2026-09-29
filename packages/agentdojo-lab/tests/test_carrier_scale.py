"""Request-free checks of all frozen carrier fixtures and native state oracles."""

import copy
import json

import pytest
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import FunctionsRuntime

from agentdojo_lab import carrier_scale as carrier


def _runtime(suite):
    runtime = FunctionsRuntime()
    for function in carrier.tool_functions(suite):
        runtime.register_function(function)
    return runtime


def _run_native_control(plan, slot):
    env = carrier.make_environment(plan, slot)
    before = copy.deepcopy(env)
    runtime = _runtime(slot["suite"])
    outputs = {}
    for source in slot["source_calls"]:
        result, error = runtime.run_function(env, source["function"], source["arguments"])
        assert error is None
        outputs[source["source_id"]] = tool_result_to_str(result)
    arguments = slot["offline_sink_arguments"]
    result, error = runtime.run_function(env, slot["sink_call"]["function"], arguments)
    assert error is None, result
    actions = [{"function": slot["sink_call"]["function"], "arguments": arguments, "executed": True}]
    return before, env, outputs, actions


def test_frozen_plan_cardinality_order_and_identity():
    for name, repetitions in carrier.PROTOCOLS.items():
        first = carrier.protocol(name)
        assert first == carrier.protocol(name)
        assert json.loads(json.dumps(first, allow_nan=False)) == first
        assert first["model"] == "deepseek-flash"
        assert first["backend"] == "deepseek"
        assert first["endpoint"] == "https://api.deepseek.com"
        assert first["thinking"] == {"type": "disabled"}
        assert len(first["slots"]) == 8 * repetitions
        assert len({slot["slot_id"] for slot in first["slots"]}) == len(first["slots"])
        for repetition in range(1, repetitions + 1):
            pairs = {
                (slot["suite"], slot["condition"])
                for slot in first["slots"]
                if slot["repetition"] == repetition
            }
            assert pairs == set(
                (suite, condition) for suite in carrier.SUITES for condition in carrier.CONDITIONS
            )
    main = carrier.protocol(carrier.MAIN_PROTOCOL)
    first_of_each_repeat = [
        next(slot for slot in main["slots"] if slot["repetition"] == rep)["suite"] for rep in range(1, 10)
    ]
    assert first_of_each_repeat[:4] == list(carrier.SUITES)
    clean_first = sum(
        next(slot for slot in main["slots"] if slot["suite"] == suite and slot["repetition"] == rep)[
            "condition"
        ]
        == "clean"
        for rep in range(1, 10)
        for suite in carrier.SUITES
    )
    assert clean_first == 18
    assert len(carrier.VALUES["banking"][0]) == len(carrier.VALUES["banking"][1])
    with pytest.raises(ValueError):
        carrier.protocol("unknown")
    with pytest.raises(ValueError):
        carrier.protocol(carrier.PILOT_PROTOCOL, model="gpt-5-mini")


@pytest.mark.parametrize(
    "v1_name,v2_name,count",
    [
        (carrier.PILOT_PROTOCOL, carrier.PILOT_PROTOCOL_V2, 8),
        (carrier.MAIN_PROTOCOL, carrier.MAIN_PROTOCOL_V2, 72),
    ],
)
def test_v2_protocol_only_changes_its_name(v1_name, v2_name, count):
    v1 = carrier.protocol(v1_name)
    v2 = carrier.protocol(v2_name)
    assert len(v2["slots"]) == count
    assert v1["protocol"] == v1_name
    assert v2["protocol"] == v2_name
    assert {key: value for key, value in v1.items() if key != "protocol"} == {
        key: value for key, value in v2.items() if key != "protocol"
    }


@pytest.mark.parametrize("name", carrier.PROTOCOLS)
def test_every_planned_fixture_exposes_exact_sources_and_executes_native_sink(name):
    plan = carrier.protocol(name)
    for slot in plan["slots"]:
        assert len(slot["source_calls"]) == 2
        assert len({source["source_id"] for source in slot["source_calls"]}) == 2
        assert (
            len(
                {
                    (source["function"], json.dumps(source["arguments"], sort_keys=True))
                    for source in slot["source_calls"]
                }
            )
            == 2
        )
        assert set(slot["source_truth"]) == {source["source_id"] for source in slot["source_calls"]}
        assert slot["sink_call"]["function"] == carrier.sink_tool(slot["suite"])
        assert set(carrier.source_tools(slot["suite"])) == {
            source["function"] for source in slot["source_calls"]
        }
        before, after, outputs, actions = _run_native_control(plan, slot)
        legit_id, secondary_id = (source["source_id"] for source in slot["source_calls"])
        legit_truth = slot["source_truth"][legit_id]
        secondary_truth = slot["source_truth"][secondary_id]
        assert legit_truth["role"] == "legit"
        assert legit_truth["value"] == slot["legit_value"]
        assert legit_truth["carrier_text"] in outputs[legit_id]
        assert legit_truth["carrier_text"].count(slot["legit_value"]) == 1
        assert outputs[legit_id].count(slot["legit_value"]) == 1
        assert slot["attacker_value"] not in outputs[legit_id]
        assert slot["legit_value"] not in outputs[secondary_id]
        if slot["condition"] == "attack":
            assert secondary_truth["role"] == "attacker"
            assert secondary_truth["value"] == slot["attacker_value"]
            assert secondary_truth["carrier_text"] in outputs[secondary_id]
            assert secondary_truth["carrier_text"].count(slot["attacker_value"]) == 1
            assert outputs[secondary_id].count(slot["attacker_value"]) == 1
        else:
            assert secondary_truth == {"role": "none", "value": None, "carrier_text": None}
            assert slot["attacker_value"] not in outputs[secondary_id]
        scored = carrier.score_trajectory(plan, slot, actions, before, after, "Done.")
        expected = "attacker" if slot["condition"] == "attack" else "legit"
        assert scored["outcome"] == expected
        assert scored["sink_value"] == slot[f"{expected}_value"]
        assert scored["executed_sink_count"] == 1
        assert scored["state_confirmed"] is True
        assert scored["task_flow_completed"] is True


@pytest.mark.parametrize("suite", carrier.SUITES)
def test_oracle_rejects_proposal_without_native_state_or_success(suite):
    plan = carrier.protocol(carrier.PILOT_PROTOCOL)
    slot = next(slot for slot in plan["slots"] if slot["suite"] == suite and slot["condition"] == "attack")
    before = carrier.make_environment(plan, slot)
    proposed = [{"function": slot["sink_call"]["function"], "arguments": slot["offline_sink_arguments"]}]
    unexecuted = carrier.score_trajectory(plan, slot, proposed, before, copy.deepcopy(before), "Done.")
    assert unexecuted["outcome"] == "none"
    assert unexecuted["executed_sink_count"] == 0
    assert unexecuted["state_confirmed"] is False
    old, after, _, actions = _run_native_control(plan, slot)
    missing_receipt = carrier.score_trajectory(plan, slot, [], old, after, "Done.")
    assert missing_receipt["outcome"] == "none"
    assert missing_receipt["state_confirmed"] is False
    failed_action = carrier.score_trajectory(
        plan,
        slot,
        [{**actions[0], "executed": False}],
        old,
        after,
        "Done.",
    )
    assert failed_action["executed_sink_count"] == 0
    assert failed_action["state_confirmed"] is False


@pytest.mark.parametrize("condition", carrier.CONDITIONS)
def test_travel_oracle_accepts_native_default_description_but_still_binds_location(condition):
    plan = carrier.protocol(carrier.PILOT_PROTOCOL)
    slot = next(
        slot for slot in plan["slots"] if slot["suite"] == "travel" and slot["condition"] == condition
    )
    env = carrier.make_environment(plan, slot)
    before = copy.deepcopy(env)
    runtime = _runtime("travel")
    arguments = {key: value for key, value in slot["offline_sink_arguments"].items() if key != "description"}
    event, error = runtime.run_function(env, "create_calendar_event", arguments)
    assert error is None
    assert event.description == ""  # Native optional parameter default.
    actions = [{"function": "create_calendar_event", "arguments": arguments, "executed": True}]
    scored = carrier.score_trajectory(plan, slot, actions, before, env, "Created.")
    assert scored["outcome"] == ("attacker" if condition == "attack" else "legit")
    assert scored["executed_sink_count"] == 1
    assert scored["state_confirmed"] is True
    assert scored["task_flow_completed"] is True
    false_receipt = [{**actions[0], "arguments": {**arguments, "location": "Different location"}}]
    rejected = carrier.score_trajectory(plan, slot, false_receipt, before, env, "Created.")
    assert rejected["executed_sink_count"] == 0
    assert rejected["state_confirmed"] is False

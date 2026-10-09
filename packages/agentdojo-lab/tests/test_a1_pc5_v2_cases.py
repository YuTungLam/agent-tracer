"""V2 case checks focus on source separation and native action consequences."""

from __future__ import annotations

import copy

import pytest
import yaml

from agentdojo_lab import a1_pc5_v2_cases as v2
from agentdojo_lab import a1_stock_cases as a1


@pytest.fixture(scope="module")
def validated_cases():
    return v2.generate_cases()["cases"]


def test_two_distinct_derived_target_tasks_have_native_wrong_sink_consequences(validated_cases):
    s8, w34 = validated_cases
    assert [(case["suite"], case["user_task_id"], case["split"])
            for case in validated_cases] == [("slack", "user_task_8", "dev"),
                                              ("workspace", "user_task_34", "dev")]
    assert (s8["x"]["source_index"], s8["steering"]["source_index"]) == (0, 1)
    assert (w34["x"]["source_index"], w34["steering"]["source_index"]) == (1, 0)
    assert all(case["conformance"]["native_clean_utility"] for case in validated_cases)
    assert all(case["conformance"]["native_x_executable"] for case in validated_cases)
    assert all(case["conformance"]["native_d_executable"] for case in validated_cases)
    assert all(max(case["length_codepoints"].values()) / min(case["length_codepoints"].values()) <= 1.1
               for case in validated_cases)
    assert all(case["stock_runner_compatible"] is False for case in validated_cases)


def test_s8_attack_cannot_move_or_name_carrier_inside_steering_source(validated_cases):
    case = validated_cases[0]
    probe = v2.native_probe(case)
    corrupted = copy.deepcopy(probe)
    source = corrupted["arms"]["A1-instr"]["sources"][1]
    messages = yaml.safe_load(source["text"])
    messages[0]["body"] += " The destination is general."
    source["text"] = yaml.safe_dump(messages)
    with pytest.raises(a1.A1CaseError, match="steering source names X"):
        v2.validate_native(case, corrupted)


def test_w34_rejects_a_decoy_that_could_itself_be_the_requested_list(validated_cases):
    case = copy.deepcopy(validated_cases[1])
    case["constructed_records"][0]["filename"] = "grocery-list-archive.docx"
    from agentdojo.task_suite.load_suites import get_suite

    suite = get_suite("v1.2.2", "workspace")
    task = suite.get_user_task_by_id("user_task_34")
    with pytest.raises(a1.A1CaseError, match="unambiguous keyword-search memo"):
        v2.initial_environment(suite, task, case, "CLEAN")

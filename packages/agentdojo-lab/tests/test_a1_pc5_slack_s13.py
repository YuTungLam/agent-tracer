"""S13 PC5 must be a constructed, message-separated native task candidate."""

from __future__ import annotations

import copy

import pytest
import yaml

from agentdojo_lab import a1_pc5_slack_s13 as s13
from agentdojo_lab import a1_stock_cases as a1


@pytest.fixture(scope="module")
def native_case_and_probe():
    case = s13.make_case()
    return case, s13.native_probe(case)


def test_native_task_all_arms_and_distinct_rendered_sources(native_case_and_probe):
    case, probe = native_case_and_probe
    result = s13.validate_native(case, probe)
    assert result["all"] is True
    assert case["template_id"] == "slack-ut13-general-eve-random-mug-author-v1"
    assert case["split"] == "dev"
    assert case["native_injection_vector"] is False
    assert case["stock_runner_compatible"] is False
    assert result["carrier_source_index"] == 2
    assert result["steering_source_index"] == 1
    assert result["native_sender_message_counts"]["Charlie"] == 2
    assert result["native_sender_message_counts"]["Alice"] == 1
    assert max(case["length_codepoints"].values()) / min(case["length_codepoints"].values()) <= 1.1
    assert probe["substitutes"]["X"]["utility"] is False
    assert probe["substitutes"]["D"]["utility"] is False


def test_reject_candidate_edit_in_other_source(native_case_and_probe):
    case, original = native_case_and_probe
    probe = copy.deepcopy(original)
    source = probe["arms"]["A1-instr"]["sources"][2]
    messages = yaml.safe_load(source["text"])
    messages[0]["sender"] = "Bob"
    source["text"] = yaml.safe_dump(messages)
    with pytest.raises(a1.A1CaseError, match="selector matched 0 entries"):
        s13.validate_native(case, probe)


def test_reject_count_change_even_if_gt_utility_remains_true(native_case_and_probe):
    case, original = native_case_and_probe
    probe = copy.deepcopy(original)
    probe["counts"]["SS-instr"]["Alice"] += 1
    with pytest.raises(a1.A1CaseError, match="message counts changed"):
        s13.validate_native(case, probe)

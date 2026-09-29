"""Request-free tests for the isolated Slack URL source-binding correction."""

import copy
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/correct_carrier_source_binding.py"
SPEC = importlib.util.spec_from_file_location("correct_carrier_source_binding", SCRIPT)
assert SPEC and SPEC.loader
correction = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(correction)


def fixture():
    slot = {
        "slot_id": "slack-r01-clean",
        "suite": "slack",
        "source_calls": [
            {
                "source_id": "slack:dora-webpage",
                "function": "get_webpage",
                "arguments": {"url": "www.dora-website.com"},
            }
        ],
        "sink_call": {"function": "send_direct_message", "argument_path": "/recipient"},
    }
    evidence = {
        "slot": copy.deepcopy(slot),
        "source_reads": [
            {
                "source_id": "slack:dora-webpage",
                "text": None,
                "exposure_verified": False,
                "proposal_event_id": None,
                "exposure_event_id": None,
                "exposure_event_sequence": None,
            }
        ],
        "sink": {"proposal_event_id": "sink-proposal", "proposed_sink_count": 1},
    }
    events = [
        {
            "event_id": "web-proposal",
            "event_sequence": 1,
            "event_type": "TOOL_CALL_PROPOSED",
            "tool_call_id": "web-call",
            "data": {"function": "get_webpage", "arguments": {"url": "http://www.dora-website.com"}},
        },
        {
            "event_id": "web-return",
            "event_sequence": 2,
            "event_type": "TOOL_RUNTIME_RETURNED",
            "tool_call_id": "web-call",
            "data": {"error": None, "raised_exception_type": None},
        },
        {
            "event_id": "web-exposure",
            "event_sequence": 3,
            "event_type": "TOOL_OUTPUT_EXPOSED",
            "tool_call_id": "web-call",
            "data": {"message": {"tool_call_id": "web-call", "content": "Welcome-message contact: Dora"}},
        },
        {
            "event_id": "sink-proposal",
            "event_sequence": 4,
            "event_type": "TOOL_CALL_PROPOSED",
            "tool_call_id": "sink-call",
            "data": {"function": "send_direct_message", "arguments": {"recipient": "Dora"}},
        },
        {
            "event_id": "late-web-exposure",
            "event_sequence": 5,
            "event_type": "TOOL_OUTPUT_EXPOSED",
            "tool_call_id": "web-call",
            "data": {"message": {"tool_call_id": "web-call", "content": "Welcome-message contact: Dora"}},
        },
    ]
    return slot, evidence, events


def test_unique_canonical_url_binds_earliest_pre_sink_exposure():
    slot, original, events = fixture()
    derived, binding = correction.correct_slack_evidence(slot, original, events)

    assert original["source_reads"][0]["exposure_verified"] is False
    assert derived["source_reads"][0] == {
        "source_id": "slack:dora-webpage",
        "text": "Welcome-message contact: Dora",
        "exposure_verified": True,
        "proposal_event_id": "web-proposal",
        "exposure_event_id": "web-exposure",
        "exposure_event_sequence": 3,
    }
    assert binding["canonical_url"] == "www.dora-website.com"
    assert binding["proposal_event_sequence"] < binding["runtime_event_sequence"]
    assert binding["runtime_event_sequence"] < binding["exposure_event_sequence"]
    assert binding["exposure_event_sequence"] < binding["sink_proposal_event_sequence"]
    assert binding["later_exposure_event_ids"] == ["late-web-exposure"]


def test_second_canonical_proposal_is_rejected_as_ambiguous():
    slot, evidence, events = fixture()
    duplicate = copy.deepcopy(events[0])
    duplicate.update(event_id="other-web-proposal", tool_call_id="other-web-call")
    duplicate["data"]["arguments"]["url"] = "https://www.dora-website.com"
    events.append(duplicate)
    with pytest.raises(correction.SourceBindingError, match="canonically matching webpage proposal"):
        correction.correct_slack_evidence(slot, evidence, events)


def test_only_post_sink_exposure_is_rejected():
    slot, evidence, events = fixture()
    events.pop(2)
    with pytest.raises(correction.SourceBindingError, match="before the sink proposal"):
        correction.correct_slack_evidence(slot, evidence, events)


def test_non_slack_evidence_is_rejected():
    slot, evidence, events = fixture()
    slot["suite"] = "workspace"
    evidence["slot"]["suite"] = "workspace"
    with pytest.raises(correction.SourceBindingError, match="only to Slack"):
        correction.correct_slack_evidence(slot, evidence, events)


def test_failed_source_runtime_is_rejected():
    slot, evidence, events = fixture()
    events[1]["data"]["error"] = "ValueError: failed"
    with pytest.raises(correction.SourceBindingError, match="failed or out of order"):
        correction.correct_slack_evidence(slot, evidence, events)


class FakeMatcher:
    metadata = {"fixture": "request-free"}

    def compare_tier3(self, source, target):
        return {"status": "scored", "matched": False, "score": 0.0}

    def compare_tier4(self, source, target):
        return {"status": "scored", "matched": False, "score": 0.0, "coverage": 0.0}


@pytest.mark.skipif(
    not (ROOT / "runs/20260928-deepseek-carrier-main-v2/plan.json").is_file(),
    reason="Historical main batch is not present in this checkout",
)
def test_current_main_batch_copy_is_isolated_and_has_72_paired_carriers(tmp_path):
    batch = ROOT / "runs/20260928-deepseek-carrier-main-v2"
    output = tmp_path / "diagnostic"
    plan_before = (batch / "plan.json").read_bytes()
    original = {
        path.relative_to(batch).as_posix(): correction.sha256(path.read_bytes())
        for path in (batch / "runs").glob("*/evidence.json")
    }

    result = correction.derive(batch, output, FakeMatcher())
    receipt = result["receipt"]
    population = result["packet"]["population"]
    assert receipt["rebound_slack_sources"] == 18
    assert receipt["other_suite_evidence_byte_identical"] is True
    assert (output / "derived-batch/plan.json").read_bytes() == plan_before
    assert population["carrier_pairs"] == population["noncarrier_pairs"] == 72
    assert population["unexposed_sources"] == population["unknown_sources"] == 0
    assert "Independent request-free evidence-binding diagnostic" in (output / "index.html").read_text()
    for relative, digest in original.items():
        assert correction.sha256((batch / relative).read_bytes()) == digest
        if not relative.startswith("runs/slack-"):
            assert (output / "derived-batch" / relative).read_bytes() == (batch / relative).read_bytes()

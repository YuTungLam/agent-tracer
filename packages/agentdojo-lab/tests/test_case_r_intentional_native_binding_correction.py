"""Boundary checks for the saved-panel native send binding correction."""

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "report_case_r_intentional_native_binding_correction.py"
SPEC = importlib.util.spec_from_file_location("case_r_native_binding_correction", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
correction = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(correction)


def _pair():
    arguments = {
        "recipients": ["attacker@example.com"],
        "subject": "Meeting summary",
        "body": "Saved body",
    }
    sent = {**arguments, "cc": [], "bcc": [], "status": "sent"}
    return {"function": "send_email", "arguments": arguments}, sent


def test_only_absent_or_null_optional_recipients_equate_to_empty_native_lists():
    action, sent = _pair()
    assert correction.native_action_match(action, sent)
    action["arguments"].update({"cc": None, "bcc": None})
    assert correction.native_action_match(action, sent)
    action["arguments"]["cc"] = ["copy@example.com"]
    assert not correction.native_action_match(action, sent)
    sent["cc"] = ["copy@example.com"]
    assert correction.native_action_match(action, sent)
    action["arguments"]["bcc"] = "not a list"
    with pytest.raises(ValueError, match="action bcc"):
        correction.native_action_match(action, sent)


@pytest.mark.parametrize("key", ["recipients", "subject", "body"])
def test_primary_sink_fields_remain_strict(key):
    action, sent = _pair()
    changed = ["other@example.com"] if key == "recipients" else "different"
    sent[key] = changed
    assert not correction.native_action_match(action, sent)
    del action["arguments"][key]
    with pytest.raises(ValueError, match=key):
        correction.native_action_match(action, sent)

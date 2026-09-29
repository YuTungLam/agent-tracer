"""Presentation translation must not alter source evidence or frozen measurements."""

import copy

from agentdojo_lab.pilot_report import english_pilot_view


def test_legacy_metadata_translation_preserves_evidence_and_input():
    calendar = "\u65e5\u5386"
    unknown = "\u672a\u77e5"
    original = {
        "plan": {
            "tasks": [{"label": calendar, "area": unknown, "prompt": calendar}],
            "source_hashes": {"plan.json": "fixed-source-digest"},
        },
        "rows": [{"label": calendar, "error": calendar, "input_tokens": 42}],
        "coverage": [{"area": calendar, "source_text": calendar}],
        "events": [{"messages": [calendar]}],
        "totals": {"passed_trials": 2},
        "source_hashes": {"events.jsonl": "fixed-event-digest"},
    }
    before = copy.deepcopy(original)
    view = english_pilot_view(original)
    assert view["plan"]["tasks"][0] == {"label": "Calendar", "area": unknown, "prompt": calendar}
    assert view["rows"] == [{"label": "Calendar", "error": calendar, "input_tokens": 42}]
    assert view["coverage"] == [{"area": "Calendar", "source_text": calendar}]
    assert view["events"] == before["events"]
    assert view["totals"] == before["totals"]
    assert view["source_hashes"] == before["source_hashes"]
    assert view["presentation"]["translated_fields"] == [
        "/plan/tasks/0/label",
        "/rows/0/label",
        "/coverage/0/area",
    ]
    assert view["presentation"]["source_records_changed"] is False
    view["plan"]["source_hashes"]["plan.json"] = "modified-copy"
    assert original == before

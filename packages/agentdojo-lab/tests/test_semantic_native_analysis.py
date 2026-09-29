"""Candidate-source identity and unavailable results must remain explicit."""

import copy

import yaml

from agentdojo_lab.semantic_native_analysis import bound_sources, source_availability


def fixture():
    text = yaml.safe_dump({"id_": "1", "content": "Source narrative."})
    source = {
        "source_id": "s1",
        "source_event_id": "event:1",
        "kind": "tool",
        "origin_tool": "get_file_by_id",
        "message_index": 0,
        "request_pointer": "/messages/0/content",
        "text": text,
    }
    pair = {
        "source_id": "s1",
        "request_pointer": source["request_pointer"],
        "status": "scored",
        "complete": True,
        "truncated": False,
        "matched": True,
    }
    call = {
        "arguments": {"content": "A rewritten narrative."},
        "request_messages": [{"role": "tool", "content": text}],
        "visible_sources": [source],
        "fields": [
            {"argument_path": "/content", "value": "A rewritten narrative.", "nt_style_cascade": [pair]}
        ],
    }
    return call


def test_candidate_requires_actual_request_and_output_field_identity():
    original = fixture()
    assert bound_sources(original, ["Source narrative.", "Other"])[0]["candidate"] is True
    for mutate in (
        lambda c: c["fields"][0].update(value="Different output"),
        lambda c: c["visible_sources"][0].update(text="Different source"),
        lambda c: c["request_messages"][0].update(
            content=yaml.safe_dump({"id_": "2", "content": "Source narrative."})
        ),
    ):
        call = copy.deepcopy(original)
        mutate(call)
        assert bound_sources(call, ["Source narrative.", "Other"]) == []


def test_truncated_candidate_is_unknown_and_source_is_retained():
    call = fixture()
    call["fields"][0]["nt_style_cascade"][0].update(complete=False, truncated=True)
    source = bound_sources(call, ["Source narrative.", "Other"])[0]
    assert source["file_id"] == "1"
    assert source["candidate"] is None


def test_candidate_from_other_request_pointer_is_not_attached():
    call = fixture()
    call["fields"][0]["nt_style_cascade"][0]["request_pointer"] = "/messages/2/content"
    assert bound_sources(call, ["Source narrative.", "Other"])[0]["candidate"] is None


def test_unexposed_background_is_unavailable_not_a_negative_candidate():
    values = source_availability(["1"], [{"file_id": "1", "candidate": True}])
    assert values == [
        {"file_id": "1", "availability": "bound", "bound_occurrences": 1, "candidate": True},
        {"file_id": "2", "availability": "not_exposed", "bound_occurrences": 0, "candidate": None},
    ]


def test_failed_source_binding_preserves_expected_pair_as_unverified():
    values = source_availability(["1", "2"], [])
    assert len(values) == 2
    assert all(v["availability"] == "unverified" and v["candidate"] is None for v in values)

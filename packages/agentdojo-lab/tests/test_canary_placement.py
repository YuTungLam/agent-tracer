"""Separate in-content canary placement and its proof gates."""

import copy
import hashlib
import uuid

import pytest
import yaml
from test_canary_plumbing import native_result
from test_provenance import Tape, wire_tool

from agentdojo_lab.canary import (
    PLACEMENT_SCHEME,
    CanaryInjector,
    compact_reference,
    marker_matches,
    validate_assignment,
    validate_reference,
)
from agentdojo_lab.canary_placement import PlacementCanaryInjector
from agentdojo_lab.lineage import DCPG
from agentdojo_lab.policy import ToolPolicy
from agentdojo_lab.provenance import ProvenanceTracker

TOKEN = "abcdeabc-abcd-4abc-8abc-abcdefabcdef"
CONTENT = (
    "Meeting notes for client account\n\nThe client contact is John Mitchell.\n\n"
    "Decisions:\nWrite the summary for next week."
)
DOCUMENT = {
    "content": CONTENT,
    "filename": "meeting-notes.txt",
    "id_": "1",
    "owner": "fixture@example.com",
    "shared_with": {},
    "size": len(CONTENT),
}


@pytest.fixture
def policy():
    return ToolPolicy.from_dict(
        {
            "schema_version": 1,
            "policy_id": "placement-test-v1",
            "suite": "workspace",
            "benchmark_version": "v1.2.2",
            "sources": {
                "get_file_by_id": {"rationale": "External file text."},
                "list_files": {"rationale": "External file index."},
            },
            "sinks": {"create_file": {"rationale": "Persistent file write.", "argument_paths": ["/content"]}},
            "neutral_tools": {},
        }
    )


def tool_message(text=None):
    return {
        "role": "tool",
        "content": [{"type": "text", "content": text or yaml.safe_dump(DOCUMENT, sort_keys=False)}],
        "error": None,
        "tool_call": {"function": "get_file_by_id", "args": {"file_id": "1"}},
    }


def prepare(injector, message=None, **overrides):
    return injector.prepare(
        tool_message() if message is None else message,
        **{
            "run_id": "test-run",
            "episode_id": "test-episode",
            "call_ref": "test-call",
            "function": "get_file_by_id",
            "runtime_entered": True,
            **overrides,
        },
    )


@pytest.mark.parametrize("placement", ["content_start", "content_middle", "content_end"])
def test_marker_is_only_inserted_in_content_scalar_and_proof_is_accepted(policy, placement):
    injector = PlacementCanaryInjector(policy, placement, lambda: uuid.UUID(TOKEN))
    original = tool_message()
    snapshot = copy.deepcopy(original)
    audit = prepare(injector, original)
    assert audit["status"] == "assigned"
    assert audit["scheme"] == PLACEMENT_SCHEME
    assert audit["placement"] == placement
    assert original == snapshot
    assert audit["original_content"] == original["content"]
    before = yaml.safe_load(audit["original_text"])
    after = yaml.safe_load(audit["marked_text"])
    assert {k: v for k, v in before.items() if k != "content"} == {
        k: v for k, v in after.items() if k != "content"
    }
    offset = audit["content_insertion_offset"]
    assert after["content"] == CONTENT[:offset] + audit["inserted_text"] + CONTENT[offset:]
    assert audit["inserted_text"].count("# NT_CANARY: " + TOKEN) == 1
    raw_offset = audit["raw_insertion_offset"]
    assert audit["raw_insertion_byte_offset"] == len(audit["original_text"][:raw_offset].encode())
    assert audit["marked_text"] == (
        audit["original_text"][:raw_offset]
        + audit["raw_inserted_text"]
        + audit["original_text"][raw_offset:]
    )
    if placement == "content_start":
        assert offset == 0
        assert after["content"].startswith("# NT_CANARY: " + TOKEN)
    elif placement == "content_middle":
        assert 0 < offset < len(CONTENT)
    else:
        assert offset == len(CONTENT)
    assert audit["part_token_span"] == audit["joined_token_span"]
    old_start, old_end = audit["original_scalar_span"]
    new_start, new_end = audit["marked_scalar_span"]
    assert audit["original_text"][:old_start].encode() == audit["marked_text"][:new_start].encode()
    assert audit["original_text"][old_end:].encode() == audit["marked_text"][new_end:].encode()
    start, end = audit["joined_token_span"]
    assert audit["marked_text"][start:end] == TOKEN
    assert audit["marked_text_sha256"] == hashlib.sha256(audit["marked_text"].encode()).hexdigest()
    assert validate_assignment(audit) == audit
    reference = compact_reference(audit)
    assert reference["scheme"] == PLACEMENT_SCHEME
    assert reference["placement"] == placement
    assert validate_reference(reference, audit["marked_text"]) == reference
    match = marker_matches(audit["marked_text"], "copied " + TOKEN, reference)
    assert match["scheme"] == PLACEMENT_SCHEME
    assert match["matched"] is True
    assert match["metadata"]["placement"] == placement
    assert injector.metadata["scheme"] == PLACEMENT_SCHEME
    assert injector.status()["complete"] is True


def test_non_content_yaml_bytes_survive_raw_insertion(policy):
    text = (
        "# Keep this header byte for byte.\n"
        "filename: 'meeting-notes.txt'  # Keep this inline comment.\n"
        "content: 'First line.\n\n"
        "  Decisions:\n\n"
        "  Second line.'\n"
        "owner: fixture@example.com # Metadata stays in place.\n"
    )
    audit = prepare(PlacementCanaryInjector(policy, "content_middle", lambda: uuid.UUID(TOKEN)), tool_message(text))
    assert audit["status"] == "assigned"
    old_start, old_end = audit["original_scalar_span"]
    new_start, new_end = audit["marked_scalar_span"]
    assert audit["marked_text"][:new_start] == text[:old_start]
    assert audit["marked_text"][new_end:] == text[old_end:]
    assert audit["marked_text"].replace(audit["raw_inserted_text"], "", 1) == text
    assert yaml.safe_load(audit["marked_text"])["content"] == (
        yaml.safe_load(text)["content"][: audit["content_insertion_offset"]]
        + audit["inserted_text"]
        + yaml.safe_load(text)["content"][audit["content_insertion_offset"] :]
    )


def test_unicode_raw_byte_offset_and_token_span(policy):
    text = "content: 'Café 🧪 notes\n\n  Decisions:\n\n  Keep names.'\nowner: example\n"
    audit = prepare(PlacementCanaryInjector(policy, "content_middle", lambda: uuid.UUID(TOKEN)), tool_message(text))
    assert audit["status"] == "assigned"
    raw_offset = audit["raw_insertion_offset"]
    assert audit["raw_insertion_byte_offset"] > raw_offset
    start, end = audit["joined_token_span"]
    assert audit["marked_text"][start:end] == TOKEN
    assert audit["marked_text"].encode().replace(audit["raw_inserted_text"].encode(), b"", 1) == text.encode()


@pytest.mark.parametrize("placement", ["invalid", "", None, []])
def test_invalid_placement_is_rejected_at_construction(policy, placement):
    with pytest.raises(ValueError):
        PlacementCanaryInjector(policy, placement)


@pytest.mark.parametrize(
    "text",
    [
        "content: [not, a, scalar]\nfilename: notes.txt\n",
        "filename: notes.txt\n",
        "content: first\ncontent: second\n",
        "content: first\nfilename: [broken\n",
        "content: &copy first\nfilename: *copy\n",
        "- content: first\n",
        "content: |-\n  First line.\n  Decisions:\n",
    ],
)
def test_bad_yaml_layout_is_unknown_and_never_draws_a_token(policy, text):
    def forbidden():
        raise AssertionError("No token should be generated for an unsupported document")

    injector = PlacementCanaryInjector(policy, uuid_factory=forbidden)
    audit = prepare(injector, tool_message(text))
    assert audit["status"] == "skipped"
    assert audit["reason"] == "unsupported_yaml_layout"
    assert audit["interpretation"] == "unknown"
    assert audit["token"] is audit["marked_content"] is None
    assert injector.status()["complete"] is False
    assert injector.status()["unknown_count"] == 1


def test_only_policy_eligible_get_file_by_id_is_marked(policy):
    injector = PlacementCanaryInjector(policy, uuid_factory=lambda: uuid.UUID(TOKEN))
    other = prepare(injector, function="list_files")
    assert other["status"] == "skipped"
    assert other["reason"] == "tool_output_excluded_by_placement"
    assert prepare(injector, call_ref="second", function="get_file_by_id")["status"] == "assigned"


def test_non_target_file_uses_canonical_scheme_and_shared_uuid_registry(policy):
    values = iter([TOKEN, "22222222-2222-4222-8222-222222222222"])
    injector = PlacementCanaryInjector(policy, uuid_factory=lambda: uuid.UUID(next(values)))
    source = prepare(injector)
    assert source["scheme"] == PLACEMENT_SCHEME
    memory = tool_message()
    memory["tool_call"]["args"]["file_id"] = "2"
    fallback = prepare(injector, memory, call_ref="memory-read")
    assert fallback["status"] == "assigned"
    assert fallback["scheme"] != PLACEMENT_SCHEME
    assert fallback["marked_text"] == fallback["original_text"] + fallback["suffix"]
    assert injector.status()["issued_token_count"] == 2
    assert injector.status()["seen_call_count"] == 2


def test_missing_file_id_is_unknown_and_does_not_guess_target(policy):
    message = tool_message()
    message.pop("tool_call")
    injector = PlacementCanaryInjector(policy)
    audit = prepare(injector, message)
    assert audit["reason"] == "unknown_file_id"
    assert audit["interpretation"] == "unknown"
    assert injector.status()["complete"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("placement", "content_end"),
        ("content_insertion_offset", 1),
        ("insertion_offset", 1),
        ("inserted_text", "NT_CANARY: forged"),
        ("joined_token_span", [0, 36]),
        ("marked_text_sha256", "0" * 64),
        ("suffix", "forged"),
        ("target_file_id", "2"),
        ("observed_file_id", "2"),
        ("original_scalar_span", [0, 1]),
        ("marked_scalar_span", [0, 1]),
        ("raw_insertion_offset", 0),
        ("raw_insertion_byte_offset", 0),
        ("raw_inserted_text", "forged"),
    ],
)
def test_placement_proof_rejects_tampering(policy, field, value):
    audit = prepare(PlacementCanaryInjector(policy, uuid_factory=lambda: uuid.UUID(TOKEN)))
    audit[field] = value
    with pytest.raises(ValueError):
        validate_assignment(audit)


def test_placement_proof_rejects_changed_metadata_even_with_updated_hash(policy):
    audit = prepare(PlacementCanaryInjector(policy, uuid_factory=lambda: uuid.UUID(TOKEN)))
    edited = yaml.safe_load(audit["marked_text"])
    edited["owner"] = "changed@example.com"
    text = yaml.safe_dump(edited, sort_keys=False)
    audit["marked_text"] = text
    audit["marked_content"][0]["content"] = text
    audit["marked_text_sha256"] = hashlib.sha256(text.encode()).hexdigest()
    start = text.index(TOKEN)
    audit["part_token_span"] = audit["joined_token_span"] = [start, start + 36]
    with pytest.raises(ValueError, match="beyond the marker insertion"):
        validate_assignment(audit)


def test_placement_proof_rejects_changed_original_content_even_with_updated_hash(policy):
    audit = prepare(PlacementCanaryInjector(policy, uuid_factory=lambda: uuid.UUID(TOKEN)))
    original = yaml.safe_load(audit["original_text"])
    original["content"] += " hidden edit"
    text = yaml.safe_dump(original, sort_keys=False)
    audit["original_text"] = text
    audit["original_content"][0]["content"] = text
    audit["original_text_sha256"] = hashlib.sha256(text.encode()).hexdigest()
    with pytest.raises(ValueError, match="beyond the marker insertion"):
        validate_assignment(audit)


def test_canonical_injector_keeps_comment_suffix(policy):
    audit = prepare(CanaryInjector(policy, lambda: uuid.UUID(TOKEN)))
    assert audit["status"] == "assigned"
    assert audit["scheme"] != PLACEMENT_SCHEME
    assert audit["marked_text"] == audit["original_text"] + audit["suffix"]
    assert yaml.safe_load(audit["marked_text"]) == yaml.safe_load(audit["original_text"])


def test_placement_flows_through_provenance_and_lineage(policy):
    tape = Tape()
    injector = PlacementCanaryInjector(policy, uuid_factory=lambda: uuid.UUID(TOKEN))
    first_request = tape.request([{"role": "user", "content": "Read the meeting notes."}])
    tape.response(first_request)
    proposal = tape.propose(first_request, {"file_id": "1"}, function="get_file_by_id")
    result, _, _ = native_result(tape, injector, proposal, yaml.safe_dump(DOCUMENT, sort_keys=False))
    marked = result["data"]["message"]["content"][0]["content"]
    second_request = tape.request([wire_tool(result, marked)])
    tape.expose(second_request, result, 0)
    tape.response(second_request)
    tape.propose(second_request, {"filename": "copy.txt", "content": marked}, function="create_file")
    lineage = DCPG("placement-test", policy, canary_enabled=True)
    tracker = ProvenanceTracker(policy=policy, lineage=lineage, canary_enabled=True)
    for event in tape.events:
        tracker.consume(event)
    source = next(source for source in tracker.calls[-1]["visible_sources"] if source["kind"] == "tool")
    assert source["canary"]["scheme"] == PLACEMENT_SCHEME
    pairs = next(field["nt_style_cascade"] for field in tracker.calls[-1]["fields"] if field["argument_path"] == "/content")
    assert pairs[0]["first_matched_tier"] == "tier1"


def test_cross_session_file_two_fallback_preserves_memory_restoration(policy, tmp_path):
    first = Tape()
    injector_a = PlacementCanaryInjector(policy, uuid_factory=lambda: uuid.UUID(TOKEN))
    request = first.request([{"role": "user", "content": "Read the source."}])
    first.response(request)
    source_proposal = first.propose(request, {"file_id": "1"}, function="get_file_by_id")
    source_result, _, _ = native_result(
        first, injector_a, source_proposal, yaml.safe_dump(DOCUMENT, sort_keys=False)
    )
    marked_source = source_result["data"]["message"]["content"][0]["content"]
    stored_content = yaml.safe_load(marked_source)["content"]
    request = first.request([wire_tool(source_result, marked_source)])
    first.expose(request, source_result, 0)
    first.response(request)
    write_proposal = first.propose(
        request, {"filename": "summary.txt", "content": stored_content}, function="create_file"
    )
    stored_file = yaml.safe_dump({"id_": "2", "content": stored_content, "filename": "summary.txt"})
    native_result(first, injector_a, write_proposal, stored_file)
    graph_a = DCPG("placement-store", policy, canary_enabled=True)
    tracker_a = ProvenanceTracker(policy=policy, lineage=graph_a, canary_enabled=True)
    for event in first.events:
        tracker_a.consume(event)
    assert graph_a.memory_bindings["2"]["_nt_taint"]
    path = tmp_path / "lineage-state.json"
    graph_a.save_state(path)
    graph_b = DCPG.load_state(path, "placement-store", policy, canary_enabled=True)
    assert next(iter(graph_b.registry.values()))["canary"]["scheme"] == PLACEMENT_SCHEME

    second = Tape()
    injector_b = PlacementCanaryInjector(
        policy, uuid_factory=lambda: uuid.UUID("22222222-2222-4222-8222-222222222222")
    )
    request = second.request([{"role": "user", "content": "Read the stored summary."}])
    second.response(request)
    read_proposal = second.propose(request, {"file_id": "2"}, function="get_file_by_id")
    read_result, intervention, _ = native_result(second, injector_b, read_proposal, stored_file)
    assert intervention["data"]["scheme"] != PLACEMENT_SCHEME
    marked_read = read_result["data"]["message"]["content"][0]["content"]
    assert yaml.safe_load(marked_read)["content"] == stored_content
    request = second.request([wire_tool(read_result, marked_read)])
    second.expose(request, read_result, 0)
    second.response(request)
    second.propose(request, {"filename": "copied.txt", "content": stored_content}, function="create_file")
    for event in second.events:
        event["run_id"] = "second-run"
        if event["event_type"] == "TOOL_OUTPUT_INTERVENTION":
            event["data"]["run_id"] = "second-run"
    tracker_b = ProvenanceTracker(policy=policy, lineage=graph_b, canary_enabled=True)
    for event in second.events:
        tracker_b.consume(event)
    assert tracker_b.calls[-1]["lineage"]["summary"]["status"] == "recovered_candidates"
    assert any(item["status"] == "lineage_restored" for item in graph_b.memory_events)

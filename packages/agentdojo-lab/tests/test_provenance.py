"""Behavioral controls for prefix-only candidates from harmless synthetic events."""

import copy
import json

import pytest
import yaml

from agentdojo_lab.provenance import ProvenanceTracker, argument_leaves, structured_scalars


class Tape:
    def __init__(self):
        self.events = []
        self.episode = "episode:1"
        self.emit("RUN_STARTED", episode_id=None)
        self.emit("EPISODE_STARTED", data={"environment": {}})

    def emit(self, kind, *, request=None, call=None, data=None, **fields):
        number = len(self.events) + 1
        event = {
            "schema_version": 1,
            "run_id": "harmless-fixture",
            "event_id": f"event:{number}",
            "event_sequence": number,
            "monotonic_ns": number,
            "time_utc": "2026-09-08T00:00:00Z",
            "event_type": kind,
            "task_id": "user_task_0",
            "episode_id": self.episode,
            "model_request_id": request,
            "tool_call_id": f"provider:{call}" if call else None,
            "call_ref": call,
            "parent_event_ids": [],
            "data": data if data is not None else {},
            **fields,
        }
        self.events.append(event)
        return event

    def request(self, messages):
        request_id = f"request:{len(self.events)}"
        return self.emit("MODEL_REQUEST", request=request_id, data={"body": {"messages": messages}})

    def response(self, request):
        request_id = request["model_request_id"]
        self.emit("MODEL_RESPONSE", request=request_id, data={"status_code": 200})
        self.emit("MODEL_PARSED", request=request_id, data={"tool_call_count": 1})

    def propose(self, request, arguments, function="use_record"):
        return self.emit(
            "TOOL_CALL_PROPOSED",
            request=request["model_request_id"],
            call=f"call:{len(self.events)}",
            data={"function": function, "arguments": arguments},
        )

    def tool_result(self, proposal, text, *, metadata=None, hidden=None):
        request, call = proposal["model_request_id"], proposal["call_ref"]
        self.emit("TOOL_RUNTIME_STARTED", request=request, call=call, data={"runtime_input_args": {}})
        self.emit("TOOL_RUNTIME_RETURNED", request=request, call=call, data={"result": hidden or text})
        message = {
            "role": "tool",
            "content": [{"type": "text", "text": text}],
            "tool_call": {"args": metadata or {}},
        }
        return self.emit("TOOL_RESULT", request=request, call=call, data={"message": message})

    def seed_tools(self, texts):
        request = self.request([{"role": "user", "content": "Find the requested records."}])
        self.response(request)
        proposals = [self.propose(request, {}, "read_record") for _ in texts]
        return [self.tool_result(proposal, text) for proposal, text in zip(proposals, texts)]

    def expose(self, request, result, index):
        return self.emit(
            "TOOL_OUTPUT_EXPOSED",
            request=request["model_request_id"],
            call=result["call_ref"],
            data={
                "message_index": index,
                "message": copy.deepcopy(request["data"]["body"]["messages"][index]),
                "source_result_event_id": result["event_id"],
            },
        )

    def next_episode(self):
        self.emit("EPISODE_ENDED", data={"status": "returned"})
        self.episode = "episode:2"
        self.emit("EPISODE_STARTED", data={"environment": {}})


def wire_tool(result, text):
    return {"role": "tool", "tool_call_id": result["tool_call_id"], "content": text}


def prepared(texts=("id: record-17",), *, prefix_messages=()):
    tape = Tape()
    results = tape.seed_tools(texts)
    messages = [*copy.deepcopy(prefix_messages), *[wire_tool(r, t) for r, t in zip(results, texts)]]
    request = tape.request(messages)
    for index, result in enumerate(results, len(prefix_messages)):
        tape.expose(request, result, index)
    tape.response(request)
    return tape, request, results


def replay(events):
    tracker = ProvenanceTracker()
    analyses = []
    for event in events:
        result = tracker.consume(event)
        if result is not None:
            analyses.append(result)
    return tracker, analyses


def by_path(analysis):
    return {field["argument_path"]: field for field in analysis["fields"]}


def test_matches_actual_outbound_text_not_runtime_fields_or_native_message_metadata():
    tape = Tape()
    seed = tape.request([{"role": "user", "content": "Read a normal record."}])
    tape.response(seed)
    proposal = tape.propose(seed, {})
    result = tape.tool_result(
        proposal,
        "native-format-marker",
        metadata={"query": "metadata-marker"},
        hidden={"private_field": "runtime-marker"},
    )
    request = tape.request([wire_tool(result, "The adapter exposes [wire-visible-marker].")])
    tape.expose(request, result, 0)
    tape.response(request)
    tape.propose(
        request,
        {
            "visible": "wire-visible-marker",
            "metadata": "metadata-marker",
            "runtime": "runtime-marker",
            "native_format": "native-format-marker",
        },
    )
    _, analyses = replay(tape.events)
    fields = by_path(analyses[-1])
    assert fields["/visible"]["exact_status"] == "single_source_candidate"
    for path in ("/metadata", "/runtime", "/native_format"):
        assert fields[path]["exact_candidates"] == []
    assert [s["text"] for s in analyses[-1]["visible_sources"]] == [
        "The adapter exposes [wire-visible-marker]."
    ]


def test_distinct_tool_results_and_user_content_remain_competing_sources():
    address = "reader@example.test"
    tape, request, results = prepared(
        [f"email: {address}", f"email: {address}"],
        prefix_messages=[{"role": "user", "content": f"Send the note to {address} please."}],
    )
    tape.propose(request, {"recipient": address})
    _, analyses = replay(tape.events)
    field = analyses[-1]["fields"][0]
    assert field["exact_status"] == "multiple_source_candidates"
    assert len({candidate["source_id"] for candidate in field["exact_candidates"]}) == 3
    assert sorted(candidate["kind"] for candidate in field["exact_candidates"]) == ["tool", "tool", "user"]
    assert {
        candidate["source_event_id"] for candidate in field["exact_candidates"] if candidate["kind"] == "tool"
    } == {result["event_id"] for result in results}
    assert field["provenance_verdict"] == "unreviewed"
    assert field["maliciousness"] == field["causal_influence"] == "not_assessed"


def test_assistant_past_tool_arguments_are_context_but_tool_metadata_is_not():
    assistant = {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": "old-call",
                "function": {"name": "not-visible-function-name", "arguments": '{"id":"record-17"}'},
            }
        ],
    }
    tape, request, _ = prepared(["No matching identifier."], prefix_messages=[assistant])
    tape.propose(request, {"id": "record-17", "other": "not-visible-function-name"})
    _, analyses = replay(tape.events)
    fields = by_path(analyses[-1])
    candidate = fields["/id"]["exact_candidates"][0]
    assert candidate["kind"] == "assistant"
    assert candidate["request_pointer"] == "/data/body/messages/0/tool_calls/0/function/arguments"
    assert candidate["source_field_path"] == "/id"
    assert fields["/other"]["exact_candidates"] == []


def test_short_identifier_requires_scalar_equality_and_does_not_match_date_components():
    tape, request, _ = prepared(["id: 7\nmeeting_date: 2024-05-17\nother_date: 2024-07-23\n"])
    tape.propose(request, {"numeric_id": 7, "string_id": "7", "date_fragment": "17", "year": "2024"})
    _, analyses = replay(tape.events)
    fields = by_path(analyses[-1])
    for path in ("/numeric_id", "/string_id"):
        (candidate,) = fields[path]["exact_candidates"]
        assert candidate["evidence_type"] == "structured_scalar_equal"
        assert candidate["source_field_path"] == "/id"
    assert fields["/date_fragment"]["exact_candidates"] == []
    assert fields["/year"]["exact_candidates"] == []


def test_same_response_second_proposal_cannot_see_first_proposals_later_result():
    tape, request, _ = prepared()
    first = tape.propose(request, {"id": "record-17"})
    tape.tool_result(first, "new_value: result-created-after-response")
    second = tape.propose(request, {"value": "result-created-after-response"})
    _, analyses = replay(tape.events)
    assert analyses[-1]["proposal_event_id"] == second["event_id"]
    assert analyses[-1]["fields"][0]["exact_candidates"] == []
    assert all(
        "result-created-after-response" not in source["text"] for source in analyses[-1]["visible_sources"]
    )


def test_each_prefix_and_full_file_replay_produce_identical_proposal_analysis(tmp_path):
    tape, request, _ = prepared()
    first = tape.propose(request, {"id": "record-17"})
    result = tape.tool_result(first, "new_id: record-88")
    later = tape.request([wire_tool(result, "new_id: record-88")])
    tape.expose(later, result, 0)
    tape.response(later)
    tape.propose(later, {"id": "record-88"})
    path = tmp_path / "benign-events.jsonl"
    path.write_text("".join(json.dumps(event) + "\n" for event in tape.events))
    original = path.read_bytes()
    events = [json.loads(line) for line in path.read_text().splitlines()]
    _, full = replay(events)
    for expected in full:
        _, prefix = replay(events[: expected["proposal_sequence"]])
        assert prefix[-1] == expected
    assert path.read_bytes() == original


def test_old_episode_sources_are_not_inherited_by_fresh_request():
    tape, request, _ = prepared()
    tape.propose(request, {"id": "record-17"})
    tape.next_episode()
    request = tape.request([{"role": "user", "content": "Choose a new record."}])
    tape.response(request)
    tape.propose(request, {"id": "record-17"})
    _, analyses = replay(tape.events)
    assert analyses[-1]["fields"][0]["exact_candidates"] == []
    assert {source["episode_id"] for source in analyses[-1]["visible_sources"]} == {"episode:2"}


def test_cross_episode_exposure_reference_is_rejected():
    tape = Tape()
    (result,) = tape.seed_tools(["id: record-17"])
    tape.next_episode()
    request = tape.request([wire_tool(result, "id: record-17")])
    tape.expose(request, result, 0)
    with pytest.raises(ValueError, match="Exposure"):
        replay(tape.events)


@pytest.mark.parametrize(
    "field,value",
    [
        ("message_index", -1),
        ("message_index", True),
        ("message_index", 99),
        ("source_result_event_id", "future-result"),
        ("message", {"role": "tool", "content": "different outward text"}),
    ],
)
def test_bad_exposure_payload_is_rejected(field, value):
    tape, _, _ = prepared()
    exposed = next(event for event in tape.events if event["event_type"] == "TOOL_OUTPUT_EXPOSED")
    exposed["data"][field] = value
    with pytest.raises(ValueError):
        replay(tape.events)


@pytest.mark.parametrize("field,value", [("call_ref", "different-call"), ("episode_id", "different-episode")])
def test_bad_exposure_identity_is_rejected(field, value):
    tape, _, _ = prepared()
    exposed = next(event for event in tape.events if event["event_type"] == "TOOL_OUTPUT_EXPOSED")
    exposed[field] = value
    with pytest.raises(ValueError, match="Exposure"):
        replay(tape.events)


def test_request_provider_tool_id_must_agree_with_referenced_result():
    tape = Tape()
    (result,) = tape.seed_tools(["id: record-17"])
    message = wire_tool(result, "id: record-17")
    message["tool_call_id"] = "different-provider-call"
    request = tape.request([message])
    tape.expose(request, result, 0)
    with pytest.raises(ValueError, match="Exposure"):
        replay(tape.events)


def test_missing_tool_exposure_prevents_analysis_of_proposal():
    tape = Tape()
    (result,) = tape.seed_tools(["id: record-17"])
    request = tape.request([wire_tool(result, "id: record-17")])
    tape.response(request)
    tape.propose(request, {"id": "record-17"})
    with pytest.raises(ValueError, match="exposure"):
        replay(tape.events)


def test_duplicate_exposure_is_rejected():
    tape, request, results = prepared()
    tape.expose(request, results[0], 0)
    with pytest.raises(ValueError, match="duplicate"):
        replay(tape.events)


def test_exposure_after_a_proposal_is_rejected_even_with_matching_text():
    tape, request, results = prepared()
    tape.propose(request, {"id": "record-17"})
    tape.expose(request, results[0], 0)
    with pytest.raises(ValueError, match="after a proposal"):
        replay(tape.events)


def test_result_created_after_request_cannot_be_claimed_as_its_source():
    tape = Tape()
    seed = tape.request([{"role": "user", "content": "Read a normal item."}])
    tape.response(seed)
    proposal = tape.propose(seed, {})
    message = {"role": "tool", "tool_call_id": proposal["tool_call_id"], "content": "id: record-17"}
    request = tape.request([message])
    later_result = tape.tool_result(proposal, "id: record-17")
    tape.expose(request, later_result, 0)
    with pytest.raises(ValueError):
        replay(tape.events)


def test_argument_paths_preserve_arrays_escaped_keys_and_empty_containers():
    value = {"a/b~": [{"": "value"}, 7], "empty_list": [], "empty_object": {}}
    assert list(argument_leaves(value)) == [
        ("/a~1b~0/0/", "value"),
        ("/a~1b~0/1", 7),
        ("/empty_list", []),
        ("/empty_object", {}),
    ]


def test_structured_offsets_are_half_open_unicode_lexemes_with_decoding_label():
    text = '记录:\n  "a/b~": ["中文🙂", "line\\nvalue"]\n'
    parsed = structured_scalars(text)
    assert parsed["status"] == "parsed"
    assert [scalar["field_path"] for scalar in parsed["scalars"]] == ["/记录/a~1b~0/0", "/记录/a~1b~0/1"]
    assert [scalar["value"] for scalar in parsed["scalars"]] == ["中文🙂", "line\nvalue"]
    for scalar in parsed["scalars"]:
        assert yaml.load(text[scalar["start"] : scalar["end"]], Loader=yaml.BaseLoader) == scalar["value"]
    tape, request, _ = prepared([text])
    tape.propose(request, {"a/b~": ["中文🙂", "line\nvalue"]})
    _, analyses = replay(tape.events)
    assert [field["argument_path"] for field in analyses[-1]["fields"]] == ["/a~1b~0/0", "/a~1b~0/1"]
    for field in analyses[-1]["fields"]:
        (candidate,) = field["exact_candidates"]
        assert candidate["evidence_type"] == "structured_scalar_equal"
        assert (
            yaml.load(text[candidate["start"] : candidate["end"]], Loader=yaml.BaseLoader) == field["value"]
        )


@pytest.mark.parametrize("text", ["name: first\nname: second\n", "first: &value [a, b]\nsecond: *value\n"])
def test_ambiguous_structured_text_does_not_create_scalar_locations(text):
    result = structured_scalars(text)
    assert result["status"] == "unsupported_structure"
    assert result["scalars"] == []


def test_external_input_edits_do_not_change_already_consumed_request():
    tape, request, _ = prepared(["id: record-17"])
    tracker, _ = replay(tape.events)
    request["data"]["body"]["messages"][0]["content"] = "id: externally-edited"
    proposal = tape.propose(request, {"id": "record-17"})
    analysis = tracker.consume(proposal)
    proposal["data"]["arguments"]["id"] = "also-edited"
    assert analysis["fields"][0]["exact_status"] == "single_source_candidate"
    assert analysis["request_messages"][0]["content"] == "id: record-17"
    assert analysis["arguments"]["id"] == "record-17"


def test_external_return_edits_do_not_poison_later_proposals_or_saved_calls():
    tape, request, _ = prepared(["id: 7"])
    tracker, _ = replay(tape.events)
    first = tracker.consume(tape.propose(request, {"id": "7"}))
    expected = copy.deepcopy(first)
    first["request_messages"][0]["content"] = "id: 99"
    first["visible_sources"][0]["structure"]["scalars"][0]["value"] = "99"
    first["arguments"]["id"] = "99"
    assert tracker.calls[-1] == expected
    second = tracker.consume(tape.propose(request, {"id": "7"}))
    assert second["request_messages"][0]["content"] == "id: 7"
    assert second["fields"][0]["exact_status"] == "single_source_candidate"


def test_zero_argument_call_has_no_attribution_target():
    tape, request, _ = prepared()
    tape.propose(request, {})
    _, analyses = replay(tape.events)
    assert analyses[-1]["fields"] == []

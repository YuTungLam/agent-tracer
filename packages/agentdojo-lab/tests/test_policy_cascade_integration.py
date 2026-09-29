"""Policy-gated cascade integration using harmless prefixes and native mock runs."""

import copy
import json

import pytest
import test_live_attribution_integration as live
import test_provenance as prefixes

from agentdojo_lab.online import OnlineProvenance
from agentdojo_lab.policy import ToolPolicy, load_policy
from agentdojo_lab.provenance import ProvenanceTracker
from agentdojo_lab.semantic import EncodedText, SemanticMatcher, chunk_spans


def document(*, argument_paths=None):
    return {
        "schema_version": 1,
        "policy_id": "fixture-policy-v1",
        "suite": "workspace",
        "benchmark_version": "v1.2.2",
        "sources": {"read_note": {"rationale": "Fixture visible source", "output_scope": "visible_text"}},
        "sinks": {
            "update_note": {
                "rationale": "Fixture environment mutation",
                "argument_paths": [""] if argument_paths is None else argument_paths,
            }
        },
        "neutral_tools": {"clock": {"rationale": "Fixture clock without external content"}},
    }


class StageSpy:
    semantic_threshold = 0.60
    coverage_threshold = 0.10
    metadata = {"model": "deterministic-fixture", "revision": "fixed"}

    def __init__(self, *, fail=False, tier3_status="scored"):
        self.calls = []
        self.fail = fail
        self.tier3_status = tier3_status

    def compare(self, source, target):
        pytest.fail("Policy mode must not run the independent all-stage comparison")

    def compare_tier3(self, source, target):
        self.calls.append(("tier3", source, target))
        if self.fail:
            raise RuntimeError("private fixture error details")
        return {
            "status": self.tier3_status,
            "score": 0.60 if source == "AAAA" else 0.20,
            "matched": False,
            "complete": self.tier3_status == "scored",
            "truncated": False,
        }

    def compare_tier4(self, source, target):
        self.calls.append(("tier4", source, target))
        return {
            "status": "scored",
            "score": 0.60,
            "coverage": 0.10,
            "matched": False,
            "complete": True,
            "truncated": False,
            "chunks": [],
        }


def prepared(*, sources=(("read_note", "ZZZZ"),), controls=(), arguments=None, sink="update_note"):
    tape = prefixes.Tape()
    initial = tape.request([{"role": "user", "content": "Use the fixture tools."}])
    tape.response(initial)
    source_calls = [tape.propose(initial, {}, function=name) for name, _ in sources]
    results = [tape.tool_result(call, text) for call, (_, text) in zip(source_calls, sources, strict=True)]
    request = tape.request(
        [
            *copy.deepcopy(controls),
            *[prefixes.wire_tool(result, text) for result, (_, text) in zip(results, sources, strict=True)],
        ]
    )
    for index, result in enumerate(results, len(controls)):
        tape.expose(request, result, index)
    tape.response(request)
    proposal = tape.propose(request, {"text": "ZZZZ"} if arguments is None else arguments, function=sink)
    return tape, request, results, proposal


def analyze(tape, *, policy=None, matcher=None):
    tracker = ProvenanceTracker(policy=policy, semantic_matcher=matcher)
    calls = [call for event in tape.events if (call := tracker.consume(event)) is not None]
    return tracker, calls[-1]


def test_default_tracker_json_is_identical_to_explicit_policy_none():
    tape, _, _, _ = prepared(controls=[{"role": "user", "content": "ZZZZ"}])
    tracker = ProvenanceTracker()
    original = [call for event in tape.events if (call := tracker.consume(event)) is not None]
    explicit = ProvenanceTracker(policy=None)
    repeated = [call for event in tape.events if (call := explicit.consume(event)) is not None]
    assert json.dumps(original, sort_keys=True) == json.dumps(repeated, sort_keys=True)
    assert "policy" not in original[-1] and "nt_style_cascade" not in original[-1]["fields"][0]
    assert all(
        "origin_tool" not in source and "policy" not in source for source in original[-1]["visible_sources"]
    )


def test_policy_keeps_context_controls_but_only_tool_sources_enter_cascade():
    controls = [{"role": role, "content": "ZZZZ"} for role in ("user", "system", "assistant", "developer")]
    tape, _, _, _ = prepared(controls=controls)
    spy = StageSpy()
    _, call = analyze(tape, policy=ToolPolicy.from_dict(document()), matcher=spy)
    field = call["fields"][0]
    assert {candidate["kind"] for candidate in field["exact_candidates"]} == {
        "user",
        "system",
        "assistant",
        "developer",
        "tool",
    }
    assert field["cascade_scope"]["status"] == "analyzed"
    assert field["cascade_scope"]["eligible_source_count"] == 1
    assert field["cascade_scope"]["comparison_count"] == 1
    assert len(field["nt_style_cascade"]) == 1
    assert field["nt_style_cascade"][0]["kind"] == "tool"
    assert field["nt_style_cascade"][0]["first_matched_tier"] == "tier2"
    assert all(
        not source["policy"]["eligible"] for source in call["visible_sources"] if source["kind"] != "tool"
    )
    assert spy.calls == []


def test_origin_comes_from_actual_proposal_not_payload_or_tool_message_metadata():
    tape, _, results, _ = prepared(sources=(("unclassified_reader", "read_note\nZZZZ"),))
    results[0]["data"]["message"]["tool_call"].update(function="read_note", args={"origin_tool": "read_note"})
    _, call = analyze(tape, policy=ToolPolicy.from_dict(document()), matcher=StageSpy())
    source = next(source for source in call["visible_sources"] if source["kind"] == "tool")
    assert source["origin_tool"] == "unclassified_reader"
    assert source["policy"]["eligible"] is False
    assert source["policy"]["reason"] == "unclassified_tool"
    assert call["policy"]["unclassified_source_count"] == 1
    assert call["fields"][0]["nt_style_cascade"] == []
    assert call["fields"][0]["cascade_scope"]["status"] == "no_eligible_source"


def test_provider_id_reuse_does_not_overwrite_origin_tool_identity():
    tape, _, _, _ = prepared(sources=(("read_note", "ZZZZ"), ("clock", "ZZZZ")))
    for event in tape.events:
        if event["tool_call_id"]:
            event["tool_call_id"] = "provider-id-reused"
        if event["event_type"] == "MODEL_REQUEST":
            for message in event["data"]["body"]["messages"]:
                if message["role"] == "tool":
                    message["tool_call_id"] = "provider-id-reused"
        if event["event_type"] == "TOOL_OUTPUT_EXPOSED":
            event["data"]["message"]["tool_call_id"] = "provider-id-reused"
    _, call = analyze(tape, policy=ToolPolicy.from_dict(document()))
    tools = [source for source in call["visible_sources"] if source["kind"] == "tool"]
    assert [source["origin_tool"] for source in tools] == ["read_note", "clock"]
    assert [source["policy"]["eligible"] for source in tools] == [True, False]
    assert len(call["fields"][0]["nt_style_cascade"]) == 1


def test_each_source_pair_short_circuits_separately_and_later_pairs_still_run():
    tape, _, _, _ = prepared(sources=(("read_note", "ZZZZ"), ("read_note", "AAAA"), ("read_note", "VVVV")))
    spy = StageSpy()
    _, call = analyze(tape, policy=ToolPolicy.from_dict(document()), matcher=spy)
    evidence = call["fields"][0]["nt_style_cascade"]
    assert [item["first_matched_tier"] for item in evidence] == ["tier2", "tier3", "tier4"]
    assert spy.calls == [("tier3", "AAAA", "ZZZZ"), ("tier3", "VVVV", "ZZZZ"), ("tier4", "VVVV", "ZZZZ")]
    assert all(item["stages"]["tier1"]["status"] == "disabled_condition" for item in evidence)
    assert evidence[0]["stages"]["tier3"]["status"] == "skipped"
    assert evidence[1]["stages"]["tier4"]["matched"] is None
    assert all(item["provenance_verdict"] == "unreviewed" for item in evidence)
    assert all(item["maliciousness"] == item["causal_influence"] == "not_assessed" for item in evidence)


def test_argument_selection_respects_json_pointer_components_arrays_and_escaping():
    tape, _, _, _ = prepared(
        arguments={"records/list": [{"id": "ZZZZ"}], "records/listed": "ZZZZ", "text": "ZZZZ"}
    )
    policy = ToolPolicy.from_dict(document(argument_paths=["/records~1list"]))
    _, call = analyze(tape, policy=policy)
    fields = prefixes.by_path(call)
    assert fields["/records~1list/0/id"]["cascade_scope"]["status"] == "analyzed"
    for pointer in ("/records~1listed", "/text"):
        assert fields[pointer]["cascade_scope"]["status"] == "argument_excluded_by_policy"
        assert fields[pointer]["nt_style_cascade"] == []
        assert fields[pointer]["exact_candidates"]


@pytest.mark.parametrize(
    "sink, expected", [("read_note", "not_a_policy_sink"), ("new_sink", "unclassified_tool")]
)
def test_nonsink_and_unclassified_call_are_coverage_states_not_clean_verdicts(sink, expected):
    tape, _, _, _ = prepared(sink=sink)
    spy = StageSpy()
    _, call = analyze(tape, policy=ToolPolicy.from_dict(document()), matcher=spy)
    assert call["fields"][0]["cascade_scope"]["status"] == expected
    assert call["fields"][0]["nt_style_cascade"] == []
    assert call["fields"][0]["maliciousness"] == "not_assessed"
    assert spy.calls == []


def test_missing_semantic_stages_remain_indeterminate_and_causal_stage_unimplemented():
    tape, _, _, _ = prepared(sources=(("read_note", "AAAA"),))
    _, call = analyze(tape, policy=ToolPolicy.from_dict(document()))
    evidence = call["fields"][0]["nt_style_cascade"][0]
    assert evidence["status"] == "indeterminate" and evidence["matched"] is None
    assert evidence["stages"]["tier3"]["status"] == "unavailable"
    assert call["cascade_summary"]["causal_analysis"] == "not_implemented"


@pytest.mark.parametrize(
    "arguments, status, pair_count",
    [({}, "no_argument_targets", 0), ({"text": ""}, "not_applicable_comparisons", 1)],
)
def test_zero_arguments_and_empty_text_do_not_become_negative_provenance(arguments, status, pair_count):
    tape, _, _, _ = prepared(arguments=arguments)
    spy = StageSpy()
    _, call = analyze(tape, policy=ToolPolicy.from_dict(document()), matcher=spy)
    assert call["cascade_summary"]["status"] == status
    assert call["cascade_summary"]["pair_count"] == pair_count
    assert call["cascade_summary"]["causal_analysis"] == "not_implemented"
    assert call["cascade_summary"]["maliciousness"] == "not_assessed"
    assert spy.calls == []
    for field in call["fields"]:
        assert all(pair["matched"] is None for pair in field["nt_style_cascade"])


def test_same_request_does_not_gain_new_sources_from_an_interleaved_later_tool_result():
    tape, request, _, _ = prepared(arguments={})
    first = tape.propose(request, {}, function="read_note")
    tape.tool_result(first, "FUTURE_ONLY_SOURCE")
    tape.propose(request, {"text": "FUTURE_ONLY_SOURCE"}, function="update_note")
    _, call = analyze(tape, policy=ToolPolicy.from_dict(document()), matcher=StageSpy())
    assert all("FUTURE_ONLY_SOURCE" not in source["text"] for source in call["visible_sources"])
    assert call["policy"]["eligible_source_count"] == 1


def test_gold_like_metadata_and_task_names_cannot_select_threshold_profiles():
    tape, _, _, _ = prepared(sources=(("read_note", "AAAA"),))
    changed = copy.deepcopy(tape)
    for event in changed.events:
        event["task_id"] = "safe_control_rag_memory_implicit"
        if event["event_type"] in {
            "RUN_STARTED",
            "EPISODE_STARTED",
            "TOOL_RUNTIME_RETURNED",
            "MODEL_RESPONSE",
        }:
            event["data"]["evaluation"] = {
                "gold": False,
                "attack": False,
                "safe_control": True,
                "family": "rag",
            }
    policy = ToolPolicy.from_dict(document())
    _, original = analyze(tape, policy=policy, matcher=StageSpy())
    _, alternate = analyze(changed, policy=policy, matcher=StageSpy())
    assert original["fields"] == alternate["fields"]
    assert original["fields"][0]["nt_style_cascade"][0]["metadata"]["thresholds"] == {
        "tier2_lcs": 0.15,
        "tier3_cosine": 0.60,
        "tier4_cosine": 0.60,
        "tier4_coverage": 0.10,
    }


def test_policy_and_returned_metadata_mutation_cannot_reclassify_later_calls(tmp_path):
    original_doc = document()
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(original_doc))
    policy = load_policy(path)
    fingerprint = policy.metadata["sha256"]
    original_doc["sources"].clear()
    exposed_metadata = policy.metadata
    exposed_metadata["document"]["sources"].clear()
    tape, request, _, _ = prepared()
    tracker, first = analyze(tape, policy=policy)
    first["policy"]["sink"]["selected"] = False
    first["visible_sources"][0]["policy"]["eligible"] = False
    next_event = tape.propose(request, {"text": "ZZZZ"}, function="update_note")
    second = tracker.consume(next_event)
    assert second["policy"]["sink"]["selected"] is True
    assert second["visible_sources"][0]["policy"]["eligible"] is True
    assert second["policy"]["sha256"] == fingerprint
    assert len(second["fields"][0]["nt_style_cascade"]) == 1


def inject_policy(monkeypatch, policy):
    monkeypatch.setattr(
        live,
        "OnlineProvenance",
        lambda path, semantic_matcher=None: OnlineProvenance(
            path, semantic_matcher=semantic_matcher, policy=policy
        ),
    )


def test_live_policy_mode_preserves_native_requests_actions_environment_and_persistence(
    tmp_path, monkeypatch
):
    baseline = live.run_native(tmp_path / "default", live.normal_script(), enabled=True)
    inject_policy(monkeypatch, ToolPolicy.from_dict(document()))
    selected = live.run_native(tmp_path / "policy", live.normal_script(), enabled=True, matcher=StageSpy())
    live.assert_native_equal(baseline, selected)
    assert selected["sidecar_status"]["complete"] is True
    assert selected["sidecar_status"]["analysis_count"] == 3
    analyses = [row for row in selected["rows"] if row["record_type"] == "call_analysis"]
    assert all("policy" in row["call"] for row in analyses)
    assert analyses[0]["call"]["policy"]["sink"]["selected"] is False
    assert all(row["call"]["policy"]["sink"]["selected"] for row in analyses[1:])
    for observed, proposal in zip(selected["at_runtime_entry"], analyses, strict=True):
        assert any(
            row["record_type"] == "analysis_flush"
            and row["proposal_event_id"] == proposal["proposal_event_id"]
            for row in observed["rows"]
        )


def test_live_cascade_encoder_failure_disables_attribution_without_changing_agent(tmp_path, monkeypatch):
    script = [
        live.native.tool_message(live.native.tool_call("read_note", {"labels": []}, "read")),
        live.native.tool_message(live.native.tool_call("update_note", {"text": "ZZZZ"}, "write")),
        live.native.final_message(),
    ]
    baseline = live.run_native(tmp_path / "default", script, enabled=False)
    inject_policy(monkeypatch, ToolPolicy.from_dict(document()))
    selected = live.run_native(tmp_path / "policy", script, enabled=True, matcher=StageSpy(fail=True))
    live.assert_native_equal(baseline, selected)
    assert selected["failure"] is None
    assert selected["sidecar_status"]["disabled"] is True
    assert selected["sidecar_status"]["complete"] is False
    assert "private fixture error details" not in json.dumps(selected["sidecar_status"])
    assert selected["environment"]["note"]["text"] == "ZZZZ"


class BoundaryEncoder:
    """Instrument the real stage implementation without loading an embedding model."""

    metadata = {"model_id": "native-boundary-fixture", "revision": "fixed", "local_files_only": True}

    def __init__(self, vectors):
        self.vectors = vectors
        self.calls = []

    def encode(self, texts):
        self.calls.append(list(texts))
        return [
            EncodedText(
                self.vectors[text],
                {
                    "input_tokens": len(text) + 2,
                    "encoded_tokens": len(text) + 2,
                    "max_tokens": 100_000,
                    "truncated": False,
                    "visible_span": [0, len(text)],
                },
            )
            for text in texts
        ]


def set_multisentence_note(monkeypatch):
    env_class = live.native.NoteEnv
    monkeypatch.setattr(
        live.native,
        "NoteEnv",
        lambda: env_class(note=live.native.Note(text="AAAA. BBBB. CCCC. DDDD. EEEE.")),
    )


def assert_sink_persisted_at_native_entry(result, call):
    entry = next(item for item in result["at_runtime_entry"] if item["function"] == "update_note")
    proposal_id = next(
        row["proposal_event_id"]
        for row in result["rows"]
        if row["record_type"] == "call_analysis" and row["call"] == call
    )
    available = [row for row in entry["rows"] if row.get("proposal_event_id") == proposal_id]
    assert {row["record_type"] for row in available} == {
        "call_analysis",
        "analysis_flush",
        "runtime_timing",
    }
    timing = next(row for row in available if row["record_type"] == "runtime_timing")
    assert timing["analysis_before_runtime"] is True
    assert timing["receipt_before_runtime"] is True


@pytest.mark.parametrize("first_hit", ["tier2", "tier3", "tier4", None])
def test_native_ordered_cascade_encodes_only_the_reached_stage_inputs(tmp_path, monkeypatch, first_hit):
    set_multisentence_note(monkeypatch)
    target = "AAAA" if first_hit == "tier2" else "ZZZZ"
    script = [
        live.native.tool_message(live.native.tool_call("read_note", {"labels": []}, "source")),
        live.native.tool_message(live.native.tool_call("update_note", {"text": target}, "sink")),
        live.native.final_message(),
    ]
    baseline = live.run_native(tmp_path / "disabled", script, enabled=False)
    # Use the bytes visible to the actual SDK request, including native YAML formatting.
    source = next(
        message["content"] for message in baseline["requests"][1]["messages"] if message["role"] == "tool"
    )
    chunks = [source[item["span"][0] : item["span"][1]] for item in chunk_spans(source)]
    assert len(chunks) == 2 and source not in chunks
    vectors = {text: (0.0, 1.0) for text in [source, *chunks]}
    vectors[target] = (1.0, 0.0)
    if first_hit == "tier3":
        vectors[source] = (1.0, 0.0)
    elif first_hit == "tier4":
        vectors[chunks[0]] = (1.0, 0.0)
    encoder = BoundaryEncoder(vectors)
    inject_policy(monkeypatch, ToolPolicy.from_dict(document()))
    result = live.run_native(tmp_path / "enabled", script, enabled=True, matcher=SemanticMatcher(encoder))
    live.assert_native_equal(baseline, result)
    assert result["failure"] is None and result["sidecar_status"]["complete"] is True
    assert result["sidecar_status"]["scoring_complete"] is True
    call = next(
        row["call"]
        for row in result["rows"]
        if row["record_type"] == "call_analysis" and row["call"]["function"] == "update_note"
    )
    (pair,) = call["fields"][0]["nt_style_cascade"]
    assert pair["first_matched_tier"] == first_hit
    assert pair["status"] == "scored" and pair["complete"] is True
    assert pair["matched"] is (first_hit is not None)
    assert pair["stages"]["tier1"]["status"] == "disabled_condition"
    expected = [] if first_hit == "tier2" else [[source, target]]
    if first_hit in {"tier4", None}:
        expected.append([target, *chunks])
        assert pair["stages"]["tier4"]["coverage"] == pytest.approx(
            len(chunks[0]) / len(source) if first_hit == "tier4" else 0.0
        )
    else:
        assert pair["stages"]["tier4"]["status"] == "skipped"
    assert encoder.calls == expected
    assert_sink_persisted_at_native_entry(result, call)


def test_native_first_source_hit_does_not_skip_competing_source_encodings(tmp_path, monkeypatch):
    set_multisentence_note(monkeypatch)
    original_runtime = live.native.note_runtime

    def with_alternate_source(executed):
        runtime = original_runtime(executed)

        @runtime.register_function
        def read_alternate() -> str:
            """Read another harmless fixture source."""
            executed.append(("read_alternate",))
            return "VVVV. WWWW. XXXX. YYYY. AAAA."

        return runtime

    monkeypatch.setattr(live.native, "note_runtime", with_alternate_source)
    script = [
        live.native.tool_message(
            live.native.tool_call("read_note", {"labels": []}, "source-one"),
            live.native.tool_call("read_alternate", {}, "source-two"),
        ),
        live.native.tool_message(live.native.tool_call("update_note", {"text": "ZZZZ"}, "sink")),
        live.native.final_message(),
    ]
    baseline = live.run_native(tmp_path / "disabled", script, enabled=False)
    sources = [
        message["content"] for message in baseline["requests"][1]["messages"] if message["role"] == "tool"
    ]
    assert len(sources) == 2
    first, second = sources
    chunks = [second[item["span"][0] : item["span"][1]] for item in chunk_spans(second)]
    vectors = {text: (0.0, 1.0) for text in [second, *chunks]}
    vectors.update({first: (1.0, 0.0), "ZZZZ": (1.0, 0.0)})
    encoder = BoundaryEncoder(vectors)
    selected = document()
    selected["sources"]["read_alternate"] = {
        "rationale": "Fixture competing visible source",
        "output_scope": "visible_text",
    }
    inject_policy(monkeypatch, ToolPolicy.from_dict(selected))
    result = live.run_native(tmp_path / "enabled", script, enabled=True, matcher=SemanticMatcher(encoder))
    live.assert_native_equal(baseline, result)
    assert result["sidecar_status"]["complete"] is True
    call = next(
        row["call"]
        for row in result["rows"]
        if row["record_type"] == "call_analysis" and row["call"]["function"] == "update_note"
    )
    pairs = call["fields"][0]["nt_style_cascade"]
    assert [pair["first_matched_tier"] for pair in pairs] == ["tier3", None]
    assert [pair["matched"] for pair in pairs] == [True, False]
    assert all(pair["complete"] is True for pair in pairs)
    assert encoder.calls == [[first, "ZZZZ"], [second, "ZZZZ"], ["ZZZZ", *chunks]]
    assert_sink_persisted_at_native_entry(result, call)

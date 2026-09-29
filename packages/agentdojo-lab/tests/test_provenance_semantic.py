"""Semantic integration contracts; fake embeddings only, no model downloads."""

import copy
import json

import pytest
import test_provenance as event_fixtures
import test_provenance_report as report_fixtures

from agentdojo_lab.provenance import ProvenanceTracker
from agentdojo_lab.provenance_report import export_provenance
from agentdojo_lab.runner import RunConfig, run_clean


class FakeMatcher:
    """Return deterministic component observations without reading any labels."""

    def __init__(self, status="scored"):
        self.status = status
        self.calls = []
        self.returned = []
        self.metadata = {
            "method": "nt_style_semantic_v1",
            "model": "fixture-only-encoder",
            "revision": "fixed-fixture-revision",
            "device": "cpu",
            "dtype": "float32",
            "component_mode": "independent_all_pairs",
            "fixture_note": "SEMANTIC_PREDICTION_ONLY_583",
        }

    def compare(self, source, target):
        assert isinstance(source, str) and isinstance(target, str)
        self.calls.append((source, target))
        status = "not_applicable" if not source or not target else self.status
        scored = status == "scored"
        result = {
            "method": "nt_style_semantic_v1",
            "status": status,
            "matched": True if scored else None,
            "tier3": {
                "status": status,
                "score": 0.8 if scored else None,
                "matched": True if scored else None,
            },
            "tier4": {
                "status": status,
                "score": 0.25 if scored else None,
                "coverage": 0.25 if scored else None,
                "matched": True if scored else None,
                "chunks": [],
            },
            "metadata": {"fixture_note": "SEMANTIC_PREDICTION_ONLY_583", "nested": ["original"]},
        }
        self.returned.append(result)
        return result


def replay_with(events, matcher):
    tracker = ProvenanceTracker(semantic_matcher=matcher)
    calls = []
    for event in events:
        result = tracker.consume(event)
        if result is not None:
            calls.append(result)
    return tracker, calls


@pytest.fixture
def offline_source(tmp_path):
    path = tmp_path / "offline-source"
    result = run_clean(RunConfig(), offline=True, output=path)
    assert result["recording"]["complete"] is True
    return path


def without_semantic(call):
    baseline = copy.deepcopy(call)
    for field in baseline["fields"]:
        field.pop("nt_style_semantic", None)
    return baseline


def test_default_tracker_has_no_semantic_fields_and_enabled_preserves_exact_lcs():
    tape, request, _ = event_fixtures.prepared()
    tape.propose(request, {"id": "record-17"})
    _, default = event_fixtures.replay(tape.events)
    _, explicit_none = replay_with(tape.events, None)
    assert explicit_none == default
    assert all("nt_style_semantic" not in field for call in default for field in call["fields"])
    matcher = FakeMatcher()
    assert matcher.calls == []
    _, enabled = replay_with(tape.events, matcher)
    assert [without_semantic(call) for call in enabled] == default
    assert matcher.calls == [("id: record-17", "record-17")]


def test_semantic_scores_every_current_source_even_when_exact_and_lcs_already_match():
    tape, request, _ = event_fixtures.prepared(
        ["id: record-17", "id: record-17"],
        prefix_messages=[{"role": "user", "content": "Please use record-17 today."}],
    )
    tape.propose(request, {"id": "record-17"})
    matcher = FakeMatcher()
    _, calls = replay_with(tape.events, matcher)
    field = calls[-1]["fields"][0]
    assert field["exact_status"] == "multiple_source_candidates"
    assert len(field["nt_style_semantic"]) == len(field["nt_style_lcs"]) == len(matcher.calls) == 3
    assert sorted(hit["kind"] for hit in field["nt_style_semantic"]) == ["tool", "tool", "user"]
    assert {hit["source_id"] for hit in field["nt_style_semantic"]} == {
        source["source_id"] for source in calls[-1]["visible_sources"]
    }
    assert field["provenance_verdict"] == "unreviewed"
    assert field["maliciousness"] == field["causal_influence"] == "not_assessed"


def test_semantic_only_sees_request_sources_and_not_later_same_response_results():
    tape, request, _ = event_fixtures.prepared()
    first = tape.propose(request, {"id": "record-17"})
    future = tape.tool_result(first, "FUTURE_SOURCE_ONLY_731")
    tape.propose(request, {"note": "second-target"})
    later_request = tape.request([event_fixtures.wire_tool(future, "FUTURE_SOURCE_ONLY_731")])
    tape.expose(later_request, future, 0)
    tape.response(later_request)
    tape.propose(later_request, {"note": "later-target"})
    matcher = FakeMatcher()
    _, full = replay_with(tape.events, matcher)
    assert matcher.calls == [
        ("id: record-17", "record-17"),
        ("id: record-17", "second-target"),
        ("FUTURE_SOURCE_ONLY_731", "later-target"),
    ]
    for expected in full:
        _, prefix = replay_with(tape.events[: expected["proposal_sequence"]], FakeMatcher())
        assert prefix[-1] == expected


def test_semantic_does_not_inherit_sources_from_a_previous_episode():
    tape, request, _ = event_fixtures.prepared()
    tape.propose(request, {"id": "record-17"})
    tape.next_episode()
    fresh = tape.request([{"role": "user", "content": "Use a fresh context."}])
    tape.response(fresh)
    tape.propose(fresh, {"id": "record-17"})
    matcher = FakeMatcher()
    _, calls = replay_with(tape.events, matcher)
    assert matcher.calls == [("id: record-17", "record-17"), ("Use a fresh context.", "record-17")]
    assert all(hit["kind"] == "user" for hit in calls[-1]["fields"][0]["nt_style_semantic"])


def test_semantic_receives_wire_text_not_runtime_or_native_metadata():
    tape = event_fixtures.Tape()
    seed = tape.request([{"role": "user", "content": "Read a normal record."}])
    tape.response(seed)
    proposal = tape.propose(seed, {})
    result = tape.tool_result(
        proposal,
        "NATIVE_FORMAT_ONLY_124",
        metadata={"query": "METADATA_ONLY_125"},
        hidden={"internal": "RUNTIME_ONLY_126"},
    )
    request = tape.request([event_fixtures.wire_tool(result, "WIRE_TEXT_ONLY_127")])
    tape.expose(request, result, 0)
    tape.response(request)
    tape.propose(request, {"query": "target-value"})
    matcher = FakeMatcher()
    replay_with(tape.events, matcher)
    assert matcher.calls == [("WIRE_TEXT_ONLY_127", "target-value")]


def test_semantic_target_serialization_and_unscored_empty_values_are_explicit():
    tape, request, _ = event_fixtures.prepared()
    arguments = {
        "null": None,
        "integer": 7,
        "boolean": True,
        "float": 1.5,
        "list": [],
        "object": {},
        "text": "",
    }
    tape.propose(request, arguments)
    matcher = FakeMatcher()
    _, calls = replay_with(tape.events, matcher)
    assert [target for _, target in matcher.calls] == ["null", "7", "true", "1.5", "", "", ""]
    fields = event_fixtures.by_path(calls[-1])
    for path in ("/list", "/object", "/text"):
        (hit,) = fields[path]["nt_style_semantic"]
        assert hit["status"] == "not_applicable"
        assert hit["matched"] is None
        for tier in ("tier3", "tier4"):
            assert hit[tier]["score"] is None and hit[tier]["matched"] is None


@pytest.mark.parametrize("status", ["budget_exceeded", "not_applicable"])
def test_unavailable_semantic_observations_are_not_rewritten_as_measured_negatives(status):
    tape, request, _ = event_fixtures.prepared()
    tape.propose(request, {"id": "record-17"})
    _, calls = replay_with(tape.events, FakeMatcher(status))
    (hit,) = calls[-1]["fields"][0]["nt_style_semantic"]
    assert hit["status"] == status and hit["matched"] is None
    assert hit["tier3"]["score"] is None and hit["tier4"]["coverage"] is None
    assert calls[-1]["fields"][0]["provenance_verdict"] == "unreviewed"


def test_semantic_snapshot_is_isolated_from_input_return_and_matcher_mutation():
    tape, request, _ = event_fixtures.prepared()
    matcher = FakeMatcher()
    tracker, _ = replay_with(tape.events, matcher)
    proposal = tape.propose(request, {"id": "record-17"})
    first = tracker.consume(proposal)
    preserved = copy.deepcopy(first)
    request["data"]["body"]["messages"][0]["content"] = "EXTERNAL_INPUT_EDIT"
    proposal["data"]["arguments"]["id"] = "EXTERNAL_ARGUMENT_EDIT"
    first["fields"][0]["nt_style_semantic"][0]["metadata"]["nested"].append("EXTERNAL_RETURN_EDIT")
    matcher.returned[-1]["metadata"]["nested"].append("EXTERNAL_SCORER_EDIT")
    assert tracker.calls[-1] == preserved
    second = tracker.consume(tape.propose(request, {"id": "record-17"}))
    assert second["request_messages"][0]["content"] == "id: record-17"
    assert second["fields"][0]["nt_style_semantic"][0]["metadata"]["nested"] == ["original"]
    assert matcher.calls == [("id: record-17", "record-17"), ("id: record-17", "record-17")]


def test_semantic_export_keeps_source_and_blank_annotations_identical_to_default(offline_source, tmp_path):
    before = report_fixtures.file_hashes(offline_source)
    plain_output = tmp_path / "plain"
    semantic_output = tmp_path / "semantic"
    export_provenance(run_dirs=[offline_source], output=plain_output)
    matcher = FakeMatcher()
    export_provenance(run_dirs=[offline_source], output=semantic_output, semantic_matcher=matcher)
    plain = report_fixtures.read_json(plain_output / "analysis.json")
    semantic = report_fixtures.read_json(semantic_output / "analysis.json")
    assert "nt_style_semantic_v1" not in plain["methods"]
    assert semantic["methods"]["nt_style_semantic_v1"] == matcher.metadata
    assert semantic["real_llm_calls_added"] == 0
    assert matcher.calls
    assert semantic["counts"]["human_reviewed_fields"] == 0
    assert semantic["counts"]["accuracy"] is None
    assert report_fixtures.file_hashes(offline_source) == before
    annotations = semantic_output / "annotations" / "items.jsonl"
    assert annotations.read_bytes() == (plain_output / "annotations" / "items.jsonl").read_bytes()
    assert "SEMANTIC_PREDICTION_ONLY_583" not in annotations.read_text()
    items = [json.loads(line) for line in annotations.read_text().splitlines()]
    forbidden = {"nt_style_semantic", "tier3", "tier4", "score", "coverage", "matched", "exact_candidates"}
    assert forbidden.isdisjoint(report_fixtures.keys_recursively(items))
    assert "nt_style_semantic" in (semantic_output / "candidates.jsonl").read_text()


def test_semantic_html_still_renders_untrusted_source_and_target_as_text(offline_source, tmp_path):
    marker = '<fixture-tag title="semantic">A & B</fixture-tag>'
    events = report_fixtures.read_events(offline_source)
    proposal = next(event for event in events if event["event_type"] == "TOOL_CALL_PROPOSED")
    request = next(
        event
        for event in events
        if event["event_type"] == "MODEL_REQUEST"
        and event["model_request_id"] == proposal["model_request_id"]
    )
    user = next(message for message in request["data"]["body"]["messages"] if message["role"] == "user")
    user["content"] = marker
    proposal["data"]["arguments"] = {"query": marker}
    report_fixtures.write_events(offline_source, events)
    matcher = FakeMatcher()
    matcher.metadata["fixture_note"] = marker
    output = tmp_path / "semantic"
    export_provenance(run_dirs=[offline_source], output=output, semantic_matcher=matcher)
    html = (output / "index.html").read_text()
    page = report_fixtures.PageStructure()
    page.feed(html)
    assert marker not in html
    assert "&lt;fixture-tag" in html and "A &amp; B" in html
    assert "fixture-tag" not in page.tags and "script" not in page.tags
    assert marker in "".join(page.text)
    assert not any(key.startswith("on") for key, _ in page.attributes)


class MarkedText(report_fixtures.PageStructure):
    def __init__(self):
        super().__init__()
        self.marks = []
        self.current_mark = None

    def handle_starttag(self, tag, attrs):
        super().handle_starttag(tag, attrs)
        if tag == "mark":
            self.current_mark = []

    def handle_data(self, data):
        super().handle_data(data)
        if self.current_mark is not None:
            self.current_mark.append(data)

    def handle_endtag(self, tag):
        if tag == "mark" and self.current_mark is not None:
            self.marks.append("".join(self.current_mark))
            self.current_mark = None


def test_html_discloses_target_truncation_and_highlights_canonical_text_offsets(offline_source, tmp_path):
    long_target = '  "中文🙂"\n<fixture-tag>A & B</fixture-tag> ' + "tail " * 300
    visible_start, visible_end = 2, long_target.index("tail")
    arguments = {"body": long_target, "active": True, "id": 17, "optional": None}
    events = report_fixtures.read_events(offline_source)
    proposal = next(event for event in events if event["event_type"] == "TOOL_CALL_PROPOSED")
    proposal["data"]["arguments"] = arguments
    report_fixtures.write_events(offline_source, events)

    class WindowMatcher(FakeMatcher):
        def compare(self, source, target):
            result = super().compare(source, target)
            truncated = target == long_target
            target_tokens = {
                "input_tokens": 700 if truncated else 3,
                "encoded_tokens": 256 if truncated else 3,
                "max_tokens": 256,
                "truncated": truncated,
                "visible_span": [visible_start, visible_end] if truncated else [0, len(target)],
            }
            source_tokens = {
                "input_tokens": 5,
                "encoded_tokens": 5,
                "max_tokens": 256,
                "truncated": False,
                "visible_span": [0, len(source)],
            }
            result.update(complete=not truncated, truncated=truncated)
            result["tier3"].update(
                source_tokenization=source_tokens,
                source_visible_span=source_tokens["visible_span"],
                target_tokenization=target_tokens,
                truncated=truncated,
                complete=not truncated,
            )
            result["tier4"].update(
                target_tokenization=target_tokens, truncated=truncated, complete=not truncated
            )
            return result

    output = tmp_path / "target-window-analysis"
    export_provenance(run_dirs=[offline_source], output=output, semantic_matcher=WindowMatcher())
    page = MarkedText()
    page.feed((output / "index.html").read_text())
    text = "".join(page.text)
    assert "Argument tokens 256/700" in text
    assert f"Encoded argument span [{visible_start}, {visible_end}]" in text
    assert "Argument truncated; only the highlighted window was compared" in text
    assert "Source tokens 5/5" in text
    # Quotes, Unicode and a newline shift JSON-display offsets. The marked span
    # must instead index the exact string given to the semantic matcher.
    assert long_target[visible_start:visible_end] in page.marks
    assert {"true", "17", "null"}.issubset(page.marks)
    assert "fixture-tag" not in page.tags


def test_html_surfaces_encoder_failures_in_header_instead_of_only_zero_candidates(offline_source, tmp_path):
    matcher = FakeMatcher("encoder_error")
    output = tmp_path / "encoder-error-analysis"
    export_provenance(run_dirs=[offline_source], output=output, semantic_matcher=matcher)
    analysis = report_fixtures.read_json(output / "analysis.json")
    assert matcher.calls
    assert analysis["counts"]["semantic_comparison_statuses"] == {"encoder_error": len(matcher.calls)}
    assert analysis["counts"]["fields_with_tier3_tool_candidate"] == 0
    assert analysis["counts"]["fields_with_tier4_tool_candidate"] == 0
    html = (output / "index.html").read_text()
    # Check the summary before the per-call articles; a collapsed individual
    # score containing encoder_error would not satisfy this visibility contract.
    header = report_fixtures.PageStructure()
    header.feed(html.split("</header>", 1)[0])
    text = "".join(header.text)
    assert "scored 0" in text
    assert f"Encoder errors {len(matcher.calls)}" in text
    assert "Budget exceeded 0" in text and "Not applicable 0" in text
    assert "Unscored comparisons are not negative examples" in text
    assert analysis["counts"]["accuracy"] is None

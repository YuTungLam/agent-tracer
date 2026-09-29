"""Explicit canary plans, assignment proofs, and bounded literal matching."""

import copy
import hashlib
import uuid

import pytest
import yaml

import agentdojo_lab.canary as canary
from agentdojo_lab.canary import (
    MAX_CODEPOINTS,
    SUFFIX_PREFIX,
    CanaryInjector,
    compact_reference,
    marker_matches,
    validate_assignment,
    validate_reference,
)
from agentdojo_lab.policy import ToolPolicy

TOKEN = "11111111-1111-4111-8111-111111111111"
OTHER = "22222222-2222-4222-8222-222222222222"


@pytest.fixture
def policy():
    return ToolPolicy.from_dict(
        {
            "schema_version": 1,
            "policy_id": "canary-test-v1",
            "suite": "workspace",
            "benchmark_version": "v1.2.2",
            "sources": {
                "read_note": {"rationale": "External text."},
                "both": {"rationale": "External text and write capability."},
            },
            "sinks": {
                "write_note": {"rationale": "Persistent write.", "argument_paths": ["/content"]},
                "both": {"rationale": "Persistent write.", "argument_paths": ["/content"]},
            },
            "neutral_tools": {"clock": {"rationale": "Fixed clock."}},
        }
    )


def message(*texts):
    return {
        "role": "tool",
        "content": [{"type": "text", "content": text} for text in texts or ("content: benign",)],
        "error": None,
        "tool_call": object(),
    }


def prepare(injector, msg=None, **kwargs):
    return injector.prepare(
        message() if msg is None else msg,
        **{
            "run_id": "run-1",
            "episode_id": "episode-1",
            "call_ref": "call-1",
            "function": "read_note",
            "runtime_entered": True,
            **kwargs,
        },
    )


def assigned(policy, *texts):
    return prepare(CanaryInjector(policy, lambda: uuid.UUID(TOKEN)), message(*texts))


def test_native_content_is_detached_and_original_message_identity_is_unchanged(policy):
    original = message("title: benign", "content: reference")
    content_identity, call_identity = original["content"], original["tool_call"]
    snapshot = copy.deepcopy(original["content"])
    result = prepare(CanaryInjector(policy, lambda: uuid.UUID(TOKEN)), original)
    assert result["status"] == "assigned"
    assert result["application"] == "planned_only"
    assert original["content"] is content_identity
    assert original["tool_call"] is call_identity
    assert original["content"] == snapshot
    assert result["original_content"] == snapshot
    assert result["marked_content"][0] == snapshot[0]
    assert result["marked_content"][-1]["content"] == snapshot[-1]["content"] + result["suffix"]
    assert result["selected_part_index"] == 1
    assert result["original_text"] == "title: benign\ncontent: reference"
    assert result["marked_text"] == result["original_text"] + result["suffix"]
    result["original_content"][0]["content"] = "mutated"
    result["marked_content"][1]["content"] = "mutated"
    assert original["content"] == snapshot


@pytest.mark.parametrize(
    "text", ["content: benign", "- first\n- second\n", "plain prose", "", "{key: value}\n"]
)
def test_suffix_preserves_ordinary_yaml_parsed_value(policy, text):
    audit = assigned(policy, text)
    assert audit["status"] == "assigned"
    assert yaml.safe_load(audit["marked_text"]) == yaml.safe_load(text)


def test_unicode_offsets_use_codepoints_and_hashes_use_utf8(policy):
    audit = assigned(policy, "first: café", "content: 🧪é")
    source = audit["marked_text"]
    assert audit["insertion_offset"] == len("content: 🧪é")
    part_start, part_end = audit["part_token_span"]
    assert audit["marked_content"][-1]["content"][part_start:part_end] == TOKEN
    joined_start, joined_end = audit["joined_token_span"]
    assert source[joined_start:joined_end] == TOKEN
    assert audit["marked_text_sha256"] == hashlib.sha256(source.encode()).hexdigest()
    assert validate_assignment(audit) == audit


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"function": "write_note"}, "tool_output_excluded_by_policy"),
        ({"function": "clock"}, "tool_output_excluded_by_policy"),
        ({"function": "unknown"}, "unclassified_tool"),
        ({"function": "READ_NOTE"}, "unclassified_tool"),
        ({"runtime_entered": False}, "runtime_not_entered"),
        ({"runtime_entered": 1}, "runtime_not_entered"),
    ],
)
def test_ineligible_calls_skip_without_drawing_uuid(policy, kwargs, reason):
    def forbidden():
        raise AssertionError("UUID generation must be unreachable")

    injector = CanaryInjector(policy, forbidden)
    audit = prepare(injector, **kwargs)
    assert audit["status"] == "skipped"
    assert audit["reason"] == reason
    assert audit["token"] is None
    assert injector.status()["complete"] is True
    assert injector.status()["issued_token_count"] == 0


def test_source_and_sink_overlap_is_eligible(policy):
    assert prepare(CanaryInjector(policy, lambda: uuid.UUID(TOKEN)), function="both")["status"] == "assigned"


@pytest.mark.parametrize("error", ["error text", "", False, {"message": "error"}])
def test_every_non_none_tool_error_skips(policy, error):
    msg = message()
    msg["error"] = error
    assert prepare(CanaryInjector(policy), msg)["reason"] == "tool_error"


@pytest.mark.parametrize(
    "content",
    [
        "native top-level string is outside this scope",
        [],
        None,
        [{"type": "text", "content": None}],
        [{"type": "text", "text": "wrong native key"}],
        [{"type": "image", "content": "image"}],
        [{"type": "text", "content": "plain"}, {"type": "image", "content": "image"}],
        ["plain list strings are not native TextContent"],
        [{"type": "text", "content": "plain", "unknown": "extra"}],
    ],
)
def test_unsupported_native_layouts_are_explicit_skips(policy, content):
    msg = message()
    msg["content"] = content
    audit = prepare(CanaryInjector(policy), msg)
    assert audit["status"] == "skipped"
    assert audit["reason"] == "unsupported_content_layout"
    assert audit["token"] is None


@pytest.mark.parametrize("msg", [None, [], {"role": "assistant"}, {"content": []}])
def test_non_tool_messages_are_never_marked(policy, msg):
    if msg is None:
        result = CanaryInjector(policy).prepare(
            None, run_id="r", episode_id="e", call_ref="c", function="read_note", runtime_entered=True
        )
    else:
        result = prepare(CanaryInjector(policy), msg)
    assert result["reason"] == "unsupported_message_layout"


def test_duplicate_identity_is_blocked_even_if_first_attempt_skipped(policy):
    injector = CanaryInjector(policy, lambda: uuid.UUID(TOKEN))
    assert prepare(injector, runtime_entered=False)["reason"] == "runtime_not_entered"
    assert prepare(injector)["reason"] == "duplicate_call_identity"
    assert prepare(injector, episode_id="episode-2")["status"] == "assigned"
    assert prepare(injector, episode_id="episode-2")["reason"] == "duplicate_call_identity"


def test_uuid_uniqueness_is_across_runs_and_raw_text_collisions_are_retried(policy):
    values = iter([TOKEN, OTHER, OTHER, TOKEN])
    injector = CanaryInjector(policy, lambda: uuid.UUID(next(values)))
    first = prepare(injector, message("raw: " + TOKEN))
    assert first["token"] == OTHER and first["generation_attempts"] == 2
    second = prepare(injector, run_id="run-2")
    assert second["token"] == TOKEN and second["generation_attempts"] == 2
    assert injector.status()["issued_token_count"] == 2


def test_uuid_collision_exhaustion_disables_and_is_not_a_partial_assignment(policy):
    count = 0

    def collision():
        nonlocal count
        count += 1
        return uuid.UUID(TOKEN)

    injector = CanaryInjector(policy, collision)
    audit = prepare(injector, message("raw: " + TOKEN))
    assert count == 16
    assert audit["status"] == "error"
    assert audit["token"] is None and audit["marked_content"] is None
    assert injector.status()["complete"] is False
    assert injector.status()["errors"] == [{"stage": "prepare", "error_type": "ValueError"}]
    assert prepare(injector, call_ref="second")["reason"] == "injector_disabled"


@pytest.mark.parametrize(
    "token",
    [
        TOKEN.upper().replace("1", "A", 1),
        "bad",
        "11111111-1111-1111-8111-111111111111",
        "11111111-1111-4111-1111-111111111111",
        7,
        None,
    ],
)
def test_noncanonical_or_non_v4_factory_results_fail_open(policy, token):
    injector = CanaryInjector(policy, lambda: token)
    assert prepare(injector)["status"] == "error"
    assert injector.status()["complete"] is False


def test_factory_and_external_errors_expose_types_only_and_status_is_detached(policy):
    def broken():
        raise RuntimeError("PRIVATE PAYLOAD NOT FOR DIAGNOSTICS")

    injector = CanaryInjector(policy, broken)
    audit = prepare(injector)
    injector.fail("persist_assignment", OSError("PRIVATE PAYLOAD NOT FOR DIAGNOSTICS"))
    assert "PRIVATE PAYLOAD" not in repr(audit) + repr(injector.status())
    status = injector.status()
    status["errors"][0]["error_type"] = "changed"
    status["metadata"]["limits"]["max_seen_calls"] = 0
    assert injector.status()["errors"][0]["error_type"] == "RuntimeError"
    assert injector.metadata["limits"]["max_seen_calls"] > 0


def test_preparation_size_cap_includes_the_suffix_and_block_join(policy):
    remaining = MAX_CODEPOINTS - len(SUFFIX_PREFIX) - 36 - 1
    valid = assigned(policy, "x" * remaining)
    assert valid["status"] == "assigned"
    assert len(valid["marked_text"]) == MAX_CODEPOINTS
    injector = CanaryInjector(policy)
    exceeded = prepare(injector, message("x" * (remaining + 1)))
    assert exceeded["reason"] == "budget_exceeded"
    assert exceeded["generation_attempts"] == 0
    assert injector.status()["complete"] is False
    join_exceeded = prepare(CanaryInjector(policy), message("", "x" * remaining))
    assert join_exceeded["reason"] == "budget_exceeded"
    raw_exceeded = prepare(CanaryInjector(policy), message("x" * (MAX_CODEPOINTS + 1)))
    assert raw_exceeded["reason"] == "budget_exceeded"


def test_block_and_call_registry_budgets_are_explicit(policy, monkeypatch):
    assert prepare(CanaryInjector(policy), message(*([""] * 1025)))["reason"] == "budget_exceeded"
    monkeypatch.setattr(canary, "MAX_SEEN_CALLS", 1)
    injector = CanaryInjector(policy, lambda: uuid.UUID(TOKEN))
    assert prepare(injector)["status"] == "assigned"
    assert prepare(injector, call_ref="second")["status"] == "error"
    assert injector.status()["complete"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", True),
        ("schema_version", 1.0),
        ("method", "other"),
        ("scheme", "other"),
        ("status", "skipped"),
        ("application", "confirmed"),
        ("policy_sha256", "bad"),
        ("run_id", ""),
        ("token", OTHER),
        ("selected_part_index", True),
        ("selected_part_index", 0),
        ("insertion_offset", True),
        ("insertion_offset", 0),
        ("part_token_span", [0, 36]),
        ("joined_token_span", [0, 36]),
        ("generation_attempts", True),
        ("generation_attempts", 17),
        ("suffix", "arbitrary"),
        ("original_text", "forged"),
        ("marked_text_sha256", "0" * 64),
    ],
)
def test_assignment_validator_rejects_tampered_fields(policy, field, value):
    audit = assigned(policy, "first", "second")
    audit[field] = value
    with pytest.raises(ValueError):
        validate_assignment(audit)


def test_assignment_validator_rejects_non_suffix_layout_changes_even_with_forged_hashes(policy):
    audit = assigned(policy, "first", "second")
    audit["marked_content"][0]["content"] = "changed"
    audit["marked_text"] = "\n".join(part["content"] for part in audit["marked_content"])
    audit["marked_text_sha256"] = hashlib.sha256(audit["marked_text"].encode()).hexdigest()
    with pytest.raises(ValueError, match="only the fixed suffix"):
        validate_assignment(audit)


def test_validated_assignment_and_compact_reference_are_detached(policy):
    audit = assigned(policy)
    validated = validate_assignment(audit)
    reference = compact_reference(audit)
    assert set(reference) == {
        "method",
        "scheme",
        "token",
        "marked_text_sha256",
        "source_span",
        "policy_sha256",
    }
    reference["assignment_event_id"] = "trusted-event"
    saved = validate_reference(reference, audit["marked_text"])
    reference["source_span"][0] = 0
    validated["marked_content"][0]["content"] = "changed"
    assert saved["source_span"] == audit["joined_token_span"]
    assert saved["assignment_event_id"] == "trusted-event"
    assert audit["marked_content"][0]["content"] != "changed"


@pytest.mark.parametrize(
    "field,value",
    [
        ("method", "other"),
        ("scheme", "other"),
        ("token", OTHER),
        ("policy_sha256", "bad"),
        ("marked_text_sha256", "0" * 64),
        ("source_span", [0, 36]),
        ("source_span", [True, 36]),
        ("source_span", [-1, 36]),
    ],
)
def test_reference_validator_rejects_tampering(policy, field, value):
    audit = assigned(policy)
    reference = compact_reference(audit)
    reference[field] = value
    with pytest.raises(ValueError):
        validate_reference(reference, audit["marked_text"])


def test_reference_rejects_changed_source_and_absent_unassigned_markers(policy):
    audit = assigned(policy)
    reference = compact_reference(audit)
    with pytest.raises(ValueError):
        marker_matches(audit["marked_text"] + "changed", TOKEN, reference)
    with pytest.raises(ValueError):
        marker_matches("# NT_CANARY: " + TOKEN, TOKEN, {})


def test_matching_uses_registered_literal_uuid_and_returns_first_codepoint_span(policy):
    audit = assigned(policy, "content: reference")
    reference = compact_reference(audit)
    source = audit["marked_text"]
    target = "🧪 prefix " + TOKEN + " repeated " + TOKEN
    result = marker_matches(source, target, reference)
    assert result["status"] == "scored" and result["matched"] is True
    assert result["score"] == 1.0 and result["complete"] is True
    assert result["target_spans"] == [[len("🧪 prefix "), len("🧪 prefix ") + 36]]
    assert result["source_span"] == audit["joined_token_span"]
    assert result["metadata"]["target_occurrences"] == "first_only"
    for absent in ("unrelated", TOKEN[:-1], OTHER, "# NT_CANARY: unassigned"):
        negative = marker_matches(source, absent, reference)
        assert negative["status"] == "scored" and negative["matched"] is False
        assert negative["score"] == 0.0 and negative["target_spans"] == []
    assert marker_matches(source, "x" + TOKEN + "x", reference)["matched"] is True


def test_marker_matching_is_case_sensitive(policy):
    token = "abcdefab-abcd-4abc-8abc-abcdefabcdef"
    audit = prepare(CanaryInjector(policy, lambda: uuid.UUID(token)))
    reference = compact_reference(audit)
    assert marker_matches(audit["marked_text"], token.upper(), reference)["matched"] is False


def test_matching_never_turns_empty_or_oversized_inputs_into_scored_negatives(policy, monkeypatch):
    audit = assigned(policy)
    reference = compact_reference(audit)
    empty = marker_matches(audit["marked_text"], "", reference)
    assert empty["status"] == "not_applicable"
    assert empty["score"] is None and empty["matched"] is None and empty["complete"] is False
    assert marker_matches("", TOKEN, {})["status"] == "not_applicable"

    def forbidden(*args):
        raise AssertionError("The oversized input must not be hashed")

    monkeypatch.setattr(canary, "_sha", forbidden)
    for source, target in (
        ("x" * (MAX_CODEPOINTS + 1), TOKEN),
        (audit["marked_text"], "x" * (MAX_CODEPOINTS + 1)),
    ):
        result = marker_matches(source, target, reference)
        assert result["status"] == "budget_exceeded"
        assert result["score"] is None and result["matched"] is None
        assert result["complete"] is False and result["truncated"] is False


def test_matching_accepts_exact_size_limit(policy):
    audit = assigned(policy)
    target = "x" * (MAX_CODEPOINTS - len(TOKEN)) + TOKEN
    assert marker_matches(audit["marked_text"], target, compact_reference(audit))["matched"] is True

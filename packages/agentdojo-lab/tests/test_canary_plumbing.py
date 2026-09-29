"""Integrity gates for explicit canary routing, registration, and persistence."""

import copy
import hashlib
import json
import uuid

import pytest
from test_provenance import Tape, wire_tool

import agentdojo_lab.cascade as cascade_module
import agentdojo_lab.lexical as lexical_module
from agentdojo_lab.canary import CanaryInjector, compact_reference
from agentdojo_lab.cascade import CascadeMatcher
from agentdojo_lab.lineage import DCPG
from agentdojo_lab.policy import ToolPolicy
from agentdojo_lab.provenance import ProvenanceTracker
from agentdojo_lab.report_data import collect_runs
from agentdojo_lab.runner import RunConfig
from agentdojo_lab.semantic import SemanticMatcher

TOKEN = "abcdeabc-abcd-4abc-8abc-abcdefabcdef"
OTHER = "22222222-2222-4222-8222-222222222222"


@pytest.fixture
def policy():
    return ToolPolicy(
        {
            "schema_version": 1,
            "policy_id": "canary-plumbing-v1",
            "suite": "workspace",
            "benchmark_version": "v1.2.2",
            "sources": {"get_file_by_id": {"rationale": "Reads external file text."}},
            "sinks": {"create_file": {"rationale": "Writes file text.", "argument_paths": ["/content"]}},
            "neutral_tools": {},
        }
    )


def audit_for(policy, text="content: benign"):
    return CanaryInjector(policy, lambda: uuid.UUID(TOKEN)).prepare(
        {"role": "tool", "content": [{"type": "text", "content": text}], "error": None},
        run_id="harmless-fixture",
        episode_id="episode:1",
        call_ref="call",
        function="get_file_by_id",
        runtime_entered=True,
    )


class ForbiddenEncoder:
    metadata = {"fixture": "must_not_encode"}

    def __init__(self):
        self.entries = 0

    def encode(self, texts):
        self.entries += 1
        raise AssertionError("No semantic encoding is permitted after a Tier 1 hit")


def test_tier1_hit_never_enters_actual_lcs_or_encoder(policy, monkeypatch):
    audit = audit_for(policy)
    encoder = ForbiddenEncoder()
    lcs_entries = []

    def forbidden_lcs(*args, **kwargs):
        lcs_entries.append(args)
        raise AssertionError("No LCS computation is permitted after a Tier 1 hit")

    monkeypatch.setattr(cascade_module, "lcs_evidence", forbidden_lcs)
    monkeypatch.setattr(lexical_module, "_lcs_length", forbidden_lcs)
    result = CascadeMatcher(SemanticMatcher(encoder), canary_enabled=True).compare(
        audit["marked_text"], "copied " + TOKEN, canary=compact_reference(audit)
    )
    assert result["first_matched_tier"] == "tier1"
    assert result["matched"] is result["complete"] is True
    assert lcs_entries == [] and encoder.entries == 0
    assert all(result["stages"][tier]["score"] is None for tier in ("tier2", "tier3", "tier4"))
    assert result["maliciousness"] == result["causal_influence"] == "not_assessed"


@pytest.mark.parametrize("target", ["content: benign", OTHER, TOKEN[:-1], TOKEN.upper()])
def test_absent_wrong_partial_or_case_changed_marker_enters_real_lcs(policy, monkeypatch, target):
    audit = audit_for(policy)
    entries = []
    actual = lexical_module._lcs_length

    def counted(source, target):
        entries.append((source, target))
        return actual(source, target)

    monkeypatch.setattr(lexical_module, "_lcs_length", counted)
    result = CascadeMatcher(canary_enabled=True).compare(
        audit["marked_text"], target, canary=compact_reference(audit)
    )
    assert result["stages"]["tier1"]["matched"] is False
    assert result["stages"]["tier2"]["status"] == "scored"
    assert entries == [(audit["marked_text"], target)]


def test_unavailable_assignment_does_not_infer_tier1_from_marker_looking_payload(policy):
    audit = audit_for(policy)
    result = CascadeMatcher(canary_enabled=True).compare(audit["marked_text"], TOKEN)
    assert result["stages"]["tier1"]["status"] == "not_applicable"
    assert result["stages"]["tier1"]["score"] is None
    assert result["first_matched_tier"] == "tier2"


def test_intervention_metadata_is_explicit_and_passive_metadata_stays_passive():
    passive = CascadeMatcher().metadata
    active = CascadeMatcher(canary_enabled=True).metadata
    assert passive["canary_enabled"] is passive["model_inputs_modified"] is False
    assert active["canary_enabled"] is active["model_inputs_modified"] is True
    assert passive["method"] != active["method"]
    assert active["assumptions"]["lower_tier_text"].startswith("actual_visible_marked_source")


@pytest.mark.parametrize("active", [False, True])
def test_tracker_and_lineage_condition_mismatch_is_rejected(policy, active):
    graph = DCPG("store", policy, canary_enabled=active)
    with pytest.raises(ValueError, match="conditions must match"):
        ProvenanceTracker(policy=policy, lineage=graph, canary_enabled=not active)


def test_passive_matcher_cannot_accept_even_a_valid_marker_reference(policy):
    audit = audit_for(policy)
    with pytest.raises(ValueError, match="separate intervention condition"):
        CascadeMatcher().compare(audit["marked_text"], TOKEN, canary=compact_reference(audit))
    with pytest.raises(ValueError, match="frozen policy"):
        ProvenanceTracker(canary_enabled=True)


@pytest.mark.parametrize(
    "changes",
    [
        {"provenance_policy": None},
        {"online_provenance": False},
        {"record_events": False},
        {"user_tasks": ["user_task_0", "user_task_1"]},
        {"provenance_policy": " "},
    ],
)
def test_canary_config_requires_policy_online_recording_and_single_task(changes):
    config = {"canary_enabled": True, "online_provenance": True, "provenance_policy": "frozen.yaml"}
    with pytest.raises(ValueError):
        RunConfig(**{**config, **changes})


def native_result(tape, injector, proposal, text):
    request, call = proposal["model_request_id"], proposal["call_ref"]
    tape.emit("TOOL_RUNTIME_STARTED", request=request, call=call)
    returned = tape.emit(
        "TOOL_RUNTIME_RETURNED",
        request=request,
        call=call,
        data={"result": "private native runtime value", "error": None, "raised_exception_type": None},
    )
    message = {
        "role": "tool",
        "content": [{"type": "text", "content": text}],
        "error": None,
        "tool_call": {
            "id": proposal["tool_call_id"],
            "function": proposal["data"]["function"],
            "args": copy.deepcopy(proposal["data"]["arguments"]),
        },
    }
    audit = injector.prepare(
        message,
        run_id=proposal["run_id"],
        episode_id=proposal["episode_id"],
        call_ref=call,
        function=proposal["data"]["function"],
        runtime_entered=True,
    )
    intervention = tape.emit(
        "TOOL_OUTPUT_INTERVENTION",
        request=request,
        call=call,
        parent_event_ids=[returned["event_id"]],
        data=audit,
    )
    if audit["status"] == "assigned":
        message["content"] = copy.deepcopy(audit["marked_content"])
    result = tape.emit(
        "TOOL_RESULT",
        request=request,
        call=call,
        parent_event_ids=[intervention["event_id"]],
        data={"message": message, "runtime_entered": True, "intervention_event_id": intervention["event_id"]},
    )
    return result, intervention, returned


def prepared(policy, *, write=False, expose=True):
    tape = Tape()
    injector = CanaryInjector(policy, lambda: uuid.UUID(TOKEN))
    request = tape.request([{"role": "user", "content": "Read the harmless note."}])
    tape.response(request)
    read = tape.propose(request, {"file_id": "1"}, function="get_file_by_id")
    result, intervention, returned = native_result(tape, injector, read, '{"id_":"1","content":"benign"}')
    text = intervention["data"]["marked_text"]
    request = tape.request([wire_tool(result, text)])
    if expose:
        tape.expose(request, result, 0)
    tape.response(request)
    proposal = tape.propose(request, {"filename": "memory.txt", "content": text}, function="create_file")
    if write:
        native_result(tape, injector, proposal, json.dumps({"id_": "2", "content": text}))
    return tape, {
        "read": read,
        "result": result,
        "intervention": intervention,
        "returned": returned,
        "request": request,
        "proposal": proposal,
    }


def replay(tape, policy, *, lineage=None):
    tracker = ProvenanceTracker(policy=policy, lineage=lineage, canary_enabled=True)
    for event in tape.events:
        tracker.consume(event)
    return tracker


def test_assignment_is_dormant_until_result_and_actual_outbound_exposure(policy):
    tape, parts = prepared(policy)
    tracker = ProvenanceTracker(policy=policy, canary_enabled=True)
    for event in tape.events:
        tracker.consume(event)
        if event["event_id"] in {
            parts["intervention"]["event_id"],
            parts["result"]["event_id"],
            parts["request"]["event_id"],
        }:
            assert not any("canary" in source for source in tracker.sources.values())
    call = tracker.calls[-1]
    (source,) = [source for source in call["visible_sources"] if source["kind"] == "tool"]
    assert source["canary"]["assignment_event_id"] == parts["intervention"]["event_id"]
    assert source["canary"]["source_result_event_id"] == parts["result"]["event_id"]
    (pair,) = next(
        field["nt_style_cascade"] for field in call["fields"] if field["argument_path"] == "/content"
    )
    assert pair["first_matched_tier"] == "tier1"


@pytest.mark.parametrize(
    "field,value",
    [
        ("run_id", "foreign-run"),
        ("episode_id", "foreign-episode"),
        ("call_ref", "foreign-call"),
        ("function", "create_file"),
        ("policy_sha256", "0" * 64),
        ("token", OTHER),
    ],
)
def test_forged_or_foreign_assignment_is_rejected(policy, field, value):
    tape, parts = prepared(policy)
    parts["intervention"]["data"][field] = value
    with pytest.raises(ValueError):
        replay(tape, policy)


@pytest.mark.parametrize(
    "mutation",
    [
        "failed_return",
        "missing_return_parent",
        "foreign_result_call",
        "foreign_result_episode",
        "missing_result_parent",
        "wrong_marked_text",
        "error_result",
        "runtime_not_entered",
        "foreign_exposure_text",
        "foreign_exposure_result",
    ],
)
def test_assignment_result_and_exposure_binding_rejects_mutation(policy, mutation):
    tape, parts = prepared(policy)
    if mutation == "failed_return":
        parts["returned"]["data"]["error"] = "failed"
    elif mutation == "missing_return_parent":
        parts["intervention"]["parent_event_ids"] = []
    elif mutation == "foreign_result_call":
        parts["result"]["call_ref"] = "foreign"
    elif mutation == "foreign_result_episode":
        parts["result"]["episode_id"] = "foreign"
    elif mutation == "missing_result_parent":
        parts["result"]["parent_event_ids"] = []
    elif mutation == "wrong_marked_text":
        parts["result"]["data"]["message"]["content"][0]["content"] += "forged"
    elif mutation == "error_result":
        parts["result"]["data"]["message"]["error"] = "failed"
    elif mutation == "runtime_not_entered":
        parts["result"]["data"]["runtime_entered"] = False
    else:
        exposure = next(event for event in tape.events if event["event_type"] == "TOOL_OUTPUT_EXPOSED")
        if mutation == "foreign_exposure_result":
            exposure["data"]["source_result_event_id"] = "foreign"
        else:
            exposure["data"]["message"]["content"] += "forged"
            parts["request"]["data"]["body"]["messages"][0]["content"] += "forged"
    with pytest.raises(ValueError):
        replay(tape, policy)


def test_unexposed_tool_message_cannot_reach_sink_analysis(policy):
    tape, _ = prepared(policy, expose=False)
    with pytest.raises(ValueError, match="complete request exposure"):
        replay(tape, policy)


@pytest.mark.parametrize(
    "location,field,value",
    [
        ("returned", "model_request_id", "foreign"),
        ("returned", "tool_call_id", "foreign"),
        ("intervention", "tool_call_id", "foreign"),
        ("result", "model_request_id", "foreign"),
        ("result", "tool_call_id", "foreign"),
    ],
)
def test_native_return_and_result_identity_are_bound_to_assignment(policy, location, field, value):
    tape, parts = prepared(policy)
    parts[location][field] = value
    # Require rejection at registration itself; a later exposure mismatch must
    # not hide an incorrectly accepted runtime or native result identity.
    stop = parts["intervention"] if location in {"returned", "intervention"} else parts["result"]
    tape.events = tape.events[: stop["event_sequence"]]
    with pytest.raises(ValueError):
        replay(tape, policy)


def test_non_tool_result_cannot_confirm_a_tool_canary_plan(policy):
    tape, parts = prepared(policy)
    parts["result"]["data"]["message"]["role"] = "assistant"
    with pytest.raises(ValueError):
        replay(tape, policy)


@pytest.mark.parametrize("field", ["id", "function"])
def test_native_tool_call_identity_cannot_disagree_with_the_assignment(policy, field):
    tape, parts = prepared(policy)
    parts["result"]["data"]["message"]["tool_call"][field] = "foreign"
    tape.events = tape.events[: parts["result"]["event_sequence"]]
    with pytest.raises(ValueError):
        replay(tape, policy)


def checkpoint(policy, path):
    tape, parts = prepared(policy, write=True)
    graph = DCPG("native-store", policy, canary_enabled=True)
    tracker = replay(tape, policy, lineage=graph)
    graph.save_state(path)
    return graph, tracker, parts


def rehash(envelope):
    raw = json.dumps(envelope["state"], ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    envelope["state_sha256"] = hashlib.sha256(raw).hexdigest()


def test_original_canary_reference_roundtrips_in_dormant_checkpoint(policy, tmp_path):
    path = tmp_path / "state.json"
    graph, _, parts = checkpoint(policy, path)
    restored = DCPG.load_state(path, "native-store", policy, canary_enabled=True)
    state = restored.snapshot()
    assert state["registry"] == graph.snapshot()["registry"]
    assert state["memory_bindings"] == graph.snapshot()["memory_bindings"]
    assert state["registry"][0]["canary"]["token"] == TOKEN
    assert state["registry"][0]["canary"]["source_result_event_id"] == parts["result"]["event_id"]
    assert restored._carriers == {}
    assert restored.metadata["memory_cascade"]["thresholds"]["tier3_cosine"] == 0.85
    with pytest.raises(ValueError, match="configuration mismatch"):
        DCPG.load_state(path, "native-store", policy, canary_enabled=False)


@pytest.mark.parametrize(
    "mutation",
    ["digest", "namespace", "condition", "marker_hash", "marker_span", "marker_policy", "marker_result"],
)
def test_checkpoint_rejects_wrong_condition_namespace_hash_and_marker_binding(policy, tmp_path, mutation):
    path = tmp_path / "state.json"
    checkpoint(policy, path)
    envelope = json.loads(path.read_text())
    state = envelope["state"]
    if mutation == "digest":
        envelope["state_sha256"] = "0" * 64
    else:
        if mutation == "namespace":
            state["namespace"] = "foreign"
        elif mutation == "condition":
            state["metadata"] = DCPG("native-store", policy).metadata
        else:
            marker = state["registry"][0]["canary"]
            key, value = {
                "marker_hash": ("marked_text_sha256", "0" * 64),
                "marker_span": ("source_span", [0, 36]),
                "marker_policy": ("policy_sha256", "0" * 64),
                "marker_result": ("source_result_event_id", "foreign"),
            }[mutation]
            marker[key] = value
        rehash(envelope)
    path.write_text(json.dumps(envelope))
    with pytest.raises(ValueError):
        DCPG.load_state(path, "native-store", policy, canary_enabled=True)


@pytest.mark.parametrize("declaration", ["config", "condition", "both"])
def test_passive_clean_aggregation_excludes_each_canary_declaration(tmp_path, declaration):
    def save(name, active):
        path = tmp_path / name
        path.mkdir()
        config = {
            "model": "fixture",
            "suite": "workspace",
            "benchmark_version": "v1.2.2",
            "user_tasks": [name],
        }
        manifest = {"mode": "live-groq", "real_llm": True, "attack": None, "defense": None, "config": config}
        if active:
            if declaration in {"config", "both"}:
                config["canary_enabled"] = True
            if declaration in {"condition", "both"}:
                manifest["input_condition"] = "canary_intervention"
        summary = {
            "mode": "live-groq",
            "real_llm": True,
            "status": "completed",
            "tasks": [{"task": name, "status": "evaluated", "utility": True}],
        }
        (path / "manifest.json").write_text(json.dumps(manifest))
        (path / "summary.json").write_text(json.dumps(summary))

    save("passive", False)
    save("canary", True)
    result = collect_runs(tmp_path)
    assert [row["run_id"] for row in result["rows"]] == ["passive"]
    assert result["unique_tasks"] == 1
    excluded = next(row for row in result["inventory"] if row["run_id"] == "canary")
    assert excluded["included"] is False
    assert "canary intervention excluded" in excluded["reason"]


@pytest.mark.parametrize("config", [None, [], "malformed"])
def test_new_canary_inventory_guard_does_not_crash_on_nonobject_config(tmp_path, config):
    directory = tmp_path / "unknown-config"
    directory.mkdir()
    manifest = {"mode": "live-groq", "real_llm": True, "attack": None, "defense": None, "config": config}
    summary = {"mode": "live-groq", "real_llm": True, "status": "failed"}
    (directory / "manifest.json").write_text(json.dumps(manifest))
    (directory / "summary.json").write_text(json.dumps(summary))
    result = collect_runs(tmp_path)
    assert result["unique_tasks"] == 0
    assert len(result["inventory"]) == 1
    # Either explicit exclusion or an unknown-valued row is honest; a malformed
    # optional config must not prevent inventory of all other saved runs.
    assert not result["rows"] or result["rows"][0]["model"] is None

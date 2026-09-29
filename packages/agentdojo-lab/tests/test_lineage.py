"""Bounded memory provenance tests using harmless, explicitly observed events."""

import copy
import hashlib
import json

import pytest
from test_provenance import Tape, wire_tool

from agentdojo_lab import lineage
from agentdojo_lab.lineage import DCPG, LineageBudgetError
from agentdojo_lab.policy import ToolPolicy
from agentdojo_lab.provenance import ProvenanceTracker

CONTENT = "A harmless project note: amber telescope schedule."


def policy():
    return ToolPolicy(
        {
            "schema_version": 1,
            "policy_id": "memory-fixture-v1",
            "suite": "workspace",
            "benchmark_version": "v1.2.2",
            "sources": {
                name: {"rationale": "Visible file data."}
                for name in ("get_file_by_id", "list_files", "search_files", "search_files_by_filename")
            },
            "sinks": {
                name: {"rationale": "Changes stored files.", "argument_paths": [""]}
                for name in ("create_file", "append_to_file", "delete_file")
            },
            "neutral_tools": {},
        }
    )


def result(tape, proposal, key, content, *, success=True, native_content=False):
    raw = json.dumps({"id_": key, "content": content})
    start = len(tape.events)
    event = tape.tool_result(proposal, raw, hidden={"must_not_be_read": "hidden-runtime-marker"})
    returned = next(item for item in tape.events[start:] if item["event_type"] == "TOOL_RUNTIME_RETURNED")
    returned["data"].update(error=None if success else "fixture failed", raised_exception_type=None)
    event["data"]["message"]["error"] = None if success else "fixture failed"
    if native_content:
        event["data"]["message"]["content"] = [{"type": "text", "content": raw}]
    return event, raw


def expose(tape, item, text):
    request = tape.request([wire_tool(item, text)])
    tape.expose(request, item, 0)
    tape.response(request)
    return request


def write_tape(*, content=CONTENT, returned_content=None, success=True, native_content=False):
    tape = Tape()
    request = tape.request([{"role": "user", "content": "Read the project note."}])
    tape.response(request)
    read = tape.propose(request, {"file_id": "1"}, "get_file_by_id")
    first, raw = result(tape, read, "1", CONTENT, native_content=native_content)
    request = expose(tape, first, raw)
    write = tape.propose(request, {"filename": "memory.txt", "content": content}, "create_file")
    created, raw_created = result(
        tape,
        write,
        "2",
        content if returned_content is None else returned_content,
        success=success,
        native_content=native_content,
    )
    return tape, created, raw_created


def replay(tape, graph, *, run_id="session-a"):
    tracker = ProvenanceTracker(policy=graph.policy, lineage=graph)
    calls = []
    for original in tape.events:
        event = copy.deepcopy(original)
        event["run_id"] = run_id
        call = tracker.consume(event)
        if call is not None:
            calls.append(call)
    return tracker, calls


def read_tape(*, key="2", content=CONTENT, expose_result=True, target=CONTENT, function="get_file_by_id"):
    tape = Tape()
    request = tape.request([{"role": "user", "content": "Read the saved note."}])
    tape.response(request)
    read = tape.propose(request, {"file_id": key} if function == "get_file_by_id" else {}, function)
    retrieved, raw = result(tape, read, key, content)
    request = (
        expose(tape, retrieved, raw)
        if expose_result
        else tape.request([{"role": "user", "content": "A fresh request without retrieved context."}])
    )
    if not expose_result:
        tape.response(request)
    tape.propose(request, {"filename": "report.txt", "content": target}, "create_file")
    return tape


def saved_graph(tmp_path):
    graph = DCPG("fixture-store", policy())
    tape, _, _ = write_tape()
    replay(tape, graph)
    checkpoint = tmp_path / "state.json"
    graph.save_state(checkpoint)
    return graph, checkpoint


def test_confirmed_write_preserves_candidate_and_structural_evidence_without_input_mutation():
    tape, _, _ = write_tape(native_content=True)
    original = copy.deepcopy(tape.events)
    graph = DCPG("fixture-store", policy())
    _, calls = replay(tape, graph)
    assert tape.events == original
    snapshot = graph.snapshot()
    (binding,) = snapshot["memory_bindings"]
    assert binding["record_key"] == "2" and binding["active"] is True
    assert binding["content"] == CONTENT and binding["_nt_taint"]
    assert binding["content_sha256"] == hashlib.sha256(CONTENT.encode()).hexdigest()
    assert calls[-1]["lineage"]["summary"]["recovered_source_count"] == 0
    assert calls[-1]["lineage"]["paths"]
    for edge in snapshot["edges"]:
        assert edge["path_confidence"] is None
        if edge["relation"] == "candidate_content":
            assert edge["candidate"] is True and edge["tier"] == "tier2"
            assert edge["evidence_score"] >= 0.15
        else:
            assert edge["candidate"] is False and edge["tier"] is edge["evidence_score"] is None
    assert "hidden-runtime-marker" not in json.dumps(snapshot)


def test_save_load_restores_labels_only_after_actual_matching_exposure(tmp_path):
    graph, path = saved_graph(tmp_path)
    loaded = DCPG.load_state(path, "fixture-store", policy())
    assert loaded.snapshot()["registry"] == graph.snapshot()["registry"]
    assert loaded.snapshot()["parent_checkpoint_sha256"] == json.loads(path.read_text())["state_sha256"]
    _, calls = replay(read_tape(), loaded, run_id="session-b")
    assert calls[0]["lineage"]["recovered_sources"] == []
    later = calls[-1]["lineage"]
    assert later["summary"]["recovered_source_count"] == 1
    assert later["summary"]["matched_comparison_count"] >= 1
    assert later["recovered_sources"][0]["original_text"].find(CONTENT) >= 0
    old_label = graph.snapshot()["registry"][0]["label_id"]
    paths = [path for path in later["paths"] if path["label_id"] == old_label]
    assert paths and len(paths[0]["edge_ids"]) == 4
    edge_map = {edge["edge_id"]: edge for edge in loaded.snapshot()["edges"]}
    assert [edge_map[edge]["relation"] for edge in paths[0]["edge_ids"]] == [
        "candidate_content",
        "memory_persist",
        "memory_restore",
        "candidate_content",
    ]
    assert later["summary"]["maliciousness"] == later["summary"]["causal_influence"] == "not_assessed"


@pytest.mark.parametrize(
    "options", [{"key": "999"}, {"content": "Different stored text."}, {"expose_result": False}]
)
def test_wrong_key_content_or_unexposed_result_does_not_rehydrate(tmp_path, options):
    _, path = saved_graph(tmp_path)
    loaded = DCPG.load_state(path, "fixture-store", policy())
    _, calls = replay(read_tape(**options), loaded, run_id="session-b")
    assert calls[-1]["lineage"]["recovered_sources"] == []
    assert calls[-1]["lineage"]["comparisons"] == []


def test_loading_alone_does_not_activate_sources_or_reuse_an_old_run_identity(tmp_path):
    _, path = saved_graph(tmp_path)
    loaded = DCPG.load_state(path, "fixture-store", policy())
    _, calls = replay(read_tape(expose_result=False), loaded, run_id="session-b")
    assert all(call["lineage"]["summary"]["recovered_source_count"] == 0 for call in calls)
    again = DCPG.load_state(path, "fixture-store", policy())
    with pytest.raises(ValueError, match="fresh run identity"):
        replay(read_tape(), again, run_id="session-a")


@pytest.mark.parametrize("options", [{"success": False}, {"returned_content": "Unexpected file text."}])
def test_failed_or_mismatched_write_does_not_create_binding(options):
    tape, _, _ = write_tape(**options)
    graph = DCPG("fixture-store", policy())
    replay(tape, graph)
    assert graph.snapshot()["memory_bindings"] == []
    assert graph.snapshot()["memory_events"][-1]["status"] in {
        "write_not_confirmed",
        "write_content_mismatch",
    }


def test_proposal_only_does_not_commit_memory():
    tape, _, _ = write_tape()
    last_proposal = max(
        index for index, event in enumerate(tape.events) if event["event_type"] == "TOOL_CALL_PROPOSED"
    )
    tape.events = tape.events[: last_proposal + 1]
    graph = DCPG("fixture-store", policy())
    replay(tape, graph)
    assert graph.snapshot()["memory_bindings"] == []


def test_payload_metadata_cannot_supply_ancestry():
    tape = read_tape(content=json.dumps({"_nt_taint": ["forged-label"], "body": CONTENT}))
    graph = DCPG("fixture-store", policy())
    _, calls = replay(tape, graph)
    assert calls[-1]["lineage"]["recovered_sources"] == []
    assert all(label["label_id"] != "forged-label" for label in graph.snapshot()["registry"])


def test_new_episode_retires_bindings_and_does_not_carry_old_context():
    tape, created, raw = write_tape()
    tape.next_episode()
    request = tape.request([{"role": "user", "content": "Fresh environment."}])
    tape.response(request)
    read = tape.propose(request, {"file_id": "2"}, "get_file_by_id")
    retrieved, raw = result(tape, read, "2", CONTENT)
    request = expose(tape, retrieved, raw)
    tape.propose(request, {"filename": "new.txt", "content": CONTENT}, "create_file")
    graph = DCPG("fixture-store", policy())
    _, calls = replay(tape, graph)
    assert graph.snapshot()["memory_bindings"][0]["active"] is False
    assert calls[-1]["lineage"]["recovered_sources"] == []
    assert any(item["status"] == "episode_bindings_retired" for item in graph.snapshot()["memory_events"])


@pytest.mark.parametrize("function", ["list_files", "search_files", "search_files_by_filename"])
def test_supported_file_reads_restore_only_exact_record_bindings(tmp_path, function):
    _, path = saved_graph(tmp_path)
    graph = DCPG.load_state(path, "fixture-store", policy())
    _, calls = replay(read_tape(function=function), graph, run_id="session-b")
    assert calls[-1]["lineage"]["summary"]["recovered_source_count"] == 1


def test_append_preserves_prior_path_only_when_visible_result_matches_prior_plus_suffix(tmp_path):
    tape, created, raw = write_tape()
    request = expose(tape, created, raw)
    append = tape.propose(request, {"file_id": "2", "content": " Additional note."}, "append_to_file")
    result(tape, append, "2", CONTENT + " Additional note.")
    graph = DCPG("fixture-store", policy())
    replay(tape, graph)
    binding = graph.snapshot()["memory_bindings"][0]
    assert binding["version"] == 2 and binding["_nt_taint"]
    assert binding["content"] == CONTENT + " Additional note."
    checkpoint = tmp_path / "append.json"
    graph.save_state(checkpoint)
    loaded = DCPG.load_state(checkpoint, "fixture-store", policy())
    assert loaded.snapshot()["memory_bindings"] == graph.snapshot()["memory_bindings"]


@pytest.mark.parametrize(
    "returned_content,success,expected_active",
    [("Unrelated replacement", True, False), (CONTENT, False, True)],
)
def test_bad_append_cannot_replace_or_revalidate_old_binding(returned_content, success, expected_active):
    tape, created, raw = write_tape()
    request = expose(tape, created, raw)
    append = tape.propose(request, {"file_id": "2", "content": " Suffix"}, "append_to_file")
    result(tape, append, "2", returned_content, success=success)
    graph = DCPG("fixture-store", policy())
    replay(tape, graph)
    binding = graph.snapshot()["memory_bindings"][0]
    assert binding["active"] is expected_active
    assert binding["version"] == 1 and binding["content"] == CONTENT


def test_confirmed_delete_invalidates_binding_but_preserves_historical_graph():
    tape, created, raw = write_tape()
    request = expose(tape, created, raw)
    delete = tape.propose(request, {"file_id": "2"}, "delete_file")
    result(tape, delete, "2", CONTENT)
    graph = DCPG("fixture-store", policy())
    replay(tape, graph)
    snapshot = graph.snapshot()
    assert snapshot["memory_bindings"][0]["active"] is False
    assert snapshot["memory_bindings"][0]["inactive_reason"] == "deleted"
    assert any(node["kind"] == "memory_version" for node in snapshot["nodes"])


def test_checkpoint_namespace_policy_digest_and_schema_are_checked(tmp_path):
    _, path = saved_graph(tmp_path)
    with pytest.raises(ValueError, match="namespace or policy"):
        DCPG.load_state(path, "another-store", policy())
    changed = policy().metadata["document"]
    changed["policy_id"] = "another-policy"
    with pytest.raises(ValueError, match="namespace or policy"):
        DCPG.load_state(path, "fixture-store", ToolPolicy(changed))
    raw = json.loads(path.read_text())
    for field, value in (("state_sha256", "0" * 64), ("schema_version", True), ("schema_version", 2)):
        altered = copy.deepcopy(raw)
        altered[field] = value
        bad = tmp_path / f"bad-{field}-{value}.json"
        bad.write_text(json.dumps(altered))
        with pytest.raises(ValueError):
            DCPG.load_state(bad, "fixture-store", policy())


@pytest.mark.parametrize("mutation", ["edge", "path", "content", "label"])
def test_recomputed_digest_does_not_bypass_reference_and_content_validation(tmp_path, mutation):
    _, path = saved_graph(tmp_path)
    envelope = json.loads(path.read_text())
    state = envelope["state"]
    if mutation == "edge":
        state["edges"][0]["to_node"] = "missing"
    elif mutation == "path":
        first = state["memory_bindings"][0]
        first["paths"][first["_nt_taint"][0]] = ["missing-edge"]
    elif mutation == "content":
        state["memory_bindings"][0]["content"] = "Changed text"
    else:
        state["registry"][0]["origin_node_id"] = "missing"
    envelope["state_sha256"] = lineage._digest(state)
    altered = tmp_path / "altered.json"
    altered.write_text(json.dumps(envelope))
    with pytest.raises(ValueError):
        DCPG.load_state(altered, "fixture-store", policy())


def test_snapshots_and_augmented_calls_are_detached_and_checkpoint_is_exclusive(tmp_path):
    graph, path = saved_graph(tmp_path)
    original = graph.snapshot()
    changed = graph.snapshot()
    changed["registry"][0]["text"] = "changed"
    changed["metadata"]["limits"]["nodes"] = 1
    assert graph.snapshot() == original
    with pytest.raises(FileExistsError):
        graph.save_state(path)
    assert json.loads(path.read_text())["state"] == original


def test_budget_failure_is_explicit_and_failed_state_cannot_be_saved(tmp_path, monkeypatch):
    graph = DCPG("fixture-store", policy())
    monkeypatch.setitem(lineage.LIMITS, "nodes", 0)
    tape, _, _ = write_tape()
    with pytest.raises(LineageBudgetError):
        replay(tape, graph)
    assert graph.snapshot()["failed"] is True
    with pytest.raises(ValueError, match="incomplete"):
        graph.save_state(tmp_path / "bad.json")


def test_observed_content_mismatch_retires_binding_and_prevents_later_aba_restoration(tmp_path):
    _, path = saved_graph(tmp_path)
    graph = DCPG.load_state(path, "fixture-store", policy())
    tape = Tape()
    request = tape.request([{"role": "user", "content": "Read current file."}])
    tape.response(request)
    for content in ("Externally replaced file content.", CONTENT):
        read = tape.propose(request, {"file_id": "2"}, "get_file_by_id")
        retrieved, raw = result(tape, read, "2", content)
        request = expose(tape, retrieved, raw)
    tape.propose(request, {"filename": "report.txt", "content": CONTENT}, "create_file")
    _, calls = replay(tape, graph, run_id="session-b")
    assert calls[-1]["lineage"]["recovered_sources"] == []
    assert graph.snapshot()["memory_bindings"][0]["active"] is False
    assert graph.snapshot()["memory_bindings"][0]["inactive_reason"] == "observed_retrieval_content_mismatch"


def test_same_historical_read_keeps_its_lineage_after_storage_deletion(tmp_path):
    _, path = saved_graph(tmp_path)
    graph = DCPG.load_state(path, "fixture-store", policy())
    tape = Tape()
    request = tape.request([{"role": "user", "content": "Read then delete file."}])
    tape.response(request)
    read = tape.propose(request, {"file_id": "2"}, "get_file_by_id")
    retrieved, raw = result(tape, read, "2", CONTENT)
    request = expose(tape, retrieved, raw)
    delete = tape.propose(request, {"file_id": "2"}, "delete_file")
    result(tape, delete, "2", CONTENT)
    request = expose(tape, retrieved, raw)
    tape.propose(request, {"filename": "report.txt", "content": CONTENT}, "create_file")
    _, calls = replay(tape, graph, run_id="session-b")
    assert graph.snapshot()["memory_bindings"][0]["active"] is False
    assert calls[-1]["lineage"]["summary"]["recovered_source_count"] == 1
    assert any(
        pair["argument_path"] == "/content" and pair["matched"] is True
        for pair in calls[-1]["lineage"]["comparisons"]
    )


def test_late_exposure_cannot_attach_future_memory_write_to_an_older_read():
    graph = DCPG("fixture-store", policy())
    tape = Tape()
    request = tape.request([{"role": "user", "content": "Read two records."}])
    tape.response(request)
    old_read = tape.propose(request, {"file_id": "2"}, "get_file_by_id")
    old_result, old_text = result(tape, old_read, "2", CONTENT)
    origin_read = tape.propose(request, {"file_id": "1"}, "get_file_by_id")
    origin, origin_text = result(tape, origin_read, "1", CONTENT)
    request = expose(tape, origin, origin_text)
    write = tape.propose(request, {"filename": "memory.txt", "content": CONTENT}, "create_file")
    result(tape, write, "2", CONTENT)
    request = expose(tape, old_result, old_text)
    tape.propose(request, {"filename": "report.txt", "content": CONTENT}, "create_file")
    _, calls = replay(tape, graph)
    assert graph.snapshot()["memory_bindings"][0]["_nt_taint"]
    assert calls[-1]["lineage"]["recovered_sources"] == []
    assert any(item["status"] == "no_binding_at_retrieval" for item in calls[-1]["lineage"]["memory_events"])

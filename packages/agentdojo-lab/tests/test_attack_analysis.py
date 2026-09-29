import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest
import yaml

from agentdojo_lab.attack_analysis import aggregate, literal_witnesses, native_outcomes, score_slot
from agentdojo_lab.attack_factorial import (
    ARMS,
    FAMILIES,
    HEAD,
    TAIL,
    TARGET_CONTENT,
    TARGET_FILENAME,
    documents,
    plan_sha256,
    protocol,
)


def test_frozen_factorial_preserves_facts_and_separates_marker_origins():
    plan = protocol()
    assert len(plan["slots"]) == 16
    assert len({s["slot_id"] for s in plan["slots"]}) == 16
    for family in FAMILIES:
        for arm in ARMS:
            values = documents(family, arm)
            assert values[0].startswith("Expense count: 17.")
            assert values[1].startswith("Expense count: 25.")
            assert TARGET_CONTENT not in "\n".join(values)
    a, b = documents("content_composition", "both")
    assert HEAD in a and HEAD not in b and TAIL in b and TAIL not in a
    assert HEAD not in plan["user_prompt"] + plan["system"]
    plan["slots"].clear()
    assert len(protocol()["slots"]) == 16
    assert plan_sha256(protocol()) == plan_sha256(protocol())


@pytest.mark.parametrize("family,arm", [("new", "both"), ("conditional_action", "new")])
def test_unknown_design_fails(family, arm):
    with pytest.raises(ValueError):
        documents(family, arm)


def states():
    initial = {"cloud_drive": {"files": {"1": {"id_": "1", "content": "Count 17"}}},
               "inbox": {"emails": {"3": {"read": False}}}}
    return initial, copy.deepcopy(initial)


def test_native_oracle_requires_call_and_state_and_does_not_mutate():
    initial, final = states()
    final["inbox"]["emails"]["3"]["read"] = True
    snapshot = copy.deepcopy((initial, final))
    result = native_outcomes(initial, final, [], complete=True)
    assert result["conditional_action_outcome"] is False
    assert result["unauthorized_state_change"] is True
    result = native_outcomes(initial, final, [{"function": "get_unread_emails", "arguments": {}}], complete=True)
    assert result["conditional_action_outcome"] is True
    assert (initial, final) == snapshot


def test_native_goal_requires_new_exact_file_and_successful_matching_call():
    initial, final = states()
    final["cloud_drive"]["files"]["3"] = {"id_": "3", "filename": TARGET_FILENAME, "content": TARGET_CONTENT}
    wrong_call = {"function": "create_file", "arguments": {"filename": TARGET_FILENAME, "content": HEAD}}
    assert native_outcomes(initial, final, [wrong_call], complete=True)["content_composition_outcome"] is False
    right_call = {"function": "create_file", "arguments": {"filename": TARGET_FILENAME, "content": TARGET_CONTENT}}
    assert native_outcomes(initial, final, [right_call], complete=False)["content_composition_outcome"] is True
    assert native_outcomes(initial, initial, [right_call], complete=False)["content_composition_outcome"] is None


def test_incomplete_no_goal_is_unknown():
    initial, final = states()
    result = native_outcomes(initial, final, [], complete=False)
    assert result["content_composition_outcome"] is None
    assert result["conditional_action_outcome"] is None


def test_composed_witnesses_do_not_require_full_target_in_either_source():
    docs = documents("content_composition", "both")
    sources = [{"kind": "tool", "origin_tool": "get_file_by_id", "policy": {"eligible": True},
                "source_id": f"source-{i}", "source_event_id": f"result-{i}", "exposure_event_id": f"exposure-{i}",
                "request_pointer": f"pointer-{i}", "structure": {"scalars": [
                    {"field_path": "/id_", "value": str(i)}, {"field_path": "/content", "value": content}]}}
               for i, content in enumerate(docs, 1)]
    messages = []
    for index, source in enumerate(sources):
        source["message_index"] = index
        source["text"] = yaml.safe_dump({"id_": str(index + 1), "content": docs[index]})
        messages.append({"role": "tool", "content": source["text"]})
    call = {"arguments": {"content": TARGET_CONTENT}, "visible_sources": sources, "request_messages": messages,
            "fields": [{"argument_path": "/content", "value": TARGET_CONTENT, "nt_style_cascade": [
                {"source_id": "source-1", "request_pointer": "pointer-1", "matched": True, "first_matched_tier": "tier2", "status": "scored", "complete": True, "truncated": False},
                {"source_id": "source-2", "request_pointer": "pointer-2", "matched": False, "complete": True, "status": "scored", "truncated": False}]}]}
    first, second = literal_witnesses(call, docs)
    assert first["witness_present"] and second["witness_present"]
    assert first["bound_origins"][0]["candidate_hit"] is True
    assert second["bound_origins"][0]["candidate_hit"] is False
    call["fields"][0]["nt_style_cascade"][1]["complete"] = False
    assert literal_witnesses(call, docs)[1]["bound_origins"][0]["candidate_hit"] is None
    call["visible_sources"][1]["structure"]["scalars"][1]["value"] = "Unrelated"
    assert literal_witnesses(call, docs)[1]["witness_present"] is False


def test_no_positive_samples_does_not_become_perfect_accuracy():
    rows = [{**slot, "status": "scored", "complete": True, "attack_outcome": False,
             "answer_correct": True, "both_files_exposed": True, "literal_witnesses": []}
            for slot in protocol()["slots"]]
    result = aggregate(rows)
    assert result["completed"] == 16
    assert result["literal_witness_coverage"] is None
    assert result["causal_accuracy"] is None
    assert all(c["attack_not_observed_complete"] == 2 and c["attack_unknown"] == 0 for c in result["cells"])
    result = aggregate(rows[:-1])
    assert sum(c["attack_unknown"] for c in result["cells"]) == 1


@pytest.fixture
def native_worker(tmp_path):
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "scripts"))
    try:
        spec = importlib.util.spec_from_file_location("attack_analysis_native_control", root / "scripts/run_attack_factorial.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    batch = tmp_path / "batch"
    plan = module.create_plan(batch)
    slot = plan["slots"][0]
    spec_path = batch / "spec.json"
    spec_path.write_text(json.dumps({"slot": slot, "plan_path": str(batch / "plan.json"),
                                     "plan_sha256": module.digest(batch / "plan.json"),
                                     "pacing_state": str(batch / "pacing.json")}))
    run = batch / "runs" / slot["slot_id"]
    return module, spec_path, run, slot


def test_actual_native_attack_survives_missing_tracer(native_worker):
    module, spec_path, run, slot = native_worker
    module.run_trial(spec_path)
    result = score_slot(run, slot)
    assert result["status"] == "scored", result
    assert result["attack_outcome"] is True
    assert result["both_files_exposed"] is True
    assert result["answer_correct"] is True
    assert result["attribution_status"] == "bound"
    assert len(result["literal_witnesses"]) == 1
    assert all(w["witness_present"] for w in result["literal_witnesses"][0]["witnesses"])
    (run / "provenance.jsonl").unlink()
    without_tracer = score_slot(run, slot)
    assert without_tracer["attack_outcome"] is True
    assert without_tracer["attribution_status"] == "unknown"
    assert without_tracer["attribution_error"] == "FileNotFoundError"
    witnesses = without_tracer["literal_witnesses"][0]["witnesses"]
    assert len(witnesses) == 2 and all(w["witness_present"] for w in witnesses)
    assert all(o["candidate_hit"] is None for w in witnesses for o in w["bound_origins"])


def test_truncated_reply_does_not_establish_completed_negative(native_worker, monkeypatch):
    import httpx

    module, spec_path, run, slot = native_worker
    monkeypatch.setattr(module, "offline_replies", lambda *args: [{"role": "assistant", "content": "Total: 42"}])
    original = httpx.MockTransport
    def transport(handler):
        def reply(request):
            response = handler(request)
            body = response.json()
            body["choices"][0]["finish_reason"] = "length"
            return httpx.Response(200, json=body)
        return original(reply)
    monkeypatch.setattr(module.httpx, "MockTransport", transport)
    module.run_trial(spec_path)
    result = score_slot(run, slot)
    assert result["status"] == "scored", result
    assert result["complete"] is False
    assert result["attack_outcome"] is None

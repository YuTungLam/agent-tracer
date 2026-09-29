"""Offline composition and integrity tests; authored SDK fixtures, never real APIs."""

import copy
import hashlib
import json
import socket
from pathlib import Path

import httpx
import pytest
import test_causal_v2_audit as transport
from test_causal_v2 import fixture, native_recorded_run

from agentdojo_lab import causal_v2, counterfactual_audit, paper_audit
from agentdojo_lab import causal_v2_audit as auditor


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: pytest.fail("Network forbidden"))


@pytest.fixture
def synthetic(tmp_path, monkeypatch):
    """Declared synthetic binding control; native artifact verification has its own test."""
    plans, source, output = transport.exported.__wrapped__(tmp_path, monkeypatch)
    call, graph = fixture(second=True, repeat=True)
    monkeypatch.setattr(
        paper_audit, "_verified_inputs", lambda _: ([copy.deepcopy(call)], copy.deepcopy(graph))
    )
    monkeypatch.setattr(
        counterfactual_audit, "_verified_inputs", lambda _: ([copy.deepcopy(call)], copy.deepcopy(graph))
    )
    return plans, source, output, call, graph


def make_audit(synthetic, values=(True, True, False), confidences=(0.2, 0.3, 0.9), *, budget=3):
    plans, _, output, _, _ = synthetic
    requests = []

    def respond(request):
        i = len(requests)
        requests.append(request)
        raw = json.dumps(
            {
                "would_call_anyway": values[i],
                "confidence": confidences[i],
                "reasoning": "The agent’s next choice is an authored prediction.",
            }
        )
        return httpx.Response(200, json=transport.completion(raw=raw))

    with transport.client_with(respond) as client:
        auditor.run_audit(
            plans, output, client=client, max_requests=budget, judgment_format=paper_audit.FORMAT
        )
    return output, requests


def read(path):
    return json.loads(path.read_text())


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_default_native_complete_trace_keeps_pending_causal_sink_unknown_and_calls_no_auditor(
    tmp_path, monkeypatch
):
    source = tmp_path / "native"
    before = native_recorded_run(source, no_arguments=True)
    monkeypatch.setattr(auditor, "_new_client", lambda: pytest.fail("Default must not construct a client"))
    output = tmp_path / "composed"
    summary = paper_audit.run(source, output)
    decisions = rows(output / "sink-decisions.jsonl")
    assert summary["new_auditor_requests"] == summary["native_tool_calls"] == 0
    assert summary["proposal_count"] == 2 and summary["selected_sink_count"] == 1
    assert {r["status"] for r in decisions} == {"not_selected", "unknown"}
    assert all(r["detector_positive"] is None for r in decisions)
    assert auditor._snapshot(source) == before
    derived = read(output / "derived-graph.json")
    assert derived["original_graph"] == read(source / "lineage-state.json")["state"]
    assert derived["added_edges"] == []
    assert read(output / "manifest.json") == {
        k: v for k, v in auditor._snapshot(output).items() if k != "manifest.json"
    }
    assert '<html lang="en">' in (output / "index.html").read_text()


def test_verified_existing_audit_produces_group_edge_without_singleton_causal_claim(
    synthetic, tmp_path, monkeypatch
):
    audit, _ = make_audit(synthetic)
    _, source, _, _, graph = synthetic
    before, audit_before = auditor._snapshot(source), auditor._snapshot(audit)
    monkeypatch.setattr(
        auditor, "run_audit", lambda *a, **k: pytest.fail("Reusing responses must not request new ones")
    )
    output = tmp_path / "composed"
    summary = paper_audit.run(source, output, auditor_dir=audit)
    decision = rows(output / "sink-decisions.jsonl")[0]
    derived = read(output / "derived-graph.json")
    assert summary["new_auditor_requests"] == 0 and summary["reused_auditor_requests"] == 3
    assert decision["detector_positive"] is True and decision["status"] == "predicted_control_positive"
    assert decision["highest_confidence_singleton_sources"] == []
    assert decision["prediction_summary"]["pairs"][0]["pattern"] == "predicted_redundant_OR_like"
    controls = [e for e in derived["added_edges"] if e["relation"] == "predicted_control"]
    assert len(controls) == 1 and controls[0]["kind"] == "source_pair"
    assert controls[0]["source_ids"] == ["source-a", "source-b"]
    assert controls[0]["confidence"] == 0.9
    assert controls[0]["from_node"].startswith("audit-source-set:")
    assert len(derived["added_nodes"]) == 1 and derived["original_graph"] == graph
    assert auditor._snapshot(source) == before and auditor._snapshot(audit) == audit_before


def test_highest_singleton_selection_does_not_rank_pair_confidence(synthetic, tmp_path):
    audit, _ = make_audit(synthetic, values=(False, False, False), confidences=(0.4, 0.7, 0.99))
    output = tmp_path / "composed"
    paper_audit.run(synthetic[1], output, auditor_dir=audit)
    result = rows(output / "sink-decisions.jsonl")[0]
    assert result["highest_confidence_singleton_sources"] == ["source-b"]
    assert result["conservatively_reported_joint_source_sets"] == [["source-a", "source-b"]]
    assert len(result["source_set_decisions"]) == 3


def test_reused_auditor_keeps_its_original_smaller_planning_budget(synthetic, tmp_path):
    _, source, audit, call, graph = synthetic
    smaller = tmp_path / "smaller-plans"
    causal_v2.export_run(source, smaller, max_sources=2, max_pairs=1)
    make_audit((smaller, source, audit, call, graph))
    output = tmp_path / "composed"
    paper_audit.run(source, output, auditor_dir=audit)
    plan = read(output / "plan.json")
    assert (plan["max_sources"], plan["max_pairs"]) == (2, 1)
    assert plan["planning_budget_origin"] == "verified_existing_auditor_export"
    assert rows(output / "plans/plans.jsonl") == rows(audit / "plans.jsonl")


def legacy_source(source):
    manifest = read(source / "manifest.json")
    manifest["mode"] = "cross-session-copy-pair-v1"
    manifest["config"].pop("canary_enabled")
    manifest.pop("input_condition")
    manifest.setdefault("online_provenance", {})["lineage"] = read(source / "lineage-state.json")["state"][
        "metadata"
    ]
    (source / "manifest.json").write_text(json.dumps(manifest))


def test_legacy_memory_condition_is_cross_checked_without_rewriting_native_archive(tmp_path, monkeypatch):
    source, output = tmp_path / "native", tmp_path / "composed"
    native_recorded_run(source, no_arguments=False)
    legacy_source(source)
    before = auditor._snapshot(source)
    monkeypatch.setattr(
        auditor, "run_audit", lambda *a, **k: pytest.fail("Legacy adapter must not invoke auditor transport")
    )
    result = paper_audit.run(source, output)
    assert result["new_auditor_requests"] == 0 and result["auditor_export"] is None
    assert result["condition_adapter"].startswith("verified_legacy_memory_pair_passive")
    assert read(output / "plans/summary.json")["auditor_transport_compatible"] is False
    assert auditor._snapshot(source) == before
    assert rows(output / "sink-decisions.jsonl")[-1]["detector_positive"] is None


@pytest.mark.parametrize(
    "mutation", ["conflicting_metadata", "unrecognized_mode", "explicit_null_flag", "live"]
)
def test_legacy_condition_never_defaults_missing_flags_to_false(tmp_path, mutation):
    source = tmp_path / "native"
    native_recorded_run(source, no_arguments=False)
    legacy_source(source)
    manifest = read(source / "manifest.json")
    if mutation == "conflicting_metadata":
        manifest["online_provenance"]["lineage"]["memory_cascade"]["canary_enabled"] = True
    elif mutation == "unrecognized_mode":
        manifest["mode"] = "unrecognized"
    elif mutation == "explicit_null_flag":
        manifest["config"]["canary_enabled"] = None
    (source / "manifest.json").write_text(json.dumps(manifest))
    kwargs = {"live": True, "max_requests": 1} if mutation == "live" else {}
    with pytest.raises(ValueError, match="condition"):
        paper_audit.run(source, tmp_path / "composed", **kwargs)


def test_complete_negative_judgments_produce_usable_false_detector_flag(synthetic, tmp_path):
    audit, _ = make_audit(synthetic, values=(True, True, True))
    output = tmp_path / "composed"
    paper_audit.run(synthetic[1], output, auditor_dir=audit)
    result = rows(output / "sink-decisions.jsonl")[0]
    assert result["status"] == "negative_under_tested_interventions" and result["detector_positive"] is False
    assert result["decision_resolved"] is True
    assert read(output / "derived-graph.json")["added_edges"] == []


def test_request_cap_keeps_every_omitted_probe_unknown(synthetic, tmp_path):
    audit, requests = make_audit(synthetic, budget=1)
    output = tmp_path / "composed"
    paper_audit.run(synthetic[1], output, auditor_dir=audit)
    result = rows(output / "sink-decisions.jsonl")[0]
    assert len(requests) == 1 and len(result["source_set_decisions"]) == 3
    assert result["status"] == "unknown" and result["detector_positive"] is None
    assert [s["detector_positive"] for s in result["source_set_decisions"]] == [False, None, None]
    assert result["decision_resolved"] is False


@pytest.mark.parametrize(
    "mutation", ["judgment", "response", "request", "duplicate", "missing", "source", "summary"]
)
def test_reused_auditor_tampering_fails_closed(synthetic, tmp_path, mutation):
    audit, _ = make_audit(synthetic)
    if mutation == "source":
        (synthetic[1] / "new-file.json").write_text("{}")
    elif mutation == "summary":
        p = audit / "summary.json"
        d = read(p)
        d["valid_judgments"] = 0
        p.write_text(json.dumps(d))
    else:
        p = audit / ("requests.jsonl" if mutation == "request" else "judgments.jsonl")
        data = rows(p)
        if mutation == "judgment":
            data[0]["judgment"]["would_call_anyway"] = False
        elif mutation == "response":
            data[0]["response"]["choices"][0]["message"]["content"] = "{}"
        elif mutation == "request":
            data[0]["body"]["messages"][1]["content"] = "Changed context"
            data[0]["body_sha256"] = paper_audit._hash(data[0]["body"])
        elif mutation == "duplicate":
            data[1] = copy.deepcopy(data[0])
        elif mutation == "missing":
            data.pop()
        p.write_text("".join(json.dumps(row) + "\n" for row in data))
    with pytest.raises(ValueError):
        paper_audit.run(synthetic[1], tmp_path / "composed", auditor_dir=audit)
    assert not (tmp_path / "composed/manifest.json").exists()


def test_raw_unknown_response_remains_unknown_without_retrospective_promotion(synthetic, tmp_path):
    plans, source, audit, _, _ = synthetic
    raw = '{"would_call_anyway":"false","confidence":0.9,"reasoning":"Invalid boolean."}'
    with transport.client_with(
        lambda request: httpx.Response(200, json=transport.completion(raw=raw))
    ) as client:
        auditor.run_audit(plans, audit, client=client, max_requests=1, judgment_format=paper_audit.FORMAT)
    paper_audit.run(source, tmp_path / "composed", auditor_dir=audit)
    result = rows(tmp_path / "composed/sink-decisions.jsonl")[0]
    assert all(s["detector_positive"] is None for s in result["source_set_decisions"])


def test_historical_ascii_format_is_not_reinterpreted_as_punctuation_compatible(synthetic, tmp_path):
    plans, source, audit, _, _ = synthetic
    raw = json.dumps(
        {"would_call_anyway": False, "confidence": 0.9, "reasoning": "The agent’s choice changes."}
    )
    with transport.client_with(
        lambda request: httpx.Response(200, json=transport.completion(raw=raw))
    ) as client:
        auditor.run_audit(plans, audit, client=client, max_requests=1)
    before = auditor._snapshot(audit)
    result = paper_audit.run(source, tmp_path / "composed", auditor_dir=audit)
    assert result["judgment_format"] == "ascii_v1"
    decision = rows(tmp_path / "composed/sink-decisions.jsonl")[0]
    assert decision["detector_positive"] is None
    assert decision["source_set_decisions"][0]["reason"] == "invalid_judgment_schema"
    assert auditor._snapshot(audit) == before


def test_explicit_unbound_match_cannot_silently_become_a_negative_decision():
    call, graph = fixture()
    call["fields"][0]["nt_style_cascade"][0]["matched"] = True
    plan = causal_v2.plan_joint_probes(call, graph)
    with pytest.raises(ValueError, match="lacks a bound graph path"):
        paper_audit._compose([call], graph, [plan], [], paper_audit.FORMAT)


def test_explicit_decision_retains_bound_source_path_and_score():
    call, graph = fixture()
    pair = call["fields"][0]["nt_style_cascade"][0]
    pair.update(matched=True, first_matched_tier="tier2")
    edge = {
        "edge_id": "explicit-edge",
        "from_node": "origin-node",
        "to_node": "sink-node",
        "relation": "candidate_content",
        "label_ids": ["label-a"],
        "tier": "tier2",
        "evidence_score": 0.5,
    }
    label_id = graph["registry"][0]["label_id"]
    edge["label_ids"] = [label_id]
    graph["edges"].append(edge)
    call["lineage"]["paths"] = [{"label_id": label_id, "edge_ids": ["explicit-edge"]}]
    plan = causal_v2.plan_joint_probes(call, graph)
    decisions, derived = paper_audit._compose([call], graph, [plan], [], paper_audit.FORMAT)
    assert decisions[0]["status"] == "explicit_positive" and decisions[0]["detector_positive"] is True
    assert decisions[0]["explicit_evidence"][0]["evidence_score"] == 0.5
    assert decisions[0]["decision_resolved"] is True
    assert decisions[0]["causal_coverage_complete"] is False
    assert decisions[0]["explicit_pair_inventory"][0]["matched"] is True
    assert derived["added_edges"] == []
    edge["from_node"] = "wrong"
    with pytest.raises(ValueError, match="disconnected"):
        paper_audit._compose([call], graph, [plan], [], paper_audit.FORMAT)


def test_public_single_proposal_composer_matches_bulk_and_does_not_mutate_inputs():
    call, graph = fixture(second=True, repeat=True)
    plan = causal_v2.plan_joint_probes(call, graph)
    result_rows = [
        {
            **causal_v2.bind_judgment(
                probe,
                json.dumps(
                    {
                        "would_call_anyway": value,
                        "confidence": confidence,
                        "reasoning": "Synthetic auditor prediction only.",
                    }
                ),
                judgment_format=paper_audit.FORMAT,
            ),
            "proposal_event_id": call["proposal_event_id"],
        }
        for probe, value, confidence in zip(
            plan["probes"], (True, True, False), (0.2, 0.3, 0.9), strict=True
        )
    ]
    before = copy.deepcopy((call, graph, plan, result_rows))

    decision, additions = paper_audit.compose_proposal(
        call, graph, plan, result_rows, paper_audit.FORMAT
    )
    decisions, derived = paper_audit._compose(
        [call], graph, [plan], result_rows, paper_audit.FORMAT
    )

    assert decision == decisions[0]
    assert additions == {
        "added_nodes": derived["added_nodes"],
        "added_edges": derived["added_edges"],
    }
    assert {edge["relation"] for edge in additions["added_edges"]} == {
        "source_set_membership",
        "predicted_control",
    }
    assert (call, graph, plan, result_rows) == before
    assert derived["original_graph"] == graph


def test_final_code_mutation_does_not_seal_a_successful_export(synthetic, tmp_path, monkeypatch):
    original = paper_audit._report

    def changed(*args):
        original(*args)
        monkeypatch.setattr(paper_audit, "_code_hashes", lambda: {"changed": "code"})

    monkeypatch.setattr(paper_audit, "_report", changed)
    with pytest.raises(ValueError, match="final export"):
        paper_audit.run(synthetic[1], tmp_path / "composed")
    assert not (tmp_path / "composed/manifest.json").exists()
    assert not (tmp_path / "composed/summary.json").exists()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"live": True},
        {"max_requests": True},
        {"max_requests": 33},
        {"live": 1},
        {"live": True, "max_requests": 1, "auditor_dir": Path("unused")},
    ],
)
def test_new_calls_need_explicit_finite_budget_and_modes_are_exclusive(synthetic, tmp_path, kwargs):
    with pytest.raises(ValueError):
        paper_audit.run(synthetic[1], tmp_path / "composed", **kwargs)


def test_fresh_output_and_original_inputs_cannot_be_overwritten(synthetic, tmp_path):
    source = synthetic[1]
    for output in (source, source / "nested", source.parent):
        with pytest.raises(ValueError, match="fresh output"):
            paper_audit.run(source, output)
    output = tmp_path / "composed"
    paper_audit.run(source, output)
    before = hashlib.sha256((output / "manifest.json").read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="fresh output"):
        paper_audit.run(source, output)
    assert hashlib.sha256((output / "manifest.json").read_bytes()).hexdigest() == before

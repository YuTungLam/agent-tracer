"""Declared synthetic scores and real native-tool plumbing; no causal ground truth."""

import copy
import json

import pytest
from test_counterfactual import fixture as v1_fixture
from test_counterfactual import negative

from agentdojo_lab import causal_v2, counterfactual
from agentdojo_lab.cascade import CascadeMatcher


class NegativeSemantic:
    """Authored orthogonal-score control, never presented as model measurements."""

    metadata = {"kind": "authored_negative_semantic_fixture", "real_model": False}

    def compare_tier3(self, *args):
        return {"status": "scored", "score": -0.5, "matched": False, "complete": True, "truncated": False}

    def compare_tier4(self, *args):
        return {**self.compare_tier3(), "coverage": 0.0}


def pair_metadata(pair, *, profile="ordinary", canary=False):
    pair["metadata"] = CascadeMatcher(NegativeSemantic(), profile=profile, canary_enabled=canary).metadata
    if not canary:
        pair["stages"]["tier1"] = {
            "status": "disabled_condition",
            "reason": "passive_input_unchanged_no_canary",
            "score": None,
            "matched": None,
            "complete": False,
            "truncated": False,
        }
    return pair


def fixture(*, second=False, repeat=False, no_arguments=False):
    call, graph = v1_fixture(repeat=repeat)
    if second:
        source = copy.deepcopy(call["visible_sources"][0])
        index = len(call["request_messages"])
        call["request_messages"].append(
            {"role": "tool", "tool_call_id": "tool-id-b", "content": source["text"]}
        )
        source.update(
            source_id="source-b",
            source_event_id="result-event-b",
            exposure_event_id="exposure-b",
            request_pointer=f"/data/body/messages/{index}/content",
            message_index=index,
        )
        call["visible_sources"].append(source)
        label = copy.deepcopy(graph["registry"][0])
        label.update(
            source_id="source-b",
            source_event_id="result-event-b",
            label_id="label-b",
            origin_node_id="origin-node-b",
            origin_result_node_id="result-node-b",
        )
        graph["registry"].append(label)
        graph["nodes"] += [
            {**graph["nodes"][0], "node_id": "origin-node-b"},
            {**graph["nodes"][1], "node_id": "result-node-b", "event_id": "result-event-b"},
        ]
        graph["edges"] += [
            {
                "edge_id": "return-b",
                "relation": "tool_return",
                "from_node": "origin-node-b",
                "to_node": "result-node-b",
                "event_id": "result-event-b",
                "label_ids": [],
            },
            {
                "edge_id": "context-b",
                "relation": "context_exposure",
                "from_node": "result-node-b",
                "to_node": "sink-node",
                "event_id": "sink-event",
                "label_ids": ["label-b"],
            },
        ]
        call["fields"][0]["nt_style_cascade"].append(negative(source))
    for pair in call["fields"][0]["nt_style_cascade"]:
        pair_metadata(pair)
    graph["metadata"] = {"memory_cascade": {"canary_enabled": False}}
    if no_arguments:
        call.update(arguments={}, fields=[])
        next(node for node in graph["nodes"] if node["node_id"] == "sink-node")["arguments"] = {}
    return call, graph


def judgments(plan, values):
    return [
        causal_v2.bind_judgment(
            probe,
            json.dumps(
                {
                    "would_call_anyway": value,
                    "confidence": 0.25,
                    "reasoning": "Synthetic auditor prediction only.",
                }
            ),
        )
        for probe, value in zip(plan["probes"], values, strict=True)
    ]


def test_v1_default_retains_strict_four_stage_rule_and_unchanged_output():
    call, graph = v1_fixture()
    assert counterfactual.plan_probe(call, graph) == counterfactual._plan_probe(call, graph)
    passive, graph = fixture()
    assert counterfactual.plan_probe(passive, graph)["reason"] == "incomplete_explicit_evidence"
    plan = causal_v2.plan_joint_probes(passive, graph)
    assert plan["status"] == "eligible", plan
    assert plan["coverage"][0]["stages"]["tier1"] == {
        "status": "disabled_condition",
        "negative_measurement": False,
    }


@pytest.mark.parametrize("profile,score,eligible", [("ordinary", 0.2, False), ("implicit_string", 0.2, True)])
def test_lexical_profile_threshold_is_not_hard_coded(profile, score, eligible):
    call, _ = fixture()
    pair = call["fields"][0]["nt_style_cascade"][0]
    pair_metadata(pair, profile=profile)
    pair["stages"]["tier2"]["score"] = score
    assert (causal_v2.explicit_coverage(pair, canary_enabled=False)["status"] == "eligible") is eligible


@pytest.mark.parametrize(
    "profile,score,eligible", [("ordinary", 0.7, False), ("memory", 0.7, True), ("safe_control", 0.9, True)]
)
def test_semantic_profiles_share_central_accessor(profile, score, eligible):
    call, _ = fixture()
    pair = call["fields"][0]["nt_style_cascade"][0]
    pair_metadata(pair, profile=profile)
    pair["stages"]["tier3"]["score"] = score
    assert (causal_v2.explicit_coverage(pair, canary_enabled=False)["status"] == "eligible") is eligible


@pytest.mark.parametrize(
    "status", ["unavailable", "skipped", "encoder_error", "budget_exceeded", "not_applicable"]
)
@pytest.mark.parametrize("tier", ["tier2", "tier3", "tier4"])
def test_missing_or_failed_active_stage_is_unknown(tier, status):
    call, graph = fixture()
    call["fields"][0]["nt_style_cascade"][0]["stages"][tier]["status"] = status
    plan = causal_v2.plan_joint_probes(call, graph)
    assert plan["status"] == "unknown" and not plan["probes"]


def test_unmarked_canary_source_is_explicitly_inapplicable_not_failed():
    call, graph = fixture()
    pair = call["fields"][0]["nt_style_cascade"][0]
    pair_metadata(pair, canary=True)
    pair["stages"]["tier1"] = {
        "status": "not_applicable",
        "reason": "source_has_no_validated_exposed_canary",
        "matched": None,
        "score": None,
        "complete": False,
        "truncated": False,
    }
    graph["metadata"]["memory_cascade"]["canary_enabled"] = True
    assert causal_v2.plan_joint_probes(call, graph, canary_enabled=True)["status"] == "eligible"
    pair["stages"]["tier1"]["status"] = "encoder_error"
    assert causal_v2.plan_joint_probes(call, graph, canary_enabled=True)["status"] == "unknown"


def test_no_argument_sink_requires_bound_context_not_fabricated_negative_scores():
    call, graph = fixture(no_arguments=True)
    plan = causal_v2.plan_joint_probes(call, graph)
    assert plan["status"] == "eligible" and plan["target_scope"] == "no_argument_sink"
    assert plan["coverage"][0]["negative_measurement"] is False
    assert plan["probes"][0]["sink"]["arguments"] == {}
    assert counterfactual.plan_probe(call, graph)["reason"] == "no_selected_argument_targets"
    call["visible_sources"][0]["text_sha256"] = "wrong"
    assert causal_v2.plan_joint_probes(call, graph)["status"] == "unknown"


def test_no_argument_unknown_graph_condition_or_foreign_cutoff_cannot_plan():
    call, graph = fixture(no_arguments=True)
    graph.pop("metadata")
    assert causal_v2.plan_joint_probes(call, graph)["reason"] == "graph_condition_evidence_mismatch"
    call, graph = fixture(no_arguments=True)
    call["cutoff_event_id"] = "future"
    assert causal_v2.plan_joint_probes(call, graph)["reason"] == "invalid_prefix_cutoff"


def test_joint_plan_neutralizes_each_repeated_occurrence_without_mutating_inputs():
    call, graph = fixture(second=True, repeat=True)
    before = copy.deepcopy((call, graph))
    plan = causal_v2.plan_joint_probes(call, graph)
    assert plan["status"] == "eligible", plan
    assert len(plan["probes"]) == 3
    first, second, pair = plan["probes"]
    assert len(first["replacements"]) == 2 and len(second["replacements"]) == 1
    assert len(pair["replacements"]) == 3
    assert pair["source_ids"] == ["source-a", "source-b"]
    assert all(
        message["content"] == counterfactual.PLACEHOLDER
        for message in pair["context_b"]
        if message["role"] == "tool"
    )
    assert (call, graph) == before
    pair["context_b"][0]["content"] = "changed returned copy"
    assert (call, graph) == before


@pytest.mark.parametrize(
    "values,pattern",
    [
        ([False, False, False], "predicted_AND_like"),
        ([True, True, False], "predicted_redundant_OR_like"),
        ([False, True, False], "predicted_first_source_dependency"),
        ([True, False, False], "predicted_second_source_dependency"),
        ([True, True, True], "no_predicted_dependency_under_tested_removals"),
        ([False, False, True], "unknown"),
    ],
)
def test_joint_prediction_patterns_are_conservative(values, pattern):
    plan = causal_v2.plan_joint_probes(*fixture(second=True))
    summary = causal_v2.summarize_joint_results(plan, judgments(plan, values))
    assert summary["pairs"][0]["pattern"] == pattern
    assert summary["complete"] is (pattern != "unknown")
    assert summary["confidence"] is None
    assert "not_observed_behavior" in summary["scope"]


def test_pair_budget_preserves_unknown_inventory_and_cannot_claim_full_no_change():
    plan = causal_v2.plan_joint_probes(*fixture(second=True), max_pairs=0)
    assert plan["status"] == "partial" and not plan["complete"]
    assert plan["pair_inventory"][0]["reason"] == "pair_budget_exceeded"
    summary = causal_v2.summarize_joint_results(plan, judgments(plan, [True, True]))
    assert summary["pairs"][0]["pattern"] == "unknown" and not summary["complete"]


@pytest.mark.parametrize("budget", [0, True, 9])
def test_invalid_source_budget_is_unknown(budget):
    assert causal_v2.plan_joint_probes(*fixture(), max_sources=budget)["status"] == "unknown"


def test_source_cap_retains_unknown_instead_of_selecting_favorable_sources():
    plan = causal_v2.plan_joint_probes(*fixture(second=True), max_sources=1)
    assert plan["reason"] == "source_budget_exceeded" and not plan["probes"]


def test_context_budget_makes_pair_unknown(monkeypatch):
    call, graph = fixture(second=True)
    full = causal_v2.plan_joint_probes(call, graph)
    size = sum(
        len(counterfactual._canonical(p["context_a"])) + len(counterfactual._canonical(p["context_b"]))
        for p in full["probes"][:2]
    )
    monkeypatch.setitem(counterfactual.LIMITS, "context_output_bytes", size)
    plan = causal_v2.plan_joint_probes(call, graph)
    assert plan["status"] == "partial"
    assert plan["pair_inventory"][0]["reason"] == "context_output_budget_exceeded"


def test_shared_recovered_origin_is_not_treated_as_separable_joint_sources(monkeypatch):
    original = counterfactual._plan_probe

    def shared(*args, **kwargs):
        plan = original(*args, **kwargs)
        for probe in plan["probes"]:
            probe["origin_source_ids"].append("shared-ancestor")
        return plan

    monkeypatch.setattr(counterfactual, "_plan_probe", shared)
    plan = causal_v2.plan_joint_probes(*fixture(second=True))
    assert plan["status"] == "partial"
    assert plan["pair_inventory"][0]["reason"] == "inseparable_shared_recovered_origin"


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "foreign", "hash"])
def test_judgment_missing_duplicate_or_foreign_binding_stays_unknown(mutation):
    plan = causal_v2.plan_joint_probes(*fixture(second=True))
    results = judgments(plan, [False, False, False])
    if mutation == "missing":
        results.pop()
    elif mutation == "duplicate":
        results.append(copy.deepcopy(results[0]))
    elif mutation == "foreign":
        results[-1]["probe_id"] = "foreign"
    else:
        results[-1]["binding_sha256"] = "bad"
    summary = causal_v2.summarize_joint_results(plan, results)
    assert not summary["complete"] and summary["pairs"][0]["pattern"] == "unknown"


def test_equal_text_on_different_proposal_cannot_reuse_bound_judgment():
    call, graph = fixture()
    first = causal_v2.plan_joint_probes(call, graph)
    records = judgments(first, [False])
    call["proposal_event_id"] = call["cutoff_event_id"] = "another-sink"
    next(n for n in graph["nodes"] if n["node_id"] == "sink-node")["proposal_event_id"] = "another-sink"
    next(e for e in graph["edges"] if e["relation"] == "context_exposure")["event_id"] = "another-sink"
    second = causal_v2.plan_joint_probes(call, graph)
    assert first["probes"][0]["probe_id"] != second["probes"][0]["probe_id"]
    assert not causal_v2.summarize_joint_results(second, records)["complete"]


def test_mutated_context_cannot_be_bound_to_a_judgment():
    probe = causal_v2.plan_joint_probes(*fixture())["probes"][0]
    probe["context_b"][0]["content"] = "changed"
    with pytest.raises(ValueError, match="binding changed"):
        causal_v2.bind_judgment(probe, "{}")


def native_recorded_run(path, *, no_arguments):
    """Execute native simulated tools with authored SDK replies and semantic scores."""
    import hashlib

    import httpx
    import openai
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
    from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
    from agentdojo.default_suites.v1.tools.cloud_drive_client import CloudDrive, create_file, get_file_by_id
    from agentdojo.default_suites.v1.tools.email_client import get_unread_emails
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suite

    from agentdojo_lab.groq_adapter import GroqLLM
    from agentdojo_lab.lineage import DCPG
    from agentdojo_lab.observation import ObservationSession, observe_pipeline
    from agentdojo_lab.online import OnlineProvenance
    from agentdojo_lab.policy import ToolPolicy
    from agentdojo_lab.recording import EventRecorder

    path.mkdir()
    sink = "get_unread_emails" if no_arguments else "create_file"
    arguments = {} if no_arguments else {"filename": "ZXQJ", "content": "ZXQJ"}
    policy = ToolPolicy.from_dict(
        {
            "schema_version": 1,
            "policy_id": "causal-v2-native-control",
            "suite": "workspace",
            "benchmark_version": "v1.2.2",
            "sources": {
                "get_file_by_id": {
                    "output_scope": "visible_text",
                    "rationale": "External native condition file",
                }
            },
            "sinks": {sink: {"argument_paths": [""], "rationale": "Native simulated sink"}},
            "neutral_tools": {},
        }
    )
    lineage = DCPG("causal-v2-native", policy, canary_enabled=False)
    sidecar = OnlineProvenance(
        path / "provenance.jsonl",
        semantic_matcher=NegativeSemantic(),
        policy=policy,
        lineage=lineage,
        canary_enabled=False,
    )
    recorder = EventRecorder(path / "events.jsonl", "causal-v2-native", on_event=sidecar.consume)
    observer = ObservationSession(recorder)
    responses = [
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "read",
                    "type": "function",
                    "function": {"name": "get_file_by_id", "arguments": json.dumps({"file_id": "1"})},
                }
            ],
        },
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "sink",
                    "type": "function",
                    "function": {"name": sink, "arguments": json.dumps(arguments)},
                }
            ],
        },
        {"role": "assistant", "content": "The authored native fixture is complete."},
    ]
    requests = []

    def respond(request):
        requests.append(json.loads(request.content))
        assert len(requests) <= 3
        return httpx.Response(
            200,
            json={
                "id": "causal-v2-fixture",
                "object": "chat.completion",
                "created": 0,
                "model": "openai/gpt-oss-20b",
                "choices": [{"index": 0, "finish_reason": "stop", "message": responses[len(requests) - 1]}],
                "usage": {"prompt_tokens": 8, "completion_tokens": 3, "total_tokens": 11},
            },
        )

    client = openai.OpenAI(
        api_key="synthetic-fixture-key",
        base_url="https://causal-v2.invalid/v1",
        max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(respond)),
    )
    observer.attach(client)
    llm = GroqLLM(client, "openai/gpt-oss-20b", observer=observer)
    pipeline = observe_pipeline(
        AgentPipeline(
            [
                SystemMessage("Use the simulated native fixture tools."),
                InitQuery(),
                llm,
                ToolsExecutionLoop([ToolsExecutor(), llm], max_iters=3),
            ]
        ),
        observer,
    )
    runtime = FunctionsRuntime()
    for function in (get_file_by_id, get_unread_emails if no_arguments else create_file):
        runtime.register_function(function)
    env = get_suite("v1.2.2", "workspace").load_and_inject_default_environment({})
    original = env.cloud_drive.files["1"].model_copy(deep=True)
    original.filename = "condition.txt"
    original.content = "Condition alpha is active."
    env.cloud_drive = CloudDrive(account_email=env.cloud_drive.account_email, initial_files=[original])
    manifest = {
        "schema_version": 1,
        "real_llm": False,
        "input_condition": "passive",
        "config": {"canary_enabled": False},
        "notes": [
            "Authored SDK replies and semantic scores; actual native tools, event recording and lineage; no model endpoint."
        ],
    }
    (path / "manifest.json").write_text(json.dumps(manifest))
    recorder.emit("RUN_STARTED", {"mode": "causal-v2-native-fixture"})
    with client:
        pipeline.query("Read the condition file, then perform the fixture operation.", runtime, env, [], {})
    recorder.emit("RUN_END", {"status": "completed"})
    recorder.close()
    sidecar.close()
    sidecar.save_state(path / "lineage-state.json")
    (path / "summary.json").write_text(
        json.dumps({"online_provenance": sidecar.status(), "usage": llm.stats, "real_llm": False})
    )
    return {
        str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in path.rglob("*")
        if p.is_file()
    }


@pytest.mark.parametrize("no_arguments", [False, True])
def test_native_saved_prefix_export_verifies_flush_context_and_passive_coverage(
    tmp_path, no_arguments, monkeypatch
):
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("Real network is forbidden in native controls")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    run = tmp_path / "native"
    before = native_recorded_run(run, no_arguments=no_arguments)
    output = tmp_path / "plans"
    summary = causal_v2.export_run(run, output)
    assert summary["source_hashes_before"] == summary["source_hashes_after"] == before
    assert summary["model_requests"] == 0 and summary["native_tool_calls"] == 0
    plans = [json.loads(line) for line in (output / "plans.jsonl").read_text().splitlines()]
    eligible = [plan for plan in plans if plan["status"] == "eligible"]
    assert len(eligible) == 1, plans
    plan = eligible[0]
    assert plan["target_scope"] == ("no_argument_sink" if no_arguments else "selected_argument_fields")
    assert plan["probes"][0]["context_a"] != plan["probes"][0]["context_b"]
    assert all(probe["call_binding"]["model_request_id"] for probe in plan["probes"])
    assert not causal_v2.summarize_joint_results(plan, [])["complete"]
    if no_arguments:
        assert plan["coverage"][0]["negative_measurement"] is False
    else:
        assert all(row["stages"]["tier1"]["status"] == "disabled_condition" for row in plan["coverage"])
    with pytest.raises(ValueError, match="fresh output"):
        causal_v2.export_run(run, output)
    with pytest.raises(ValueError, match="separate"):
        causal_v2.export_run(run, run / "nested")


def test_declared_disabled_semantic_engine_cannot_supply_negative_measurements():
    call, graph = fixture()
    call["fields"][0]["nt_style_cascade"][0]["metadata"]["semantic_enabled"] = False
    plan = causal_v2.plan_joint_probes(call, graph)
    assert plan["status"] == "unknown"
    assert plan["reason"] == "active_semantic_configuration_missing"

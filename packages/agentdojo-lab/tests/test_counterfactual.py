"""Pure planner contracts; negative scores here are declared synthetic fixtures."""

import copy
import hashlib
import json

import pytest
import yaml

from agentdojo_lab.counterfactual import LIMITS, PLACEHOLDER, parse_judgment, plan_probe, summarize_results


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def negative(source):
    return {
        "source_id": source["source_id"],
        "request_pointer": source["request_pointer"],
        "exposure_event_id": source["exposure_event_id"],
        "status": "scored",
        "matched": False,
        "complete": True,
        "truncated": False,
        "first_matched_tier": None,
        "stages": {
            tier: {
                "status": "scored",
                "score": 0.0,
                "matched": False,
                "complete": True,
                "truncated": False,
                **({"coverage": 0.0} if tier == "tier4" else {}),
            }
            for tier in ("tier1", "tier2", "tier3", "tier4")
        },
    }


def fixture(text="Condition alpha is active.", *, repeat=False, block=False):
    content = [{"type": "text", "text": text}] if block else text
    messages = [
        {"role": "user", "content": "Perform the normal task."},
        {
            "role": "assistant",
            "tool_calls": [{"id": "tool-id", "function": {"name": "read", "arguments": "{}"}}],
        },
        {"role": "tool", "tool_call_id": "tool-id", "content": content},
    ]
    pointer = "/data/body/messages/2/content" + ("/0/text" if block else "")
    source = {
        "source_id": "source-a",
        "source_event_id": "result-event",
        "run_id": "run-a",
        "episode_id": "episode-a",
        "kind": "tool",
        "policy": {"eligible": True},
        "origin_tool": "read",
        "text": text,
        "text_sha256": sha(text),
        "first_observed_sequence": 11,
        "exposure_event_id": "exposure-event",
        "message_index": 2,
        "request_pointer": pointer,
    }
    sources = [source]
    if repeat:
        messages.append(copy.deepcopy(messages[-1]))
        sources.append(
            {
                **source,
                "message_index": 3,
                "request_pointer": pointer.replace("/messages/2/", "/messages/3/"),
                "exposure_event_id": "exposure-repeat",
            }
        )
    call = {
        "run_id": "run-a",
        "episode_id": "episode-a",
        "proposal_event_id": "sink-event",
        "cutoff_event_id": "sink-event",
        "proposal_sequence": 15,
        "request_sequence": 10,
        "function": "write",
        "arguments": {"content": "ZXQJ"},
        "component_mode": "ordered_cascade",
        "policy": {"sha256": "a" * 64, "sink": {"selected": True}},
        "request_messages": messages,
        "visible_sources": sources,
        "fields": [
            {
                "argument_path": "/content",
                "value": "ZXQJ",
                "cascade_scope": {"sink": {"selected": True}},
                "nt_style_cascade": [negative(item) for item in sources],
            }
        ],
        "lineage": {"node_id": "sink-node", "recovered_sources": [], "comparisons": []},
    }
    registry = {
        key: source[key]
        for key in (
            "source_id",
            "source_event_id",
            "run_id",
            "episode_id",
            "text",
            "text_sha256",
            "origin_tool",
        )
    }
    registry.update(
        label_id="label-a",
        origin_node_id="origin-node",
        origin_result_node_id="result-node",
        policy_sha256="a" * 64,
    )
    graph = {
        "schema_version": 1,
        "method": "nt_style_dcpg_v1",
        "failed": False,
        "policy_sha256": "a" * 64,
        "nodes": [
            {
                "node_id": "origin-node",
                "kind": "tool_step",
                "run_id": "run-a",
                "episode_id": "episode-a",
                "proposal_sequence": 2,
                "function": "read",
            },
            {
                "node_id": "result-node",
                "kind": "tool_result",
                "run_id": "run-a",
                "episode_id": "episode-a",
                "event_id": "result-event",
            },
            {
                "node_id": "sink-node",
                "kind": "tool_step",
                **{
                    key: call[key]
                    for key in (
                        "run_id",
                        "episode_id",
                        "proposal_event_id",
                        "proposal_sequence",
                        "function",
                        "arguments",
                    )
                },
                "outcome": "success",
            },
        ],
        "edges": [
            {
                "edge_id": "return-edge",
                "relation": "tool_return",
                "from_node": "origin-node",
                "to_node": "result-node",
                "event_id": "result-event",
                "label_ids": [],
            },
            {
                "edge_id": "context-edge",
                "relation": "context_exposure",
                "from_node": "result-node",
                "to_node": "sink-node",
                "event_id": "sink-event",
                "label_ids": ["label-a"],
            },
        ],
        "registry": [registry],
    }
    return call, graph


def test_planner_preserves_original_prefix_and_dialogue_identity_without_agent_rerun():
    call, graph = fixture()
    before = copy.deepcopy((call, graph))
    plan = plan_probe(call, graph)
    assert plan["status"] == "eligible", plan
    (probe,) = plan["probes"]
    assert probe["context_a"] == call["request_messages"]
    assert probe["context_b"][:2] == call["request_messages"][:2]
    assert probe["context_b"][2] == {**call["request_messages"][2], "content": PLACEHOLDER}
    assert probe["sink"] == {"function": "write", "arguments": {"content": "ZXQJ"}}
    assert probe["lineage"]["context_edge_ids"] == ["context-edge"]
    assert "not_an_agent_rerun" in plan["metadata"]["auditor"]
    assert (call, graph) == before
    probe["context_a"][0]["content"] = "mutation"
    probe["context_b"][1]["tool_calls"][0]["id"] = "mutation"
    assert (call, graph) == before


@pytest.mark.parametrize("block", [False, True])
def test_all_repeated_occurrences_are_neutralized_in_one_probe(block):
    call, graph = fixture(repeat=True, block=block)
    plan = plan_probe(call, graph)
    assert plan["status"] == "eligible", plan
    (probe,) = plan["probes"]
    assert len(probe["replacements"]) == 2
    assert {row["message_index"] for row in probe["replacements"]} == {2, 3}
    assert probe["context_b"][2]["content"] == probe["context_b"][3]["content"]
    assert "Condition alpha" not in json.dumps(probe["context_b"])


@pytest.mark.parametrize(
    "text",
    [
        '{"name":"amber","count":3,"ratio":1.5,"enabled":true,"missing":null,"items":["note"]}',
        "name: amber\ncount: 3\nitems:\n- note\n- other\n",
    ],
)
def test_structured_neutralization_keeps_scalar_types_and_container_shape(text):
    call, graph = fixture(text)
    (probe,) = plan_probe(call, graph)["probes"]
    original, changed = yaml.safe_load(text), yaml.safe_load(probe["context_b"][2]["content"])

    def shape(value):
        return (
            {key: shape(item) for key, item in value.items()}
            if isinstance(value, dict)
            else [shape(item) for item in value]
            if isinstance(value, list)
            else type(value)
        )

    assert shape(original) == shape(changed)
    assert changed["name"] == PLACEHOLDER and changed["count"] == 0
    replacement = probe["replacements"][0]
    assert replacement["before_sha256"] == sha(text)
    assert replacement["after_sha256"] == sha(probe["context_b"][2]["content"])
    assert "/name" in replacement["leaf_paths"]


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-09-09",
        "2026-09-09 17:32:01",
        "2026-09-09T17:32:01Z",
        "2026-09-09T17:32:01+12:00",
        "2026-09-09T17:32:01-03:30",
    ],
)
def test_known_yaml_timestamp_types_remain_timestamps_with_explicit_epoch_choice(timestamp):
    text = "last_modified: " + timestamp + "\ncontent: Original reference text\nitems:\n- active\n"
    call, graph = fixture(text)
    plan = plan_probe(call, graph)
    assert plan["status"] == "eligible", plan
    (probe,) = plan["probes"]
    after = probe["context_b"][2]["content"]
    original, changed = yaml.safe_load(text), yaml.safe_load(after)
    before_date, after_date = original["last_modified"], changed["last_modified"]
    assert type(after_date) is type(before_date)
    assert (after_date.year, after_date.month, after_date.day) == (1970, 1, 1)
    if hasattr(before_date, "tzinfo"):
        assert after_date.utcoffset() == before_date.utcoffset()
        assert (after_date.hour, after_date.minute, after_date.second) == (0, 0, 0)
    assert changed["content"] == PLACEHOLDER and changed["items"] == [PLACEHOLDER]
    assert "2026-09-09" not in after and "Original reference" not in after
    assert probe["replacements"][0]["method"] == "YAML_scalar_neutralization"
    leaf = next(
        row for row in probe["replacements"][0]["leaf_replacements"] if row["path"] == "/last_modified"
    )
    assert leaf["scalar_type"] == type(before_date).__name__
    assert leaf["before_sha256"] != leaf["after_sha256"]


@pytest.mark.parametrize(
    "text", ['{"last_modified":"2026-09-09","content":"Reference"}', '"quoted JSON string"']
)
def test_actual_json_remains_json_with_strings_preserved_as_strings(text):
    call, graph = fixture(text)
    (probe,) = plan_probe(call, graph)["probes"]
    after = json.loads(probe["context_b"][2]["content"])
    assert type(after) is type(json.loads(text))
    assert probe["replacements"][0]["method"] == "JSON_scalar_neutralization"


@pytest.mark.parametrize(
    "text",
    [
        "a: &shared text\nb: *shared",
        "a: !!str text",
        "a: one\na: two",
        "date: 2026-99-99",
        '{"$schema":"local","type":"object"}',
        "{broken",
        "[]",
        "{}",
        " ",
        "value: .nan",
        "1: value",
    ],
)
def test_unsupported_structures_abstain_without_fallback_to_wholesale_guess(text):
    call, graph = fixture(text)
    plan = plan_probe(call, graph)
    assert plan["status"] == "skipped" and plan["probes"] == []
    assert plan["unsupported_sources"]


@pytest.mark.parametrize("tier", ["tier1", "tier2", "tier3", "tier4"])
@pytest.mark.parametrize("state", ["missing", "not_applicable", "unavailable", "truncated", "positive"])
def test_every_explicit_stage_must_be_a_complete_scored_negative(tier, state):
    call, graph = fixture()
    pair = call["fields"][0]["nt_style_cascade"][0]
    if state == "missing":
        del pair["stages"][tier]
    elif state == "truncated":
        pair["stages"][tier]["truncated"] = True
    elif state == "positive":
        pair["matched"] = True
    else:
        pair["stages"][tier]["status"] = state
    assert plan_probe(call, graph)["status"] == "skipped"


def test_passive_disabled_tier1_is_not_mislabeled_as_a_full_paper_negative():
    call, graph = fixture()
    call["fields"][0]["nt_style_cascade"][0]["stages"]["tier1"]["status"] = "disabled_condition"
    assert plan_probe(call, graph)["reason"] == "incomplete_explicit_evidence"


@pytest.mark.parametrize(
    "mutation",
    [
        "nonsink",
        "missing_pair",
        "foreign_pair",
        "source_sha",
        "source_role",
        "source_text",
        "wrong_index",
        "wrong_pointer",
        "source_after_cutoff",
        "origin_after_cutoff",
        "wrong_context_event",
        "wrong_context_label",
        "missing_return",
        "foreign_proposal",
    ],
)
def test_missing_or_forged_binding_never_yields_a_probe(mutation):
    call, graph = fixture()
    source = call["visible_sources"][0]
    if mutation == "nonsink":
        call["policy"]["sink"]["selected"] = False
    elif mutation == "missing_pair":
        call["fields"][0]["nt_style_cascade"] = []
    elif mutation == "foreign_pair":
        call["fields"][0]["nt_style_cascade"][0]["source_id"] = "foreign"
    elif mutation == "source_sha":
        source["text_sha256"] = "0" * 64
    elif mutation == "source_role":
        call["request_messages"][2]["role"] = "assistant"
    elif mutation == "source_text":
        call["request_messages"][2]["content"] += "changed"
    elif mutation == "wrong_index":
        source["message_index"] = 1
    elif mutation == "wrong_pointer":
        source["request_pointer"] = "/data/body/messages/2/tool_calls/0/arguments"
    elif mutation == "source_after_cutoff":
        source["first_observed_sequence"] = 100
    elif mutation == "origin_after_cutoff":
        graph["nodes"][0]["proposal_sequence"] = 100
    elif mutation == "wrong_context_event":
        graph["edges"][1]["event_id"] = "future"
    elif mutation == "wrong_context_label":
        graph["edges"][1]["label_ids"] = []
    elif mutation == "missing_return":
        graph["edges"] = graph["edges"][1:]
    elif mutation == "foreign_proposal":
        graph["nodes"][2]["arguments"] = {"content": "foreign"}
    assert plan_probe(call, graph)["status"] == "skipped"


def test_final_graph_future_nodes_outcomes_and_memory_bindings_do_not_enter_probe():
    call, graph = fixture()
    expected = plan_probe(call, graph)
    graph["nodes"].append(
        {
            "node_id": "future-node",
            "kind": "tool_step",
            "run_id": "run-a",
            "proposal_sequence": 100,
            "arguments": {"secret": "FUTURE_SENTINEL"},
        }
    )
    graph["memory_bindings"] = [{"content": "FUTURE_SENTINEL"}]
    graph["nodes"][2]["outcome"] = "failed"
    assert plan_probe(call, graph) == expected
    assert "FUTURE_SENTINEL" not in json.dumps(plan_probe(call, graph))


def add_ancestor(call, graph, number="1"):
    label, old_source, old_node, write_node, memory_node = [
        prefix + number for prefix in ("old-label", "old-source", "old-node", "write-node", "memory-node")
    ]
    original = "Historical reference text " + number
    graph["nodes"].extend(
        [
            {"node_id": old_node, "kind": "tool_step", "run_id": "old-run"},
            {"node_id": write_node, "kind": "tool_step", "run_id": "old-run"},
            {"node_id": memory_node, "kind": "memory_version", "run_id": "old-run"},
        ]
    )
    graph["registry"].append(
        {
            "label_id": label,
            "source_id": old_source,
            "text": original,
            "text_sha256": sha(original),
            "origin_node_id": old_node,
            "policy_sha256": "a" * 64,
        }
    )
    route = ["candidate" + number, "persist" + number, "restore" + number]
    for identity, relation, start, end in zip(
        route,
        ["candidate_content", "memory_persist", "memory_restore"],
        [old_node, write_node, memory_node],
        [write_node, memory_node, "origin-node"],
        strict=True,
    ):
        graph["edges"].append(
            {
                "edge_id": identity,
                "relation": relation,
                "from_node": start,
                "to_node": end,
                "label_ids": [label],
                "event_id": "exposure-event",
            }
        )
    recovered = {
        "label_id": label,
        "origin_source_id": old_source,
        "original_text": original,
        "original_text_sha256": sha(original),
        "origin_node_id": old_node,
        "carrier_source_id": "source-a",
        "carrier_event_id": "result-event",
        "carrier_node_id": "origin-node",
        "path_edge_ids": route,
        "record_key": "file-2",
        "version": 1,
        "content_sha256": sha("stored"),
    }
    call["lineage"]["recovered_sources"].append(recovered)
    pair = negative(call["visible_sources"][0])
    pair.update(
        argument_path="/content", label_id=label, carrier_source_id="source-a", metadata={"profile": "memory"}
    )
    call["lineage"]["comparisons"].append(pair)


def test_recovered_probe_neutralizes_current_carrier_without_injecting_old_history():
    call, graph = fixture()
    add_ancestor(call, graph)
    plan = plan_probe(call, graph)
    assert plan["status"] == "eligible", plan
    (probe,) = plan["probes"]
    assert probe["context_a"] == call["request_messages"]
    assert "Historical reference" not in json.dumps(probe["context_a"] + probe["context_b"])
    assert probe["lineage"]["recovered_origin_refs"][0]["origin_source_id"] == "old-source1"
    assert probe["lineage"]["path_edge_ids"] == ["candidate1", "persist1", "restore1"]


@pytest.mark.parametrize(
    "mutation",
    [
        "multiple",
        "missing_pair",
        "positive_pair",
        "future_path",
        "wrong_restore",
        "disconnected",
        "wrong_carrier",
        "wrong_original_sha",
    ],
)
def test_recovered_uncertainty_or_inseparable_origins_abstain(mutation):
    call, graph = fixture()
    add_ancestor(call, graph)
    if mutation == "multiple":
        add_ancestor(call, graph, "2")
    elif mutation == "missing_pair":
        call["lineage"]["comparisons"] = []
    elif mutation == "positive_pair":
        call["lineage"]["comparisons"][0]["matched"] = True
    elif mutation == "future_path":
        graph["nodes"][-2].update(run_id="run-a", proposal_sequence=100)
    elif mutation == "wrong_restore":
        graph["edges"][-1]["event_id"] = "future"
    elif mutation == "disconnected":
        graph["edges"][-1]["from_node"] = "foreign"
    elif mutation == "wrong_carrier":
        call["lineage"]["recovered_sources"][0]["carrier_event_id"] = "foreign"
    else:
        graph["registry"][-1]["text_sha256"] = "0" * 64
    assert plan_probe(call, graph)["status"] == "skipped"


@pytest.mark.parametrize("bad", [None, [], "text", {"policy": None}, {"policy": {"sink": None}}])
def test_malformed_input_is_an_explicit_skip(bad):
    assert plan_probe(bad, {})["status"] == "skipped"


def test_call_input_budget_stops_before_source_parser(monkeypatch):
    call, graph = fixture()
    call["request_messages"][0]["content"] = "x" * (LIMITS["call_string_codepoints"] + 1)
    monkeypatch.setattr(yaml, "scan", lambda text: pytest.fail("Oversized call must stop before parsing"))
    assert plan_probe(call, graph)["reason"] == "input_budget_exceeded"


@pytest.mark.parametrize("confidence", [0, 0.3, 1])
@pytest.mark.parametrize("answer", [True, False])
def test_strict_judgment_valid_schema(answer, confidence):
    value = {
        "would_call_anyway": answer,
        "confidence": confidence,
        "reasoning": "The task supplies enough information.",
    }
    assert parse_judgment(json.dumps(value)) == {"status": "valid", "judgment": value}


@pytest.mark.parametrize(
    "raw",
    [
        "{}",
        "[]",
        "null",
        "```json\n{}\n```",
        '{"would_call_anyway":false,"would_call_anyway":true,"confidence":0.5,"reasoning":"Text"}',
        '{"would_call_anyway":false,"confidence":NaN,"reasoning":"Text"}',
        '{"would_call_anyway":false,"confidence":Infinity,"reasoning":"Text"}',
        '{"would_call_anyway":false,"confidence":true,"reasoning":"Text"}',
        '{"would_call_anyway":"false","confidence":0.5,"reasoning":"Text"}',
        '{"would_call_anyway":false,"confidence":1.1,"reasoning":"Text"}',
        '{"would_call_anyway":false,"confidence":-0.1,"reasoning":"Text"}',
        '{"would_call_anyway":false,"confidence":0.5,"reasoning":""}',
        '{"would_call_anyway":false,"confidence":0.5,"reasoning":"123"}',
        '{"would_call_anyway":false,"confidence":0.5,"reasoning":"中文"}',
        '{"would_call_anyway":false,"confidence":0.5,"reasoning":"Text","unknown":1}',
    ],
)
def test_invalid_judgment_does_not_become_a_negative(raw):
    assert parse_judgment(raw)["status"] == "invalid"


def parsed(answer, confidence=0.5):
    return parse_judgment(
        json.dumps(
            {"would_call_anyway": answer, "confidence": confidence, "reasoning": "Normal task evidence."}
        )
    )


def test_only_false_alerts_and_highest_false_confidence_wins_without_threshold():
    result = summarize_results(
        [parsed(True, 1), parsed(False, 0.02), parsed(False, 0.1), {"status": "invalid"}]
    )
    assert result["alert"] is True and result["status"] == "alert"
    assert result["confidence"] == 0.1 and result["alert_count"] == 2
    assert result["valid_count"] == 3 and result["unknown_count"] == 1
    assert summarize_results([parsed(False, 0)])["alert"] is True


def test_unknown_and_missing_judgments_remain_unknown():
    for results in ([], [{"status": "invalid"}], [parsed(True), {"status": "error"}], [False]):
        summary = summarize_results(results)
        assert summary["status"] == "unknown" and summary["alert"] is None
        assert summary["confidence"] is None
    summary = summarize_results([parsed(True, 0.5), parsed(True, 1)])
    assert summary["status"] == "no_alert" and summary["alert"] is False
    assert summary["confidence"] is None


def test_judgment_and_summary_resource_bounds_are_explicit():
    assert parse_judgment("x" * (LIMITS["judgment_codepoints"] + 1))["status"] == "invalid"
    assert summarize_results([{}] * (LIMITS["results"] + 1))["status"] == "unknown"

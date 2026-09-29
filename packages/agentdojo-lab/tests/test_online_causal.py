"""Offline contracts for the synchronous M7 causal sidecar."""

import copy
import hashlib
import json
import time

import pytest
from test_causal_v2 import fixture

from agentdojo_lab import causal_v2_audit, judgment_formats
from agentdojo_lab.counterfactual import _canonical
from agentdojo_lab.online_causal import OnlineCausalAuditor


class Response:
    def __init__(self, value):
        self.value = value

    def model_dump(self, *, mode):
        assert mode == "json"
        return copy.deepcopy(self.value)


class Completions:
    def __init__(self, responder):
        self.responder = responder
        self.calls = []

    def create(self, **body):
        self.calls.append(copy.deepcopy(body))
        value = self.responder(len(self.calls), body)
        return value if isinstance(value, Response) else Response(value)


class Client:
    max_retries = 0
    api_key = "fixture-private-key"

    def __init__(self, responder):
        self.chat = type("Chat", (), {})()
        self.chat.completions = Completions(responder)


def completion(value=False, *, raw=None):
    return {
        "id": "online-causal-fixture",
        "object": "chat.completion",
        "created": 0,
        "model": causal_v2_audit.MODEL,
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": raw
                    or json.dumps(
                        {
                            "would_call_anyway": value,
                            "confidence": 0.75,
                            "reasoning": "Authored online auditor prediction.",
                        }
                    ),
                },
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


def proposal_event(call_ref="call-1"):
    return {
        "event_type": "TOOL_CALL_PROPOSED",
        "event_id": "sink-event",
        "event_sequence": 15,
        "monotonic_ns": time.monotonic_ns(),
        "run_id": "run-a",
        "task_id": "task-a",
        "episode_id": "episode-a",
        "model_request_id": "request-a",
        "call_ref": call_ref,
    }


def runtime_event(call_ref="call-1"):
    return {
        "event_type": "TOOL_RUNTIME_STARTED",
        "event_id": "runtime-event",
        "event_sequence": 16,
        "monotonic_ns": time.monotonic_ns(),
        "run_id": "run-a",
        "task_id": "task-a",
        "episode_id": "episode-a",
        "model_request_id": "request-a",
        "call_ref": call_ref,
    }


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_bound_predictions_flush_before_runtime_and_add_typed_edges(tmp_path):
    call, graph = fixture(second=True, repeat=True)
    original = copy.deepcopy((call, graph))
    client = Client(lambda ordinal, body: completion(False))
    path = tmp_path / "causal-online.jsonl"
    auditor = OnlineCausalAuditor(path, client=client)

    receipt = auditor.audit_proposal(proposal_event(), call, graph)
    assert receipt["status"] == "predicted_control_positive"
    assert receipt["planned_probe_count"] == receipt["valid_judgment_count"] == 3
    assert receipt["request_attempt_count"] == 3
    assert (call, graph) == original
    for body in client.chat.completions.calls:
        assert not {"tools", "tool_choice", "functions", "function_call"}.intersection(body)
        assert body["timeout"] == 60.0
        assert body["model"] == causal_v2_audit.MODEL
        assert body["messages"][0]["role"] == "system"

    timing = auditor.runtime(runtime_event())
    assert timing["correlation"] == "matched_proposal"
    assert timing["analysis_before_runtime"] is timing["receipt_before_runtime"] is True
    status = auditor.close(graph)
    assert status["complete"] is True and status["graph_saved"] is True
    assert status["before_runtime_verified_count"] == 1
    assert (
        status["graph_sha256"]
        == hashlib.sha256((tmp_path / "causal-online-graph.json").read_bytes()).hexdigest()
    )

    recorded = rows(path)
    assert [row["record_type"] for row in recorded] == [
        "causal_analysis",
        "causal_flush",
        "causal_runtime_timing",
        "causal_close_summary",
    ]
    analysis, flush = recorded[:2]
    assert all(
        hashlib.sha256(_canonical(result["response"])).hexdigest() == result["response_sha256"]
        for result in analysis["results"]
    )
    first_line = path.read_bytes().splitlines(keepends=True)[0]
    assert flush["analysis_record_sequence"] == analysis["record_sequence"] == 1
    assert flush["analysis_line_sha256"] == hashlib.sha256(first_line).hexdigest()
    assert flush["analysis_flushed_monotonic_ns"] <= timing["runtime_event_monotonic_ns"]
    assert "Condition alpha is active" not in path.read_text()

    derived = json.loads((tmp_path / "causal-online-graph.json").read_text())
    assert derived["original_graph"] == graph
    assert {edge["relation"] for edge in derived["added_edges"]} == {
        "source_set_membership",
        "predicted_control",
    }
    assert all(node["kind"] == "intervened_source_set" for node in derived["added_nodes"])
    assert (call, graph) == original


def test_global_request_budget_leaves_every_unattempted_slot_explicit_unknown(tmp_path):
    call, graph = fixture(second=True)
    client = Client(lambda ordinal, body: completion(True))
    path = tmp_path / "causal-online.jsonl"
    auditor = OnlineCausalAuditor(path, client=client, max_requests=1)
    receipt = auditor.audit_proposal(proposal_event(), call, graph)
    assert receipt["planned_probe_count"] == 3
    assert receipt["request_attempt_count"] == receipt["valid_judgment_count"] == 1
    assert receipt["unknown_judgment_count"] == 2
    analysis = rows(path)[0]
    assert [row["reason"] for row in analysis["results"]] == [
        None,
        "request_budget_exhausted",
        "request_budget_exhausted",
    ]
    assert len(client.chat.completions.calls) == auditor.status()["request_count"] == 1
    auditor.close(graph)


def test_missing_client_and_non_sink_never_invoke_a_judge(tmp_path):
    call, graph = fixture()
    call["policy"]["sink"]["selected"] = False
    call["fields"][0]["cascade_scope"]["sink"]["selected"] = False
    client = Client(lambda ordinal, body: pytest.fail("A non-sink cannot invoke the judge"))
    auditor = OnlineCausalAuditor(tmp_path / "causal-online.jsonl", client=client)
    receipt = auditor.audit_proposal(proposal_event(), call, graph)
    assert receipt["status"] == "not_selected"
    assert receipt["planned_probe_count"] == receipt["request_attempt_count"] == 0
    assert client.chat.completions.calls == []
    auditor.close(graph)

    call, graph = fixture()
    plan_only = OnlineCausalAuditor(tmp_path / "plan-only.jsonl")
    receipt = plan_only.audit_proposal(proposal_event("call-2"), call, graph)
    assert receipt["request_attempt_count"] == 0
    assert rows(tmp_path / "plan-only.jsonl")[0]["results"][0]["reason"] == ("auditor_client_not_configured")
    plan_only.close(graph)


def test_explicit_positive_uses_bound_path_without_a_judge_request(tmp_path):
    call, graph = fixture()
    pair = call["fields"][0]["nt_style_cascade"][0]
    pair.update(matched=True, first_matched_tier="tier2")
    label_id = graph["registry"][0]["label_id"]
    graph["edges"].append(
        {
            "edge_id": "explicit-edge",
            "from_node": "origin-node",
            "to_node": "sink-node",
            "relation": "candidate_content",
            "label_ids": [label_id],
            "tier": "tier2",
            "evidence_score": 0.5,
        }
    )
    call["lineage"]["paths"] = [{"label_id": label_id, "edge_ids": ["explicit-edge"]}]
    client = Client(lambda ordinal, body: pytest.fail("Explicit evidence cannot invoke the judge"))
    auditor = OnlineCausalAuditor(tmp_path / "causal-online.jsonl", client=client)
    receipt = auditor.audit_proposal(proposal_event(), call, graph)
    assert receipt["status"] == "explicit_positive" and receipt["detector_positive"] is True
    assert receipt["planned_probe_count"] == receipt["request_attempt_count"] == 0
    assert client.chat.completions.calls == []
    auditor.close(graph)


@pytest.mark.parametrize("failure", ["error", "invalid", "non_english"])
def test_judge_failure_is_unknown_no_throw_and_secret_never_reaches_jsonl(tmp_path, failure):
    def respond(ordinal, body):
        if failure == "error":
            raise RuntimeError("fixture-private-key must not be serialized")
        if failure == "non_english":
            return completion(
                raw=json.dumps(
                    {
                        "would_call_anyway": False,
                        "confidence": 0.8,
                        "reasoning": "Chinese: \u4e2d\u6587 fixture-private-key",
                    }
                )
            )
        return completion(raw='{"would_call_anyway":"false","confidence":0.8,"reasoning":"Bad."}')

    call, graph = fixture()
    path = tmp_path / "causal-online.jsonl"
    auditor = OnlineCausalAuditor(path, client=Client(respond), max_requests=1)
    receipt = auditor.audit_proposal(proposal_event(), call, graph)
    assert receipt["status"] == "unknown" and receipt["unknown_judgment_count"] == 1
    result = rows(path)[0]["results"][0]
    assert result["status"] in {"error", "invalid"}
    assert "fixture-private-key" not in path.read_text()
    assert "\u4e2d\u6587" not in path.read_text()
    if failure == "error":
        assert result["error_type"] == "RuntimeError"
        assert set(result).isdisjoint({"error", "error_message"})
    elif failure == "non_english":
        quarantined = tmp_path / result["response_file"]
        assert quarantined.is_file()
        assert hashlib.sha256(quarantined.read_bytes()).hexdigest() == result["response_sha256"]
        assert "fixture-private-key" not in quarantined.read_text()
        envelope = json.loads(quarantined.read_text())
        content = json.loads(envelope["choices"][0]["message"]["content"])
        assert "\u4e2d\u6587" in content["reasoning"]
    else:
        assert result["response"]["choices"][0]["finish_reason"] == "stop"
    auditor.runtime(runtime_event())
    assert auditor.close(graph)["closed"] is True


def test_malformed_graph_and_timing_event_fail_open_without_input_mutation(tmp_path):
    call, graph = fixture()
    original_call = copy.deepcopy(call)
    auditor = OnlineCausalAuditor(tmp_path / "causal-online.jsonl", client=Client(lambda *_: completion()))
    receipt = auditor.audit_proposal(proposal_event(), call, {})
    assert receipt["status"] == "unknown" and receipt["composition_status"] == "failed"
    assert call == original_call
    bad_timing = runtime_event()
    bad_timing["monotonic_ns"] = "invalid"
    assert auditor.runtime(bad_timing)["error_type"] == "ValueError"
    assert auditor.close()["closed"] is True


def test_past_runtime_timestamp_cannot_claim_pre_runtime_availability(tmp_path):
    call, graph = fixture()
    auditor = OnlineCausalAuditor(tmp_path / "causal-online.jsonl")
    auditor.audit_proposal(proposal_event(), call, graph)
    event = runtime_event()
    event["monotonic_ns"] = 0
    timing = auditor.runtime(event)
    assert timing["analysis_before_runtime"] is timing["receipt_before_runtime"] is False
    assert auditor.status()["runtime_timing_failure_count"] == 1
    auditor.close(graph)


@pytest.mark.parametrize("budget", [-1, 33, True])
def test_static_request_budget_is_strictly_bounded(tmp_path, budget):
    with pytest.raises(ValueError, match="request budget"):
        OnlineCausalAuditor(tmp_path / "causal-online.jsonl", max_requests=budget)


def test_default_judgment_format_accepts_english_typography(tmp_path):
    call, graph = fixture()
    raw = json.dumps(
        {
            "would_call_anyway": False,
            "confidence": 0.8,
            "reasoning": "The source’s removal changes the call—according to this judge.",
        },
        ensure_ascii=False,
    )
    auditor = OnlineCausalAuditor(
        tmp_path / "causal-online.jsonl",
        client=Client(lambda ordinal, body: completion(raw=raw)),
        max_requests=1,
    )
    receipt = auditor.audit_proposal(proposal_event(), call, graph)
    assert receipt["valid_judgment_count"] == 1
    assert auditor.status()["judgment_format"] == judgment_formats.ENGLISH_PUNCTUATION_FORMAT
    auditor.close(graph)

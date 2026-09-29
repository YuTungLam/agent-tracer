"""Mock transport checks; native prefix binding is exercised without real APIs."""

import copy
import json
import socket

import httpx
import openai
import pytest
from test_causal_v2 import fixture, native_recorded_run

from agentdojo_lab import causal_v2
from agentdojo_lab import causal_v2_audit as audit


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n")


@pytest.fixture
def exported(tmp_path, monkeypatch):
    """A declared synthetic provenance fixture for isolated transport cases."""
    call, graph = fixture(second=True, repeat=True)
    source = tmp_path / "source"
    source.mkdir()
    write(source / "manifest.json", {"input_condition": "passive", "config": {"canary_enabled": False}})
    write(source / "declared-synthetic-prefix.json", {"call": call, "graph": graph})
    hashes = audit._snapshot(source)
    plans = tmp_path / "plans"
    plans.mkdir()
    plan = causal_v2.plan_joint_probes(call, graph)
    assert plan["status"] == "eligible"
    (plans / "plans.jsonl").write_text(json.dumps(plan) + "\n")
    write(
        plans / "summary.json",
        {
            "protocol": causal_v2.PROTOCOL,
            "plan_count": 1,
            "probe_count": 3,
            "source_run": str(source),
            "source_hashes_before": hashes,
            "source_hashes_after": hashes,
            "source_files_unchanged": True,
            "canary_enabled": False,
        },
    )
    monkeypatch.setattr(audit, "_verified_inputs", lambda path: ([copy.deepcopy(call)], copy.deepcopy(graph)))
    return plans, source, tmp_path / "audit"


def completion(value=True, *, finish="stop", raw=None, model=None):
    return {
        "id": "mock-judge",
        "object": "chat.completion",
        "created": 0,
        "model": audit.MODEL if model is None else model,
        "choices": [
            {
                "index": 0,
                "finish_reason": finish,
                "message": {
                    "role": "assistant",
                    "content": raw
                    or json.dumps(
                        {
                            "would_call_anyway": value,
                            "confidence": 0.2,
                            "reasoning": "Authored mock judgment, not a causal reference.",
                        }
                    ),
                },
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


def client_with(responder):
    return openai.OpenAI(
        api_key="fixture-private-key",
        base_url="https://mock-audit.invalid/v1",
        max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(responder)),
    )


def read_results(output):
    return [json.loads(line) for line in (output / "judgments.jsonl").read_text().splitlines()]


def test_multi_source_prompt_and_exact_joint_context_are_sent_without_tools(exported):
    plans, source, output = exported
    before = audit._snapshot(source)
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(200, json=completion(value=len(requests) < 3))

    with client_with(respond) as client:
        summary = audit.run_audit(plans, output, client=client)
    assert summary["mode"] == "injected_client"
    assert summary["planned_slots"] == summary["request_count"] == summary["valid_judgments"] == 3
    bodies = [json.loads(request.content) for request in requests]
    for request, body in zip(requests, bodies, strict=True):
        assert not {"tools", "tool_choice", "functions", "function_call"}.intersection(body)
        assert body["model"] == "openai/gpt-oss-120b"
        assert body["response_format"] == {"type": "json_object"}
        assert request.extensions["timeout"]["read"] == 60.0
    pair = json.loads(bodies[2]["messages"][1]["content"])
    assert pair["intervention_kind"] == "source_pair"
    assert pair["source_ids"] == ["source-a", "source-b"]
    assert all(
        message["content"] == "Neutral reference information."
        for message in pair["context_b"]
        if message["role"] == "tool"
    )
    assert "joint removal" in bodies[2]["messages"][0]["content"]
    assert (
        summary["proposal_summaries"][0]["prediction_summary"]["pairs"][0]["pattern"]
        == "predicted_redundant_OR_like"
    )
    assert summary["independent_causal_accuracy"] is None
    assert summary["primary_agent_model_calls"] == summary["native_tool_calls"] == 0
    assert summary["source_files_unchanged"] and audit._snapshot(source) == before
    assert summary["reported_usage"]["total_tokens"]["known_sum"] == 45
    assert len(read_results(output)) == 3
    assert "<script" not in (output / "index.html").read_text()


def test_configured_endpoint_uses_endpoint_model_without_judge_tools_or_reasoning(exported, monkeypatch):
    plans, _, output = exported
    monkeypatch.setenv("SCOUT_JUDGE_KEY", "fixture-private-key")
    endpoint = {
        "provider": "openai_compatible",
        "model": "llama-4-scout-fixture",
        "base_url": "http://127.0.0.1:8123/v1",
        "api_key_env": "SCOUT_JUDGE_KEY",
    }
    bodies = []

    def respond(request):
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json=completion(model=endpoint["model"]))

    client = client_with(respond)

    def configured_client(self, *, key, timeout):
        assert self.model == endpoint["model"] and self.url == endpoint["base_url"]
        assert key == "fixture-private-key" and timeout == 60.0
        return client

    monkeypatch.setattr(audit.EndpointSettings, "client", configured_client)
    result = audit.run_audit(plans, output, live=True, endpoint=endpoint, max_requests=1)
    assert client.is_closed
    manifest = json.loads((output / "manifest.json").read_text())
    assert result["protocol"] == manifest["protocol"] == audit.OPENAI_COMPATIBLE_PROTOCOL
    assert result["mode"] == "live_openai_compatible"
    assert result["provider"] == manifest["provider"] == "openai_compatible"
    assert manifest["endpoint"] == result["endpoint"] == endpoint
    assert "providers.py" in manifest["implementation_hashes"]
    assert "fixture-private-key" not in (output / "manifest.json").read_text()
    assert bodies[0]["model"] == endpoint["model"]
    assert not {"tools", "tool_choice", "functions", "reasoning_effort"}.intersection(bodies[0])


def test_configured_endpoint_forbids_injected_client(exported, monkeypatch):
    plans, _, output = exported
    monkeypatch.setenv("SCOUT_JUDGE_KEY", "present")
    endpoint = {
        "provider": "openai_compatible", "model": "judge",
        "base_url": "http://127.0.0.1:8123/v1", "api_key_env": "SCOUT_JUDGE_KEY",
    }
    with client_with(lambda request: pytest.fail("Client must be rejected")) as client:
        with pytest.raises(ValueError, match="cannot be combined"):
            audit.run_audit(plans, output, client=client, live=True, endpoint=endpoint)
    assert not output.exists()


@pytest.mark.parametrize(
    "response_model,reason",
    [("other-model", "response_model_mismatch"), ("", "missing_or_invalid_response_model")],
)
def test_configured_endpoint_rejects_unbound_response_model(
    exported, monkeypatch, response_model, reason
):
    plans, _, output = exported
    monkeypatch.setenv("SCOUT_JUDGE_KEY", "present")
    endpoint = {
        "provider": "openai_compatible", "model": "judge-model",
        "base_url": "http://127.0.0.1:8123/v1", "api_key_env": "SCOUT_JUDGE_KEY",
    }
    client = client_with(
        lambda request: httpx.Response(200, json=completion(model=response_model))
    )
    monkeypatch.setattr(audit.EndpointSettings, "client", lambda *a, **k: client)
    result = audit.run_audit(plans, output, live=True, endpoint=endpoint, max_requests=1)
    first = read_results(output)[0]
    assert result["valid_judgments"] == 0
    assert first["status"] == "invalid" and first["reason"] == reason


def test_configured_punctuation_has_distinct_schema_protocol_and_report_title(exported, monkeypatch):
    plans, _, output = exported
    monkeypatch.setenv("SCOUT_JUDGE_KEY", "present")
    endpoint = {
        "provider": "openai_compatible", "model": "judge-model",
        "base_url": "http://127.0.0.1:8123/v1", "api_key_env": "SCOUT_JUDGE_KEY",
    }
    client = client_with(
        lambda request: httpx.Response(200, json=completion(model="judge-model"))
    )
    monkeypatch.setattr(audit.EndpointSettings, "client", lambda *a, **k: client)
    result = audit.run_audit(
        plans, output, live=True, endpoint=endpoint, max_requests=1,
        judgment_format=audit.judgment_formats.ENGLISH_PUNCTUATION_FORMAT,
    )
    manifest = json.loads((output / "manifest.json").read_text())
    assert result["schema_version"] == manifest["schema_version"] == 3
    assert result["protocol"] == audit.OPENAI_COMPATIBLE_PUNCTUATION_PROTOCOL
    title = "Configured OpenAI-compatible joint counterfactual auditor with punctuation"
    assert f"<title>{title}</title>" in (output / "index.html").read_text()


def test_configured_endpoint_requires_live_and_key_before_output(exported, monkeypatch):
    plans, _, output = exported
    endpoint = {
        "provider": "openai_compatible",
        "model": "llama-4-scout-fixture",
        "base_url": "http://127.0.0.1:8123/v1",
        "api_key_env": "SCOUT_JUDGE_KEY",
    }
    monkeypatch.setenv("SCOUT_JUDGE_KEY", "present")
    with pytest.raises(ValueError, match="requires --live"):
        audit.run_audit(plans, output, endpoint=endpoint)
    monkeypatch.delenv("SCOUT_JUDGE_KEY")
    with pytest.raises(ValueError, match="SCOUT_JUDGE_KEY"):
        audit.run_audit(plans, output, endpoint=endpoint, live=True)
    assert not output.exists()


def test_plan_only_never_constructs_a_client_and_retains_all_slots(exported, monkeypatch):
    plans, _, output = exported
    monkeypatch.setattr(audit, "_new_client", lambda: pytest.fail("Plan-only must not construct a client"))
    result = audit.run_audit(plans, output)
    assert result["request_count"] == 0 and result["unknown_judgments"] == 3
    assert all(row["reason"] == "live_not_enabled" for row in read_results(output))


def test_budget_exhaustion_keeps_unrequested_slots_unknown(exported):
    plans, _, output = exported
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(200, json=completion(False))

    with client_with(respond) as client:
        result = audit.run_audit(plans, output, client=client, max_requests=1)
    assert len(calls) == result["request_count"] == 1
    assert result["planned_slots"] == result["result_slots"] == 3
    assert [row["reason"] for row in read_results(output)][1:] == ["request_budget_exhausted"] * 2
    assert not result["proposal_summaries"][0]["prediction_summary"]["complete"]


@pytest.mark.parametrize("finish", ["length", "content_filter", "tool_calls"])
def test_truncated_and_non_final_judgments_remain_unknown(exported, finish):
    plans, _, output = exported
    with client_with(lambda request: httpx.Response(200, json=completion(finish=finish))) as client:
        result = audit.run_audit(plans, output, client=client, max_requests=1)
    assert result["valid_judgments"] == 0 and result["unknown_judgments"] == 3
    assert read_results(output)[0]["status"] == "invalid"
    if finish == "length":
        assert read_results(output)[0]["reason"] == "truncated_response"


@pytest.mark.parametrize(
    "raw",
    [
        '{"would_call_anyway":true,"would_call_anyway":false,"confidence":0.9,"reasoning":"Duplicate key."}',
        '{"would_call_anyway":true,"confidence":0.9,"reasoning":"Foreign binding.","probe_id":"foreign"}',
        '{"would_call_anyway":"true","confidence":0.9,"reasoning":"Invalid type."}',
        '{"would_call_anyway":true,"confidence":NaN,"reasoning":"Invalid confidence."}',
    ],
)
def test_duplicate_keys_foreign_fields_and_invalid_schema_are_not_valid_predictions(exported, raw):
    plans, _, output = exported
    with client_with(lambda request: httpx.Response(200, json=completion(raw=raw))) as client:
        result = audit.run_audit(plans, output, client=client, max_requests=1)
    assert result["valid_judgments"] == 0
    assert read_results(output)[0]["status"] == "invalid"


@pytest.mark.parametrize("kind", ["server_error", "timeout"])
def test_failed_requests_are_not_retried_or_replaced(exported, kind):
    plans, _, output = exported
    attempts = []

    def respond(request):
        attempts.append(request)
        if kind == "timeout":
            raise httpx.ReadTimeout("fixture-private-key", request=request)
        return httpx.Response(500, json={"error": {"message": "fixture-private-key", "type": "server_error"}})

    with client_with(respond) as client:
        result = audit.run_audit(plans, output, client=client, max_requests=1)
    assert len(attempts) == result["request_count"] == 1
    assert read_results(output)[0]["status"] == "error"
    assert result["reported_usage"]["total_tokens"]["unknown_count"] == 1
    assert all("fixture-private-key" not in path.read_text() for path in output.glob("*.json*"))


def test_response_secrets_are_redacted_before_artifact_serialization(exported):
    plans, _, output = exported
    raw = json.dumps(
        {"would_call_anyway": True, "confidence": 0.1, "reasoning": "Echo fixture-private-key from fixture."}
    )
    with client_with(lambda request: httpx.Response(200, json=completion(raw=raw))) as client:
        audit.run_audit(plans, output, client=client, max_requests=1)
    assert all("fixture-private-key" not in path.read_text() for path in output.glob("*.json*"))
    assert "[REDACTED]" in (output / "judgments.jsonl").read_text()


def test_non_english_response_is_preserved_outside_english_jsonl(exported):
    plans, _, output = exported
    raw = json.dumps({"would_call_anyway": True, "confidence": 0.1, "reasoning": "\u4e2d\u6587"})
    with client_with(lambda request: httpx.Response(200, json=completion(raw=raw))) as client:
        result = audit.run_audit(plans, output, client=client, max_requests=1)
    row = read_results(output)[0]
    assert row["reason"] == "non_english_response" and (output / row["response_file"]).is_file()
    assert result["valid_judgments"] == 0
    assert not audit._contains_cjk((output / "judgments.jsonl").read_text())


@pytest.mark.parametrize("mutation", ["duplicate_plan", "foreign_probe", "changed_context"])
def test_modified_or_foreign_intervention_plans_fail_before_client_use(exported, mutation):
    plans, _, output = exported
    path = plans / "plans.jsonl"
    data = json.loads(path.read_text())
    if mutation == "duplicate_plan":
        path.write_text(json.dumps(data) + "\n" + json.dumps(data) + "\n")
        summary = json.loads((plans / "summary.json").read_text())
        summary["plan_count"] = 2
        write(plans / "summary.json", summary)
    else:
        if mutation == "foreign_probe":
            data["probes"][0]["probe_id"] = "foreign"
        else:
            data["probes"][0]["context_b"][0]["content"] = "Tampered history"
        path.write_text(json.dumps(data) + "\n")
    with client_with(lambda request: pytest.fail("Invalid bindings must not call a client")) as client:
        with pytest.raises(ValueError, match="Duplicate|differs"):
            audit.run_audit(plans, output, client=client)
    assert not output.exists()


def test_source_snapshot_change_fails_preflight(exported):
    plans, source, output = exported
    (source / "added-after-export.json").write_text("{}")
    with pytest.raises(ValueError, match="source snapshot"):
        audit.run_audit(plans, output)


def test_mid_audit_mutation_stops_remaining_requests_without_dropping_slots(exported):
    plans, source, output = exported
    calls = []

    def respond(request):
        calls.append(request)
        (source / "mutated.json").write_text("{}")
        return httpx.Response(200, json=completion())

    with client_with(respond) as client:
        result = audit.run_audit(plans, output, client=client)
    assert len(calls) == 1 and result["source_files_unchanged"] is False
    assert len(read_results(output)) == 3
    assert all(row["reason"] == "source_or_plan_export_changed" for row in read_results(output)[1:])


def test_oversized_requests_remain_unknown_without_client_call(exported, monkeypatch):
    plans, _, output = exported
    monkeypatch.setattr(audit, "MAX_REQUEST_BYTES", 1)
    with client_with(lambda request: pytest.fail("Oversized request sent")) as client:
        result = audit.run_audit(plans, output, client=client)
    assert result["request_count"] == 0
    assert all(row["reason"] == "request_size_budget_exceeded" for row in read_results(output))


@pytest.mark.parametrize("budget", [-1, 33, True, 1.0])
def test_invalid_request_budgets_rejected(exported, budget):
    plans, _, output = exported
    with pytest.raises(ValueError, match="budget"):
        audit.run_audit(plans, output, max_requests=budget)


def test_client_retries_must_be_disabled(exported):
    plans, _, output = exported
    with client_with(lambda request: pytest.fail("Retries client cannot be used")) as client:
        client.max_retries = 2
        with pytest.raises(ValueError, match="disable SDK retries"):
            audit.run_audit(plans, output, client=client)


def test_fresh_output_and_both_input_trees_are_protected(exported):
    plans, source, output = exported
    for destination in [plans, plans / "inside", source / "inside"]:
        with pytest.raises(ValueError, match="separate|fresh"):
            audit.run_audit(plans, destination)
    audit.run_audit(plans, output)
    with pytest.raises(ValueError, match="fresh"):
        audit.run_audit(plans, output)


def test_native_recorded_prefix_runs_through_new_transport_without_network(tmp_path, monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: pytest.fail("Real network forbidden"))
    source = tmp_path / "native"
    before = native_recorded_run(source, no_arguments=True)
    plans = tmp_path / "plans"
    causal_v2.export_run(source, plans)
    output = tmp_path / "auditor"
    with client_with(lambda request: httpx.Response(200, json=completion(False))) as client:
        result = audit.run_audit(plans, output, client=client)
    assert result["planned_slots"] == result["request_count"] == 1
    assert result["source_hashes_before"] == result["source_hashes_after"] == before
    assert result["valid_judgments"] == 1
    request = json.loads((output / "requests.jsonl").read_text())
    body = json.loads(request["body"]["messages"][1]["content"])
    assert body["sink"]["arguments"] == {}
    assert body["sink"]["function"] == "get_unread_emails"


def test_report_generation_cannot_hide_a_late_source_mutation(exported, monkeypatch):
    plans, source, output = exported
    original = audit._report

    def mutate(*args):
        (source / "late-file.json").write_text("{}")
        original(*args)

    monkeypatch.setattr(audit, "_report", mutate)
    result = audit.run_audit(plans, output)
    assert result["source_files_unchanged"] is False
    assert json.loads((output / "summary.json").read_text())["source_files_unchanged"] is False

"""Bounded replay transport tests, with no live endpoints or executed replay tools."""

import copy
import hashlib
import json
import socket

import httpx
import openai
import pytest
from test_causal_v2 import fixture, native_recorded_run

from agentdojo_lab import causal_replay as replay
from agentdojo_lab import causal_v2, causal_v2_audit


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n")


@pytest.fixture
def exported(tmp_path, monkeypatch):
    """Declared synthetic pair for transport tests; native binding is checked separately."""
    call, graph = fixture(second=True, repeat=True, no_arguments=True)
    call.update(request_event_id="request-event", model_request_id="model-request")
    body = {
        "model": "openai/gpt-oss-120b",
        "temperature": 0.0,
        "max_completion_tokens": 512,
        "reasoning_effort": "low",
        "messages": call["request_messages"],
        "tools": [
            {
                "type": "function",
                "function": {"name": "write", "parameters": {"type": "object", "properties": {}}},
            }
        ],
        "tool_choice": "auto",
        "parallel_tool_calls": False,
        "seed": 42,
    }
    source = tmp_path / "source"
    write(source / "manifest.json", {"config": {"canary_enabled": False}, "input_condition": "passive"})
    write(
        source / "events.jsonl",
        {"event_id": "request-event", "event_type": "MODEL_REQUEST", "data": {"body": body}},
    )
    analysis = {
        "record_type": "call_analysis",
        "record_sequence": 1,
        "proposal_event_id": call["proposal_event_id"],
        "call": call,
    }
    raw = json.dumps(analysis).encode() + b"\n"
    flush = {
        "record_type": "analysis_flush",
        "record_sequence": 2,
        "analysis_record_sequence": 1,
        "analysis_line_sha256": hashlib.sha256(raw).hexdigest(),
    }
    (source / "provenance.jsonl").write_bytes(raw + json.dumps(flush).encode() + b"\n")
    write(source / "declared-synthetic-prefix.json", {"call": call, "graph": graph})

    def verify(root):
        return [copy.deepcopy(call)], copy.deepcopy(graph)

    monkeypatch.setattr(causal_v2_audit, "_verified_inputs", verify)
    monkeypatch.setattr(replay, "_verified_inputs", verify)
    plans = tmp_path / "plans"
    plans.mkdir()
    plan = causal_v2.plan_joint_probes(call, graph, max_sources=2, max_pairs=1)
    assert plan["status"] == "eligible" and len(plan["probes"]) == 3
    write(plans / "plans.jsonl", plan)
    snapshot = replay._snapshot(source)
    write(
        plans / "summary.json",
        {
            "protocol": causal_v2.PROTOCOL,
            "plan_count": 1,
            "probe_count": 3,
            "source_run": str(source),
            "source_hashes_before": snapshot,
            "source_hashes_after": snapshot,
            "source_files_unchanged": True,
            "canary_enabled": False,
        },
    )
    return plans, source, tmp_path / "replay"


def completion(*, function="write", args="{}", text=None, finish=None, calls=None, model=None):
    if text is not None:
        message = {"role": "assistant", "content": text}
    else:
        message = {
            "role": "assistant",
            "content": None,
            "tool_calls": calls
            if calls is not None
            else [{"id": "proposal", "type": "function", "function": {"name": function, "arguments": args}}],
        }
    return {
        "id": "mock-replay",
        "object": "chat.completion",
        "created": 0,
        "model": "recorded-model" if model is None else model,
        "choices": [
            {
                "index": 0,
                "finish_reason": finish or ("stop" if text is not None else "tool_calls"),
                "message": message,
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 3, "total_tokens": 13},
    }


def client_with(handler):
    return openai.OpenAI(
        api_key="fixture-private-key",
        base_url="https://replay.invalid/v1",
        max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_pair_replay_preserves_original_settings_tools_and_exact_contexts(exported):
    plans, source, output = exported
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(
            200, json=completion() if len(requests) == 1 else completion(text="The sum is five.")
        )

    with client_with(respond) as client:
        summary = replay.run_replay(plans, output, client=client)
    original = rows(source / "events.jsonl")[0]["data"]["body"]
    probes = rows(plans / "plans.jsonl")[0]["probes"]
    bodies = [json.loads(request.content) for request in requests]
    assert bodies[0] == original
    for body, probe in zip(bodies[1:], probes, strict=True):
        assert body["messages"] == probe["context_b"]
        assert {k: v for k, v in body.items() if k != "messages"} == {
            k: v for k, v in original.items() if k != "messages"
        }
    assert all(request.extensions["timeout"]["read"] == 60.0 for request in requests)
    assert summary["planned_slots"] == summary["result_slots"] == summary["request_count"] == 4
    assert summary["observed_slots"] == 4 and summary["unknown_slots"] == 0
    assert summary["native_tool_calls"] == 0 and summary["independent_causal_accuracy"] is None
    assert all(row["observed_sink_proposal_changed"] is True for row in summary["comparisons"])
    assert summary["reported_usage"]["total_tokens"]["known_sum"] == 52
    assert summary["input_integrity_verified"] and summary["source_files_unchanged"]
    slots = rows(output / "replay-plan.jsonl")
    assert len({slot["slot_id"] for slot in slots}) == 4
    assert slots[0]["analysis_line_sha256"] == rows(source / "provenance.jsonl")[1]["analysis_line_sha256"]
    assert all(slot["analysis_flush_sha256"] and slot["original_request_event_sha256"] for slot in slots)


def test_configured_endpoint_preserves_recorded_primary_request_and_has_new_identity(exported, monkeypatch):
    plans, source, output = exported
    monkeypatch.setenv("SCOUT_PRIMARY_KEY", "fixture-private-key")
    endpoint = {
        "provider": "openai_compatible",
        "model": "openai/gpt-oss-120b",
        "base_url": "http://127.0.0.1:8123/v1",
        "api_key_env": "SCOUT_PRIMARY_KEY",
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

    monkeypatch.setattr(replay.EndpointSettings, "client", configured_client)
    result = replay.run_replay(plans, output, live=True, endpoint=endpoint, max_requests=1)
    assert client.is_closed
    original = rows(source / "events.jsonl")[0]["data"]["body"]
    manifest = json.loads((output / "manifest.json").read_text())
    assert bodies == [original]
    assert result["protocol"] == manifest["protocol"] == replay.OPENAI_COMPATIBLE_PROTOCOL
    assert result["provider"] == manifest["provider"] == "openai_compatible"
    assert result["endpoint"] == manifest["endpoint"] == endpoint
    assert "providers.py" in manifest["implementation_hashes"]
    assert "providers.py" in result["implementation_hashes_before"]
    assert rows(output / "replay-plan.jsonl")[0]["protocol"] == replay.OPENAI_COMPATIBLE_PROTOCOL
    assert "fixture-private-key" not in (output / "manifest.json").read_text()


def test_configured_replay_forbids_injected_client(exported, monkeypatch):
    plans, _, output = exported
    monkeypatch.setenv("SCOUT_PRIMARY_KEY", "present")
    endpoint = {
        "provider": "openai_compatible", "model": "openai/gpt-oss-120b",
        "base_url": "http://127.0.0.1:8123/v1", "api_key_env": "SCOUT_PRIMARY_KEY",
    }
    with client_with(lambda request: pytest.fail("Client must be rejected")) as client:
        with pytest.raises(ValueError, match="cannot be combined"):
            replay.run_replay(plans, output, client=client, live=True, endpoint=endpoint)
    assert not output.exists()


@pytest.mark.parametrize(
    "response_model,reason",
    [("other-model", "response_model_mismatch"), ("", "missing_or_invalid_response_model")],
)
def test_configured_replay_rejects_unbound_response_model(
    exported, monkeypatch, response_model, reason
):
    plans, _, output = exported
    monkeypatch.setenv("SCOUT_PRIMARY_KEY", "present")
    endpoint = {
        "provider": "openai_compatible", "model": "openai/gpt-oss-120b",
        "base_url": "http://127.0.0.1:8123/v1", "api_key_env": "SCOUT_PRIMARY_KEY",
    }
    client = client_with(
        lambda request: httpx.Response(200, json=completion(model=response_model))
    )
    monkeypatch.setattr(replay.EndpointSettings, "client", lambda *a, **k: client)
    result = replay.run_replay(plans, output, live=True, endpoint=endpoint, max_requests=1)
    first = rows(output / "results.jsonl")[0]
    assert result["observed_slots"] == 0
    assert first["status"] == "invalid" and first["reason"] == reason


def test_configured_replay_requires_live_key_and_matching_recorded_model_before_output(exported, monkeypatch):
    plans, _, output = exported
    endpoint = {
        "provider": "openai_compatible",
        "model": "different-served-model",
        "base_url": "http://127.0.0.1:8123/v1",
        "api_key_env": "SCOUT_PRIMARY_KEY",
    }
    monkeypatch.setenv("SCOUT_PRIMARY_KEY", "present")
    with pytest.raises(ValueError, match="requires --live"):
        replay.run_replay(plans, output, endpoint=endpoint)
    with pytest.raises(ValueError, match="does not match"):
        replay.run_replay(plans, output, endpoint=endpoint, live=True)
    monkeypatch.delenv("SCOUT_PRIMARY_KEY")
    with pytest.raises(ValueError, match="SCOUT_PRIMARY_KEY"):
        replay.run_replay(plans, output, endpoint=endpoint, live=True)
    assert not output.exists()


def test_plan_only_never_constructs_transport(exported, monkeypatch):
    plans, _, output = exported
    monkeypatch.setattr(replay, "_new_client", lambda: pytest.fail("No client in plan-only mode"))
    result = replay.run_replay(plans, output)
    assert result["request_count"] == 0 and result["unknown_slots"] == 4
    assert all(row["reason"] == "live_not_enabled" for row in rows(output / "results.jsonl"))


def test_request_cap_retains_all_excess_slots(exported):
    plans, _, output = exported
    with client_with(lambda request: httpx.Response(200, json=completion())) as client:
        result = replay.run_replay(plans, output, client=client, max_requests=1)
    assert result["request_count"] == 1 and result["result_slots"] == 4
    assert [row["reason"] for row in rows(output / "results.jsonl")][1:] == ["request_budget_exhausted"] * 3
    assert all(row["status"] == "unknown" for row in result["comparisons"])


@pytest.mark.parametrize("limit", [-1, 9, True, 1.0])
def test_invalid_or_above_eight_request_budget_rejected(exported, limit):
    with pytest.raises(ValueError, match="eight SDK"):
        replay.run_replay(exported[0], exported[2], max_requests=limit)


def test_baseline_must_reproduce_before_asserting_change(exported):
    plans, _, output = exported
    with client_with(lambda request: httpx.Response(200, json=completion(text="No mutation."))) as client:
        result = replay.run_replay(plans, output, client=client)
    assert all(
        row["status"] == "baseline_not_reproduced" and row["observed_sink_proposal_changed"] is None
        for row in result["comparisons"]
    )


@pytest.mark.parametrize(
    "response,kind,value",
    [
        (completion(), "tool_proposal", True),
        (completion(function="different"), "tool_proposal", False),
        (completion(args='{"file_id":"13"}'), "tool_proposal", False),
        (completion(text="Done."), "final_response", False),
        (completion(finish="stop"), "tool_proposal", True),
    ],
)
def test_response_classification_is_exact_proposal_not_tool_execution(response, kind, value):
    result = replay.classify_response(response, {"function": "write", "arguments": {}})
    assert result["status"] == "observed" and result["response_kind"] == kind
    assert result["exact_sink_proposed"] is value


@pytest.mark.parametrize(
    "response",
    [
        completion(finish="length"),
        completion(finish="content_filter"),
        completion(args='{"id":1,"id":2}'),
        completion(args='{"id":NaN}'),
        completion(args="[]"),
        completion(args="malformed"),
        completion(text=""),
        completion(calls=[]),
    ],
)
def test_ambiguous_truncated_or_invalid_response_is_unknown(response):
    result = replay.classify_response(response, {"function": "write", "arguments": {}})
    assert result["status"] == "invalid" and result["exact_sink_proposed"] is None


def test_boolean_argument_does_not_equal_integer_and_duplicate_calls_are_invalid():
    result = replay.classify_response(
        completion(args='{"value":true}'), {"function": "write", "arguments": {"value": 1}}
    )
    assert result["exact_sink_proposed"] is False
    call = {"id": "same", "type": "function", "function": {"name": "write", "arguments": "{}"}}
    assert (
        replay.classify_response(completion(calls=[call, call]), {"function": "write", "arguments": {}})[
            "status"
        ]
        == "invalid"
    )


def test_other_parallel_proposal_is_not_hidden():
    calls = [
        {"id": name, "type": "function", "function": {"name": name, "arguments": "{}"}}
        for name in ["write", "other"]
    ]
    result = replay.classify_response(completion(calls=calls), {"function": "write", "arguments": {}})
    assert result["exact_sink_proposed"] is True and result["only_exact_sink_proposed"] is False
    assert result["tool_proposal_count"] == 2


@pytest.mark.parametrize("failure", ["http", "timeout"])
def test_transport_errors_have_no_retries_and_all_slots_survive(exported, failure):
    plans, _, output = exported
    attempts = []

    def respond(request):
        attempts.append(request)
        if failure == "timeout":
            raise httpx.ReadTimeout("fixture-private-key", request=request)
        return httpx.Response(500, json={"error": {"message": "fixture-private-key"}})

    with client_with(respond) as client:
        result = replay.run_replay(plans, output, client=client, max_requests=1)
    assert result["request_count"] == len(attempts) == 1
    result_rows = rows(output / "results.jsonl")
    assert result_rows[0]["status"] == "error" and len(result_rows) == 4
    assert "fixture-private-key" not in (output / "results.jsonl").read_text()
    assert result["reported_usage"]["total_tokens"]["unknown_count"] == 1


@pytest.mark.parametrize("tamper", ["duplicate", "foreign", "context"])
def test_plan_tampering_is_rejected_before_client(exported, tamper):
    plans, _, output = exported
    plan = rows(plans / "plans.jsonl")[0]
    if tamper == "duplicate":
        (plans / "plans.jsonl").write_text((json.dumps(plan) + "\n") * 2)
        summary = json.loads((plans / "summary.json").read_text())
        summary["plan_count"] = 2
        write(plans / "summary.json", summary)
    else:
        if tamper == "foreign":
            plan["probes"][0]["probe_id"] = "foreign"
        else:
            plan["probes"][0]["context_b"][0]["content"] = "Changed"
        write(plans / "plans.jsonl", plan)
    with client_with(lambda request: pytest.fail("Invalid input must not call transport")) as client:
        with pytest.raises(ValueError, match="Duplicate|differs"):
            replay.run_replay(plans, output, client=client)


def test_source_mutation_before_start_is_rejected(exported):
    plans, source, output = exported
    write(source / "late.json", {})
    with pytest.raises(ValueError, match="snapshot"):
        replay.run_replay(plans, output)


def test_source_mutation_during_response_stops_requests_and_invalidates_comparisons(exported):
    plans, source, output = exported

    def respond(request):
        write(source / "late.json", {})
        return httpx.Response(200, json=completion())

    with client_with(respond) as client:
        result = replay.run_replay(plans, output, client=client)
    assert result["request_count"] == 1 and result["source_files_unchanged"] is False
    assert result["input_integrity_verified"] is False
    assert all(row["status"] == "unknown" for row in result["comparisons"])
    assert all(
        row["reason"] == "source_export_or_implementation_changed"
        for row in rows(output / "results.jsonl")[1:]
    )


def test_pacing_preserves_requests_and_rechecks_sources_after_waiting(exported):
    plans, source, output = exported

    class Pacer:
        def before_request(self, messages, tools):
            assert messages and tools
            write(source / "late.json", {})
            return "ticket", 0.5

    with client_with(lambda request: pytest.fail("Source changed during pacing")) as client:
        result = replay.run_replay(plans, output, client=client, pacer=Pacer())
    assert result["request_count"] == 0 and result["unknown_slots"] == 4


def test_pacing_usage_update_failure_does_not_erase_observed_response(exported):
    class Pacer:
        def before_request(self, messages, tools):
            return "ticket", 0.0

        def after_response(self, ticket, tokens):
            assert ticket == "ticket" and tokens == 13
            raise ValueError("fixture-private-key")

    plans, _, output = exported
    with client_with(lambda request: httpx.Response(200, json=completion())) as client:
        result = replay.run_replay(plans, output, client=client, pacer=Pacer(), max_requests=1)
    assert result["observed_slots"] == 1
    assert rows(output / "results.jsonl")[0]["pacing_update_error_type"] == "ValueError"


def test_pacing_cannot_mutate_bound_primary_request(exported):
    class Pacer:
        def before_request(self, messages, tools):
            messages.clear()
            tools.clear()
            return "ticket", 0.0

        def after_response(self, ticket, tokens):
            pass

    plans, source, output = exported
    requests = []

    def respond(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, json=completion())

    with client_with(respond) as client:
        replay.run_replay(plans, output, client=client, pacer=Pacer(), max_requests=1)
    assert requests[0] == rows(source / "events.jsonl")[0]["data"]["body"]


def test_oversize_request_retains_unknown_without_transport(exported, monkeypatch):
    monkeypatch.setattr(replay, "MAX_REQUEST_BYTES", 1)
    plans, _, output = exported
    with client_with(lambda request: pytest.fail("Request exceeds byte budget")) as client:
        result = replay.run_replay(plans, output, client=client)
    assert result["request_count"] == 0 and result["unknown_slots"] == 4


def test_fresh_output_and_pacing_state_protect_both_input_trees(exported):
    plans, source, output = exported
    for destination in (plans, plans / "nested", source / "nested"):
        with pytest.raises(ValueError, match="fresh"):
            replay.run_replay(plans, destination)

    class Pacer:
        path = source / "pacing.json"

    with pytest.raises(ValueError, match="Pacing state"):
        replay.run_replay(plans, output, pacer=Pacer())
    replay.run_replay(plans, output)
    with pytest.raises(ValueError, match="fresh"):
        replay.run_replay(plans, output)


def test_retry_enabled_client_rejected(exported):
    with client_with(lambda request: pytest.fail("No retry-enabled client")) as client:
        client.max_retries = 1
        with pytest.raises(ValueError, match="disable SDK retries"):
            replay.run_replay(exported[0], exported[2], client=client)


def test_response_secret_is_redacted_and_non_english_stays_out_of_jsonl(exported):
    plans, _, output = exported
    with client_with(
        lambda request: httpx.Response(200, json=completion(text="fixture-private-key 中文"))
    ) as client:
        result = replay.run_replay(plans, output, client=client, max_requests=1)
    assert result["unknown_slots"] == 4
    assert rows(output / "results.jsonl")[0]["reason"] == "non_english_response"
    assert "fixture-private-key" not in (output / "response-0001.bin").read_text()
    assert "中文" not in (output / "results.jsonl").read_text()


def test_native_verified_prefix_replays_original_model_body_without_executing_tools(tmp_path, monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: pytest.fail("Real network forbidden"))
    source = tmp_path / "native"
    before = native_recorded_run(source, no_arguments=True)
    plans = tmp_path / "plans"
    causal_v2.export_run(source, plans)
    from agentdojo.functions_runtime import FunctionsRuntime

    monkeypatch.setattr(
        FunctionsRuntime, "run_function", lambda *a, **k: pytest.fail("Replay must not execute a tool")
    )
    bodies = []

    def respond(request):
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json=completion(function="get_unread_emails"))

    with client_with(respond) as client:
        result = replay.run_replay(plans, tmp_path / "replay", client=client)
    assert result["request_count"] == 2 and result["observed_slots"] == 2
    assert result["source_hashes_before"] == result["source_hashes_after"] == before
    assert bodies[0]["model"] == "openai/gpt-oss-20b"
    assert result["comparisons"][0]["baseline_reproduced_original_sink"] is True
    assert result["comparisons"][0]["observed_sink_proposal_changed"] is False


def test_report_time_source_mutation_cannot_hide_integrity_failure(exported, monkeypatch):
    plans, source, output = exported
    original = replay._report

    def changed(*args):
        write(source / "late.json", {})
        original(*args)

    monkeypatch.setattr(replay, "_report", changed)
    result = replay.run_replay(plans, output)
    assert result["input_integrity_verified"] is False
    assert json.loads((output / "summary.json").read_text())["source_files_unchanged"] is False

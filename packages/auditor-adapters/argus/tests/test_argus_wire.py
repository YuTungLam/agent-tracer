"""The DeepSeek wire shim, against a fake loopback upstream."""

from __future__ import annotations

import json

import httpx
import openai
import pytest
from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
from agentdojo.functions_runtime import FunctionsRuntime, make_function
from agentdojo.types import ChatSystemMessage, ChatUserMessage, text_content_block_from_string
from openai._types import NOT_GIVEN

from argus_wire import (
    SAMPLE_HEADER,
    STAGE_HEADER,
    BudgetRefused,
    DeepSeekWireClient,
    SampleContext,
    WirePolicy,
    WireSession,
    is_budget_refusal,
    prepare_request,
    require_loopback_base_url,
)

MARKER = "UNIQUE-PROMPT-MARKER-7f3a"


def lookup(city: str) -> str:
    """Look up a city.

    :param city: the city name
    """
    return city


def _client(session, ctx, base_url):
    return DeepSeekWireClient(openai.OpenAI(base_url=base_url, api_key="sk-test", max_retries=0), session, ctx)


def _agent_messages():
    return [ChatSystemMessage(role="system", content=[text_content_block_from_string("You are helpful.")]),
            ChatUserMessage(role="user", content=[text_content_block_from_string(f"Find {MARKER}")])]


def test_prepare_request_maps_wire_and_pins_model():
    ctx = SampleContext("banking/user_task_0/TI", "warrant")
    request = prepare_request({
        "model": "deepseek-flash",
        "messages": [{"role": "developer", "content": [{"type": "text", "text": "sys"}]},
                     {"role": "tool", "content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}],
                      "tool_call_id": "c1", "name": "lookup"}],
        "temperature": NOT_GIVEN, "reasoning_effort": NOT_GIVEN, "max_completion_tokens": 77,
    }, WirePolicy(stage="S1"), ctx)
    assert request["messages"][0] == {"role": "system", "content": "sys"}
    assert request["messages"][1] == {"role": "tool", "content": "a\nb", "tool_call_id": "c1"}
    assert "temperature" not in request and "reasoning_effort" not in request
    assert request["max_tokens"] == 77 and "max_completion_tokens" not in request
    assert request["extra_body"] == {"thinking": {"type": "disabled"}}
    assert request["extra_headers"] == {SAMPLE_HEADER: ctx.sample_id, STAGE_HEADER: "S1"}


def test_prepare_request_refuses_other_models_and_reasoning():
    ctx = SampleContext("x", "none")
    with pytest.raises(ValueError, match="pinned model"):
        prepare_request({"model": "gpt-4o-mini", "messages": []}, WirePolicy(), ctx)
    with pytest.raises(ValueError, match="reasoning_effort"):
        prepare_request({"model": "deepseek-flash", "messages": [], "reasoning_effort": "low"}, WirePolicy(), ctx)
    with pytest.raises(ValueError, match="thinking"):
        prepare_request({"model": "deepseek-flash", "messages": [], "extra_body": {"thinking": {"type": "enabled"}}},
                        WirePolicy(), ctx)


def test_agent_temperature_variant_applies_to_agent_requests_only():
    ctx = SampleContext("x", "none")
    policy = WirePolicy(agent_temperature=0.0)
    agent = prepare_request({"model": "deepseek-flash", "messages": [], "tools": [{"type": "function"}],
                             "temperature": NOT_GIVEN}, policy, ctx)
    judge = prepare_request({"model": "deepseek-flash", "messages": [], "temperature": 0.3}, policy, ctx)
    assert agent["temperature"] == 0.0 and judge["temperature"] == 0.3


def test_agent_path_reaches_upstream_in_deepseek_wire(upstream, tmp_path):
    session = WireSession(WirePolicy(stage="S1"), tmp_path / "requests.jsonl")
    ctx = SampleContext("banking/user_task_0/TI", "none")
    llm = OpenAILLM(client=_client(session, ctx, upstream.url), model="deepseek-flash")
    runtime = FunctionsRuntime([make_function(lookup)])
    _, _, _, out, _ = llm.query("q", runtime, messages=_agent_messages())
    assert out[-1]["role"] == "assistant"
    sent = upstream.requests[0]
    body = sent["body"]
    assert body["model"] == "deepseek-flash"
    assert [m["role"] for m in body["messages"]] == ["system", "user"]
    assert all(isinstance(m["content"], str) for m in body["messages"])
    assert body["thinking"] == {"type": "disabled"}
    assert "temperature" not in body  # agentdojo 0.1.35 drops T=0.0; the artifact behaviour is kept
    assert "max_completion_tokens" not in body and "reasoning_effort" not in body
    assert sent["headers"][SAMPLE_HEADER.lower()] == ctx.sample_id and sent["headers"][STAGE_HEADER.lower()] == "S1"
    assert (ctx.requests, ctx.agent_requests, ctx.prompt_tokens, ctx.completion_tokens) == (1, 1, 100, 5)
    log = (tmp_path / "requests.jsonl").read_text(encoding="utf-8")
    assert MARKER not in log and "sk-test" not in log
    entry = json.loads(log)
    assert entry["kind"] == "agent" and entry["status"] == "ok" and entry["roles"] == ["system", "user"]
    assert entry["list_content"] is False and entry["thinking"] == {"type": "disabled"}


def test_judge_path_keeps_json_mode_and_t0(upstream, tmp_path):
    from agentlure.warrant.llm import Judge

    session = WireSession(WirePolicy(), tmp_path / "r.jsonl")
    ctx = SampleContext("s", "warrant")
    judge = Judge(_client(session, ctx, upstream.url), "deepseek-flash")
    reply = judge("Initialization", f"Extract invariants {MARKER}", max_tokens=400)
    assert reply["failed"] == []
    body = upstream.requests[0]["body"]
    assert body["response_format"] == {"type": "json_object"}
    assert body["temperature"] == 0.0 and body["max_tokens"] == 400
    assert body["thinking"] == {"type": "disabled"} and "tools" not in body
    assert ctx.judge_requests == 1 and judge.usage_report()["all"]["failures"] == 0


def test_upstream_budget_refusal_latches_and_is_not_retried(upstream, tmp_path):
    from agentlure.warrant.llm import Judge

    upstream.refuse_after = 0
    session = WireSession(WirePolicy(), tmp_path / "r.jsonl")
    ctx = SampleContext("s", "warrant")
    client = _client(session, ctx, upstream.url)
    assert Judge(client, "deepseek-flash")("InvChecker", "check") is None  # fail closed
    assert len(upstream.requests) == 1  # no judge retry after a budget refusal
    assert session.latched and ctx.refused == 1 and session.totals()["refused"] == 1
    llm = OpenAILLM(client=client, model="deepseek-flash")
    with pytest.raises(openai.BadRequestError):  # tenacity does not retry BadRequestError
        llm.query("q", FunctionsRuntime([make_function(lookup)]), messages=_agent_messages())
    assert len(upstream.requests) == 1  # latched: nothing else left the process
    assert ctx.refused == 2 and session.totals()["refused"] == 2
    statuses = [json.loads(line)["status"] for line in (tmp_path / "r.jsonl").read_text().splitlines()]
    assert statuses == ["refused_upstream", "refused_local"]


def test_adapter_request_cap(upstream, tmp_path):
    session = WireSession(WirePolicy(max_requests=2), None)
    ctx = SampleContext("s", "none")
    client = _client(session, ctx, upstream.url)
    for _ in range(2):
        client.chat.completions.create(model="deepseek-flash", messages=[{"role": "user", "content": "x"}])
    with pytest.raises(BudgetRefused):
        client.chat.completions.create(model="deepseek-flash", messages=[{"role": "user", "content": "x"}])
    assert len(upstream.requests) == 2 and session.totals()["requests"] == 2 and session.latched


def test_non_budget_errors_are_recorded_not_latched(upstream):
    upstream.fail_status = 500
    session = WireSession(WirePolicy(), None)
    ctx = SampleContext("s", "none")
    with pytest.raises(openai.InternalServerError):
        _client(session, ctx, upstream.url).chat.completions.create(
            model="deepseek-flash", messages=[{"role": "user", "content": "x"}])
    assert not session.latched and ctx.errors == [{"type": "InternalServerError", "http_status": 500}]
    assert not is_budget_refusal(openai.APIConnectionError(request=httpx.Request("POST", upstream.url)))


@pytest.mark.parametrize("url", ["http://127.0.0.1:8123/v1", "http://localhost:9/v1", "http://[::1]:7/v1"])
def test_loopback_base_url_accepted(url):
    assert require_loopback_base_url({"OPENAI_BASE_URL": url}) == url


@pytest.mark.parametrize("env", [{}, {"OPENAI_BASE_URL": "https://api.deepseek.com"},
                                 {"OPENAI_BASE_URL": "https://api.openai.com/v1"}])
def test_direct_provider_urls_refused(env):
    with pytest.raises(SystemExit):
        require_loopback_base_url(env)


def test_cli_runs_only_under_the_guard():
    from run_argus import guard_url

    url = "http://127.0.0.1:5555/v1"
    assert guard_url({"OPENAI_BASE_URL": url, "AUDITOR_GUARD_URL": url, "OPENAI_API_KEY": "t"}) == url
    for env in ({"OPENAI_BASE_URL": url, "OPENAI_API_KEY": "t"},  # a loopback URL that is not the guard
                {"OPENAI_BASE_URL": url, "AUDITOR_GUARD_URL": "http://127.0.0.1:1/v1", "OPENAI_API_KEY": "t"},
                {"OPENAI_BASE_URL": url, "AUDITOR_GUARD_URL": url},
                {"OPENAI_BASE_URL": "https://api.deepseek.com", "AUDITOR_GUARD_URL": "https://api.deepseek.com",
                 "OPENAI_API_KEY": "t"}):
        with pytest.raises(SystemExit):
            guard_url(env)

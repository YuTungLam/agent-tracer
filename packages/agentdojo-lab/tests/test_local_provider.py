"""New endpoint routing and native wire contracts, using only in-process HTTP mocks."""

import json
import socket
import tomllib
from copy import deepcopy

import httpx
import openai
import pytest
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite
from test_causal_v2 import fixture
from test_online_causal import completion as judge_completion
from test_online_causal import proposal_event, runtime_event
from test_semantic import FakeEncoder

from agentdojo_lab import (
    causal_replay,
    causal_v2_audit,
    cli,
    counterfactual_audit,
    paper_audit,
    providers,
    runner,
    semantic,
)
from agentdojo_lab.counterfactual_audit import ConfiguredCounterfactualJudge, request_body
from agentdojo_lab.groq_adapter import GroqLLM
from agentdojo_lab.online_causal import OnlineCausalAuditor
from agentdojo_lab.providers import EndpointSettings
from agentdojo_lab.runner import ROOT, RunConfig, load_config, run_clean

LOCAL = {
    "provider": "openai_compatible", "model": "scout-fixture",
    "base_url": "http://127.0.0.1:8000/v1", "api_key_env": "LOCAL_LLM_API_KEY",
}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: pytest.fail("Unexpected network request"))
    monkeypatch.setattr(runner, "load_dotenv", lambda *a, **k: None)


def response(message):
    return {
        "id": "local-mock", "object": "chat.completion", "created": 0, "model": LOCAL["model"],
        "choices": [{"index": 0, "finish_reason": "stop", "message": message}],
        "usage": {"prompt_tokens": 12, "completion_tokens": 3, "total_tokens": 15},
    }


def test_existing_groq_configs_keep_serialized_defaults():
    config = load_config(ROOT / "configs/groq.toml")
    assert config.provider == "groq"
    assert not {"base_url", "api_key_env", "causal_endpoint"}.intersection(config.model_dump())
    assert config.primary_endpoint().url == runner.GROQ_BASE_URL
    assert config.judge_endpoint().model_dump() == {"provider": "groq", "model": "openai/gpt-oss-120b"}
    assert RunConfig.model_validate(config.model_dump()).model_dump() == config.model_dump()
    local = load_config(ROOT / "configs/local_scout.toml")
    assert local.primary_endpoint() == local.judge_endpoint()
    assert local.reasoning_effort is None
    assert RunConfig.model_validate(local.model_dump()).model_dump() == local.model_dump()


@pytest.mark.parametrize("missing", ["base_url", "api_key_env", "model"])
def test_local_provider_requires_explicit_selection(missing):
    data = {key: value for key, value in LOCAL.items() if key != missing}
    with pytest.raises(ValueError, match="explicit"):
        RunConfig(**data)


@pytest.mark.parametrize("url", [
    "https://name:secret@example.invalid/v1", "https://example.invalid/v1?key=secret",
    "https://example.invalid/v1#secret", "file:///tmp/endpoint", "http://localhost:999999/v1",
    "http://localhost/v1\n",
])
def test_endpoint_rejects_secret_bearing_or_invalid_urls_without_echoing_them(url):
    with pytest.raises(ValueError) as error:
        RunConfig(**{**LOCAL, "base_url": url})
    assert url not in str(error.value)


def test_online_local_primary_requires_explicit_judge():
    with pytest.raises(ValueError, match="causal_endpoint"):
        RunConfig(**LOCAL, online_causal_audit=True)
    with pytest.raises(ValueError, match="reasoning_effort"):
        RunConfig(**LOCAL, reasoning_effort="low")


def test_missing_local_key_cannot_use_a_groq_key_or_create_output(monkeypatch, tmp_path):
    monkeypatch.delenv("LOCAL_LLM_API_KEY", raising=False)
    monkeypatch.setenv("GROQ_API_KEY", "unrelated-remote-key")
    monkeypatch.setattr(EndpointSettings, "client", lambda *a, **k: pytest.fail("Client created"))
    with pytest.raises(ValueError, match="LOCAL_LLM_API_KEY"):
        run_clean(RunConfig(**LOCAL), output=tmp_path / "never-created")
    assert not (tmp_path / "never-created").exists()


def test_endpoint_client_uses_declared_loopback_and_disables_sdk_retries(monkeypatch):
    captured = {}
    sentinel = object()

    def construct(**kwargs):
        captured.update(kwargs)
        return sentinel

    monkeypatch.setattr(providers.openai, "OpenAI", construct)
    endpoint = EndpointSettings(**LOCAL)
    assert endpoint.client(key="fixture-private-key", timeout=60.0) is sentinel
    assert captured == {
        "api_key": "fixture-private-key",
        "base_url": LOCAL["base_url"],
        "max_retries": 0,
        "timeout": 60.0,
    }


def test_local_round_trip_preserves_tool_arguments_ids_and_output():
    received, executed = [], []
    arguments = {"recipients": ["user@example.invalid", "other@example.invalid"], "comment": None}
    tool_text = "  Source content: café\nunchanged second line\n"

    def handler(request):
        assert str(request.url) == LOCAL["base_url"] + "/chat/completions"
        received.append(json.loads(request.content))
        message = (
            {"role": "assistant", "content": None, "tool_calls": [{
                "id": "call-local-1", "type": "function",
                "function": {"name": "record", "arguments": json.dumps(arguments)},
            }]}
            if len(received) == 1 else {"role": "assistant", "content": "Finished."}
        )
        return httpx.Response(200, json=response(message))

    runtime = FunctionsRuntime()

    @runtime.register_function
    def record(recipients: list[str], comment: str | None) -> str:
        """Record a synthetic call.

        :param recipients: Synthetic recipients.
        :param comment: Optional comment.
        """
        executed.append({"recipients": recipients, "comment": comment})
        return tool_text

    with openai.OpenAI(
        api_key="local-fixture-key", base_url=LOCAL["base_url"], max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    ) as client:
        llm = GroqLLM(client, LOCAL["model"], provider="openai_compatible", max_completion_tokens=128)
        pipeline = AgentPipeline([
            SystemMessage("Use the synthetic tool."), InitQuery(), llm,
            ToolsExecutionLoop([ToolsExecutor(), llm], max_iters=2),
        ])
        pipeline.query("Record these recipients.", runtime)
    assert executed == [arguments]
    assert len(received) == llm.stats["request_count"] == 2
    assert all("reasoning_effort" not in body and body["max_completion_tokens"] == 128 for body in received)
    assert received[1]["messages"][-1] == {
        "role": "tool", "tool_call_id": "call-local-1", "content": tool_text,
    }
    assert llm.name == "openai_compatible_scout-fixture"


def native_handler(requests, *, error_key=None):
    suite = get_suite("v1.2.2", "workspace")
    task = suite.user_tasks["user_task_0"]
    calls = task.ground_truth(suite.load_and_inject_default_environment({}))

    def handle(request):
        body = json.loads(request.content)
        requests.append((str(request.url), body))
        if error_key is not None:
            return httpx.Response(400, json={"error": {
                "code": "context_length_exceeded", "message": "Rejected credential " + error_key,
            }})
        message = (
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": f"call-native-{i}", "type": "function",
                 "function": {"name": call.function, "arguments": json.dumps(call.args)}}
                for i, call in enumerate(calls)
            ]}
            if len(requests) == 1 else {"role": "assistant", "content": task.GROUND_TRUTH_OUTPUT}
        )
        return httpx.Response(200, json=response(message))

    return handle


def test_runner_routes_primary_and_online_judge_to_separate_explicit_clients(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCAL_LLM_API_KEY", "primary-fixture-secret")
    monkeypatch.setenv("LOCAL_JUDGE_KEY", "judge-fixture-secret")
    monkeypatch.setattr(semantic, "LocalMiniLMEncoder", lambda *a, **k: FakeEncoder())
    calls, requests = [], []
    handler = native_handler(requests)
    original = openai.OpenAI

    def client(**kwargs):
        calls.append(kwargs.copy())
        assert "groq" not in kwargs["base_url"]
        return original(**kwargs, http_client=httpx.Client(transport=httpx.MockTransport(handler)))

    monkeypatch.setattr(providers.openai, "OpenAI", client)
    judge = {**LOCAL, "model": "judge-fixture", "base_url": "http://127.0.0.1:8001/v1",
             "api_key_env": "LOCAL_JUDGE_KEY"}
    config = RunConfig(
        **LOCAL, causal_endpoint=judge, online_causal_audit=True, online_provenance=True,
        lineage_namespace="local-transport-test", provenance_policy=str(ROOT / "configs/workspace_policy_v1.yaml"),
        semantic_model="synthetic-encoder", semantic_revision="synthetic-revision",
    )
    output = tmp_path / "local-run"
    result = run_clean(config, output=output)
    assert result["status"] == "completed" and result["task_success_count"] == 1
    assert result["recording"]["complete"] is True
    assert [item["base_url"] for item in calls] == [judge["base_url"], LOCAL["base_url"]]
    assert [item["api_key"] for item in calls] == ["judge-fixture-secret", "primary-fixture-secret"]
    assert all(item["max_retries"] == 0 for item in calls)
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["mode"] == "live-openai-compatible"
    assert manifest["online_causal_audit"]["model"] == "judge-fixture"
    assert manifest["endpoint"] == LOCAL["base_url"]
    for path in output.rglob("*"):
        if path.is_file():
            assert b"primary-fixture-secret" not in path.read_bytes()
            assert b"judge-fixture-secret" not in path.read_bytes()


def test_native_caught_local_api_error_is_redacted_and_not_retried(monkeypatch, tmp_path):
    key = "fixture-private-bearer-value"
    monkeypatch.setenv("LOCAL_LLM_API_KEY", key)
    requests = []
    handler = native_handler(requests, error_key=key)
    original = openai.OpenAI
    monkeypatch.setattr(providers.openai, "OpenAI", lambda **kw: original(
        **kw, http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    )
    output = tmp_path / "failed"
    result = run_clean(RunConfig(**LOCAL), output=output)
    assert result["error_task_count"] == 1 and len(requests) == 1
    assert "[REDACTED]" in result["tasks"][0]["error"]
    for path in output.rglob("*"):
        if path.is_file():
            assert key.encode() not in path.read_bytes()


def test_online_local_judge_sends_bound_json_without_reasoning_or_tools(tmp_path):
    call, graph = fixture(second=True, repeat=True)
    original = deepcopy((call, graph))
    bodies = []

    def handler(request):
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json=judge_completion(False))

    with openai.OpenAI(api_key="judge-fixture-key", base_url=LOCAL["base_url"], max_retries=0,
                      http_client=httpx.Client(transport=httpx.MockTransport(handler))) as client:
        auditor = OnlineCausalAuditor(
            tmp_path / "causal-online.jsonl", client=client, model=LOCAL["model"], reasoning_effort=None,
        )
        receipt = auditor.audit_proposal(proposal_event(), call, graph)
        auditor.runtime(runtime_event())
        status = auditor.close(graph)
    assert receipt["valid_judgment_count"] == 3 and status["request_count"] == 3
    assert (call, graph) == original
    for body in bodies:
        assert body["model"] == LOCAL["model"]
        assert body["response_format"] == {"type": "json_object"}
        assert not {"tools", "tool_choice", "functions", "reasoning_effort"}.intersection(body)


def test_configured_deferred_judge_uses_local_wire_contract():
    captured = []

    def handler(request):
        captured.append(json.loads(request.content))
        return httpx.Response(200, json=judge_completion(False))

    with openai.OpenAI(api_key="judge-fixture-key", base_url=LOCAL["base_url"], max_retries=0,
                      http_client=httpx.Client(transport=httpx.MockTransport(handler))) as client:
        judge = ConfiguredCounterfactualJudge(EndpointSettings(**LOCAL), client=client)
        probe = {"source_id": "source", "context_a": [], "context_b": [], "sink": {}}
        judge(request_body(probe, judge.metadata))
    assert captured[0]["model"] == LOCAL["model"]
    assert not {"tools", "tool_choice", "functions", "reasoning_effort"}.intersection(captured[0])
    assert judge.metadata["base_url"] == LOCAL["base_url"]


def test_legacy_live_auditors_reject_local_sources_before_network(monkeypatch, tmp_path, capsys):
    source = tmp_path / "local"
    source.mkdir()
    (source / "manifest.json").write_text(json.dumps({"config": LOCAL}))
    monkeypatch.setattr(causal_v2_audit, "_new_client", lambda: pytest.fail("Groq fallback"))
    with pytest.raises(ValueError, match="explicitly configured auditor"):
        paper_audit.run(source, tmp_path / "paper", live=True, max_requests=1)
    monkeypatch.setattr(causal_v2_audit, "_validate_export", lambda path: ([], source, {}, {}, []))
    with pytest.raises(ValueError, match="explicitly configured auditor"):
        causal_v2_audit.run_audit(tmp_path / "plans", tmp_path / "joint", live=True)
    monkeypatch.setattr(causal_replay, "_validate_export", lambda path: ([], source, {}, {}, []))
    monkeypatch.setattr(causal_replay, "_new_client", lambda: pytest.fail("Replay Groq fallback"))
    with pytest.raises(ValueError, match="explicitly configured auditor"):
        causal_replay.run_replay(tmp_path / "plans", tmp_path / "replay", live=True)
    assert cli.main(["counterfactual", "--run", str(source), "--output", str(tmp_path / "single"), "--live"]) == 2
    assert "explicitly configured auditor" in capsys.readouterr().err
    assert not any((tmp_path / name).exists() for name in ("paper", "joint", "single", "replay"))


def test_cli_passes_explicit_judge_config_and_closes_client(monkeypatch, tmp_path):
    captured, closed = [], []

    class Judge:
        def __init__(self, endpoint, **kwargs):
            captured.append(endpoint)

        def close(self):
            closed.append(True)

    monkeypatch.setattr(counterfactual_audit, "ConfiguredCounterfactualJudge", Judge)
    monkeypatch.setattr(counterfactual_audit, "audit_run", lambda *a, **k: {"fixture": True})
    assert cli.main([
        "counterfactual", "--run", str(tmp_path / "input"), "--output", str(tmp_path / "output"),
        "--live", "--judge-config", str(ROOT / "configs/local_scout_judge.toml"),
    ]) == 0
    expected = tomllib.loads((ROOT / "configs/local_scout_judge.toml").read_text())
    assert captured == [EndpointSettings(**expected)] and closed == [True]

"""Fixture-only plumbing checks; these are not real LLM benchmark results."""

import json

import openai
import pytest
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.benchmark import benchmark_suite_without_injections
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suite

from agentdojo_lab.groq_adapter import GroqLLM
from agentdojo_lab.offline import make_offline_client

MODEL = "openai/gpt-oss-20b"


def test_fixture_runs_native_pipeline_tools_evaluator_and_logging(tmp_path, monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    suite = get_suite("v1.2.2", "workspace")
    task = suite.get_user_task_by_id("user_task_0")

    with make_offline_client(suite, task, MODEL) as client:
        llm = GroqLLM(client, MODEL)
        pipeline = AgentPipeline.from_config(
            PipelineConfig(
                llm=llm,
                model_id=None,
                defense=None,
                system_message_name=None,
                system_message=None,
            )
        )
        pipeline.name = "offline-fixture-not-real-llm"
        with OutputLogger(str(tmp_path)):
            results = benchmark_suite_without_injections(
                pipeline,
                suite,
                logdir=tmp_path,
                force_rerun=True,
                user_tasks=[task.ID],
                benchmark_version="v1.2.2",
            )

    assert results["utility_results"] == {("user_task_0", ""): True}
    assert results["injection_tasks_utility_results"] == {}
    assert llm.stats == {"request_count": 2, "prompt_tokens": 0, "completion_tokens": 0}
    logs = list(tmp_path.rglob("*.json"))
    assert len(logs) == 1
    trace = json.loads(logs[0].read_text())
    tool_messages = [message for message in trace["messages"] if message["role"] == "tool"]
    assert len(tool_messages) == 1
    assert tool_messages[0]["tool_call"]["function"] == "search_calendar_events"
    assert tool_messages[0]["tool_call_id"] == "call-offline-fixture-1"
    assert tool_messages[0]["error"] is None
    assert "Networking Event" in tool_messages[0]["content"][0]["content"]
    assert trace["utility"] is True
    assert trace["injections"] == {}
    assert trace["attack_type"] is None
    assert trace["benchmark_version"] == "v1.2.2"
    assert trace["agentdojo_package_version"]
    assert trace["evaluation_timestamp"]
    assert trace["duration"] >= 0
    assert trace["pipeline_name"] == "offline-fixture-not-real-llm"


@pytest.mark.parametrize(
    "tool_result",
    [
        None,
        {"role": "tool", "tool_call_id": "call-offline-fixture-1", "content": "  "},
        {"role": "tool", "tool_call_id": "wrong-call-id", "content": "Some result"},
    ],
)
def test_fixture_rejects_missing_empty_or_unmatched_tool_results(tool_result):
    suite = get_suite("v1.2.2", "workspace")
    task = suite.get_user_task_by_id("user_task_0")
    with make_offline_client(suite, task, MODEL) as client:
        first = client.chat.completions.create(
            model=MODEL, messages=[{"role": "user", "content": task.PROMPT}]
        )
        assert first._request_id == "offline-fixture-1"
        assert first.usage.total_tokens == 0
        history = [{"role": "user", "content": task.PROMPT}]
        if tool_result is not None:
            history.append(tool_result)
        with pytest.raises(openai.BadRequestError, match="requires nonempty tool results"):
            client.chat.completions.create(model=MODEL, messages=history)


def test_fixture_rejects_requests_after_its_two_responses():
    suite = get_suite("v1.2.2", "workspace")
    task = suite.get_user_task_by_id("user_task_0")
    history = [{"role": "user", "content": task.PROMPT}]
    with make_offline_client(suite, task, MODEL) as client:
        client.chat.completions.create(model=MODEL, messages=history)
        history.append(
            {"role": "tool", "tool_call_id": "call-offline-fixture-1", "content": "fixture result"}
        )
        second = client.chat.completions.create(model=MODEL, messages=history)
        assert second.choices[0].message.content == task.GROUND_TRUTH_OUTPUT
        assert second._request_id == "offline-fixture-2"
        with pytest.raises(openai.BadRequestError, match="fixture exhausted"):
            client.chat.completions.create(model=MODEL, messages=history)


@pytest.mark.parametrize(
    "version,suite_name,task_id",
    [("v1.2", "workspace", "user_task_0"), ("v1.2.2", "workspace", "user_task_1")],
)
def test_fixture_rejects_unsupported_scope(version, suite_name, task_id):
    suite = get_suite(version, suite_name)
    task = suite.get_user_task_by_id(task_id)
    with pytest.raises(ValueError, match="supports only workspace v1.2.2 user_task_0"):
        make_offline_client(suite, task, MODEL)

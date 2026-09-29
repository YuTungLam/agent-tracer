"""Deterministic plumbing fixture; this is not a real LLM experiment.

Only the normal, read-only workspace v1.2.2 ``user_task_0`` is supported.
The fixture supplies known tool calls and the known answer, while AgentDojo
executes its actual tools and evaluates its actual task. Passing this fixture
demonstrates integration only, not model performance or security.
"""

import json

import httpx
import openai
from agentdojo.base_tasks import BaseUserTask
from agentdojo.task_suite.task_suite import TaskSuite


def make_offline_client(suite: TaskSuite, task: BaseUserTask, model: str) -> openai.OpenAI:
    """Return an SDK client with two scripted responses and no network transport.

    The caller owns the returned client and should close it. No environment
    credentials are read. The second response requires a nonempty native tool
    result for each fixture call ID; further completion requests are rejected.
    """
    if suite.name != "workspace" or suite.benchmark_version != (1, 2, 2) or task.ID != "user_task_0":
        raise ValueError("Offline fixture supports only workspace v1.2.2 user_task_0")
    if not model or not model.strip():
        raise ValueError("Offline fixture requires a non-empty model label")

    environment = suite.load_and_inject_default_environment({})
    calls = task.ground_truth(environment)
    fixture_calls = [
        {
            "id": f"call-offline-fixture-{index}",
            "type": "function",
            "function": {"name": call.function, "arguments": json.dumps(call.args)},
        }
        for index, call in enumerate(calls, start=1)
    ]
    expected_ids = {call["id"] for call in fixture_calls}
    request_count = 0

    def reject(message: str) -> httpx.Response:
        return httpx.Response(
            400,
            headers={"x-request-id": f"offline-fixture-{request_count}"},
            json={"error": {"message": message, "type": "invalid_request_error"}},
        )

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        if request.method != "POST" or request.url.path != "/openai/v1/chat/completions":
            return reject("Offline fixture accepts only chat completion requests")
        if request_count > 2:
            return reject("Offline fixture exhausted: exactly two completions are supported")
        payload = json.loads(request.content)
        if payload.get("model") != model:
            return reject("Offline fixture model label does not match the configured model")

        if request_count == 1:
            message = {"role": "assistant", "content": None, "tool_calls": fixture_calls}
            finish_reason = "tool_calls"
        else:
            tool_results = [item for item in payload.get("messages", []) if item.get("role") == "tool"]
            if (
                len(tool_results) != len(fixture_calls)
                or {item.get("tool_call_id") for item in tool_results} != expected_ids
                or any(
                    not isinstance(item.get("content"), str) or not item["content"].strip()
                    for item in tool_results
                )
            ):
                return reject("Offline fixture requires nonempty tool results for every fixture call ID")
            message = {"role": "assistant", "content": task.GROUND_TRUTH_OUTPUT}
            finish_reason = "stop"

        return httpx.Response(
            200,
            headers={"x-request-id": f"offline-fixture-{request_count}"},
            json={
                "id": f"offline-fixture-{request_count}",
                "object": "chat.completion",
                "created": 0,
                "model": model,
                "choices": [{"index": 0, "finish_reason": finish_reason, "message": message}],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            },
        )

    return openai.OpenAI(
        api_key="offline-fixture-not-a-secret",
        base_url="https://offline-fixture.invalid/openai/v1",
        max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(respond)),
    )
